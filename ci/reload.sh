#!/bin/sh
#
# Reload nginx a number of times in a row and look for what a reload leaks.
#
# Every reload builds a new cycle: a new configuration pool, new workers,
# re-opened listening sockets.  Whatever a module allocates or opens per
# cycle and never releases grows the process on every "nginx -s reload" and
# is invisible to a test suite, which starts nginx once.
#
# usage: ci/reload.sh <nginx binary>
#
# Set RELOAD_LOAD_MODULE to the path of the .so to exercise a loadable
# build -- or, here, to both of them separated by a space and in load
# order, the stream one first.  RELOADS sets a different number of rounds,
# RELOAD_PORT moves the listener.
#
# ci/reload.conf carries the part that differs per module.  It is sourced,
# with $WORK and $PORT already set, and defines:
#
#     RELOAD_STREAM  directives for a stream block, may be empty; the
#                    block itself is left out when it is
#     RELOAD_HTTP    directives for the http block, may be empty
#     RELOAD_SERVER  directives for the server block
#     RELOAD_EXPECT  the body the probe below has to return
#     reload_probe() prints what the server answered
#
# Asserted after every reload:
#
#   The module still answers.  Catches per-cycle state that is gone or
#   stale after the handover.
#
#   The worker generation drains back to the configured count.  A worker
#   that outlives its cycle is the leak in process form: the server ends up
#   carrying one worker per reload it has served.
#
#   The master's descriptor count does not move.  A listening socket or a
#   channel descriptor kept from the previous cycle is countable, and a
#   worker cannot see it, since it only knows the cycle it was forked into.
#   Needs /proc and is skipped with a message where there is none.
#
#   No worker died by signal.  A crashed and respawned worker looks like a
#   reloaded one from the outside; the error log separates the two.
#
# The master's resident size is not checked.  Measured here, a healthy
# series grows the master by about twenty-five pages per reload, the
# allocator keeping what it has freed, while a leaked cycle pool is a
# handful of pages: a band wide enough not to flap would be wider than
# what it has to catch.

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/reload
PORT=${RELOAD_PORT:-18200}
RELOADS=${RELOADS:-8}

# Two workers, so that "the generation drained" is a statement about a set
# of processes and not about a single one that happens to be replaced.
WORKERS=2

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }
command -v pgrep > /dev/null || { echo "pgrep(1) is needed" >&2; exit 2; }

[ -r "$SRC/ci/reload.conf" ] || {
	echo "ci/reload.sh: ci/reload.conf is missing" >&2
	exit 2
}

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs"

ngx_user=
if [ "$(id -u)" = 0 ]; then
	ngx_user="user root $(id -gn);"
fi

ngx_load=
for so in ${RELOAD_LOAD_MODULE:-}; do
	ngx_load="$ngx_load
load_module $so;"
done

# shellcheck source=reload.conf
. "$SRC/ci/reload.conf"

# A stream block is written only when the module asked for one.  An empty
# "stream { }" is accepted by nginx, but it would pull the subsystem into
# every repository's reload gate, and most of them have nothing to put in
# it.
ngx_stream=
if [ -n "${RELOAD_STREAM:-}" ]; then
	ngx_stream="stream {
$RELOAD_STREAM
}"
fi

cat > "$WORK/conf/nginx.conf" <<EOF
$ngx_load
$ngx_user
worker_processes $WORKERS;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 64; }
$ngx_stream
http {
    access_log off;
$RELOAD_HTTP

    server {
        listen 127.0.0.1:$PORT;
$RELOAD_SERVER
    }
}
EOF

fail=0
note() {
	echo "  $1" >&2
	fail=1
}

echo "--- the configuration is read ---"
"$NGINX" -p "$WORK" -c conf/nginx.conf -t

"$NGINX" -p "$WORK" -c conf/nginx.conf
sleep 1

MASTER=$(cat "$WORK/logs/nginx.pid")

stop() {
	[ -s "$WORK/logs/nginx.pid" ] && kill "$(cat "$WORK/logs/nginx.pid")" 2> /dev/null
	return 0
}
trap stop EXIT

# The set of worker pids, sorted, on one line.  Tells a finished handover
# from one still in flight: while the old generation drains both sets are
# present and any count taken then is noise.
#
# Matched on the process title and not on "every child of the master": a
# module that asks for a cache starts a cache manager and a cache loader,
# which are children too.
workers() {
	pgrep -P "$MASTER" -f 'worker process' 2> /dev/null | sort | tr '\n' ' '
}

master_fds() {
	[ -r "/proc/$MASTER/fd" ] || return 1
	# shellcheck disable=SC2012  # a count of entries, and those names are
	# decimal integers, so they cannot contain a newline
	ls "/proc/$MASTER/fd" 2> /dev/null | wc -l | tr -d ' '
}

# Wait until the master has exactly $WORKERS children and none of them is
# one of the processes that served the previous cycle.
await_generation() {
	before=$1
	n=0
	while [ $n -lt 100 ]; do
		now=$(workers)
		count=$(echo "$now" | wc -w | tr -d ' ')
		if [ "$count" = "$WORKERS" ] && [ "$now" != "$before" ]; then
			overlap=0
			for p in $now; do
				case " $before " in
				*" $p "*) overlap=1 ;;
				esac
			done
			[ "$overlap" = 0 ] && return 0
		fi
		n=$((n + 1))
		sleep 0.1 2> /dev/null || sleep 1
	done
	return 1
}

echo "--- the module answers before the first reload ---"
got=$(reload_probe || true)
if [ "$got" = "$RELOAD_EXPECT" ]; then
	echo "  $got"
else
	note "expected \"$RELOAD_EXPECT\", got \"$got\""
	exit 1
fi

FDS_BASE=$(master_fds || true)
GEN=$(workers)

echo "--- $RELOADS reloads ---"
absorbed=0
answered=0
r=1
while [ $r -le "$RELOADS" ]; do
	"$NGINX" -p "$WORK" -c conf/nginx.conf -s reload
	if await_generation "$GEN"; then
		absorbed=$((absorbed + 1))
	else
		note "reload $r: no fresh worker generation within 10 s"
		r=$((r + 1))
		continue
	fi
	GEN=$(workers)

	got=$(reload_probe || true)
	if [ "$got" = "$RELOAD_EXPECT" ]; then
		answered=$((answered + 1))
	else
		note "reload $r: expected \"$RELOAD_EXPECT\", got \"$got\""
	fi
	r=$((r + 1))
done
echo "  $absorbed of $RELOADS absorbed, $answered answered correctly"

# "absorbed" already means the old generation was gone and a full new one
# had answered, so a separate drain assertion would be the same claim twice.
[ "$absorbed" = "$RELOADS" ] || note "not every reload was absorbed"
[ "$answered" = "$RELOADS" ] || note "the module did not answer after every reload"

echo "--- the master kept its descriptors ---"
FDS_END=$(master_fds || true)
if [ -z "$FDS_BASE" ] || [ -z "$FDS_END" ]; then
	echo "  skipped, /proc/$MASTER/fd is not readable here"
elif [ "$FDS_END" = "$FDS_BASE" ]; then
	echo "  $FDS_END before and after $RELOADS reloads"
else
	note "the count moved $FDS_BASE -> $FDS_END over $RELOADS reloads"
fi

echo "--- no worker died by signal ---"
if grep -qE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$WORK/logs/error.log" 2> /dev/null; then
	grep -nE 'exited on signal|SIGSEGV|SIGABRT|SIGBUS' "$WORK/logs/error.log" | head -5 >&2
	note "see the lines above"
else
	echo "  none"
fi

echo "--- nginx is still running ---"
if kill -0 "$MASTER" 2> /dev/null; then
	echo "  yes"
else
	note "the master is gone"
fi

if grep -qE '\[alert\]|\[crit\]|\[emerg\]' "$WORK/logs/error.log" 2> /dev/null; then
	echo "--- the error log complains ---" >&2
	grep -E '\[alert\]|\[crit\]|\[emerg\]' "$WORK/logs/error.log" | head -5 >&2
	fail=1
fi

[ "$fail" -eq 0 ] || { echo "ci/reload.sh: failed" >&2; exit 1; }
echo "ci/reload.sh: ok"
