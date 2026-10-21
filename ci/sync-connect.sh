#!/bin/sh
#
# Run the authentication checks with a connect(2) that comes back connected.
#
# ngx_event_connect_peer() then returns NGX_OK, and nginx registers no write
# event: a module that installs a write handler and waits for it never hears
# anything again.  That is what bug 299038 on FreeBSD was, and this is the
# check that keeps the fix in place -- without it every request below waits
# for a free LDAP connection and times out.
#
# usage: ci/sync-connect.sh <nginx binary>

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/sync-connect

rm -rf "$WORK"
mkdir -p "$WORK"

cc=${CC:-cc}
command -v "$cc" > /dev/null || { echo "a C compiler is needed" >&2; exit 2; }

lib=$WORK/sync-connect.so
log=$WORK/connects.log

echo "== build the shim"
"$cc" -shared -fPIC -O2 -o "$lib" "$SRC/ci/sync-connect.c" -ldl 2> "$WORK/cc.log" ||
	"$cc" -shared -fPIC -O2 -o "$lib" "$SRC/ci/sync-connect.c" 2>> "$WORK/cc.log" ||
	{ echo "  the shim did not build" >&2; cat "$WORK/cc.log" >&2; exit 2; }
echo "  $lib"

echo "== the whole authentication matrix, with synchronous connects"
AUTH_PRELOAD=$lib SYNC_CONNECT_LOG=$log AUTH_PORT=${SYNC_PORT:-18580} \
	CI_WORK=${CI_WORK:-$SRC/ci-work} "$SRC/ci/auth.sh" "$NGINX" |
	sed 's/^/  /'

echo "== was the forced path taken at all"
if [ ! -s "$log" ]; then
	echo "  nothing was recorded, so the shim never ran" >&2
	exit 1
fi
printf '  %s connects, of them %s came back connected\n' \
	"$(grep -c . "$log")" "$(grep -c 'rc=0' "$log")"
grep -q 'rc=0' "$log" ||
	{ echo "  no connect returned 0, the case was not reached" >&2; exit 1; }

echo "ci/sync-connect.sh: ok"
