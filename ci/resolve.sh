#!/bin/sh
#
# Ask whether a host in a url is asked again, or only once when the
# configuration is read.
#
# The module used to keep the addresses ngx_parse_url() found while the
# configuration was read, so a directory that moved was reached again on the
# next reload and not before.  With auth_ldap_resolver the name is asked
# before every connection, and this is the check that keeps it that way: the
# answer is changed under a running nginx, and nothing is reloaded.
#
# usage: ci/resolve.sh <nginx binary>

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/resolve
PORT=${RESOLVE_PORT:-18590}
DNS=${RESOLVE_DNS_PORT:-15353}

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }
command -v perl > /dev/null || { echo "perl(1) is needed" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"
echo in > "$WORK/html/t.txt"
chmod 644 "$WORK/html/t.txt"

fail=0
note() {
	echo "  $1" >&2
	fail=1
}

LDAP_PORT=$("$SRC/ci/ldap.sh")

# Nothing listens on this one, so the first request cannot get through.
echo 127.0.0.2 > "$WORK/answer"
perl "$SRC/ci/dns.pl" "$DNS" "$WORK/answer" > "$WORK/logs/dns.log" 2>&1 &
dns=$!

cleanup() {
	if [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	kill "$dns" 2>/dev/null || true
	"$SRC/ci/ldap.sh" stop 2>/dev/null || true
	sleep 1
}
trap cleanup EXIT INT TERM

# debug, because the address each attempt went to is what this driver reads
cat > "$WORK/conf/nginx.conf" <<CONF
daemon on;
master_process on;
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $WORK/logs/error.log debug;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $WORK/tmp;

    auth_ldap_resolver 127.0.0.1:$DNS ipv6=off;
    auth_ldap_resolver_timeout 2s;

    ldap_server moving {
        url ldap://directory.test:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        require valid_user;
        connections 1;
        connect_timeout 1s;
        reconnect_timeout 1s;
        request_timeout 3s;
    }

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;

        location = /t.txt {
            auth_ldap "Moving";
            auth_ldap_servers moving;
        }
    }
}
CONF

"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"

waited=0
until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/nothing"; do
	waited=$((waited + 1))
	[ "$waited" -lt 60 ] || { echo "nginx did not come up" >&2; exit 1; }
	sleep 1
done

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$@" || echo 000; }

echo "== a name that answers with an address nothing listens on"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/t.txt")
echo "  $out"
[ "$out" = 500 ] ||
	note "a directory that cannot be reached has to end in 500, got $out"
grep -q "127.0.0.2" "$WORK/logs/error.log" ||
	note "the log does not show that the first answer was used"

echo "== the answer changes, and nothing is reloaded"
echo 127.0.0.1 > "$WORK/answer"

# The module waits out reconnect_timeout and asks the name again; give it a
# few of those before asking once more.
ok=0
i=0
while [ $i -lt 12 ]; do
	sleep 1
	out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/t.txt")
	[ "$out" = 200 ] && { ok=1; break; }
	i=$((i + 1))
done
echo "  after ${i}s: $out"
[ "$ok" = 1 ] ||
	note "the changed answer was not taken up, got $out"
grep -q "127.0.0.1:$LDAP_PORT" "$WORK/logs/error.log" ||
	note "the log does not show that the second answer was used"

echo "== the name was asked more than once"
asked=$(grep -c "Connecting to LDAP server" "$WORK/logs/error.log" || echo 0)
echo "  $asked attempts"
[ "$asked" -ge 2 ] ||
	note "only one attempt was made, so nothing was asked again"

echo "== error log"
if grep -qE '\[(alert|emerg)\]' "$WORK/logs/error.log"; then
	note "alert or emerg in the error log"
	grep -E '\[(alert|emerg)\]' "$WORK/logs/error.log" | head -3 >&2
else
	echo "  clean"
fi

[ "$fail" -eq 0 ] || { echo "ci/resolve.sh: failed" >&2; exit 1; }
echo "ci/resolve.sh: ok"
