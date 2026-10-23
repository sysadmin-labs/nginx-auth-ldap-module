#!/bin/sh
#
# Drive the module over ldaps:// and check what "ssl_check_cert on" is worth.
#
# Four cases, and the last two are the ones that matter: a certificate whose
# chain the configuration does not trust has to be refused, and one that is
# trusted but names something else has to be refused as well.  Before the
# verification was switched on in the module, both of them were let through.
#
# usage: ci/ldaps.sh <nginx binary>

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/ldaps
PORT=${LDAPS_PORT:-18600}
LPORT=${LDAPS_LDAP_PORT:-13900}

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"
echo in > "$WORK/html/t.txt"
chmod 644 "$WORK/html/t.txt"

fail=0
note() { echo "  $1" >&2; fail=1; }

"$SRC/ci/ldap.sh" tls "$LPORT" > /dev/null
CA=${CI_WORK:-$SRC/ci-work}/ldap/tls/ca.crt
CRL_NONE=${CI_WORK:-$SRC/ci-work}/ldap/tls/crl-none.pem
CRL_SERVER=${CI_WORK:-$SRC/ci-work}/ldap/tls/crl-server.pem
[ -f "$CA" ] || { echo "the test ca is missing" >&2; exit 1; }

load=
[ -n "${LDAPS_LOAD_MODULE:-}" ] && load="load_module $LDAPS_LOAD_MODULE;"

server_block() {
	# $1 name, $2 host, $3 ssl_check_cert, $4 ca file or empty,
	# $5 revocation list or empty
	cat <<BLOCK
    ldap_server $1 {
        url ldaps://$2:$LPORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        require valid_user;
        ssl_check_cert $3;
BLOCK
	[ -n "$4" ] && echo "        ssl_ca_file $4;"
	[ -n "${5:-}" ] && echo "        ssl_crl_file $5;"
	cat <<BLOCK
    }
BLOCK
}

write_conf() {
	# $1 file, $2... server blocks already rendered into $WORK/blocks
	{
		echo "$load"
		cat <<CONF
daemon on;
master_process on;
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $2 info;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $WORK/tmp;
CONF
		cat "$WORK/blocks"
		cat <<CONF

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;
CONF
		cat "$WORK/locations"
		cat <<CONF
    }
}
CONF
	} > "$1"
}

start() {
	"$NGINX" -p "$WORK" -c "$1"
	# wait for the port rather than for a second: a fixed wait is what
	# makes a driver flap on a loaded machine
	waited=0
	until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/nothing"; do
		waited=$((waited + 1))
		[ "$waited" -lt 60 ] || { echo "nginx did not come up" >&2; exit 1; }
		sleep 1
	done
}

stop() {
	if [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	sleep 1
}

cleanup() {
	stop
	"$SRC/ci/ldap.sh" stop 2>/dev/null || true
}
trap cleanup EXIT INT TERM

code() { curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@" || echo 000; }

# A server whose certificate is refused never has a usable connection, so
# the request waits for one until its own request_timeout runs out, ten
# seconds by default, and is then answered 500: the module could not decide,
# which is not the same as a wrong password.  That wait is why these two
# cases get a longer leash than the rest.
refused() { curl -s -o /dev/null -w '%{http_code}' --max-time "${LDAPS_TMO:-25}" "$@" || echo 000; }

# --- the three cases that share one nginx, and so one certificate store
{
	server_block off      127.0.0.1 off "";
	server_block byname   localhost on  "$CA";
	server_block byaddr   127.0.0.1 on  "$CA";
	server_block systemca localhost on  "";
	server_block bychain  127.0.0.1 chain "$CA";
	server_block crlok    localhost on  "$CA" "$CRL_NONE";
	server_block crlbad   localhost on  "$CA" "$CRL_SERVER";
} > "$WORK/blocks"
cat > "$WORK/locations" <<'LOC'

        location = /off.txt {
            auth_ldap "off";
            auth_ldap_servers off;
            alias ROOT/t.txt;
        }

        location = /byname.txt {
            auth_ldap "byname";
            auth_ldap_servers byname;
            alias ROOT/t.txt;
        }

        location = /byaddr.txt {
            auth_ldap "byaddr";
            auth_ldap_servers byaddr;
            alias ROOT/t.txt;
        }

        location = /systemca.txt {
            auth_ldap "systemca";
            auth_ldap_servers systemca;
            alias ROOT/t.txt;
        }

        location = /bychain.txt {
            auth_ldap "bychain";
            auth_ldap_servers bychain;
            alias ROOT/t.txt;
        }

        location = /crlok.txt {
            auth_ldap "crlok";
            auth_ldap_servers crlok;
            alias ROOT/t.txt;
        }

        location = /crlbad.txt {
            auth_ldap "crlbad";
            auth_ldap_servers crlbad;
            alias ROOT/t.txt;
        }
LOC
sed "s|ROOT|$WORK/html|g" "$WORK/locations" > "$WORK/locations.new"
mv "$WORK/locations.new" "$WORK/locations"
write_conf "$WORK/conf/trusted.conf" "$WORK/logs/trusted.log"
start "$WORK/conf/trusted.conf"

echo "== ssl_check_cert off: the certificate is not looked at"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/off.txt")
echo "  $out"
[ "$out" = 200 ] || note "expected 200 without verification, got $out"

echo "== on, trusted ca, reached under the name in the certificate"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/byname.txt")
echo "  $out"
[ "$out" = 200 ] || note "a certificate that verifies has to be accepted, got $out"

echo "== the ca one server names is not the ca of the next"
# This server verifies against the store of the system, where the ca of the
# test directory is not.  It shares the SSL context of the whole
# configuration with the server above, which has just named that ca: loaded
# into the context, it would be the store of this server too, and a
# directory nobody told this server to trust would be accepted.
out=$(refused -u alice:alicepw "http://127.0.0.1:$PORT/systemca.txt")
echo "  $out"
[ "$out" = 500 ] ||
	note "a server with no ca of its own accepted the one another server named, got $out"

echo "== a revocation list that revokes nothing lets the certificate through"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/crlok.txt")
echo "  $out"
[ "$out" = 200 ] ||
	note "an empty revocation list must not refuse anything, got $out"

echo "== and one that revokes this certificate does not"
# Same authority, same certificate, same name: the only difference is the
# list.  Without it the pair says nothing, which is why there are two.
out=$(refused -u alice:alicepw "http://127.0.0.1:$PORT/crlbad.txt")
echo "  $out"
[ "$out" = 500 ] ||
	note "a revoked certificate has to end in 500, got $out"
grep -q "did not verify" "$WORK/logs/trusted.log" ||
	note "the error log does not say that the certificate did not verify"

echo "== chain, trusted ca, reached under an address it does not name"
# Same certificate and same address as the case below, which "on" refuses:
# "chain" asks for the chain and leaves the name alone, and that is the
# setting for a directory whose certificate names something else -- or names
# it only in its common name, which is not held against anything any more.
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/bychain.txt")
echo "  $out"
[ "$out" = 200 ] ||
	note "chain verifies the chain and not the name, so this has to pass, got $out"

echo "== on, trusted ca, reached under an address the certificate does not name"
out=$(refused -u alice:alicepw "http://127.0.0.1:$PORT/byaddr.txt")
echo "  $out"
[ "$out" = 500 ] ||
	note "a name that does not match has to end in 500, got $out"
grep -q "names neither" "$WORK/logs/trusted.log" ||
	note "the error log does not say that the name did not match"

stop

# --- and the one that needs a store of its own: nothing trusts this ca
{ server_block untrusted localhost on ""; } > "$WORK/blocks"
cat > "$WORK/locations" <<'LOC'

        location = /untrusted.txt {
            auth_ldap "untrusted";
            auth_ldap_servers untrusted;
            alias ROOT/t.txt;
        }
LOC
sed "s|ROOT|$WORK/html|g" "$WORK/locations" > "$WORK/locations.new"
mv "$WORK/locations.new" "$WORK/locations"
write_conf "$WORK/conf/untrusted.conf" "$WORK/logs/untrusted.log"
start "$WORK/conf/untrusted.conf"

echo "== on, and the ca of the server is trusted by nobody"
out=$(refused -u alice:alicepw "http://127.0.0.1:$PORT/untrusted.txt")
echo "  $out"
[ "$out" = 500 ] ||
	note "an unverifiable certificate has to end in 500, got $out"
grep -q "did not verify" "$WORK/logs/untrusted.log" ||
	note "the error log does not say that the certificate did not verify"

echo "== error log"
if grep -qE '\[(alert|emerg)\]' "$WORK/logs/trusted.log" "$WORK/logs/untrusted.log"; then
	note "alert or emerg in an error log"
	grep -hE '\[(alert|emerg)\]' "$WORK/logs"/*.log | head -3 >&2
else
	echo "  clean"
fi

[ "$fail" -eq 0 ] || { echo "ci/ldaps.sh: failed" >&2; exit 1; }
echo "ci/ldaps.sh: ok"
