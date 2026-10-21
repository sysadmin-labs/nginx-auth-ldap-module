#!/bin/sh
#
# Drive the module against a real directory: who gets in, who does not, and
# what the server says when nobody has identified themselves yet.
#
# t/ cannot do this.  The module needs an LDAP server to answer at all, and
# what is interesting is the answer to a request, not the parsing of the
# configuration.
#
# usage: ci/auth.sh <nginx binary>
#
# Set AUTH_LOAD_MODULE to the path of ngx_http_auth_ldap_module.so to test a
# loadable build, AUTH_PRELOAD to a library that is put in front of it, and
# AUTH_LOG_LEVEL to raise the error log above info.

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/auth
PORT=${AUTH_PORT:-18570}

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

# Static files, not "return 200": a return answers in the rewrite phase,
# which runs before the access phase the module lives in, so every request
# would come back 200 without ever reaching auth_ldap.
echo in > "$WORK/html/staff.txt"
echo in > "$WORK/html/anyone.txt"
echo open > "$WORK/html/open.txt"
chmod 644 "$WORK/html"/*.txt

fail=0
note() {
	echo "  $1" >&2
	fail=1
}

LDAP_PORT=$("$SRC/ci/ldap.sh")

load=
[ -n "${AUTH_LOAD_MODULE:-}" ] && load="load_module $AUTH_LOAD_MODULE;"

cat > "$WORK/conf/nginx.conf" <<CONF
$load
daemon on;
master_process on;
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $WORK/logs/error.log ${AUTH_LOG_LEVEL:-info};
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $WORK/tmp;

    ldap_server staff {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        group_attribute member;
        group_attribute_is_dn on;
        satisfy all;
        require valid_user;
        require group "cn=staff,ou=groups,dc=test,dc=local";
        connections 2;
    }

    ldap_server anyone {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        require valid_user;
        connections 2;
    }

    ldap_server vargroup {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        group_attribute member;
        group_attribute_is_dn on;
        satisfy all;
        require valid_user;
        require group "cn=\$http_x_group,ou=groups,dc=test,dc=local";
        connections 2;
    }

    ldap_server vardn {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        require valid_user "uid=\$remote_user,ou=people,dc=test,dc=local";
        connections 2;
    }

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;

        location = /staff.txt {
            auth_ldap "Restricted";
            auth_ldap_servers staff;
        }

        location = /anyone.txt {
            auth_ldap "Anyone";
            auth_ldap_servers anyone;
        }

        location = /vargroup.txt {
            auth_ldap "Group from a header";
            auth_ldap_servers vargroup;
            alias $WORK/html/staff.txt;
        }

        location = /vardn.txt {
            auth_ldap "DN from the login name";
            auth_ldap_servers vardn;
            alias $WORK/html/staff.txt;
        }

        location = /open.txt {
        }
    }
}
CONF

cleanup() {
	# runs from an EXIT trap under set -e, where a failing line would
	# abort the function and become the exit status of the script
	if [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	"$SRC/ci/ldap.sh" stop 2>/dev/null || true
	sleep 1
}
trap cleanup EXIT INT TERM

if [ -n "${AUTH_PRELOAD:-}" ]; then
	LD_PRELOAD=$AUTH_PRELOAD "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
else
	"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
fi
sleep 1

code() {
	curl -s -o "$WORK/body" -w '%{http_code}' --max-time 5 "$@" || echo 000
}

echo "== no credentials: 401 and one well formed challenge"
out=$(curl -s -D "$WORK/head.crlf" -o /dev/null -w '%{http_code}' --max-time 5 \
	"http://127.0.0.1:$PORT/staff.txt" || echo 000)
# a header line ends in CR, which an anchored match would otherwise trip over
tr -d '\r' < "$WORK/head.crlf" > "$WORK/head"
echo "  $out  $(grep -i '^www-authenticate' "$WORK/head")"
[ "$out" = 401 ] || note "expected 401 without credentials, got $out"
[ "$(grep -ci '^www-authenticate' "$WORK/head")" = 1 ] ||
	note "there has to be exactly one WWW-Authenticate header"
grep -qi '^www-authenticate: Basic realm="Restricted"' "$WORK/head" ||
	note "the challenge does not name the realm"
# a header list that was not terminated shows up as garbage behind the value
grep -qiE '^www-authenticate: Basic realm="Restricted"$' "$WORK/head" ||
	note "there is more in the header than the realm"

echo "== a member of the group gets in"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/staff.txt")
echo "  $out  $(tr -d '\n' < "$WORK/body")"
[ "$out" = 200 ] || note "alice is in the group and has to pass, got $out"

echo "== the wrong password does not"
out=$(code -u alice:wrongpw "http://127.0.0.1:$PORT/staff.txt")
echo "  $out"
[ "$out" = 401 ] || note "a wrong password has to end in 401, got $out"

echo "== somebody outside the group does not"
out=$(code -u bob:bobpw "http://127.0.0.1:$PORT/staff.txt")
echo "  $out"
[ "$out" = 403 ] || [ "$out" = 401 ] ||
	note "bob is not in the group and has to be refused, got $out"

echo "== without the group requirement he does"
out=$(code -u bob:bobpw "http://127.0.0.1:$PORT/anyone.txt")
echo "  $out"
[ "$out" = 200 ] || note "bob has valid credentials and has to pass here, got $out"

echo "== a login name is searched for, not interpreted"
# An unescaped asterisk makes the search filter match the first user there
# is, and the module then binds that user with the password it was handed:
# a login as "*" with any valid password.  That is CVE-2020-14013.
out=$(code -u '*:alicepw' "http://127.0.0.1:$PORT/staff.txt")
echo "  * with a valid password: $out"
[ "$out" = 401 ] || note "a wildcard was accepted as a login name, got $out"
out=$(code -u 'alice)(objectClass=*:alicepw' "http://127.0.0.1:$PORT/staff.txt")
echo "  a name that closes the filter: $out"
[ "$out" = 401 ] || note "a name with filter syntax was accepted, got $out"

echo "== a group that comes from a header is a name, not a filter"
out=$(code -u alice:alicepw -H 'X-Group: staff' "http://127.0.0.1:$PORT/vargroup.txt")
echo "  the group she is in: $out"
[ "$out" = 200 ] || note "alice is in staff and has to pass, got $out"
out=$(code -u alice:alicepw -H 'X-Group: *' "http://127.0.0.1:$PORT/vargroup.txt")
echo "  a wildcard as the group: $out"
[ "$out" = 401 ] || note "a wildcard as a group name was accepted, got $out"
out=$(code -u alice:alicepw -H 'X-Group: nosuch)(objectClass=*' "http://127.0.0.1:$PORT/vargroup.txt")
echo "  a group that closes the filter: $out"
[ "$out" = 401 ] || note "a group with filter syntax was accepted, got $out"

echo "== a bind DN built from the login name keeps its shape"
# What is asserted here is the refusal.  The matching case is not, and the
# reason is a defect of the module that this fork has not fixed yet: a
# request through one ldap_server leaves the next request through a server
# with "require valid_user <dn>" with an invalid-credentials answer for
# credentials that are correct.  Three requests reproduce it, and the
# imported state behaves the same way:
#
#     /vardn.txt -> 200, /staff.txt -> 200, /vardn.txt -> 401
out=$(code -u 'alice,ou=people,dc=test,dc=local,x=y:alicepw' "http://127.0.0.1:$PORT/vardn.txt")
echo "  a name with commas in it: $out"
[ "$out" = 401 ] || note "a login name that adds relative names was accepted, got $out"
grep -q "is not shaped like its configuration" "$WORK/logs/error.log" ||
	note "the error log does not say that the bind DN was refused"

echo "== a location without auth_ldap stays open"
out=$(code "http://127.0.0.1:$PORT/open.txt")
[ "$out" = 200 ] || note "the open location answered $out"
echo "  $out"

echo "== the connection was used, not waited for"
if grep -q "Authentication timed out" "$WORK/logs/error.log"; then
	note "a request timed out waiting for an LDAP connection"
	grep -n "timed out" "$WORK/logs/error.log" | head -3 >&2
else
	echo "  no timeout"
fi

echo "== error log"
if grep -qE '\[(alert|emerg)\]' "$WORK/logs/error.log"; then
	note "alert or emerg in the error log"
	grep -E '\[(alert|emerg)\]' "$WORK/logs/error.log" | head -3 >&2
else
	echo "  clean"
fi

[ "$fail" -eq 0 ] || { echo "ci/auth.sh: failed" >&2; exit 1; }
echo "ci/auth.sh: ok"
