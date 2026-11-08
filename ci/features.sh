#!/bin/sh
#
# Drive the features this fork added against a real directory: a bind
# password read from a file, a search filter of the server's own, the user
# DN and attributes handed on as variables, the realm as a variable that can
# turn the check off, and the line a refused login leaves in the log.
#
# t/ reaches the configuration parser only; what is interesting here is what
# the module does with a directory answering, so a slapd is started and real
# requests are made.
#
# usage: ci/features.sh <nginx binary>
#
# AUTH_LOAD_MODULE, AUTH_PRELOAD, AUTH_LOG_LEVEL, AUTH_WRAP, AUTH_PORT and
# AUTH_TMO work as they do in ci/auth.sh, so the sanitizer and valgrind
# workflows can drive this the same way.

set -eu

NGINX=${1:?path to the nginx binary missing}
SRC=$(cd "$(dirname "$0")/.." && pwd)
WORK=${CI_WORK:-$SRC/ci-work}/features
PORT=${AUTH_PORT:-18580}

command -v curl > /dev/null || { echo "curl(1) is needed" >&2; exit 2; }

rm -rf "$WORK"
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"

echo in > "$WORK/html/page.txt"
echo open > "$WORK/html/open.txt"
chmod 644 "$WORK/html"/*.txt

# The bind password in a file of its own, with the trailing newline an editor
# leaves: binddn_passwd_file has to read the password and drop that newline,
# or the bind fails and every login is refused.
printf 'secret\n' > "$WORK/conf/bindpw"
chmod 600 "$WORK/conf/bindpw"

fail=0
note() {
	echo "  $1" >&2
	fail=1
}

LDAP_PORT=$("$SRC/ci/ldap.sh")

load=
[ -n "${AUTH_LOAD_MODULE:-}" ] && load="load_module $AUTH_LOAD_MODULE;"

if [ -n "${AUTH_WRAP:-}" ]; then
	processes="daemon off;
master_process off;"
else
	processes="daemon on;
master_process on;"
fi

cat > "$WORK/conf/nginx.conf" <<CONF
$load
$processes
worker_processes 1;
pid $WORK/logs/nginx.pid;
error_log $WORK/logs/error.log ${AUTH_LOG_LEVEL:-info};
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $WORK/tmp;

    auth_ldap_cache_enabled on;
    auth_ldap_cache_expiration_time 60s;
    auth_ldap_cache_size 1k;

    # The realm as a variable: a header turns the check off for the request,
    # the way "auth_basic off" does, and otherwise it is the realm.
    map \$http_x_open \$open_realm {
        default "Restricted";
        yes     off;
    }

    # The bind password comes from a file, not from the configuration.
    ldap_server byfile {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd_file $WORK/conf/bindpw;
        require valid_user;
        connections 2;
    }

    # A filter of the server's own, matching the login against uid or mail,
    # and the attributes read from the entry it finds.
    ldap_server byattr {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        user_filter "(|(uid=\$remote_user)(mail=\$remote_user))";
        user_attributes mail cn;
        require valid_user;
        connections 2;
    }

    server {
        listen 127.0.0.1:$PORT;
        root $WORK/html;

        location = /byfile.txt {
            auth_ldap "ByFile";
            auth_ldap_servers byfile;
            alias $WORK/html/page.txt;
        }

        location = /byattr.txt {
            auth_ldap "ByAttr";
            auth_ldap_servers byattr;
            add_header X-User-DN \$ldap_user_dn always;
            add_header X-User-Mail \$ldap_attr_mail always;
            add_header X-User-CN \$ldap_attr_cn always;
            alias $WORK/html/page.txt;
        }

        location = /maybe.txt {
            auth_ldap \$open_realm;
            auth_ldap_servers byattr;
            alias $WORK/html/open.txt;
        }
    }
}
CONF

cleanup() {
	if [ -n "${wrapped:-}" ]; then
		kill -QUIT "$wrapped" 2>/dev/null || true
		wait "$wrapped" 2>/dev/null || true
	elif [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	"$SRC/ci/ldap.sh" stop 2>/dev/null || true
	sleep 1
}
trap cleanup EXIT INT TERM

if [ -n "${AUTH_WRAP:-}" ]; then
	# shellcheck disable=SC2086
	$AUTH_WRAP "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
	wrapped=$!
elif [ -n "${AUTH_PRELOAD:-}" ]; then
	LD_PRELOAD=$AUTH_PRELOAD "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
else
	"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
fi

waited=0
until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/open.txt"; do
	waited=$((waited + 1))
	[ "$waited" -lt 120 ] || { echo "nginx did not come up" >&2; exit 1; }
	sleep 1
done

TMO=${AUTH_TMO:-5}
[ -n "${AUTH_WRAP:-}" ] && TMO=${AUTH_TMO:-30}

code() {
	curl -s -o "$WORK/body" -w '%{http_code}' --max-time "$TMO" "$@" || echo 000
}

echo "== the bind password read from a file lets the search bind"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/byfile.txt")
echo "  $out"
[ "$out" = 200 ] ||
	note "the bind password from the file did not work, got $out"

echo "== the wrong password is still refused through that server"
out=$(code -u alice:wrongpw "http://127.0.0.1:$PORT/byfile.txt")
echo "  $out"
[ "$out" = 401 ] || note "a wrong password passed through byfile, got $out"

echo "== user_filter finds the user by the login"
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/byattr.txt")
echo "  by uid: $out"
[ "$out" = 200 ] || note "alice by her uid has to pass, got $out"

echo "== user_filter finds the user by another attribute"
out=$(code -u 'alice@test.local:alicepw' "http://127.0.0.1:$PORT/byattr.txt")
echo "  by mail: $out"
[ "$out" = 200 ] || note "alice by her mail address has to pass, got $out"

echo "== a login that matches no attribute is refused"
out=$(code -u 'nobody@test.local:x' "http://127.0.0.1:$PORT/byattr.txt")
echo "  $out"
[ "$out" = 401 ] || note "a login that matches nothing was let in, got $out"

echo "== the login still cannot forge the filter"
out=$(code -u '*@test.local:alicepw' "http://127.0.0.1:$PORT/byattr.txt")
echo "  a wildcard in the login: $out"
[ "$out" = 401 ] || note "a wildcard in the login was accepted, got $out"

echo "== the user DN and attributes come back as variables"
out=$(curl -s -D "$WORK/head.crlf" -o /dev/null -w '%{http_code}' \
	--max-time "$TMO" -u alice:alicepw "http://127.0.0.1:$PORT/byattr.txt" || echo 000)
tr -d '\r' < "$WORK/head.crlf" > "$WORK/head"
echo "  $out  $(grep -i '^x-user-' "$WORK/head" | tr '\n' ' ')"
[ "$out" = 200 ] || note "the attribute request did not pass, got $out"
grep -qi '^x-user-dn: uid=alice,ou=people,dc=test,dc=local$' "$WORK/head" ||
	note "\$ldap_user_dn did not come back as the user DN"
grep -qi '^x-user-mail: alice@test.local$' "$WORK/head" ||
	note "\$ldap_attr_mail did not come back as the mail address"
grep -qi '^x-user-cn: Alice Example$' "$WORK/head" ||
	note "\$ldap_attr_cn did not come back as the common name"

echo "== a refused login leaves a line naming the user and the server"
out=$(code -u alice:wrongpw "http://127.0.0.1:$PORT/byattr.txt")
echo "  $out"
[ "$out" = 401 ] || note "a wrong password passed, got $out"
grep -q 'authentication denied for user "alice"' "$WORK/logs/error.log" ||
	note "the error log does not name the denied user"
grep -q 'user bind failed for "alice" on server "byattr"' "$WORK/logs/error.log" ||
	note "the bind failure does not name the user and the server"
grep -qi 'wrongpw' "$WORK/logs/error.log" &&
	note "the password reached the error log"

echo "== the realm variable off turns the check off"
out=$(code -H 'X-Open: yes' "http://127.0.0.1:$PORT/maybe.txt")
echo "  with the header: $out"
[ "$out" = 200 ] || note "the off value did not open the location, got $out"

echo "== without it the realm is asked for"
out=$(curl -s -D "$WORK/head.crlf" -o /dev/null -w '%{http_code}' \
	--max-time "$TMO" "http://127.0.0.1:$PORT/maybe.txt" || echo 000)
tr -d '\r' < "$WORK/head.crlf" > "$WORK/head"
echo "  $out  $(grep -i '^www-authenticate' "$WORK/head")"
[ "$out" = 401 ] || note "the realm variable did not ask for credentials, got $out"
grep -qiE '^www-authenticate: Basic realm="Restricted"$' "$WORK/head" ||
	note "the challenge does not name the realm the variable gave"

echo "== error log"
if grep -qE '\[(alert|emerg)\]' "$WORK/logs/error.log"; then
	note "alert or emerg in the error log"
	grep -E '\[(alert|emerg)\]' "$WORK/logs/error.log" | head -3 >&2
else
	echo "  clean"
fi

[ "$fail" -eq 0 ] || { echo "ci/features.sh: failed" >&2; exit 1; }
echo "ci/features.sh: ok"
