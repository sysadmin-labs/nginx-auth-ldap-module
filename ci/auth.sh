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
# loadable build, AUTH_PRELOAD to a library that is put in front of it,
# AUTH_LOG_LEVEL to raise the error log above info, and AUTH_WRAP to a
# command nginx is started under, such as valgrind.

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

# A wrapper cannot follow nginx into the background, so a wrapped run is one
# process that stays in the foreground.  The module's exit handler runs there
# as well: nginx calls it from the single process cycle too.
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

    # On, because the cache is a part of the module like any other and the
    # checks below are the only thing that walks it.  The expiration is far
    # longer than the run, so an entry made by one request is still there
    # for the next.
    auth_ldap_cache_enabled on;
    auth_ldap_cache_expiration_time 60s;
    auth_ldap_cache_size 1k;

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

    # The members of cn=byname are login names, not DNs, so the name the
    # request sends goes into the group filter as a value of its own.  That
    # is the other half of CVE-2020-14013.
    ldap_server byloginname {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        group_attribute description;
        satisfy all;
        require valid_user;
        require group "cn=byname,ou=groups,dc=test,dc=local";
        connections 2;
    }

    # A group whose own name carries a comma, which a backslash makes part
    # of the value rather than a separator.
    ldap_server comma {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        group_attribute description;
        satisfy all;
        require valid_user;
        require group "cn=Admins\\,Global,ou=groups,dc=test,dc=local";
        connections 2;
    }

    ldap_server varbase {
        url ldap://127.0.0.1:$LDAP_PORT/ou=people,dc=test,dc=local?uid?sub?(objectClass=inetOrgPerson);
        binddn "cn=admin,dc=test,dc=local";
        binddn_passwd secret;
        group_attribute member;
        group_attribute_is_dn on;
        satisfy all;
        require valid_user;
        require group "cn=staff,\$http_x_base";
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

        location = /byloginname.txt {
            auth_ldap "Members by login name";
            auth_ldap_servers byloginname;
            alias $WORK/html/staff.txt;
        }

        location = /comma.txt {
            auth_ldap "A group with a comma in its name";
            auth_ldap_servers comma;
            alias $WORK/html/staff.txt;
        }

        location = /varbase.txt {
            auth_ldap "Group base from a header";
            auth_ldap_servers varbase;
            alias $WORK/html/staff.txt;
        }

        # Two servers in one list: the cache is read for both of them, and
        # the outcome of whichever one decides belongs to that one alone.
        location = /both.txt {
            auth_ldap "Two servers";
            auth_ldap_servers staff anyone;
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
	if [ -n "${wrapped:-}" ]; then
		kill -QUIT "$wrapped" 2>/dev/null || true
		# a wrapper writes its verdict when the process it watches is
		# gone, so the rest of the script has to wait for that
		wait "$wrapped" 2>/dev/null || true
	elif [ -f "$WORK/logs/nginx.pid" ]; then
		kill -QUIT "$(cat "$WORK/logs/nginx.pid")" 2>/dev/null || true
	fi
	"$SRC/ci/ldap.sh" stop 2>/dev/null || true
	sleep 1
}
trap cleanup EXIT INT TERM

if [ -n "${AUTH_WRAP:-}" ]; then
	# word splitting is the point: AUTH_WRAP is a command with its options
	# shellcheck disable=SC2086
	$AUTH_WRAP "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf" &
	wrapped=$!
elif [ -n "${AUTH_PRELOAD:-}" ]; then
	LD_PRELOAD=$AUTH_PRELOAD "$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
else
	"$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf"
fi

# Wait for the port rather than for a second: under a wrapper the start
# takes a good deal longer than that, and a fixed wait is what makes a
# driver flap.
waited=0
until curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/open.txt"; do
	waited=$((waited + 1))
	[ "$waited" -lt 120 ] || { echo "nginx did not come up" >&2; exit 1; }
	sleep 1
done

# Under a wrapper every request carries valgrind's or the sanitizers' cost,
# and a leash cut for a plain run is what makes such a driver flap.
TMO=${AUTH_TMO:-5}
[ -n "${AUTH_WRAP:-}" ] && TMO=${AUTH_TMO:-30}

code() {
	curl -s -o "$WORK/body" -w '%{http_code}' --max-time "$TMO" "$@" || echo 000
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
[ "$out" = 401 ] ||
	note "bob is not in the group and has to end in 401, got $out"

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

echo "== a login name in the group filter is a name, not a filter"
# cn=byname lists alice by her login name.  The account a*e exists, so the
# search finds it and the group filter is reached with that name in it:
# unescaped it reads as "starts with a, ends with e", which is what alice's
# membership says, and the holder of a*e is let into a group nobody put
# them in.
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/byloginname.txt")
echo "  the member, by her login name: $out"
[ "$out" = 200 ] || note "alice is a member by name and has to pass, got $out"
out=$(code -u 'a*e:astarpw' "http://127.0.0.1:$PORT/byloginname.txt")
echo "  a name that matches that member as a pattern: $out"
[ "$out" = 401 ] ||
	note "a name with filter syntax matched a member of the group, got $out"
out=$(code -u bob:bobpw "http://127.0.0.1:$PORT/byloginname.txt")
echo "  a name that is in no group: $out"
[ "$out" = 401 ] || note "bob is in no group by name and has to be refused, got $out"

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
# the variable sits inside the name here, not at its end, so a comma of its
# own would add a relative name and move the search
out=$(code -u alice:alicepw -H 'X-Group: staff,ou=groups' "http://127.0.0.1:$PORT/vargroup.txt")
echo "  a group name that adds a relative name: $out"
[ "$out" = 401 ] || note "a group name that adds a relative name was accepted, got $out"
grep -q 'the group DN .* is not shaped like its configuration' "$WORK/logs/error.log" ||
	note "the error log does not say that the group DN was refused"

echo "== a bind DN built from the login name is the DN that is bound"
# The bind DN used to be handed to libldap as it came out of the complex
# value, which is a length and a buffer with no null byte behind it.  The
# first request after a restart happened to find a zero there and passed;
# any request after one through another location sent the DN with a piece of
# the pool stuck to the end, and the directory refused credentials that were
# correct.  Three requests are what it takes to see it.
for n in 1 2 3; do
	out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/vardn.txt")
	echo "  request $n through the bind DN: $out"
	[ "$out" = 200 ] ||
		note "alice has to pass through a bind DN built from her login name, got $out"
	[ "$n" = 2 ] && continue
	out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/staff.txt")
	[ "$out" = 200 ] || note "the request in between answered $out"
done
grep -q "Invalid DN syntax" "$WORK/logs/error.log" &&
	note "the directory was sent something that is not a DN"

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
grep -q 'the bind DN .* is not shaped like its configuration' "$WORK/logs/error.log" ||
	note "the error log does not say that the bind DN was refused"

echo "== a comma a backslash holds is part of the name, not a separator"
# The group is cn=Admins\,Global.  Split at the first comma the string
# carries, the filter asserts on "cn=Admins\" and the search runs under
# "Global,ou=groups,dc=test,dc=local", which is nowhere.
out=$(code -u alice:alicepw "http://127.0.0.1:$PORT/comma.txt")
echo "  the member of that group: $out"
[ "$out" = 200 ] ||
	note "a group whose name carries a comma was split in the middle, got $out"

echo "== a relative name holds one value, written as text"
# The template is "uid=$remote_user,...", so a login name with a plus in it
# builds one relative name with two values -- uid=alice and uid=admin -- and
# leaves the number of commas exactly where it was.  Counting commas cannot
# see it; reading the name as a name can.
out=$(code -u 'alice+uid=admin:alicepw' "http://127.0.0.1:$PORT/vardn.txt")
echo "  a login name that adds a second value: $out"
[ "$out" = 401 ] ||
	note "a login name with a plus in it was accepted, got $out"
grep -q "holds more than one value" "$WORK/logs/error.log" ||
	note "the error log does not say that the relative name was refused"
# A value in the hexadecimal form a DN allows carries bytes the written form
# does not show, and libldap hands the decoded bytes on.
out=$(code -u alice:alicepw -H 'X-Group: #040461626300' \
	"http://127.0.0.1:$PORT/vargroup.txt")
echo "  a group value written as hexadecimal: $out"
[ "$out" = 401 ] ||
	note "a hexadecimal group value was accepted, got $out"
grep -q "written as hexadecimal" "$WORK/logs/error.log" ||
	note "the error log does not say that the hexadecimal value was refused"

echo "== the base a group is searched under keeps its shape"
out=$(code -u alice:alicepw -H 'X-Base: ou=groups,dc=test,dc=local' \
	"http://127.0.0.1:$PORT/varbase.txt")
echo "  the base the group is in: $out"
[ "$out" = 200 ] || note "alice is in that group and has to pass, got $out"
out=$(code -u alice:alicepw -H 'X-Base: ou=nowhere,dc=test,dc=local' \
	"http://127.0.0.1:$PORT/varbase.txt")
echo "  a base that holds no such group: $out"
[ "$out" = 401 ] || note "a base without that group let her in, got $out"
out=$(code -u alice:alicepw -H 'X-Base: *' "http://127.0.0.1:$PORT/varbase.txt")
echo "  a base that is not a name at all: $out"
[ "$out" = 401 ] || note "a base that is not a distinguished name was accepted, got $out"

echo "== an outcome belongs to the server that decided it"
# carol is a valid user and in no group, so of the two servers in the list
# the first refuses her and the second lets her in.  The outcome written
# into the cache is the one of the server that decided, under that server's
# key: written under the other one's, the refusal of the first server would
# come back as the answer of the second.  carol is used here and nowhere
# else, so the entry is this check's own.
out=$(code -u carol:carolpw "http://127.0.0.1:$PORT/both.txt")
echo "  two servers, the second one lets her in: $out"
[ "$out" = 200 ] || note "carol has valid credentials and has to pass here, got $out"
out=$(code -u carol:carolpw "http://127.0.0.1:$PORT/anyone.txt")
echo "  the second server on its own: $out"
[ "$out" = 200 ] ||
	note "a refusal of one server was answered for another one, got $out"

echo "== a rule that is decided per request is not cached"
out=$(code -u alice:alicepw -H 'X-Group: staff' "http://127.0.0.1:$PORT/vargroup.txt")
echo "  the group she is in: $out"
[ "$out" = 200 ] || note "alice is in staff and has to pass, got $out"
out=$(code -u alice:alicepw -H 'X-Group: nosuch' "http://127.0.0.1:$PORT/vargroup.txt")
echo "  a group she is not in, same credentials: $out"
[ "$out" = 401 ] ||
	note "an outcome was cached although the rule is decided per request, got $out"

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
