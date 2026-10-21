#!/bin/sh
#
# Start a slapd for the drivers and fill it with a directory to test against.
#
# The configuration is written here, in the classic slapd.conf form, because
# that is the one form every packaging of OpenLDAP still reads: the paths of
# the schema files and of the backend module are the only thing that differs
# between Debian, Red Hat and FreeBSD, and they are looked up below.
#
# usage: ci/ldap.sh [port]
#        ci/ldap.sh tls [port]     with TLS, a CA of its own and a
#                                  certificate that names "localhost" and
#                                  nothing else
#
# Leaves a running slapd and prints the port.  ci/auth.sh and the other
# drivers call this; stop it with ci/ldap.sh stop.

set -eu

WORK=${CI_WORK:-$(cd "$(dirname "$0")/.." && pwd)/ci-work}/ldap
TLS=0
if [ "${1:-}" = tls ]; then
	TLS=1
	shift
fi

PORT=${1:-${LDAP_PORT:-13890}}

if [ "${1:-}" = stop ]; then
	if [ -f "$WORK/slapd.pid" ]; then
		kill "$(cat "$WORK/slapd.pid")" 2> /dev/null || true
	fi
	pkill -f "slapd -f $WORK/slapd.conf" 2> /dev/null || true
	exit 0
fi

slapd=$(command -v slapd || echo /usr/sbin/slapd)
[ -x "$slapd" ] || { echo "slapd(8) is needed" >&2; exit 2; }
command -v ldapadd > /dev/null || { echo "ldapadd(1) is needed" >&2; exit 2; }
command -v ldapsearch > /dev/null || { echo "ldapsearch(1) is needed" >&2; exit 2; }

for d in /etc/ldap/schema /etc/openldap/schema /usr/local/etc/openldap/schema; do
	[ -f "$d/core.schema" ] && { schema=$d; break; }
done
[ -n "${schema:-}" ] || { echo "no core.schema found" >&2; exit 2; }

for d in /usr/lib/ldap /usr/lib64/openldap /usr/local/libexec/openldap; do
	[ -f "$d/back_mdb.so" ] && { modules=$d; break; }
done

# a slapd from an earlier run would still hold the port and the database
pkill -f "slapd -f $WORK/slapd.conf" 2> /dev/null || true
sleep 1

rm -rf "$WORK"
mkdir -p "$WORK/db"

if [ "$TLS" = 1 ]; then
	command -v openssl > /dev/null || { echo "openssl(1) is needed" >&2; exit 2; }
	mkdir -p "$WORK/tls"

	openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
		-keyout "$WORK/tls/ca.key" -out "$WORK/tls/ca.crt" \
		-subj "/CN=ldap test ca" > /dev/null 2>&1 ||
		{ echo "the test ca could not be made" >&2; exit 2; }

	# the name is "localhost" and there is no address in it: that is what
	# lets a driver tell a name that matches from one that does not
	openssl req -new -newkey rsa:2048 -nodes \
		-keyout "$WORK/tls/server.key" -out "$WORK/tls/server.csr" \
		-subj "/CN=localhost" > /dev/null 2>&1 &&
	openssl x509 -req -in "$WORK/tls/server.csr" -days 30 \
		-CA "$WORK/tls/ca.crt" -CAkey "$WORK/tls/ca.key" -set_serial 1 \
		-extfile /dev/stdin -out "$WORK/tls/server.crt" > /dev/null 2>&1 <<EXT ||
subjectAltName = DNS:localhost
EXT
		{ echo "the server certificate could not be made" >&2; exit 2; }

	chmod 644 "$WORK/tls"/*.crt "$WORK/tls"/*.key
fi

{
	echo "include $schema/core.schema"
	echo "include $schema/cosine.schema"
	echo "include $schema/inetorgperson.schema"
	echo "pidfile  $WORK/slapd.pid"
	echo "argsfile $WORK/slapd.args"
	# where mdb is a module it has to be loaded, where it is built in the
	# directive would be an error
	[ -n "${modules:-}" ] && {
		echo "modulepath $modules"
		echo "moduleload back_mdb.so"
	}
	echo "database mdb"
	echo "maxsize 33554432"
	echo "suffix \"dc=test,dc=local\""
	echo "rootdn \"cn=admin,dc=test,dc=local\""
	echo "rootpw secret"
	echo "directory $WORK/db"
	echo "index objectClass eq"
	[ "$TLS" = 1 ] && {
		echo "TLSCACertificateFile $WORK/tls/ca.crt"
		echo "TLSCertificateFile $WORK/tls/server.crt"
		echo "TLSCertificateKeyFile $WORK/tls/server.key"
		echo "TLSVerifyClient never"
	}
} > "$WORK/slapd.conf"

if [ "$TLS" = 1 ]; then
	# by name, so that both families are bound: the module picks one of the
	# addresses a name resolves to at random
	listen="ldaps://localhost:$PORT ldap://localhost:$((PORT + 1))"
else
	listen="ldap://127.0.0.1:$PORT"
fi

"$slapd" -f "$WORK/slapd.conf" -h "$listen" -d 0 > "$WORK/slapd.log" 2>&1 &

# filling the directory and waiting for it goes over plain ldap, which is
# there in both modes
if [ "$TLS" = 1 ]; then
	plain=$((PORT + 1))
else
	plain=$PORT
fi

i=0
while [ $i -lt 50 ]; do
	ldapsearch -x -H "ldap://127.0.0.1:$plain" -b "" -s base > /dev/null 2>&1 && break
	i=$((i + 1))
	sleep 0.2
done
[ $i -lt 50 ] || { echo "slapd did not come up, see $WORK/slapd.log" >&2
		   tail -5 "$WORK/slapd.log" >&2; exit 1; }

cat > "$WORK/test.ldif" <<'LDIF'
dn: dc=test,dc=local
objectClass: dcObject
objectClass: organization
o: test
dc: test

dn: ou=people,dc=test,dc=local
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=test,dc=local
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
uid: alice
cn: Alice Example
sn: Example
mail: alice@test.local
userPassword: alicepw

dn: uid=bob,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
uid: bob
cn: Bob Example
sn: Example
mail: bob@test.local
userPassword: bobpw

dn: uid=a*e,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
uid: a*e
cn: Star
sn: Star
mail: star@test.local
userPassword: astarpw

dn: uid=carol,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
uid: carol
cn: Carol
sn: Carol
mail: carol@test.local
userPassword: carolpw

dn: cn=Admins\,Global,ou=groups,dc=test,dc=local
objectClass: organizationalRole
cn: Admins,Global
description: alice

dn: cn=byname,ou=groups,dc=test,dc=local
objectClass: organizationalRole
cn: byname
description: alice

dn: cn=staff,ou=groups,dc=test,dc=local
objectClass: groupOfNames
cn: staff
member: uid=alice,ou=people,dc=test,dc=local
LDIF

ldapadd -x -H "ldap://127.0.0.1:$plain" -D "cn=admin,dc=test,dc=local" -w secret \
	-f "$WORK/test.ldif" > "$WORK/ldapadd.log" 2>&1 ||
	{ echo "the directory could not be filled" >&2; cat "$WORK/ldapadd.log" >&2; exit 1; }

echo "$PORT"
