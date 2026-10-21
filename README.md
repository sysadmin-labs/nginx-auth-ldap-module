# nginx-auth-ldap-module

[![Build & Test][build-test-badge]][build-test-link]
[![Auth][auth-badge]][auth-link]
[![LDAPS][ldaps-badge]][ldaps-link]
[![Resolve][resolve-badge]][resolve-link]
[![Sync connect][sync-connect-badge]][sync-connect-link]
[![FreeBSD][freebsd-badge]][freebsd-link]
[![A/UBSan][sanitizers-badge]][sanitizers-link]
[![Valgrind][valgrind-badge]][valgrind-link]
[![Reload][reload-badge]][reload-link]
[![CodeQL][codeql-badge]][codeql-link]
[![Lint][lint-badge]][lint-link]

[build-test-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/build-test.yml/badge.svg
[build-test-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/build-test.yml
[auth-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/auth.yml/badge.svg
[auth-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/auth.yml
[ldaps-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/ldaps.yml/badge.svg
[ldaps-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/ldaps.yml
[resolve-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/resolve.yml/badge.svg
[resolve-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/resolve.yml
[sync-connect-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/sync-connect.yml/badge.svg
[sync-connect-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/sync-connect.yml
[freebsd-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/freebsd.yml/badge.svg
[freebsd-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/freebsd.yml
[sanitizers-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/sanitizers.yml/badge.svg
[sanitizers-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/sanitizers.yml
[valgrind-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/valgrind.yml/badge.svg
[valgrind-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/valgrind.yml
[reload-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/reload.yml/badge.svg
[reload-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/reload.yml
[codeql-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/codeql.yml/badge.svg
[codeql-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/codeql.yml
[lint-badge]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/lint.yml/badge.svg
[lint-link]: https://github.com/sysadmin-labs/nginx-auth-ldap-module/actions/workflows/lint.yml

HTTP basic authentication against an LDAP directory: `auth_ldap` with server
blocks, group requirements, a connection pool and an answer cache.

A maintained fork of `kvspb/nginx-auth-ldap`, whose code upstream last
changed in April 2024.  What this fork fixes, and what it does not, is in
the [changelog](CHANGELOG.md).

## Synopsis

```nginx
http {
    ldap_server directory {
        url ldap://127.0.0.1:389/ou=people,dc=example,dc=com?uid?sub?(objectClass=inetOrgPerson);

        binddn "cn=readonly,dc=example,dc=com";
        binddn_passwd secret;

        group_attribute member;
        group_attribute_is_dn on;

        satisfy all;
        require valid_user;
        require group "cn=staff,ou=groups,dc=example,dc=com";

        connections 4;
    }

    server {
        listen 80;

        location /private {
            auth_ldap "Restricted";
            auth_ldap_servers directory;
        }
    }
}
```

## Directives

### `ldap_server`

**syntax:** `ldap_server <name> { ... }`
**context:** `http`

Describes one directory.  The name is what `auth_ldap_servers` refers to.
Inside the block:

| parameter | meaning |
|---|---|
| `url` | `ldap://` or `ldaps://` followed by host, port, base DN, the attribute a login name is matched against, the scope and a filter.  The host and the attribute are both required; a url without a host is refused when the configuration is read. |
| `binddn`, `binddn_passwd` | the account the search is made with.  Without them the search is anonymous. |
| `group_attribute` | the attribute a group lists its members in, `member` or `uniqueMember` as a rule.  There is no default: a `require group` rule without it refuses every request. |
| `group_attribute_is_dn` | `on` when that attribute holds distinguished names, `off`, the default, when it holds login names |
| `require valid_user` | any account that binds is let in |
| `require valid_user "<dn>"` | the login name goes into that template, and the result is the DN that is bound, instead of the DN the search found |
| `require user "<dn>"` | that one account |
| `require group "<dn>"` | membership in that group |
| `satisfy` | `all` means every `require` has to hold, `any` means one of them is enough, which is the default |
| `connections` | how many connections to the directory this block keeps, at least 1, which is also the default |
| `connect_timeout`, `bind_timeout`, `request_timeout` | 10s, 5s and 10s by default |
| `reconnect_timeout` | how long a connection that was lost waits before it is made again, 10s |
| `max_down_retries` | how often a connection that the directory dropped is rebuilt right away instead of waiting out `reconnect_timeout`, 0 by default.  Counted for the connection, so one that keeps failing does not spend the allowance of the others. |
| `referral` | `on` by default; `off` makes a referral an error instead of a redirection |
| `ssl_check_cert`, `ssl_ca_file`, `ssl_ca_dir` | for `ldaps://`: `off` by default, `on` for the chain and the name, `chain` for the chain alone.  A block that verifies gets a store of its own, holding the authorities it names and nothing else, or the trust store of the system where it names none; one that cannot be loaded fails the configuration.  With `off` the `ssl_ca_*` values are not read at all.  With `on` a certificate is accepted when its chain verifies and it names the host the url names, or the address the connection was made to; the name has to stand in a subject alternative name, because RFC 9525 says that is where a name belongs, and a partial wildcard is refused.  `chain` is for a directory whose certificate names something else, or names it only in its common name. |
| `ssl_crl_file` | a revocation list from the same authority.  Where it is set, the certificate of the directory is held against it; the authorities above it are not, because a list for every link is what OpenSSL would then want and an authority that publishes none would verify nothing at all. |
| `include` | reads a file into the block, for the password that does not belong in the main configuration |

Every one of them takes a value, and a line the block does not know is
refused rather than dropped.

`ssl_ca_dir` is read the way OpenSSL reads a directory of authorities, by
hash, so the directory needs the symbolic links `c_rehash` leaves behind; a
directory of certificates without them trusts nothing.  And
`ssl_check_cert on` needs an nginx built against OpenSSL 1.0.2 or newer,
where `X509_check_host()` is: against an older one the configuration is
refused rather than started with the check turned off.

### `auth_ldap`

**syntax:** `auth_ldap <realm> | off`
**default:** `off`
**context:** `http`, `server`, `location`, `limit_except`

Switches the authentication on and names the realm the browser shows.

### `auth_ldap_servers`

**syntax:** `auth_ldap_servers <name> ...`
**context:** `http`, `server`, `location`, `limit_except`

Which directories are asked, and in that order: a directory that refuses is
followed by the next one, and only one that lets the request in ends the
list.

### `auth_ldap_cache_enabled`

**syntax:** `auth_ldap_cache_enabled on | off`
**default:** `off`
**context:** `http`

Remembers the outcome of a bind, so that a browser that sends its
credentials with every request does not cause a bind with every request.
The cache holds the hash of the credentials, not the credentials.

### `auth_ldap_cache_expiration_time`

**syntax:** `auth_ldap_cache_expiration_time <time>`
**default:** `10s`
**context:** `http`

### `auth_ldap_cache_size`

**syntax:** `auth_ldap_cache_size <size>`
**default:** `100`
**context:** `http`

How many outcomes the cache holds.  The value is a size, so `1k` means 1024
of them.  With the cache switched on, fewer than 100 is refused when the
configuration is read, as is an expiration below one second; with it
switched off neither is looked at.

### `auth_ldap_resolver`

**syntax:** `auth_ldap_resolver <address> ...`
**context:** `http`

Which nameservers a host in a `url` is asked of, in nginx's own syntax, so
`ipv6=off` and `valid=` work as they do elsewhere.  Without this the
addresses the configuration resolved are all there is, and a directory that
moves is reached again on the next reload and not before.  With it the name
is asked before every connection a worker makes, so an answer that changed
is taken up as soon as a connection is rebuilt -- which `reconnect_timeout`
bounds.

A host that cannot be resolved while the configuration is read is an error
without this directive and none with it.

### `auth_ldap_resolver_timeout`

**syntax:** `auth_ldap_resolver_timeout <time>`
**default:** `30s`
**context:** `http`

### `auth_ldap_servers_size`

**syntax:** `auth_ldap_servers_size <number>`
**default:** `7`
**context:** `http`

The number sizes the array the blocks go into, and it is read when the first
`ldap_server` block creates that array: set after that block, it does
nothing at all.  More blocks than the number work as long as every one of
them stands before the first `auth_ldap_servers`: the array moves when it
grows, and a location holds pointers into it.

## Behaviour

A `require` rule may hold a variable, as in
`require group "cn=$http_x_group,ou=groups,dc=example,dc=com"`.  The value is
then a name and nothing else: it is escaped before it goes into a filter, and
the whole rule has to be a distinguished name or the request is refused.
Where the variable stands inside the name, as above, a comma it brings would
add a relative name nobody wrote, and that is refused too.  Where the
variable ends the rule, as in
`require group "cn=staff,$http_x_base"`, the tail of the name is the
variable's to give, so the request chooses the base the group is searched
under -- which is what putting a variable there says.

A server with such a rule is answered without the cache, whose key is the
user, the password and the bytes of the server and cannot see a rule that is
decided per request.

A request the module cannot decide is answered 500: no directory answered,
or none could be reached.  A directory whose certificate is refused has no
usable connection at all, so a request through it waits out its
`request_timeout` before it gets that answer.

A host in a `url` is resolved while the configuration is read.  With
`auth_ldap_resolver` it is asked again before every connection, so a
directory that moved is reached without a reload; without it the addresses
from that first resolution are the ones used.

The handler runs in the access phase, so a refused request never reaches the
content phase.  Every worker keeps its own connections, made when it starts
and closed when it leaves, and a request that finds them all busy waits for
one to come free rather than opening another -- with `connections` at its
default of one, that means behind the request before it.

## Building

```sh
./configure --with-http_ssl_module \
    --add-module=/path/to/nginx-auth-ldap-module
```

or as a loadable module

```sh
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-auth-ldap-module
```

with `load_module modules/ngx_http_auth_ldap_module.so;` in the main
context.

The OpenLDAP client library is required and is looked for at configure time;
where its headers are not in the default search path, point to them with
`--with-cc-opt` and `--with-ld-opt`.  `--with-http_ssl_module` is what
`ldaps://` needs: that part of the module is compiled only when nginx has
OpenSSL, and without it a `url ldaps://...` is refused when the
configuration is read.

## Testing

```sh
ci/build.sh 1.30.5 /tmp/nginx-test
TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
ci/auth.sh /tmp/nginx-test/sbin/nginx
ci/ldaps.sh /tmp/nginx-test/sbin/nginx
ci/resolve.sh /tmp/nginx-test/sbin/nginx
ci/sync-connect.sh /tmp/nginx-test/sbin/nginx
ci/reload.sh /tmp/nginx-test/sbin/nginx
```

`t/` covers the configuration parser.  The drivers need a directory and
start one themselves: `ci/ldap.sh` runs a slapd with four users and two groups, and with a
certificate authority, a server certificate and two revocation lists when it
is asked for TLS.  `ci/auth.sh` asks who gets in, `ci/ldaps.sh` does the
same over TLS and holds four certificates and two revocation lists against
each other, `ci/resolve.sh` changes what a name answers under a running
nginx, `ci/sync-connect.sh` repeats the matrix with a `connect(2)` that
comes back already connected, and `ci/reload.sh` authenticates again after
every one of eight reloads.

## Credits and license

The module is the work of Valery Komarov, Jiri Hruska and Victor Hahn
Castell, BSD 2-Clause.  This fork keeps that licence, and
[LICENSE](LICENSE) says which part of the result is whose.

Several of the fixes were proposed upstream before they were made here, and
those proposals are the work of their authors: the escaping of filter values
by onovy (pull request 239), the handling of a connect that has already
completed by NuLL3rr0r (617), the terminated header list together with the
freeing of the parsed url by freultwah (250) and the header list again by
jessp01 (252, 253), the address the certificate of the directory is held
against by mmguero (237), who also reported the crash it caused (issue 236),
and by Ericbla (251), the comma a backslash makes part of a group name by
DreDub2k (issue 224), and the lookup of the cache for every server of a
location, whose consequences are fixed here, by landryb (219).
