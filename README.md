# nginx-auth-ldap-module

[![Build & Test][build-test-badge]][build-test-link]
[![Auth][auth-badge]][auth-link]
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

A maintained fork of `kvspb/nginx-auth-ldap`.  Upstream last touched the
module's code in December 2023, and that change was a typo in a comment; the
one tag it carries is from 2011, and the pull request for the bug fixed here
has been open since October 2026.  The fixes this fork carries are in the
[changelog](CHANGELOG.md).

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
| `url` | `ldap://` or `ldaps://` followed by host, port, base DN, the attribute a login name is matched against, the scope and a filter.  The attribute is required. |
| `binddn`, `binddn_passwd` | the account the search is made with.  Without them the search is anonymous. |
| `group_attribute` | the attribute a group lists its members in, `member` or `uniqueMember` as a rule |
| `group_attribute_is_dn` | `on` when that attribute holds distinguished names, `off` when it holds login names |
| `require valid_user` | any account that binds is let in |
| `require user "<dn>"` | that one account |
| `require group "<dn>"` | membership in that group |
| `satisfy` | `all` means every `require` has to hold, `any` means one of them is enough |
| `connections` | how many connections to the directory this block keeps, at least 1, which is also the default |
| `connect_timeout`, `bind_timeout`, `request_timeout` | 10s, 5s and 10s by default |
| `reconnect_timeout` | how long a connection that was lost waits before it is made again, 10s |
| `max_down_retries` | how often a request may be retried on another connection while the directory is down, 0 by default |
| `referral` | `on` by default; `off` makes a referral an error instead of a redirection |
| `ssl_check_cert`, `ssl_ca_file`, `ssl_ca_dir` | for `ldaps://`: whether the certificate of the directory is verified and against what |
| `include` | reads a file into the block, for the password that does not belong in the main configuration |

A value with a space has to be quoted as a whole, the way nginx quotes.

### `auth_ldap`

**syntax:** `auth_ldap <realm> | off`
**default:** `off`
**context:** `http`, `server`, `location`, `limit_except`

Switches the authentication on and names the realm the browser shows.

### `auth_ldap_servers`

**syntax:** `auth_ldap_servers <name> ...`
**context:** `http`, `server`, `location`, `limit_except`

Which directories are asked, in that order.  The first one that answers
decides.

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

**syntax:** `auth_ldap_cache_size <number>`
**default:** `100`
**context:** `http`

### `auth_ldap_servers_size`

**syntax:** `auth_ldap_servers_size <number>`
**default:** `7`
**context:** `http`

How many `ldap_server` blocks the configuration is expected to hold.  More
of them still work; the number only sizes an array.

## Behaviour

The handler runs in the access phase, so a refused request never reaches the
content phase.  Every worker keeps its own connections, made when it starts
and closed when it leaves, and a request that finds them all busy waits for
one to come free rather than opening another.

With `connections` left at its default of one, every request through a block
waits behind the request before it.  For anything that serves more than a
few logins at a time that is worth raising.

## Building

```sh
./configure --add-module=/path/to/nginx-auth-ldap-module
```

or as a loadable module

```sh
./configure --add-dynamic-module=/path/to/nginx-auth-ldap-module
```

with `load_module modules/ngx_http_auth_ldap_module.so;` in the main
context.  The OpenLDAP client library is required and is looked for at
configure time; where its headers are not in the default search path, as on
FreeBSD, point to them with `--with-cc-opt` and `--with-ld-opt`.

## Testing

```sh
ci/build.sh 1.30.5 /tmp/nginx-test
TEST_NGINX_BINARY=/tmp/nginx-test/sbin/nginx prove -r t/
ci/auth.sh /tmp/nginx-test/sbin/nginx
ci/sync-connect.sh /tmp/nginx-test/sbin/nginx
ci/reload.sh /tmp/nginx-test/sbin/nginx
```

`t/` covers the configuration parser.  The drivers need a directory and
start one themselves: `ci/ldap.sh` runs a slapd with two users and a group,
`ci/auth.sh` asks who gets in, `ci/sync-connect.sh` repeats that with a
`connect(2)` that comes back already connected, and `ci/reload.sh`
authenticates again after every one of eight reloads.

## Credits and license

The module is the work of Valery Komarov, Jiri Hruska and Victor Hahn
Castell, BSD 2-Clause, see [LICENSE](LICENSE).  This fork keeps that licence
and adds the fixes listed in the changelog.
