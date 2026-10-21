# Changelog

## v0.2.0 (2026-10-21)

First release of this fork, from upstream `241200e`.

### Fixed

- A login name went into the LDAP search filter and into the group filter as
  it stood.  A name of `*` therefore matched the first user in the directory,
  which the module then bound with the password it was handed: whoever held
  one valid password could authenticate under any name, and a group
  requirement went the same way.  That is CVE-2020-14013, open upstream since
  2020 (pull request 239, onovy).
- A connection that was already established when `ngx_event_connect_peer()`
  returned left the module waiting for a write event that nginx does not
  register in that case, so the connection never became usable and every
  request queued behind it until it timed out.  It bites on kqueue; on epoll
  the event is registered anyway (FreeBSD bug 299038, pull request 617,
  NuLL3rr0r).
- The `WWW-Authenticate` header was pushed without terminating the header
  list, which nginx has needed since 1.23 (pull request 250, freultwah).
- The parsed url of every `ldap_server` was never given back, 170 bytes per
  server and again for every reload (same pull request).
- The connections of a worker were closed by a pool cleanup, which runs after
  nginx has looked for leftovers: every reload wrote two
  `open socket left in connection` alerts per worker and ended in `aborting`.
- The list of servers of a location holds pointers, and the cache path
  indexed it as an array of structs.  With the cache switched on that read
  far past the end of the allocation on every request.
- The last entry of a cache bucket was never considered for reuse, so a
  bucket held seven usable slots out of eight.
- An outcome is no longer cached for a server whose `require` rule is a
  variable: the key is the user, the password and the bytes of the server, so
  a rule that is decided per request is not in it.
- A bind DN that `require valid_user "<dn>"` builds from a variable is
  refused when the variable adds a relative name of its own, and the value of
  the first relative name of a group is escaped before it goes into a filter.
- Over `ldaps://`: a certificate whose name does not match crashed the worker
  (nginx leaves `sockaddr` unset on a connection it dialled out, and the
  address fallback read it), the certificate was never freed, the error
  return of `X509_check_host()` counted as a match, the address fallback
  compared the wrong bytes of the wrong structure, and the trust store was
  loaded again on every reconnect.

### Added

- `ci/ldap.sh` starts a slapd with two users and a group, with TLS and a CA
  of its own when it is asked for one.  `ci/auth.sh` drives who gets in,
  `ci/ldaps.sh` the same over TLS plus a certificate nobody trusts and one
  that names something else, `ci/sync-connect.sh` the whole matrix with a
  `connect(2)` that comes back connected, and `ci/reload.sh` authenticates
  again after each of eight reloads.
- `t/` covers the configuration parser.
- Workflows for the suite, the drivers, the sanitizers, valgrind, CodeQL and
  the linters.

### Not fixed

- A request through one `ldap_server` leaves the next request through a
  server with `require valid_user "<dn>"` answering invalid credentials for
  credentials that are correct.  Three requests reproduce it, and the
  imported state behaves the same way.
- The addresses of a directory are resolved when the configuration is read,
  so a changed DNS answer is picked up on the next reload and not before.
