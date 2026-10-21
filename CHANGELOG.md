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
- Closing a connection closed it twice: the unbind goes through libldap,
  whose sockbuf calls the close again.  One pass is enough.
- A bind DN that `require valid_user "<dn>"` builds was handed to
  `ldap_sasl_bind()` as it came out of the complex value, which is a length
  and a buffer with no null byte behind it.  The DN therefore reached the
  directory with whatever the pool had put behind the value stuck to the end
  of it: the first request after a start happened to find a zero there and
  passed, and a request after one through another location was refused with
  invalid credentials for credentials that were correct, or with invalid DN
  syntax.  Besides refusing the right password it sent a piece of the
  worker's memory to the directory.  The search path copies `len + 1` for
  the same reason; this one did not.
- The list of servers of a location holds pointers, and the cache path
  indexed it as an array of structs.  With the cache switched on that read
  far past the end of the allocation on every request.
- The last entry of a cache bucket was never considered for reuse, so a
  bucket held seven usable slots out of eight.
- An outcome is no longer cached for a server whose `require` rule is a
  variable: the key is the user, the password and the bytes of the server, so
  a rule that is decided per request is not in it.
- The cache is read for every server of a location, and each of those reads
  left its key in the request (pull request 219, landryb).  The outcome of
  the server that decided was then written under the key of whichever server
  the loop had looked at last, so an outcome came back for a server that
  never gave it.  The key now belongs to the lookup, and only the key of the
  server that is about to decide is kept.
- A cached refusal of one server was taken as the answer for the whole list.
  A request walks the servers until one lets it in, so a refusal says
  nothing about the servers behind it -- and since a refusal is written
  before the next server is asked, the request ran into the refusal it had
  just caused itself and ended there.  A refusal now decides only for the
  server it belongs to; a cached pass still decides for the list.
- The attribute name of a group's first relative name went into the filter
  as it stood, and everything behind that name went to the directory as the
  base to search under, both of them straight from the rule.  The name has
  to be an attribute description now, the whole rule has to be a
  distinguished name, and a variable that does not end the rule may not add
  a relative name to it.
- `require valid_user "<dn>"` evaluated its template twice, once to check it
  and once to bind: the DN that was checked was not the DN that was bound.
- A request the module could not decide came back as `NGX_ERROR`, which an
  access phase handler cannot answer with: nginx closed the connection and
  the client saw nothing at all.  A directory that cannot be reached -- one
  whose certificate is refused, for instance -- left the request waiting out
  its `request_timeout` and then dropped it.  It is a 500 now.
- A bind DN that `require valid_user "<dn>"` builds from a variable is
  refused when the variable adds a relative name of its own, and the value of
  the first relative name of a group is escaped before it goes into a filter.
- Over `ldaps://`: a certificate whose name does not match crashed the worker
  (nginx leaves `sockaddr` unset on a connection it dialled out, and the
  address fallback read it), the certificate was never freed, the error
  return of `X509_check_host()` counted as a match, the address fallback
  compared the wrong bytes of the wrong structure, and the trust store was
  loaded again on every reconnect.  A url that names no host went into
  `X509_check_host()` as a null pointer, and a partial wildcard in a
  certificate was a match.
- The flag that says the trust store has been filled was set even when
  filling it had failed, and it sat in front of the field the cache key
  stops at, so the first handshake of a worker changed the key of a server
  that had not changed.
- A connection given back to the pool twice was linked to itself, and a walk
  over the pool then had no end.  Giving it back twice is now a no-op, the
  way taking it out twice already was.

### Changed

- Authorities named with `ssl_ca_file` or `ssl_ca_dir` take the place of the
  trust store of the system instead of being added to it.  A configuration
  that says which authority signs its directory means that one.

### Added

- `ci/ldap.sh` starts a slapd with four users and two groups, with TLS and a CA
  of its own when it is asked for one.  `ci/auth.sh` drives who gets in,
  `ci/ldaps.sh` the same over TLS plus a certificate nobody trusts and one
  that names something else, `ci/sync-connect.sh` the whole matrix with a
  `connect(2)` that comes back connected, and `ci/reload.sh` authenticates
  again after each of eight reloads.
- `t/` covers the configuration parser.
- Workflows for the suite, the drivers, the sanitizers, valgrind, CodeQL and
  the linters.  The two that look for leaks walk a request rather than only
  the configuration parser, and the valgrind job fails when valgrind has
  left no summary behind, since a clean run under `-q` says nothing at all
  and looks exactly like a run that never happened.

### Not fixed

- The addresses of a directory are resolved when the configuration is read,
  so a changed DNS answer is picked up on the next reload and not before
  (issue 63; pull request 251 carries a resolver for it, which is not taken
  over here).
- Revocation of the certificate of a directory is not checked, and there is
  no way to ask for it.
- `max_down_retries` counts on the server rather than on the connection, so
  with more than one connection they all count into the same number and one
  that comes back resets it for the others.  Issue 226 is about what that
  setting does in practice.
- `ssl_check_cert` is a flag: there is no way to verify the chain and leave
  the name alone, which pull requests 237 and 251 both propose as a third
  setting.
- The name of a certificate may be taken from its common name where the
  certificate carries no subject alternative name.  RFC 9525 says it should
  not be, and issue 254 asks for that; nginx's own check does the same, and
  this module follows nginx rather than differing from it.
