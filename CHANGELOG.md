# Changelog

## v0.2.2 (2026-10-21)

### Fixed

- The bind DN that `require valid_user` builds would not compile where
  nginx builds with clang.  `written` is read after a branch that assigns
  it only when the DN parsed, which holds but which the compiler cannot
  see; nginx makes `-Wconditional-uninitialized` an error, so the build
  stopped on FreeBSD.

### Added

- A build with clang, because nginx picks the warnings it turns on from the
  compiler.  The gcc matrix cannot see that class of warning at all.

## v0.2.1 (2026-10-21)

What the first release of this fork wrote down as not fixed, fixed.

### Fixed

- The bind DN that `require valid_user "<dn>"` builds is read as the
  distinguished name it is and bound as libldap writes it out again.
  Counting its commas was not enough: a login name with a plus in it builds
  one relative name with two values and leaves the count where it was.
- A value in a relative name that is written in the hexadecimal form a DN
  allows is refused, in a group rule as in a bind DN.  The written form does
  not show the bytes it carries, a null byte among them, and libldap hands
  the decoded bytes on.
- A host in a `url` is asked again before every connection where
  `auth_ldap_resolver` says where to ask, so a directory that moved is
  reached without a reload.  The addresses the configuration resolved used
  to be all there was.

### Changed

- `max_down_retries` is counted for the connection and no longer for the
  server.  With more than one connection they counted into the same number
  and one that came back reset it for all the others.
- The name in a certificate has to stand in a subject alternative name.  It
  could come from the common name, which RFC 9525 says it should not, and
  nginx's own check still allows -- here it does not.  Where that is the
  certificate one has, `ssl_check_cert chain` is the setting for it.

### Added

- `ssl_check_cert chain`, a third setting between `off` and `on`: the chain
  is verified and the name is left alone, for a directory whose certificate
  names something other than the way it is reached.
- `ssl_crl_file`, a revocation list the certificate of the directory is held
  against.
- `auth_ldap_resolver` and `auth_ldap_resolver_timeout`, which say where a
  host in a `url` is asked of.  A host that cannot be resolved while the
  configuration is read is an error without them and none with them.
- `ci/resolve.sh` and `ci/dns.pl`: a nameserver that answers from a file, so
  that the answer can be changed under a running nginx and the module can be
  asked whether it asked again.

## v0.2.0 (2026-10-21)

First release of this fork, from upstream `241200e`.  The number follows
upstream's own, whose single tag is `v0.1`.

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
- Over `ldaps://`: a certificate whose name does not match crashed the worker
  (nginx leaves `sockaddr` unset on a connection it dialled out, and the
  address fallback read it), the certificate was never freed, the error
  return of `X509_check_host()` counted as a match, the address fallback
  compared the wrong bytes of the wrong structure, and the trust store was
  loaded again on every reconnect (issue 236, mmguero; pull requests 237,
  mmguero, and 251, Ericbla).  A partial wildcard in a certificate was a
  match, and a url that names no host went into `X509_check_host()` as a
  null pointer -- that check stays, although such a url is now refused
  before it can be reached.
- The flag that says the trust store has been filled was set even when
  filling it had failed, and it sat in front of the field the cache key
  stops at, so the first handshake of a worker changed the key of a server
  that had not changed.
- A connection given back to the pool twice was linked to itself, and a walk
  over the pool then had no end.  Giving it back twice is now a no-op, the
  way taking it out twice already was.
- A connection that was closed while a request held it went back into the
  pool all the same: closing cleared its own pointer to the request but not
  the request's pointer to it, so the request handed back a connection that
  was gone and the next one bound on a handle of NULL.  Closing now clears
  both, and only a connection that is ready and still has its handle goes
  back in.
- The retry after `LDAP_SERVER_DOWN` called the reconnect handler with the
  read event of the nginx connection that closing had just given back, so
  the handler read the LDAP connection out of a slot the free list had
  already taken over.  It arms the reconnect timer instead.
- `max_down_retries_count` sat in front of the field the cache key stops at,
  so a directory that dropped a connection changed the key of a server whose
  configuration had not changed.  It is behind that field now, where the
  other fields that change while the worker runs are.
- The cache was read for every server of a location, including the ones this
  request had already been refused by: a pass cached for such a server in
  the meantime overrode the refusal this request had just had from it.  The
  lookup starts at the server that is about to decide.
- An error from the bind fell through to the rebind phase, where there was
  nothing to undo, instead of moving on to the next server.
- The comma that separates the relative names of a group was looked for with
  `ngx_strchr()`, which finds one that a backslash makes part of a value:
  `cn=Admins\,Global,ou=groups,dc=x` became an assertion on `cn=Admins\` and
  a search under `Global,ou=groups,dc=x` (issue 224, DreDub2k).  The count that holds a
  rule against its template reads a name the same way, so the two cannot
  disagree.
- A rule counted as ending in a variable when its last character closed a
  brace, whatever that brace belonged to, and the looser rule that goes with
  a variable at the end was then applied to a rule with a variable in the
  middle as well.  It now takes exactly one variable, at the end, and nothing
  behind it.
- A url that names no host, which RFC 4516 allows, was read as a string
  while the configuration was parsed: the master process went down on
  `nginx -t`.  Such a url is refused now.
- A line an `ldap_server` block does not know was taken and dropped without
  a word, so a `require` rule with a typo in it left a server with no rule
  at all -- which lets in everyone who can bind.  It is refused, as is a
  line with no value, and `ssl_check_cert` and `group_attribute_is_dn` now
  read `off` as well as `on` instead of quietly ignoring everything that is
  not `on`.
- `ssl_check_cert on` on an nginx built against OpenSSL older than 1.0.2
  logged that it could not verify anything and then came up anyway, with
  verification off.  It fails the configuration.
- `ngx_palloc()` for the url and `ngx_pcalloc()` for a group rule went
  unchecked into `ngx_sprintf()` and `ngx_memcpy()`.

### Changed

- Every `ldap_server` that verifies a certificate gets a trust store of its
  own, holding the authorities it names and nothing else, or the trust store
  of the system where it names none.  The authorities used to go into the
  SSL context, which belongs to the configuration and is shared by every
  server in it: one server's authority was trusted by all of them, and a
  server that named none put the store of the system back behind the ones
  that had been named.  Authorities that cannot be loaded now fail the
  configuration instead of leaving a server that trusts whatever is in the
  store of the system.

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
