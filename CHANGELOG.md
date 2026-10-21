# Changelog

## v0.2.0 (2026-10-21)

First release of this fork, from upstream `241200e`.

### Fixed

- A connection that is established inside `connect(2)` left the module
  waiting for an event that never comes.  `ngx_event_connect_peer()` answers
  `NGX_OK` in that case and registers no write event, so the handler the
  module installs is never called, the connection stays in
  `STATE_CONNECTING` and every request queues behind it until it times out.
  It happens on kqueue, where nginx registers the read event alone; on epoll
  the write event is registered anyway, which is why the failure was only
  ever seen on FreeBSD.  Reported in FreeBSD bug 299038, with the upstream
  pull request kvspb/nginx-auth-ldap#617 open since then.
- The `WWW-Authenticate` header was built without terminating the header
  list, which nginx has needed since 1.23.  Carried as a patch in the
  FreeBSD ports so far.
- The connections of a worker were closed by a pool cleanup, which runs
  after nginx has already looked for leftovers: every reload wrote two
  `open socket left in connection` alerts per worker and ended in
  `aborting`.  They are closed in the exit handler now, before that check.

### Added

- A test suite for the configuration parser, and drivers that run against a
  real directory: who gets in, who does not, what an unauthenticated request
  is told, and whether the connections survive a reload.
- `ci/sync-connect.sh` forces the connect that the first fix is about, with
  a small library in front of `connect(2)`, since no kernel measured here
  produces it on a loopback connection.
- Workflows for Linux and FreeBSD, the sanitizers, valgrind, CodeQL and the
  linters.
