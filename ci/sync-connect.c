/*
 * Make connect(2) come back connected, so that ngx_event_connect_peer()
 * returns NGX_OK instead of NGX_AGAIN.
 *
 * That is the state a FreeBSD machine reached on its own in bug 299038:
 * the connect to a directory on the same host completed inside the call,
 * nginx registered no write event, and a module that waits for one waits
 * for good.  It cannot be produced by asking the kernel nicely -- on every
 * system measured here, loopback connects report EINPROGRESS -- so the
 * state is forced from the outside: the socket is put back into blocking
 * mode for the duration of the call, which finishes the handshake, and the
 * zero that connect then returns is what nginx reads.
 *
 * Only for the drivers under ci/.  SYNC_CONNECT_LOG names a file that every
 * forced connect is recorded in, so a test can tell whether the path was
 * actually taken.  The file is opened when the library is loaded, and for
 * two reasons.  The name has to be read then, because nginx reuses the
 * environment block for its process title and getenv() cannot be relied on
 * afterwards.  And the file has to be opened then, because the worker that
 * makes the connections is forked from a master that may have been root and
 * has dropped its privileges by the time it connects: it inherits the open
 * descriptor, where opening the file itself would be denied, and nothing
 * would be recorded although every connect had been forced.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static int sync_connect_fd = -1;

__attribute__((constructor))
static void
sync_connect_init(void)
{
	const char *log = getenv("SYNC_CONNECT_LOG");

	if (log != NULL) {
		sync_connect_fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0644);
	}
}

int
connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	int flags, rc, saved;

	if (real_connect == NULL) {
		real_connect = (int (*)(int, const struct sockaddr *, socklen_t))
		    dlsym(RTLD_NEXT, "connect");
		if (real_connect == NULL) {
			return -1;
		}
	}

	flags = fcntl(fd, F_GETFL, 0);
	saved = flags;

	if (flags != -1 && (flags & O_NONBLOCK)) {
		(void) fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	}

	rc = real_connect(fd, addr, len);

	if (saved != -1 && (saved & O_NONBLOCK)) {
		(void) fcntl(fd, F_SETFL, saved);
	}

	/*
	 * The caller reads errno when connect answers -1, so what is done for
	 * the record here must not be what it reads.  One write, appended, so
	 * that the worker and the master cannot interleave a line.
	 */
	if (sync_connect_fd != -1) {
		int  err = errno;
		char line[64];
		int  n = snprintf(line, sizeof(line), "fd=%d rc=%d\n", fd, rc);

		if (n > 0 && (size_t) n < sizeof(line)) {
			(void) write(sync_connect_fd, line, (size_t) n);
		}

		errno = err;
	}

	return rc;
}
