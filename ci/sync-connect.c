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
 * actually taken.  The name is read when the library is loaded, not when a
 * connect happens: nginx reuses the environment block for its process
 * title, and getenv() cannot be relied on afterwards.
 */

#define _GNU_SOURCE

#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t);
static char *sync_connect_log;

__attribute__((constructor))
static void
sync_connect_init(void)
{
	const char *log = getenv("SYNC_CONNECT_LOG");

	if (log != NULL) {
		sync_connect_log = strdup(log);
	}
}

int
connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	int    flags, rc, saved;
	FILE  *f;

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

	if (sync_connect_log != NULL
	    && (f = fopen(sync_connect_log, "a")) != NULL)
	{
		(void) fprintf(f, "fd=%d rc=%d\n", fd, rc);
		(void) fclose(f);
	}

	return rc;
}
