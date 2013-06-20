/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mph@hoth.dk> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Martin Topholm
 * ----------------------------------------------------------------------------
 */

#include <sys/param.h>

#include <regex.h>
#include <unistd.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include "xping.h"

static regex_t re_reply, re_other;

/* FIXME: shut down a fork'ed ping */
/* FIXME: shut pings down on program exit */
static void
killping(struct target *t)
{
	if (t->pid && kill(t->pid, 0) == 0) {
		kill(t->pid, SIGTERM);
		t->pid = 0;
	}
}

static void
execping(struct target *t)
{
	char address[64];

	if (sa(t)->sa_family == AF_INET6) {
		evutil_inet_ntop(sa(t)->sa_family, &sin6(t)->sin6_addr, address, sizeof(address));
		execlp("ping6", "ping6", "-n", address, NULL);
	} else {
		evutil_inet_ntop(sa(t)->sa_family, &sin(t)->sin_addr, address, sizeof(address));
		execlp("ping", "ping", "-n", address, NULL);
	}
	exit(1); /* in case exec fails */
}

static void
readping(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	regmatch_t match[5];
	struct evbuffer_ptr evbufptr;
	size_t len;
	char buf[BUFSIZ];
	char *end;
	long int seq;
	int n;

	evbuffer_read(t->evbuf, fd, 512);
	evbufptr = evbuffer_search_eol(t->evbuf, NULL, &len, EVBUFFER_EOL_ANY);
	while (evbufptr.pos != -1) {
		len += evbufptr.pos;
		n = evbuffer_remove(t->evbuf, buf, MIN(sizeof(buf)-1, len));
		buf[n] = '\0';
		if (regexec(&re_reply, buf, 5, match, 0) == 0) {
			seq = strtol(buf + match[1].rm_so, &end, 10) + t->seqdelta;
			target_mark(t, seq, '.');
		} else if (regexec(&re_other, buf, 5, match, 0) == 0) {
			seq = strtol(buf + match[1].rm_so, &end, 10) + t->seqdelta;
			if (match[2].rm_so != match[2].rm_eo)
				target_mark(t, seq, '#');
			else
				target_mark(t, seq, '%');
		}
		evbufptr = evbuffer_search_eol(t->evbuf, NULL, &len, EVBUFFER_EOL_LF);
	}
}

void
probe_setup(struct event_base *parent_event_base)
{
	signal(SIGCHLD, SIG_IGN);
	if (regcomp(&re_reply, "64 bytes.*seq=([0-9][0-9]*) ",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr, "regcomp: error compiling regular expression\n");
		exit(1);
	}
	if (regcomp(&re_other, "From .*icmp_seq=([0-9][0-9]*) "
            "( Destination Host Unreachable| Destination unreachable| )",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr, "regcomp: error compiling regular expression\n");
		exit(1);
	}
}

struct target *
probe_add(const char *line)
{
	struct target *t;
	union addr sa;
	int salen;

	t = malloc(sizeof(*t));
	if (t == NULL)
		return (NULL);
	memset(t, 0, sizeof(*t));
	memset(t->res, ' ', sizeof(t->res));
	strncat(t->host, line, sizeof(t->host) - 1);
	t->evbuf = evbuffer_new();
	if (t->evbuf == NULL) {
		free(t);
		return (NULL);
	}
	DL_APPEND(list, t);

	salen = sizeof(sa);
	if (evutil_parse_sockaddr_port(t->host, &sa.sa, &salen) == 0) {
		sa(t)->sa_family = sa.sa.sa_family;
		if (sa.sa.sa_family == AF_INET6) {
			memcpy(&sin6(t)->sin6_addr, &sa.sin6.sin6_addr,
			    sizeof(sin6(t)->sin6_addr));
		} else {
			memcpy(&sin(t)->sin_addr, &sa.sin.sin_addr,
			    sizeof(sin(t)->sin_addr));
		}
		t->resolved = 1;
	}
	return (t);
}

void
probe_resolved(struct target *t, int af, void *addresses)
{
	if (af == AF_INET6) {
		sin6(t)->sin6_family = AF_INET6;
		memmove(&sin6(t)->sin6_addr, (struct in6_addr *)addresses,
		    sizeof(sin6(t)->sin6_addr));
		killping(t);
		t->resolved = 1;
	} else if (af == AF_INET) {
		sin(t)->sin_family = AF_INET;
		memmove(&sin(t)->sin_addr, (struct in_addr *)addresses,
		    sizeof(sin(t)->sin_addr));
		killping(t);
		t->resolved = 1;
	} else if (af == 0) {
		t->resolved = 0;
		killping(t);
	}
}

void
probe_send(struct target *t)
{
	struct event *ev;
	int pair[2];
	pid_t pid;

	/* Clear ahead to avoid overwriting a result in case of small
	 * timing indiscrepancies */
	SETRES(t, 1, ' ');

	/* Check for existing ping process */
	if (t->pid && kill(t->pid, 0) == 0)
		return;

	/* Create ipc socket pair and fork ping process */
	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
		SETRES(t, 0, '!'); /* transmit error */
		return;
	}
	t->seqdelta = t->npkts - 1;
	evutil_make_socket_nonblocking(pair[0]);
	ev = event_new(ev_base, pair[0], EV_READ|EV_PERSIST, readping, t);
	event_add(ev, NULL);
	switch (pid = fork()) {
	case -1:
		SETRES(t, 0, '!'); /* transmit error */
		return;
	case 0:
		evutil_closesocket(pair[0]);
		dup2(pair[1], 1);
		dup2(pair[1], 2);
		execping(t);
		/* NEVER REACHED */
		break;
	default:
		evutil_closesocket(pair[1]);
		t->pid = pid;
		t->fd = pair[0];
		break;
	}
}
