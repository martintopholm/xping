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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include "xping.h"
#include "tricks.h"

struct probe {
	char		host[MAXHOST];
	int		resolved;
	union addr	sa;
	int		pid;
	int		fd;
	int		seqdelta;
	int		seqlast;
	int		early_mark;
	struct event	*ev_read;
	struct evbuffer	*evbuf;
	void		*dnstask;
	void		*owner;
};

static regex_t re_reply, re_other, re_xmiterr;

static void
killping(struct probe *prb)
{
	if (prb->pid && kill(prb->pid, 0) == 0) {
		kill(prb->pid, SIGTERM);
		prb->pid = 0;
	}
}

static void
execping(struct probe *prb)
{
	char address[64];
	char interval[24];

	evutil_snprintf(interval, sizeof(interval), "%f",
	    (double)i_interval/1000);

	if (sa(prb)->sa_family == AF_INET6) {
		evutil_inet_ntop(sa(prb)->sa_family, &sin6(prb)->sin6_addr,
		    address, sizeof(address));
		execlp("ping6", "ping6", "-ni", interval, address, NULL);
	} else {
		evutil_inet_ntop(sa(prb)->sa_family, &sin(prb)->sin_addr,
		    address, sizeof(address));
		execlp("ping", "ping", "-ni", interval, address, NULL);
	}
	exit(1); /* in case exec fails */
}

static void
readping(int fd, short what, void *thunk)
{
	struct probe *prb = thunk;
	regmatch_t match[5];
	struct evbuffer_ptr evbufptr;
	double rtt;
	size_t len;
	char buf[BUFSIZ];
	char *end;
	long int seq;
	int mark;
	int n;

	evbuffer_read(prb->evbuf, fd, 512);
	evbufptr = evbuffer_search_eol(prb->evbuf, NULL, &len,
	    EVBUFFER_EOL_ANY);
	while (evbufptr.pos != -1) {
		len += evbufptr.pos;
		n = evbuffer_remove(prb->evbuf, buf, MIN(sizeof(buf)-1, len));
		buf[n] = '\0';
		mark = '\0';
		if (regexec(&re_reply, buf, 5, match, 0) == 0) {
			seq = strtol(buf + match[1].rm_so, &end, 10);
			rtt = strtod(buf + match[2].rm_so, &end);
			mark = '.';
		} else if (regexec(&re_other, buf, 5, match, 0) == 0) {
			seq = strtol(buf + match[1].rm_so, &end, 10);
			if (match[2].rm_so != match[2].rm_eo)
				mark = '#';
			else
				mark = '%';
		} else if (regexec(&re_xmiterr, buf, 5, match, 0) == 0) {
			/* Transmit errors are quickly identified,
			 * thus assume they refer to most recent packet */
			target_mark(prb->owner, prb->seqlast, '!');
		}
		if (mark != '\0') {
			/* Adjust sequence adjustment delta. In cast the
			 * first packet has icmp_seq=0 instead of 1 */
			if (prb->seqlast < 32768 && seq == 0)
				prb->seqdelta++;
			/*
			 * seq newer than last sent, thus packet arrived too
			 * early (before probe_send. Cached mark until
			 * probe_send is called next_time.
			 */
			if (prb->seqlast < seq + prb->seqdelta) {
				AZ(prb->early_mark == '\0');
				prb->early_mark = mark;
				return;
			}
			target_mark(prb->owner, seq + prb->seqdelta, mark);

			/* Check for timing drift: If packet isn't the
			 * latest reply and ping thinks rtt is less than
			 * i_interval it must have drifted */
			if (mark == '.' &&
			    seq + prb->seqdelta < prb->seqlast &&
			    rtt < i_interval) {
				killping(prb);
				target_mark(prb->owner, prb->seqlast, '!');
			}
		}
		evbufptr = evbuffer_search_eol(prb->evbuf, NULL, &len,
		    EVBUFFER_EOL_LF);
	}
}

/*
 * Store newly resolved address in target struct (or if af == 0
 * unresolved). Only change address and reset probe if address actually
 * changed.
 */
static void
resolved(int af, void *address, void *thunk)
{
	struct probe *prb = thunk;
	if (af == AF_INET6) {
		if (sin6(prb)->sin6_family == AF_INET6 &&
		    memcmp(&sin6(prb)->sin6_addr, (struct in6_addr *)address,
		    sizeof(sin6(prb)->sin6_addr)) == 0)
			return;
		sin6(prb)->sin6_family = AF_INET6;
		memmove(&sin6(prb)->sin6_addr, (struct in6_addr *)address,
		    sizeof(sin6(prb)->sin6_addr));
		killping(prb);
		prb->resolved = 1;
	} else if (af == AF_INET) {
		if (sin(prb)->sin_family == AF_INET &&
		    memcmp(&sin(prb)->sin_addr, (struct in_addr *)address,
		    sizeof(sin(prb)->sin_addr)) == 0)
			return;
		sin(prb)->sin_family = AF_INET;
		memmove(&sin(prb)->sin_addr, (struct in_addr *)address,
		    sizeof(sin(prb)->sin_addr));
		killping(prb);
		prb->resolved = 1;
	} else if (af == 0) {
		prb->resolved = 0;
		killping(prb);
	}
	target_resolved(prb->owner, af, address);
}

/*
 * Set up regular expressions for matching reply lines, unreachable lines,
 * and send errors.
 *
 * FreeBSD-9:
 *     64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.030 ms
 *     ping: sendto: Host is down
 *
 * iputils-s20121221:
 *     64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.027 ms
 *     From 192.0.2.1 icmp_seq=1 Destination Host Unreachable
 *
 * iputils-sss20101006
 *     64 bytes from 127.0.0.1: icmp_req=1 ttl=64 time=0.028 ms
 *     From 192.0.2.1 icmp_seq=1 Destination Net Unreachable
 */
void
probe_setup(struct event_base *parent_event_base)
{
	signal(SIGCHLD, SIG_IGN);
	if (regcomp(&re_reply,
	    "[0-9]+ bytes.*icmp_.eq=([0-9][0-9]*) .*time=([0-9].[0-9]*)",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr,
		    "regcomp: error compiling regular expression\n");
		exit(1);
	}
	if (regcomp(&re_other, "From .*icmp_.eq=([0-9][0-9]*)"
	    "( Destination Host Unreachable| Destination unreachable| )",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr,
		    "regcomp: error compiling regular expression\n");
		exit(1);
	}
	if (regcomp(&re_xmiterr, "(ping|ping6|connect): "
	    "(sentto|UDP connect|sendmsg|Network is unreachable)",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr,
		    "regcomp: error compiling regular expression\n");
		exit(1);
	}
}

void probe_cleanup(void)
{

	regfree(&re_reply);
	regfree(&re_other);
	regfree(&re_xmiterr);
}

struct probe *
probe_new(const char *line, void *owner)
{
	struct probe *prb;
	union addr sa;
	int salen;

	prb = calloc(1, sizeof(*prb));
	if (prb == NULL) {
		perror("malloc");
		return (NULL);
	}
	prb->fd = -1;
	prb->owner = owner;
	strncat(prb->host, line, sizeof(prb->host) - 1);
	prb->evbuf = evbuffer_new();
	if (prb->evbuf == NULL) {
		probe_free(prb);
		return NULL;
	}

	salen = sizeof(sa);
	if (evutil_parse_sockaddr_port(prb->host, &sa.sa, &salen) == 0) {
		sa(prb)->sa_family = sa.sa.sa_family;
		if (sa.sa.sa_family == AF_INET6) {
			memcpy(&sin6(prb)->sin6_addr, &sa.sin6.sin6_addr,
			    sizeof(sin6(prb)->sin6_addr));
		} else {
			memcpy(&sin(prb)->sin_addr, &sa.sin.sin_addr,
			    sizeof(sin(prb)->sin_addr));
		}
		prb->resolved = 1;
	} else {
		prb->dnstask = dnstask_new(prb->host, resolved, prb);
		if (prb->dnstask == NULL) {
			probe_free(prb);
			return NULL;
		}
	}
	return (prb);
}

void probe_free(struct probe *prb)
{

	if (prb->fd >= 0)
		close(prb->fd);
	if (prb->ev_read)
		event_free(prb->ev_read);
	if (prb->dnstask)
		dnstask_free(prb->dnstask);
	if (prb->evbuf)
		evbuffer_free(prb->evbuf);
	free(prb);
}

void
probe_send(struct probe *prb, int seq)
{
	int pair[2];
	pid_t pid;

	if (!prb->resolved) {
		target_mark(prb->owner, seq, '@');
		return;
	}

	/* Save most recent sequence number to close gap between
	 * probe_send returning (target_probe increasing npkts) and forked
	 * program outputting */
	prb->seqlast = seq;

	/* Clear ahead to avoid overwriting a result in case of small
	 * timing indiscrepancies */
	target_mark(prb->owner, seq+1, ' ');

	/* If we have a cached early mark, send it right away. */
	if (prb->early_mark != '\0') {
		target_mark(prb->owner, seq, prb->early_mark);
		prb->early_mark = '\0';
	}

	/* Check for existing ping process */
	if (prb->pid && kill(prb->pid, 0) == 0)
		return;

	/* Create ipc socket pair and fork ping process */
	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
		target_mark(prb->owner, seq, '!'); /* transmit error */
		return;
	}
	prb->seqdelta = seq - 1; /* linux ping(8) begins icmp_seq=1 */
	evutil_make_socket_nonblocking(pair[0]);
	if (prb->fd >= 0)
		close(prb->fd);
	if (prb->ev_read != NULL)
		event_free(prb->ev_read);
	prb->ev_read = event_new(ev_base, pair[0], EV_READ|EV_PERSIST, readping, prb);
	event_add(prb->ev_read, NULL);
	switch (pid = fork()) {
	case -1:
		target_mark(prb->owner, seq, '!'); /* transmit error */
		return;
	case 0:
		evutil_closesocket(pair[0]);
		dup2(pair[1], 1);
		dup2(pair[1], 2);
		execping(prb);
		/* NEVER REACHED */
		break;
	default:
		evutil_closesocket(pair[1]);
		prb->pid = pid;
		prb->fd = pair[0];
		break;
	}
}
