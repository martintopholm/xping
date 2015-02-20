/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mph@hoth.dk> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Martin Topholm
 * ----------------------------------------------------------------------------
 */

#include <errno.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include "xping.h"

static regex_t re_target;
static struct timeval tv_timeout;
static void session_eventcb(struct bufferevent *, short, void *);
static void session_readcb_drain(struct bufferevent *, void *);

/* state for active tcp connection with a server */
struct session {
	struct target	*t;
	int		seq;
	struct bufferevent *bev;

	struct event	*ev_timeout;
	int		completed;
};


/*
 * Drop a session and free the associated state. bufferevent_free is
 * responsible for closing the actual socket
 */
static void
session_free(struct session *session)
{
	if (session->ev_timeout)
		event_free(session->ev_timeout);
	if (session->bev) {
		bufferevent_disable(session->bev, EV_READ|EV_WRITE);
		bufferevent_free(session->bev);
	}
	free(session);
}

/*
 * Construct a http request and send it.
 */
static void
session_send(struct session *session)
{
	/* XXX: compose http request */
	evbuffer_add_printf(bufferevent_get_output(session->bev),
	    "GET %s HTTP/1.1\r\n"
	    "Host: %s\r\n"
	    "Connection: close\r\n"
	    "User-Agent: xping/%s\r\n"
	    "\r\n", session->t->query, session->t->host, version);
}

/*
 * Read response status. Attempt to read the status line, but if CRLF
 * can not be found in the first 2048 bytes, consider it an error and
 * disconnect. Once status line is read switch to draining the rest of
 * the data. The server should close the connection due to
 * "Connection: close" header otherwise it will be caught by timeout.
 *
 * Even though status line says 200, the actual success is registered
 * on socket close.
 */
static void
session_readcb_status(struct bufferevent *bev, void *thunk)
{
	struct session *session = thunk;
	struct evbuffer *evbuf = bufferevent_get_input(bev);
	size_t len;
	char *line;
	char *protocol;
	char *number;

	line = evbuffer_readln(evbuf, &len, EVBUFFER_EOL_CRLF);
	if (line == NULL) {
		if (evbuffer_get_length(evbuf) > 2048) {
			session_free(session);
			return;
		} else
			return; /* wait for more data */
	}
	/* Parse response line */
	protocol = strsep(&line, " ");
	if (line == NULL)
		return session_free(session);
	number = strsep(&line, " ");
	if (line == NULL)
		return session_free(session);
	(void)protocol;
	(void)number;
	if (atoi(number) < 400 && atoi(number) >= 200 ) {
		session->completed = 1;
	}else{
		target_mark(session->t, session->seq, '%');
	}
	/* Drain the response on future callbacks */
	bufferevent_setcb(session->bev, session_readcb_drain, NULL,
	    session_eventcb, session);
}

/*
 * Discard any data received. This is used after reading the response's
 * status line.
 */
static void
session_readcb_drain(struct bufferevent *bev, void *thunk)
{
	struct evbuffer *evbuf = bufferevent_get_input(bev);
	evbuffer_drain(evbuf, evbuffer_get_length(evbuf));
}

/*
 * Handle socket events, such as connection failure or success.
 *   - BEV_EVENT_ERROR           - network is unreachable
 *   - BEV_EVENT_ERROR+READING   - connection refused or connection timed out
 *   - BEV_EVENT_TIMEOUT+READING - write timeout, if activated by
 *                                 bufferevent_set_timeouts
 */
static void
session_eventcb(struct bufferevent *bev, short what, void *thunk)
{
	struct session *session = thunk;
	switch (what & ~(BEV_EVENT_READING|BEV_EVENT_WRITING)) {
	case BEV_EVENT_CONNECTED:
		session_send(session);
		return;
	case BEV_EVENT_EOF:
		bufferevent_disable(bev, EV_READ|EV_WRITE);
		if (session->completed)
			target_mark(session->t, session->seq, '.');
		else
			target_mark(session->t, session->seq, '%');
		break;
	case BEV_EVENT_ERROR:
		bufferevent_disable(bev, EV_READ|EV_WRITE);
		target_mark(session->t, session->seq, '#');
		break;
	case BEV_EVENT_TIMEOUT:
		target_mark(session->t, session->seq, '?');
		break;
	}
	session_free(session);
}

/*
 * React to manual timeout event (not bufferevent_set_timeouts) by
 * closing the session. As bufferevent timeouts on either read or write,
 * a real slow (loris) server could keep the session alive indefinetly.
 */
static void
session_timeout(int fd, short what, void *thunk)
{
	struct session *session = thunk;
	session_free(session);
}

/*
 * Prepare datastructures needed for probe
 *  1. protocol
 *  2. separator, protocol
 *  3. hostname
 *  4. separator, forced address
 *  5. address
 *  6. port
 *  7. url
 */
#define RE_PROTO 1
#define RE_HOST 3
#define RE_FORCED 5
#define RE_PORT 6
#define RE_URL 7
#define RE_MAX 8
void
probe_setup()
{
	tv_timeout.tv_sec = 3 * i_interval / 1000;
	tv_timeout.tv_usec = 3 * i_interval % 1000 * 1000;
	if (regcomp(&re_target,
	    "^(http:(//)?)?([0-9A-Za-z.-]+)(\\[([0-9A-Fa-f.:]+)\\])?(:[0-9]+)?(/[^ ]*)?$",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr, "regcomp: error compiling regular expression\n");
		exit(1);
	}
}

/*
 * Helper function to probe_add, will encode a nibble as hex.
 */
static char
to_hex(int ch) {
    static char hex[] = "0123456789abcdef";
    return hex[ch & 0xf];
}

/*
 * Lookup table to determine which characters NOT to encode. Stolen from
 * libevents http.c and set slash (/) to not be encoded.
 */
static const char uri_chars[256] = {
	/* 0 */
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 0, 0, 0, 0, 0, 0,
	/* 64 */
	0, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 0, 0, 1,
	0, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 0, 1, 0,
	/* 128 */
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	/* 192 */
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
};


/*
 * Allocate structure for a new target and parse source line into the
 * structure. Report errors on stderr.
 */
struct target *
probe_add(const char *line)
{
	struct target *t;
	union addr sa;
	int salen;
	int port;
	regmatch_t match[RE_MAX];
	char forced[512];
	char *end;
	int i, j;

	if (regexec(&re_target, line, RE_MAX, match, 0) != 0) {
		fprintf(stderr, "probe_add: can't parse %.128s\n", line);
		return NULL;
	}

	t = calloc(1, sizeof(*t));
	if (t == NULL) {
		perror("probe_add: calloc");
		return (t);
	}
	memset(t->res, ' ', sizeof(t->res));

	strncat(t->host, line + match[RE_HOST].rm_so,
	    MIN(sizeof(t->host) - 1,
	    match[RE_HOST].rm_eo - match[RE_HOST].rm_so));
	if (match[RE_PORT].rm_so  != -1)
		port = strtol(line + match[RE_PORT].rm_so + 1, &end, 10);
	else
		port = 80;

	/* t->query NULL termination is provided by calloc */
	if (match[RE_URL].rm_so != -1)
		for (i = match[RE_URL].rm_so, j = 0; i < match[RE_URL].rm_eo &&
		    j + 3 < sizeof(t->query) - 1; i++) {
			const char *src = &line[i];
			if (uri_chars[(unsigned char)*src])
				t->query[j++] = *src;
			else if (*src == ' ')
				t->query[j++] = '+';
			else
				t->query[j++] = '%',
				    t->query[j++] = to_hex(*src >> 4),
				    t->query[j++] = to_hex(*src & 0xf);
		}
	else
		t->query[0] = '/';

	/*
	 * Check for presence of forced address e.g. example.com[127.0.0.1].
	 * If present parse the address or return an error. Otherwise
	 * check the hostname for an ip literal, if it doesn't parse
	 * leave it to target_add to resolve.
	 */
	salen = sizeof(sa);
	if (match[RE_FORCED].rm_so != -1) {
		forced[0] = '\0';
		strncat(forced, line + match[RE_FORCED].rm_so,
		    MIN(sizeof(forced) - 1,
		    match[RE_FORCED].rm_eo - match[RE_FORCED].rm_so));
		if (evutil_parse_sockaddr_port(forced, &sa.sa, &salen) == 0) {
			sa(t)->sa_family = sa.sa.sa_family;
			if (sa.sa.sa_family == AF_INET6) {
				memcpy(&sin6(t)->sin6_addr, &sa.sin6.sin6_addr,
				    sizeof(sin6(t)->sin6_addr));
			} else {
				memcpy(&sin(t)->sin_addr, &sa.sin.sin_addr,
				    sizeof(sin(t)->sin_addr));
			}
			t->resolved = 1;
		} else {
			fprintf(stderr, "probe_add: can't parse %.128s\n",
			    line);
			return NULL;
		}
	} else {
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
	}
	sin(t)->sin_port = htons(port);
	DL_APPEND(list, t);
	return (t);
}

/*
 * Resolving of target complete store resolved address.
 */
void
probe_resolved(struct target *t, int af, void *addresses)
{
	if (af == AF_INET6) {
		sin6(t)->sin6_family = AF_INET6;
		memmove(&sin6(t)->sin6_addr, (struct in6_addr *)addresses,
		    sizeof(sin6(t)->sin6_addr));
		t->resolved = 1;
	} else if (af == AF_INET) {
		sin(t)->sin_family = AF_INET;
		memmove(&sin(t)->sin_addr, (struct in_addr *)addresses,
		    sizeof(sin(t)->sin_addr));
		t->resolved = 1;
	} else if (af == 0) {
		t->resolved = 0;
	}
}

/*
 * Allocate session state for a single target probe and launch the probe.
 */
void probe_send(struct target *t, int seq)
{
	struct session *session;
	char buf[512];
	int salen;

	target_unmark(t, seq);
	session = calloc(1, sizeof(*session));
	if (session == NULL) {
		target_mark(t, seq, '!');
		return;
	}
	session->t = t;
	session->seq = seq;
	session->bev = bufferevent_socket_new(ev_base, -1,
	    BEV_OPT_CLOSE_ON_FREE);
	if (session->bev == NULL) {
		target_mark(t, seq, '!');
		free(session);
		return;
	}
	bufferevent_setcb(session->bev, session_readcb_status, NULL,
	    session_eventcb, session);
	evutil_inet_ntop(AF_INET, &sin(t)->sin_addr, buf, sizeof(buf));
	bufferevent_enable(session->bev, EV_READ);
	salen = sa(t)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) :
	    sizeof(struct sockaddr_in);
	if (bufferevent_socket_connect(session->bev, sa(t), salen) < 0) {
		target_mark(t, seq, '!');
		return;
	}
	bufferevent_setwatermark(session->bev, EV_READ, 0, 4096);

	session->ev_timeout = event_new(ev_base, -1, 0, session_timeout,
	    session);
	if (session->ev_timeout == NULL) {
		target_mark(t, seq, '!');
		session_free(session);
		return;
	}
	event_add(session->ev_timeout, &tv_timeout);
}
