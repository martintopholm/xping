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
#ifdef WITH_SSL
#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#endif /* WITH_SSL */
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include "xping.h"

struct probe {
	char		host[MAXHOST];
	int		resolved;
	union addr	sa;
	char		query[64];
#ifdef WITH_SSL
	SSL_CTX		*ssl_ctx;
#endif /* WITH_SSL */
	struct session	*sessions;
	void		*dnstask;
	void		*owner;
};

struct session {
	struct probe	*prb;
	int		seq;
	struct bufferevent *bev;
	struct event	*ev_timeout;
	char		*statusline;
	int		completed;
#ifdef WITH_SSL
	SSL		*ssl;
#endif /* WITH_SSL */
	struct session	*next;
};

static regex_t re_target;
static struct timeval tv_timeout;
static void session_eventcb(struct bufferevent *, short, void *);
static void session_readcb_drain(struct bufferevent *, void *);

/*
 * Drop a session and free the associated state. bufferevent_free is
 * responsible for closing the actual socket
 */
static void
session_free(struct session *session)
{

	if (session->statusline)
		free(session->statusline);
	LL_DELETE(session->prb->sessions, session);
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
	    "\r\n", session->prb->query, session->prb->host, version);
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
	session->statusline = line;
	/* Parse response line */
	protocol = strsep(&line, " ");
	if (line == NULL) {
		session_free(session);
		return;
	}
	number = strsep(&line, " ");
	if (line == NULL) {
		session_free(session);
		return;
	}
	(void)protocol;
	(void)number;
	if (atoi(number) < 400 && atoi(number) >= 200 ) {
		session->completed = 1;
	} else {
		target_mark(session->prb->owner, session->seq, '%');
	}
	/* Drain the response on future callbacks */
	bufferevent_setcb(session->bev, session_readcb_drain, NULL,
	    session_eventcb, session);
	session_readcb_drain(bev, session);
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
			target_mark(session->prb->owner, session->seq, '.');
		else
			target_mark(session->prb->owner, session->seq, '%');
		break;
	case BEV_EVENT_ERROR:
		bufferevent_disable(bev, EV_READ|EV_WRITE);
		target_mark(session->prb->owner, session->seq, '#');
		break;
	case BEV_EVENT_TIMEOUT:
		target_mark(session->prb->owner, session->seq, '?');
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

	if (session->completed)
		target_mark(session->prb->owner, session->seq, '?');
	session_free(session);
}

/*
 * Resolving of target complete store resolved address.
 */
static void
resolved(int af, void *address, void *thunk)
{
	struct probe *prb = thunk;
	if (af == AF_INET6) {
		sin6(prb)->sin6_family = AF_INET6;
		memmove(&sin6(prb)->sin6_addr, (struct in6_addr *)address,
		    sizeof(sin6(prb)->sin6_addr));
		prb->resolved = 1;
	} else if (af == AF_INET) {
		sin(prb)->sin_family = AF_INET;
		memmove(&sin(prb)->sin_addr, (struct in_addr *)address,
		    sizeof(sin(prb)->sin_addr));
		prb->resolved = 1;
	} else if (af == 0) {
		prb->resolved = 0;
	}
	target_resolved(prb->owner, af, address);
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
	if (regcomp(&re_target, "^(https?:(//)?)?"
            "([0-9A-Za-z.-]+)(\\[([0-9A-Fa-f.:]+)\\])?(:[0-9]+)?(/[^ ]*)?$",
	    REG_EXTENDED | REG_NEWLINE) != 0) {
		fprintf(stderr,
		    "regcomp: error compiling regular expression\n");
		exit(1);
	}
#ifdef WITH_SSL
	SSL_library_init();
#endif /* WITH_SSL */
}

void
probe_cleanup(void)
{

	regfree(&re_target);
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
struct probe *
probe_new(const char *line, void *owner)
{
	struct probe *prb;
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

	prb = calloc(1, sizeof(*prb));
	if (prb == NULL) {
		perror("probe_add: calloc");
		return (prb);
	}
	prb->owner = owner;

	if (line[match[RE_PROTO].rm_so + 4] == 's') {
#ifdef WITH_SSL
		long ssl_options;
		prb->ssl_ctx = SSL_CTX_new(SSLv23_method());
		if (prb->ssl_ctx == NULL) {
			perror("probe_add: SSL_CTX_new");
			return NULL;
		}
		ssl_options = SSL_CTX_get_options(prb->ssl_ctx);
		ssl_options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1;
		SSL_CTX_set_options(prb->ssl_ctx, ssl_options);
#else /* !WITH_SSL */
		free(prb);
		fprintf(stderr, "probe_add: ssl support not compiled in\n");
		return NULL;
#endif /* WITH_SSL */
	}

	strncat(prb->host, line + match[RE_HOST].rm_so,
	    MIN(sizeof(prb->host) - 1,
	    match[RE_HOST].rm_eo - match[RE_HOST].rm_so));
	if (match[RE_PORT].rm_so  != -1)
		port = strtol(line + match[RE_PORT].rm_so + 1, &end, 10);
#ifdef WITH_SSL
	else if (prb->ssl_ctx != NULL)
		port = 443;
#endif /* !WITH_SSL */
	else
		port = 80;

	/* prb->query NULL termination is provided by calloc */
	if (match[RE_URL].rm_so != -1)
		for (i = match[RE_URL].rm_so, j = 0; i < match[RE_URL].rm_eo &&
		    j + 3 < sizeof(prb->query) - 1; i++) {
			const char *src = &line[i];
			if (uri_chars[(unsigned char)*src])
				prb->query[j++] = *src;
			else if (*src == ' ')
				prb->query[j++] = '+';
			else
				prb->query[j++] = '%',
				    prb->query[j++] = to_hex(*src >> 4),
				    prb->query[j++] = to_hex(*src & 0xf);
		}
	else
		prb->query[0] = '/';

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
			sa(prb)->sa_family = sa.sa.sa_family;
			if (sa.sa.sa_family == AF_INET6) {
				memcpy(&sin6(prb)->sin6_addr,
				    &sa.sin6.sin6_addr,
				    sizeof(sin6(prb)->sin6_addr));
			} else {
				memcpy(&sin(prb)->sin_addr, &sa.sin.sin_addr,
				    sizeof(sin(prb)->sin_addr));
			}
			prb->resolved = 1;
		} else {
			fprintf(stderr, "probe_add: can't parse %.128s\n",
			    line);
			free(prb);
			return NULL;
		}
	} else {
		salen = sizeof(sa);
		if (evutil_parse_sockaddr_port(prb->host, &sa.sa,
		    &salen) == 0) {
			sa(prb)->sa_family = sa.sa.sa_family;
			if (sa.sa.sa_family == AF_INET6) {
				memcpy(&sin6(prb)->sin6_addr,
				    &sa.sin6.sin6_addr,
				    sizeof(sin6(prb)->sin6_addr));
			} else {
				memcpy(&sin(prb)->sin_addr, &sa.sin.sin_addr,
				    sizeof(sin(prb)->sin_addr));
			}
			prb->resolved = 1;
		} else {
			prb->dnstask = dnstask_new(prb->host, resolved, prb);
			if (prb->dnstask == NULL) {
				free(prb);
				return NULL;
			}
		}
	}
	sin(prb)->sin_port = htons(port);
	return (prb);
}

void probe_free(struct probe *prb)
{
	struct session *s, *s_tmp;

	LL_FOREACH_SAFE(prb->sessions, s, s_tmp) {
		session_free(s);
	}
	if (prb->dnstask)
		dnstask_free(prb->dnstask);
	free(prb);
}

/*
 * Allocate session state for a single target probe and launch the probe.
 */
void probe_send(struct probe *prb, int seq)
{
	struct session *session;
	char buf[512];
	int salen;

	if (!prb->resolved) {
		target_mark(prb->owner, seq, '@');
		return;
	}
	session = calloc(1, sizeof(*session));
	if (session == NULL) {
		target_mark(prb->owner, seq, '!');
		return;
	}
	session->prb = prb;
	session->seq = seq;
	LL_APPEND(prb->sessions, session);
#ifdef WITH_SSL
	if (prb->ssl_ctx != NULL) {
		session->ssl = SSL_new(prb->ssl_ctx);
		if (session->ssl == NULL) {
			target_mark(prb->owner, seq, '!');
			session_free(session);
			return;
		}
		session->bev = bufferevent_openssl_socket_new(ev_base, -1,
		    session->ssl, BUFFEREVENT_SSL_CONNECTING,
		    BEV_OPT_DEFER_CALLBACKS | BEV_OPT_CLOSE_ON_FREE);
	} else {
		session->bev = bufferevent_socket_new(ev_base, -1,
		    BEV_OPT_CLOSE_ON_FREE);
	}
#else /* !WITH_SSL */
	session->bev = bufferevent_socket_new(ev_base, -1,
	    BEV_OPT_CLOSE_ON_FREE);
#endif
	if (session->bev == NULL) {
		target_mark(prb->owner, seq, '!');
		session_free(session);
		return;
	}
	bufferevent_setcb(session->bev, session_readcb_status, NULL,
	    session_eventcb, session);
	evutil_inet_ntop(AF_INET, &sin(prb)->sin_addr, buf, sizeof(buf));
	bufferevent_enable(session->bev, EV_READ);
	salen = sa(prb)->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) :
	    sizeof(struct sockaddr_in);
	if (bufferevent_socket_connect(session->bev, sa(prb), salen) < 0) {
		target_mark(prb->owner, seq, '!');
		return;
	}
	bufferevent_setwatermark(session->bev, EV_READ, 0, 4096);

	session->ev_timeout = event_new(ev_base, -1, 0, session_timeout,
	    session);
	if (session->ev_timeout == NULL) {
		target_mark(prb->owner, seq, '!');
		session_free(session);
		return;
	}
	event_add(session->ev_timeout, &tv_timeout);
}
