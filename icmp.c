/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mph@hoth.dk> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Martin Topholm
 * ----------------------------------------------------------------------------
 */

#include <sys/param.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <unistd.h>

#include <event2/event.h>

#include "xping.h"

/* inherit stuff from xping.c */
extern int fd4;
extern int fd6;
void read_packet4(int fd, short what, void *thunk);
void read_packet6(int fd, short what, void *thunk);
int write_packet4(int fd, short what, void *thunk);
int write_packet6(int fd, short what, void *thunk);
void activatetarget(struct target *);
void resolvetarget(int, short, void *);

char	outpacket[IP_MAXPACKET];
char	outpacket6[IP_MAXPACKET];
int	datalen = 56;
int	ident;

/*
 * Prepare datastructures and events needed for probe
 */
void
probe_setup()
{
	struct event *ev;
	int i;

	/* Prepare datapacket */
	ident = getpid() & 0xffff;
	for (i=0; i<datalen; i++) {
		outpacket[ICMP_MINLEN + i] = '0' + i;
		outpacket6[ICMP6_MINLEN + i] = '0' + i;
	}

	evutil_make_socket_nonblocking(fd4);
	ev = event_new(ev_base, fd4, EV_READ|EV_PERSIST, read_packet4, NULL);
	event_add(ev, NULL);
	evutil_make_socket_nonblocking(fd6);
	ev = event_new(ev_base, fd6, EV_READ|EV_PERSIST, read_packet6, NULL);
	event_add(ev, NULL);
}

/*
 * Allocate structure for a new target and insert into list of all
 * our targets.
 */
struct target *
probe_add(const char *line)
{
	union addr sa;
	struct timeval tv;
	struct target * t;
	int salen;

	t = malloc(sizeof(*t));
	if (t == NULL)
		return (t);
	memset(t, 0, sizeof(*t));
	memset(t->res, ' ', sizeof(t->res));
	strncat(t->host, line, sizeof(t->host) - 1);
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
		activatetarget(t);
	} else {
		t->ev_resolve = event_new(ev_base, -1, 0, resolvetarget, t);
		evutil_timerclear(&tv);
		event_add(t->ev_resolve, &tv);
	}
	numtargets++;
	return (t);
}

/*
 * Send out a single probe for a target.
 */
void
probe_send(struct target *t)
{
	int len;
	int n;
	if (sa(t)->sa_family == AF_INET6) {
		n = write_packet6(fd6, 0, t);
		len = ICMP6_MINLEN + datalen;
	} else {
		n = write_packet4(fd4, 0, t);
		len = ICMP_MINLEN + datalen;
	}
	SETRES(t, 0, ' ');

	if (n < 0) {
		SETRES(t, 0, '!'); /* transmit error */
	} else if (n != len) {
		SETRES(t, 0, '$'); /* partial transmit */
	}
}
