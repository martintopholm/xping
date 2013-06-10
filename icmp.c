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
