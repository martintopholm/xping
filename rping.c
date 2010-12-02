#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <util-internal.h>
#include <ncurses.h>

#include "queue.h"


struct event_base *ev_base;
struct evdns_base *dns;

int ident;

#define NUM 300
#define SETRES(t,i,r) t->res[(t->npkts+i) % NUM] = r
#define GETRES(t,i) t->res[(t->npkts+i) % NUM]

SLIST_HEAD(slisthead, target) head = SLIST_HEAD_INITIALIZER(head);
struct target {
	char		host[64];
	int		resolved;

	struct sockaddr_in sin;
	int		npkts;
	char		res[NUM+1];

	SLIST_ENTRY(target) entries;
};

void redraw();

// struct in_addr *in_addrs = addresses; 
// struct in6_addr *in6_addrs = addresses;
void resolved_host(int result, char type, int count, int ttl, void *addresses,
    void *thunk) 
{
	char asdf[64];
	struct target *t = thunk;


	if (result == DNS_ERR_NONE && type == DNS_IPv4_A && count > 0) {
		t->sin.sin_family = AF_INET;
		memmove(&t->sin.sin_addr, (struct in_addr *)addresses,
		    sizeof(t->sin.sin_addr));
		t->resolved = 1;
	}

	evutil_format_sockaddr_port((struct sockaddr *)&t->sin, asdf, sizeof(asdf));
	mvprintw(10, 0, "resolved_host %d %d %d %d %s %s\n", result, type, count, ttl, t->host, asdf );
}

void read_packet(int fd, short what, void *thunk)
{
}

void write_packet(int fd, short what, void *thunk)
{
	struct target *t = thunk;

	if (!t->resolved) {
		if (t->npkts > 0) {
			SETRES(t, -1, '#');
		}
		SETRES(t, 0, ' ');
		t->npkts++;
		redraw();
		return;
	}

	if (t->npkts > 0 && GETRES(t, -1) == ' ') {
		SETRES(t, -1, '?');
		//write(STDOUT_FILENO, "\a", 1);
	}

	/* FIXME Send packet here */
	SETRES(t, 0, ' ');
	t->npkts++;

	redraw();
}

void redraw()
{
	struct target *t;
	int row, col;
	int y;

	int i, imax, ifirst, ilast;

	getmaxyx(stdscr,row,col);
	t = SLIST_FIRST(&head);
	if (t == NULL) return;

	imax = (t->npkts > col - 20 ? col - 20 : t->npkts);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	mvprintw(0, 0, "%d %d %d\n", imax, ifirst, ilast);
	y = 1;
	SLIST_FOREACH(t, &head, entries) {
		mvprintw(y, 0, "%19.19s ", t->host);
		for (i=ifirst; i<ilast; i++) {
			addch(t->res[i % NUM]);
		}
		y++;
	}
	move(y, 0);

	refresh();
}

int main(int argc, char *argv[])
{
	struct timeval tv;
	struct event *ev;
	struct target *t;
	int salen;
	int fd;
	int i;

	/* Open RAW-socket and drop root-privs */
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	setuid(getuid());

	ev_base = event_base_new();
	dns = evdns_base_new(ev_base, 1);

	SLIST_INIT(&head);
	for (i=argc-1; i>0; i--) {
		t = malloc(sizeof(*t));
		memset(t, 0, sizeof(*t));
		memset(t->res, ' ', sizeof(t->res));

		strncat(t->host, argv[i], sizeof(t->host) - 1);
		SLIST_INSERT_HEAD(&head, t, entries);
	}
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	SLIST_FOREACH(t, &head, entries) {
		ev = event_new(ev_base, fd, EV_READ|EV_PERSIST,
		    write_packet, t);
		event_add(ev, &tv);
		usleep(100*1000);
	}
	SLIST_FOREACH(t, &head, entries) {
		salen = sizeof(t->sin);
		if (evutil_parse_sockaddr_port(t->host,
		    (struct sockaddr *)&t->sin, &salen) == 0) {
			t->resolved = 1;
		} else {
			evdns_base_resolve_ipv4(dns, t->host, 0,
			    resolved_host, t);
		}
	}

	initscr();
	event_base_dispatch(ev_base);
	endwin();

	close(fd);
	return 0;
}
