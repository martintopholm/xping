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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <ncurses.h>

#include "queue.h"

#ifndef VERSION
#define VERSION "xping [compiled " __DATE__ " " __TIME__ "]"
#endif /* !VERSION */


/* Option flags */
int	i_interval = 1000;
int	a_flag = 0;
int	A_flag = 0;

/* Global structures */
struct	event_base *ev_base;
struct	evdns_base *dns;
char	outpacket[IP_MAXPACKET];
int	datalen = 56;
int	ident;

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

struct statistics {
	int		transmitted;
	int		received;

	int		sendto_err;
	int		recvfrom_err;
	int		runt;
	int		other;
} statistics, *stats;

static void redraw();
static u_short in_cksum(u_short *, int);


// struct in_addr *in_addrs = addresses; 
// struct in6_addr *in6_addrs = addresses;
void resolved_host(int result, char type, int count, int ttl, void *addresses,
    void *thunk) 
{
	struct target *t = thunk;

	if (result == DNS_ERR_NONE && type == DNS_IPv4_A && count > 0) {
		t->sin.sin_family = AF_INET;
		memmove(&t->sin.sin_addr, (struct in_addr *)addresses,
		    sizeof(t->sin.sin_addr));
		t->resolved = 1;
	}

}

void read_packet(int fd, short what, void *thunk)
{
	struct target *t;
	char inpacket[IP_MAXPACKET];
	struct sockaddr_in sin;
	struct ip *ip;
	struct ip *oip;
	struct icmp *icp;
	struct icmp *oicp;
	socklen_t salen;
	int hlen;
	int seq;
	int n;

	salen = sizeof(sin);
	memset(inpacket, 0, sizeof(inpacket));
	n = recvfrom(fd, inpacket, sizeof(inpacket), 0,
	    (struct sockaddr *)&sin, &salen); 
	if (n < 0) {
		stats->recvfrom_err++;
		return;
	}

	ip = (struct ip *)inpacket;
	hlen = ip->ip_hl << 2;
	if (n < hlen + ICMP_MINLEN) {
		stats->runt++;
		return;
	}

	icp = (struct icmp *)(inpacket + hlen);
	if (icp->icmp_type == ICMP_ECHOREPLY) {
		if (icp->icmp_id != ident)
			return; /*  skip other ping sessions */
		seq = ntohs(icp->icmp_seq);

		/* Search for our target */
		SLIST_FOREACH(t, &head, entries) {
			if (memcmp(&t->sin.sin_addr, &sin.sin_addr,
			    sizeof(t->sin.sin_addr)) == 0) {
				break;
			}
		}
		if (t == NULL) 
			return; /* reply from unknown src */

		/* XXX Checksum is propably verified by host OS */
		t->res[seq % NUM] = '.';
		if (a_flag) write(STDOUT_FILENO, "\a", 1);
		stats->received++;
	} else {
		/* Check aspects of the original packet */
		oip = (struct ip *)icp->icmp_data;
		oicp = (struct icmp *)(oip + 1);
		if (oip->ip_p != IPPROTO_ICMP)
			return;
		if (oicp->icmp_type != ICMP_ECHO)
			return;
		if (oicp->icmp_id != ident)
			return;
		seq = ntohs(oicp->icmp_seq);

		/* Search for our target */
		SLIST_FOREACH(t, &head, entries) {
			if (memcmp(&t->sin.sin_addr, &oip->ip_dst,
			    sizeof(t->sin.sin_addr)) == 0) {
				break;
			}
		}
		if (t == NULL) 
			return; /* original target is unknown */

		if (icp->icmp_type == ICMP_UNREACH) {
			t->res[seq % NUM] = '#';
		} else {
			t->res[seq % NUM] = '%';
		}
		stats->other++;
	}
	redraw();
}

void write_packet(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	struct icmp *icp;
	int len;
	int n;

	/* Register unresolved missed packets */
	if (!t->resolved) {
		if (t->npkts > 0) {
			SETRES(t, -1, '@');
		}
		SETRES(t, 0, '@');
		t->npkts++;
		redraw();
		return;
	}

	/* Register missed reply */
	if (t->npkts > 0 && GETRES(t, -1) == ' ') {
		SETRES(t, -1, '?');
		if (A_flag) write(STDOUT_FILENO, "\a", 1);
	}

	/* Send packet */
	len = ICMP_MINLEN + datalen;
	icp = (struct icmp *)outpacket;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = htons(t->npkts);
	icp->icmp_id = ident;
	icp->icmp_cksum = in_cksum((u_short *)icp, len);
	SETRES(t, 0, ' ');

	n = sendto(fd, outpacket, len, 0, (struct sockaddr *)&t->sin,
            sizeof(t->sin));
	if (n < 0) {
		stats->sendto_err++;
		SETRES(t, 0, '$'); /* transmit error */
	}
	if (n != len) {
		stats->sendto_err++;
		SETRES(t, 0, '!'); /* partial transmit */
	}
	stats->transmitted++;
	t->npkts++;
	redraw();
}

void redraw()
{
	struct target *t;
	int col;
	int y;

	int i, imax, ifirst, ilast;

	t = SLIST_FIRST(&head);
	if (t == NULL) return;

	col = getmaxx(stdscr);
	imax = MIN(t->npkts, col - 20);
	imax = MIN(imax, NUM);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	move(0, 0);
	clrtoeol();
	mvprintw(0, col/2 - strlen(VERSION)/2, "%s", VERSION);

	y = 2;
	SLIST_FOREACH(t, &head, entries) {
		mvprintw(y, 0, "%19.19s ", t->host);
		for (i=ifirst; i<ilast; i++) {
			if (i < t->npkts) addch(t->res[i % NUM]);
			else addch(' ');
		}
		y++;
	}

	y++;
	mvprintw(y++, 0, "Sent: %d", stats->transmitted);
	mvprintw(y++, 0, "Recv: %d", stats->received);
	mvprintw(y++, 0, "ErrO: %d", stats->sendto_err);
	mvprintw(y++, 0, "ErrI: %d", stats->recvfrom_err);
	mvprintw(y++, 0, "Runt: %d", stats->runt);
	mvprintw(y++, 0, "Othr: %d", stats->other);
	y++;
	mvprintw(y++, 0, "Legend recv: .=echoreply ?=noreply #=unreach %=other"); 
	mvprintw(y++, 0, "       send: @=resolving !=partial $=other");
	move(y++, 0);

	refresh();
}

void usage(const char *whine)
{
        if (whine != NULL) {
                fprintf(stderr, "%s\n", whine);
        }
	fprintf(stderr,
	    "usage: xping [-AVh] [-i interval] host [host [...]]\n"
	    "\n");
        exit(EX_USAGE);
}

int main(int argc, char *argv[])
{
	struct timeval tv;
	struct event *ev;
	struct target *t;
	char *end;
	int salen;
	int fd;
	int i;
	char ch;

	/* Open RAW-socket and drop root-privs */
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	setuid(getuid());
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	/* Parse command line options */
	while ((ch = getopt(argc, argv, "Aai:h")) != -1) {
		switch(ch) {
		case 'a':
			a_flag = 1;
		case 'A':
			A_flag = 1;
			break;
		case 'i':
			i_interval = strtod(optarg, &end) * 1000;
			if (*optarg != '\0' && *end != '\0')
				usage("Invalid interval");
			if (i_interval < 1000 && getuid() != 0)
				usage("Dangerous interval");
			break;
		case 'V':
			fprintf(stderr, "version %s\n", VERSION);
		case 'h':
			usage(NULL);
			/* NOTREACHED */
		default:
			usage(NULL);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc < 1) {
		usage("no arguments");
	}

	/* Prepare statistics and datapacket */
	stats = &statistics;
	memset(stats, 0, sizeof(stats));
	ident = htons(getpid() & 0xffff);
	for (i=0; i<datalen; i++) {
		outpacket[ICMP_MINLEN + i] = '0' + i;
	}

	/* Prepare event system and inbound socket */
	ev_base = event_base_new();
	dns = evdns_base_new(ev_base, 1);
	evutil_make_socket_nonblocking(fd);
	ev = event_new(ev_base, fd, EV_READ|EV_PERSIST,
	    read_packet, NULL);
	event_add(ev, NULL);

	/* Add and schedule targets */
	SLIST_INIT(&head);
	for (i=argc-1; i>=0; i--) {
		t = malloc(sizeof(*t));
		memset(t, 0, sizeof(*t));
		memset(t->res, ' ', sizeof(t->res));

		strncat(t->host, argv[i], sizeof(t->host) - 1);
		SLIST_INSERT_HEAD(&head, t, entries);
	}
	tv.tv_sec = i_interval / 1000;
	tv.tv_usec = i_interval % 1000 * 1000;
	SLIST_FOREACH(t, &head, entries) {
		ev = event_new(ev_base, fd, EV_PERSIST,
		    write_packet, t);
		event_add(ev, &tv);
		usleep(100*1000);
	}

	/* Resolve hostnames */
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

/* From the original ping.c by Mike Muus... */
/*
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(u_short *addr, int len)
{
	int nleft, sum;
	u_short *w;
	union {
		u_short us;
		u_char  uc[2];
	} last;
	u_short answer;

	nleft = len;
	sum = 0;
	w = addr;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		last.uc[0] = *(u_char *)w;
		last.uc[1] = 0;
		sum += last.us;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
	sum += (sum >> 16);                     /* add carry */
	answer = ~sum;                          /* truncate to 16 bits */
	return(answer);
}
