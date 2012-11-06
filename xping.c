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
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <ncurses.h>

#include "queue.h"
#include "uthash.h"

extern const char version[];
extern const char built[];

/* Option flags */
int	i_interval = 1000;
int	a_flag = 0;
int	A_flag = 0;
int	v4_flag = 0;
int	v6_flag = 0;

/* Global structures */
int	fd4;
int	fd6;
struct	event_base *ev_base;
struct	evdns_base *dns;
char	outpacket[IP_MAXPACKET];
char	outpacket6[IP_MAXPACKET];
int	datalen = 56;
int	ident;

#define ICMP6_MINLEN sizeof(struct icmp6_hdr)
#define NUM 300
#define SETRES(t,i,r) t->res[(t->npkts+i) % NUM] = r
#define GETRES(t,i) t->res[(t->npkts+i) % NUM]

union addr {
	struct sockaddr	sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

SLIST_HEAD(slisthead, target) head = SLIST_HEAD_INITIALIZER(head);
struct target *hash = NULL;
struct target {
	char		host[64];
	int		resolved;
	int		evdns_type;

	union addr	sa;
	int		npkts;
	char		res[NUM+1];

	struct target	*duplicate;
	SLIST_ENTRY(target) entries;
	UT_hash_handle	hh;
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

#define sa(x) ((struct sockaddr *)(&x->sa))
#define sin(x) ((struct sockaddr_in *)(&x->sa))
#define sin6(x) ((struct sockaddr_in6 *)(&x->sa))

/*
 * Insert a new target into the hash table. Mark as a duplicate if the
 * key already exists.
 */
void
newtarget(struct target *t)
{
	struct target *result;

	HASH_FIND(hh, hash, &t->sa, sizeof(union addr), result);
	if (result)
		t->duplicate = result;
	else
		HASH_ADD(hh, hash, sa, sizeof(union addr), t);
}

/*
 * Lookup target in the hash table
 */
struct target *
findtarget(int af, void *address)
{
	struct target *result;
	union addr sa;

	memset(&sa, 0, sizeof(sa));
	if (af == AF_INET) {
		sa.sin.sin_family = AF_INET;
		memmove(&sa.sin.sin_addr, (struct in_addr *)address,
		    sizeof(sa.sin.sin_addr));
	} else if (af == AF_INET6) {
		sa.sin6.sin6_family = AF_INET6;
		memmove(&sa.sin6.sin6_addr, (struct in6_addr *)address,
		    sizeof(sa.sin6.sin6_addr));
	} else {
		return NULL;
	}
	HASH_FIND(hh, hash, &sa, sizeof(union addr), result);
	return (result);
}

/*
 * Callback for resolved domain names. On missing AAAA-record retry for
 * A-record instead.
 */
void
resolved_host(int result, char type, int count, int ttl, void *addresses,
    void *thunk)
{
	struct target *t = thunk;

	/*
	 * libevent resolver may give NXDOMAIN for an AAAA query when
	 * domain exists, but given RR doesn't. It appears when using
	 * search domains. Resolver appears try search domains after
	 * getting NOERROR with 0 answers.
	 *
	 * As a workaround assume that NXDOMAIN is the same as 0 answers
	 * and try A lookup anyway unless we're in IPv6-only mode.
	 */
	if (result == DNS_ERR_NOTEXIST || result == DNS_ERR_NODATA) {
		if (t->evdns_type == DNS_IPv6_AAAA && !v6_flag) {
			t->evdns_type = DNS_IPv4_A;
			evdns_base_resolve_ipv4(dns, t->host, 0,
			    resolved_host, t);
		}
	}

	if (result != DNS_ERR_NONE)
		return;

	if (type == DNS_IPv6_AAAA && count > 0) {
		sin6(t)->sin6_family = AF_INET6;
		memmove(&sin6(t)->sin6_addr, (struct in6_addr *)addresses,
		    sizeof(sin6(t)->sin6_addr));
		t->resolved = 1;
		newtarget(t);
	} else if (type == DNS_IPv4_A && count > 0) {
		sin(t)->sin_family = AF_INET;
		memmove(&sin(t)->sin_addr, (struct in_addr *)addresses,
		    sizeof(sin(t)->sin_addr));
		t->resolved = 1;
		newtarget(t);
	}
}

void
read_packet4(int fd, short what, void *thunk)
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
	if (ip->ip_p != IPPROTO_ICMP) {
		return;
	}
	if (n < hlen + ICMP_MINLEN) {
		stats->runt++;
		return;
	}

	icp = (struct icmp *)(inpacket + hlen);
	if (icp->icmp_type == ICMP_ECHOREPLY) {
		if (icp->icmp_id != htons(ident))
			return; /*  skip other ping sessions */
		seq = ntohs(icp->icmp_seq);

		t = findtarget(AF_INET, &sin.sin_addr);
		if (t == NULL)
			return; /* reply from unknown src */

		t->res[seq % NUM] = '.';
		if (a_flag)
			write(STDOUT_FILENO, "\a", 1);
		stats->received++;
	} else {
		/* Skip short icmp error packets. */
		if (n < ICMP_MINLEN * 2 + sizeof(struct ip))
			return;

		/* Check aspects of the original packet */
		oip = (struct ip *)icp->icmp_data;
		oicp = (struct icmp *)(oip + 1);
		if (oip->ip_p != IPPROTO_ICMP)
			return;
		if (oicp->icmp_type != ICMP_ECHO)
			return;
		if (oicp->icmp_id != htons(ident))
			return;
		seq = ntohs(oicp->icmp_seq);

		t = findtarget(AF_INET, &oip->ip_dst);
		if (t == NULL)
			return; /* original target is unknown */

		if (icp->icmp_type == ICMP_UNREACH) {
			t->res[seq % NUM] = '#';
		} else {
			t->res[seq % NUM] = '%';
		}
		if (A_flag)
			write(STDOUT_FILENO, "\a", 1);
		stats->other++;
	}
	redraw();
}

void
read_packet6(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	char inpacket[IP_MAXPACKET];
	struct sockaddr_in6 sin6;
	struct ip6_hdr *oip6;
	struct icmp6_hdr *icmp6h;
	struct icmp6_hdr *oicmp6h;
	socklen_t salen;
	int seq;
	int n;

	salen = sizeof(sin6);
	memset(inpacket, 0, sizeof(inpacket));
	n = recvfrom(fd, inpacket, sizeof(inpacket), 0,
	    (struct sockaddr *)&sin6, &salen);
	if (n < 0) {
		stats->recvfrom_err++;
		return;
	}
	if (n < ICMP6_MINLEN) {
		stats->runt++;
		return;
	}

	/* SOCK_RAW for IPPROTO_ICMPV6 doesn't include IPv6 header */
	icmp6h = (struct icmp6_hdr *)(inpacket);
	if (icmp6h->icmp6_type == ICMP6_ECHO_REPLY) {
		if (icmp6h->icmp6_id != htons(ident))
			return; /*  skip other ping sessions */
		seq = ntohs(icmp6h->icmp6_seq);

		t = findtarget(AF_INET6, &sin6.sin6_addr);
		if (t == NULL)
			return; /* reply from unknown src */

		if (n != sizeof(struct icmp6_hdr) + datalen)
			return;

		t->res[seq % NUM] = '.';
		if (a_flag)
			write(STDOUT_FILENO, "\a", 1);
		stats->received++;
	} else {
		/* Skip short icmp error packets. */
		if (n < ICMP6_MINLEN * 2 + sizeof(struct ip6_hdr))
			return;

		/* Check aspects of the original packet */
		oip6 = (struct ip6_hdr *)(icmp6h + 1);
		oicmp6h = (struct icmp6_hdr *)(oip6 + 1);
		if (oip6->ip6_nxt != IPPROTO_ICMPV6)
			return;
		if (oicmp6h->icmp6_type != ICMP6_ECHO_REQUEST)
			return;
		if (oicmp6h->icmp6_id != htons(ident))
			return;
		seq = ntohs(oicmp6h->icmp6_seq);

		t = findtarget(AF_INET6, &oip6->ip6_dst);
		if (t == NULL)
			return; /* original target is unknown */

		if (icmp6h->icmp6_type == ICMP6_DST_UNREACH)
			t->res[seq % NUM] = '#';
		else
			t->res[seq % NUM] = '%';
		stats->other++;
	}

	redraw();
}

int
write_packet4(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	struct icmp *icp;
	int len;

	len = ICMP_MINLEN + datalen;
	icp = (struct icmp *)outpacket;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = htons(t->npkts);
	icp->icmp_id = htons(ident);
	icp->icmp_cksum = in_cksum((u_short *)icp, len);

	return sendto(fd, outpacket, len, 0, sa(t),
	    sizeof(struct sockaddr_in));
}

int
write_packet6(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	struct icmp6_hdr *icmp6h;
	int len;

	len = ICMP6_MINLEN + datalen;
	icmp6h = (struct icmp6_hdr *)outpacket6;
	icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_cksum = 0;
	icmp6h->icmp6_seq = htons(t->npkts);
	icmp6h->icmp6_id = htons(ident);
	return sendto(fd, outpacket6, len, 0, sa(t),
	    sizeof(struct sockaddr_in6));
}

/*
 * Register status for send and "timed out" requests and send appropriate
 * request for target.
 */
void
write_packet(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	int len;
	int n;

	if (t->duplicate != NULL) {
		t->npkts++;
		return;
	}

	if (t->npkts > 0 && GETRES(t, -1) == ' ') {
		SETRES(t, -1, '?');
		if (A_flag)
			write(STDOUT_FILENO, "\a", 1);
	}

	if (sa(t)->sa_family == AF_INET6) {
		n = write_packet6(fd6, what, thunk);
		len = ICMP6_MINLEN + datalen;
	} else {
		n = write_packet4(fd4, what, thunk);
		len = ICMP_MINLEN + datalen;
	}
	SETRES(t, 0, ' ');

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

/*
 * Does the initial scheduling of the packet transmission. Reschedules
 * callbck to self if DNS isn't resolved (and IPv4 or IPv6 socket determined).
 */
void
write_first_packet(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	struct event *ev;
	struct timeval tv;

	tv.tv_sec = i_interval / 1000;
	tv.tv_usec = i_interval % 1000 * 1000;

	/* Register unresolved missed packets */
	if (!t->resolved) {
		ev = event_new(ev_base, fd4, 0, write_first_packet, thunk);
		event_add(ev, &tv);
		if (t->npkts > 0) {
			SETRES(t, -1, '@');
		}
		SETRES(t, 0, '@');
		t->npkts++;
		redraw();
		return;
	}

	/* Schedule targets on proper socket */
	if (sa(t)->sa_family == AF_INET6) {
		write_packet(fd6, what, thunk);
		ev = event_new(ev_base, fd6, EV_PERSIST, write_packet, t);
	} else {
		write_packet(fd4, what, thunk);
		ev = event_new(ev_base, fd4, EV_PERSIST, write_packet, t);
	}
	event_add(ev, &tv);
}

/*
 * Draws the recorded replies on the terminal.
 */
void
redraw()
{
	struct target *t;
	int col;
	int y;

	int i, imax, ifirst, ilast;

	t = SLIST_FIRST(&head);
	if (t == NULL)
		return;

	col = getmaxx(stdscr);
	imax = MIN(t->npkts, col - 20);
	imax = MIN(imax, NUM);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	move(0, 0);
	clrtoeol();
	mvprintw(0, col/2 - (8+strlen(version)+strlen(built))/2,
	    "xping [%s]", version);

	y = 2;
	SLIST_FOREACH(t, &head, entries) {
		mvprintw(y, 0, "%19.19s ", t->host);
		if (t->duplicate != NULL)
			mvprintw(y, 20, "(duplicate of %s)", t->duplicate->host);
		else {
			for (i=ifirst; i<ilast; i++) {
				if (i < t->npkts)
					addch(t->res[i % NUM]);
				else
					addch(' ');
			}
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
	mvprintw(y++, 0, "Legend recv: .=echoreply ?=noreply #=unreach "
	    "%%=other");
	mvprintw(y++, 0, "       send: @=resolving !=partial $=other");
	move(y++, 0);

	refresh();
}

void
usage(const char *whine)
{
	if (whine != NULL) {
		fprintf(stderr, "%s\n", whine);
	}
	fprintf(stderr,
	    "usage: xping [-46AVh] [-i interval] host [host [...]]\n"
	    "\n");
	exit(EX_USAGE);
}

/*
 * Continiously probing multiple hosts using ICMP-ECHO. As packets are
 * received dots are printed on the screen. Hosts not responding before
 * next packet is due will get a questionmark in the display. The probing
 * stops when SIGINT is received.
 */
int
main(int argc, char *argv[])
{
	struct timeval tv;
	struct event *ev;
	struct target *t;
	char *end;
	int salen;
	int i;
	char ch;

	/* Open RAW-socket and drop root-privs */
	fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	setuid(getuid());
	if (fd4 < 0) {
		perror("socket");
		return 1;
	}
	if (fd6 < 0) {
		perror("socket (IPv6)");
		return 1;
	}

	/* Parse command line options */
	while ((ch = getopt(argc, argv, "46Aai:hV")) != -1) {
		switch(ch) {
		case '4':
			v4_flag = 1;
			v6_flag = 0;
			break;
		case '6':
			v4_flag = 0;
			v6_flag = 1;
			break;
		case 'a':
			a_flag = 1;
			break;
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
			fprintf(stderr, "%s %s (built %s)\n", "xping",
			    version, built);
			return (0);
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
	memset(stats, 0, sizeof(*stats));
	ident = getpid() & 0xffff;
	for (i=0; i<datalen; i++) {
		outpacket[ICMP_MINLEN + i] = '0' + i;
		outpacket6[ICMP6_MINLEN + i] = '0' + i;
	}

	/* Prepare event system and inbound socket */
	ev_base = event_base_new();
	dns = evdns_base_new(ev_base, 1);
	evutil_make_socket_nonblocking(fd4);
	ev = event_new(ev_base, fd4, EV_READ|EV_PERSIST, read_packet4, NULL);
	event_add(ev, NULL);
	evutil_make_socket_nonblocking(fd6);
	ev = event_new(ev_base, fd6, EV_READ|EV_PERSIST, read_packet6, NULL);
	event_add(ev, NULL);

	/* Add and resolve targets */
	SLIST_INIT(&head);
	for (i=argc-1; i>=0; i--) {
		t = malloc(sizeof(*t));
		memset(t, 0, sizeof(*t));
		memset(t->res, ' ', sizeof(t->res));
		strncat(t->host, argv[i], sizeof(t->host) - 1);
		SLIST_INSERT_HEAD(&head, t, entries);

		salen = sizeof(t->sa);
		if (evutil_parse_sockaddr_port(t->host, sa(t), &salen) == 0) {
			t->resolved = 1;
			newtarget(t);
		} else {
			if (v4_flag) {
				t->evdns_type = DNS_IPv4_A;
				evdns_base_resolve_ipv4(dns, t->host, 0,
				    resolved_host, t);
			} else {
				t->evdns_type = DNS_IPv6_AAAA;
				evdns_base_resolve_ipv6(dns, t->host, 0,
				    resolved_host, t);
			}
		}
	}
	/* Schedule and resolve targets */
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	SLIST_FOREACH(t, &head, entries) {
		if (sa(t)->sa_family == AF_INET6) {
			ev = event_new(ev_base, fd6, 0, write_first_packet, t);
		} else {
			ev = event_new(ev_base, fd4, 0, write_first_packet, t);
		}
		event_add(ev, &tv);
		tv.tv_usec += 100*1000; /* target spacing: 100ms */
		tv.tv_sec += (tv.tv_usec >= 1000000 ? 1 : 0);
		tv.tv_usec -= (tv.tv_usec >= 1000000 ? 1000000 : 0);
	}

	initscr();
	event_base_dispatch(ev_base);
	endwin();

	close(fd4);
	close(fd6);
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
