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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>

#include "xping.h"

/* Option flags */
int	i_interval = 1000;
int	a_flag = 0;
int	c_count = 0;
int	A_flag = 0;
int	C_flag = 0;
int	T_flag = 0;
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
struct	timeval tv_interval;
int	numtargets = 0;
int	numcomplete = 0;

struct target *hash = NULL;
struct target *list = NULL;

#define SETRES(t,i,r) t->res[(t->npkts+i) % NUM] = r
#define GETRES(t,i) t->res[(t->npkts+i) % NUM]

void activatetarget(struct target *);
void deactivatetarget(struct target *);
void marktarget(int, void *, int, int);
void resolvetarget(int, short, void *);

static u_short in_cksum(u_short *, int);

void (*init)(void) = termio_init;
void (*update)(struct target *) = termio_update;
void (*cleanup)(void) = termio_cleanup;

/*
 * Signal to catch program termination
 */
void sigint(int sig)
{
	event_base_loopexit(ev_base, NULL);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

/*
 * Callback for resolved domain names. On missing AAAA-record retry for
 * A-record instead. When resolving fails reschedule a new request either
 * by built-in delay. type isn't available for failed requests.
 */
void
resolved_host(int result, char type, int count, int ttl, void *addresses,
    void *thunk)
{
	struct target *t = thunk;
	struct timeval tv;

	/*
	 * If request for AAAA-record failed (NXDOMAIN, SERVFAIL, et al),
	 * retry for A-record. Otherwise reschedule a new request.
	 * All diagnostics about the failed request are useless, since
	 * they might refer to a search domain request, which is done
	 * transparently after the real request.
	 */
	if (result != DNS_ERR_NONE || count <= 0) {
		if (t->evdns_type == DNS_IPv6_AAAA && !v6_flag) {
			t->evdns_type = DNS_IPv4_A;
			evdns_base_resolve_ipv4(dns, t->host, 0,
			    resolved_host, t);
		} else {
			evutil_timerclear(&tv);
			tv.tv_sec = 60; /* neg-TTL might be search domain's */
			event_add(t->ev_resolve, &tv);
			deactivatetarget(t);
		}
		return;
	}

	/* Lookup succeeded, set address in record */
	if (t->evdns_type == DNS_IPv6_AAAA) {
		sin6(t)->sin6_family = AF_INET6;
		memmove(&sin6(t)->sin6_addr, (struct in6_addr *)addresses,
		    sizeof(sin6(t)->sin6_addr));
	} else if (t->evdns_type == DNS_IPv4_A) {
		sin(t)->sin_family = AF_INET;
		memmove(&sin(t)->sin_addr, (struct in_addr *)addresses,
		    sizeof(sin(t)->sin_addr));
	}
	activatetarget(t);

	/* Schedule new request, if tracking domain name */
	if (T_flag) {
		evutil_timerclear(&tv);
		tv.tv_sec = MAX(ttl, 1); /* enforce min-TTL */
		event_add(t->ev_resolve, &tv);
	}
}

void
read_packet4(int fd, short what, void *thunk)
{
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
		marktarget(AF_INET, &sin.sin_addr, seq, '.');
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
		if (icp->icmp_type == ICMP_UNREACH)
			marktarget(AF_INET, &oip->ip_dst, seq, '#');
		else
			marktarget(AF_INET, &oip->ip_dst, seq, '%');
		stats->other++;
	}
}

void
read_packet6(int fd, short what, void *thunk)
{
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
		if (n != sizeof(struct icmp6_hdr) + datalen)
			return;

		seq = ntohs(icmp6h->icmp6_seq);
		marktarget(AF_INET6, &sin6.sin6_addr, seq, '.');
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
		if (icmp6h->icmp6_type == ICMP6_DST_UNREACH)
			marktarget(AF_INET6, &oip6->ip6_dst, seq, '#');
		else
			marktarget(AF_INET6, &oip6->ip6_dst, seq, '%');
		stats->other++;
	}
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
 * request for target. Reschedules transmision if socket and address
 * family mismatches.
 */
void
write_packet(int fd, short what, void *thunk)
{
	struct target *t = thunk;
	int len;
	int n;

	/* Check packet count limit */
	if (c_count && t->npkts >= c_count) {
		numcomplete++;
		event_del(t->ev_write);
		if (numcomplete >= numtargets) {
			event_base_loopexit(ev_base, NULL);
		}
		return;
	}

	/* Skip any duplicate targets */
	if (t->duplicate != NULL) {
		t->npkts++;
		return;
	}

	/* Unresolved request */
	if (!t->resolved) {
		SETRES(t, 0, '@');
		t->npkts++;
		update(t);
		return;
	}

	/* Missed request */
	if (t->npkts > 0 && GETRES(t, -1) != '.') {
		if (GETRES(t, -1) == ' ')
			SETRES(t, -1, '?');
		if (A_flag == 1)
			write(STDOUT_FILENO, "\a", 1);
		else if (A_flag >= 2 &&
		    GETRES(t, -4) == '.' &&
		    GETRES(t, -3) == '.' &&
		    GETRES(t, -2) != '.' &&
		    GETRES(t, -1) != '.')
			write(STDOUT_FILENO, "\a", 1);
		update(t);
	}

	/* Transmit request */
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
		SETRES(t, 0, '!'); /* transmit error */
	} else if (n != len) {
		stats->sendto_err++;
		SETRES(t, 0, '$'); /* partial transmit */
	}
	stats->transmitted++;
	t->npkts++;

	/* Reschedule event if socket doesn't match address family. */
	if ((sa(t)->sa_family == AF_INET6 && fd == fd4) ||
	    (sa(t)->sa_family == AF_INET && fd == fd6)) {
		if (t->ev_write) {
			event_del(t->ev_write);
			event_free(t->ev_write);
		}
		t->ev_write = event_new(ev_base,
		    (sa(t)->sa_family == AF_INET6 ? fd6 : fd4), EV_PERSIST,
		    write_packet, t);
		event_add(t->ev_write, &tv_interval);
	}

	update(t);
}

/*
 * Does the scheduling of periodic transmissions.
 */
void
write_first_packet(int fd, short what, void *thunk)
{
	struct target *t = thunk;

	t->ev_write = event_new(ev_base, fd, EV_PERSIST, write_packet, t);
	event_add(t->ev_write, &tv_interval);
	write_packet(fd, what, thunk);
}

/*
 * Allocate structure for a new target and insert into list of all
 * our targets.
 */
struct target *
newtarget(const char *hostname)
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
	strncat(t->host, hostname, sizeof(t->host) - 1);
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
 * Insert a new target into the hash table. Mark as a duplicate if the
 * key already exists.
 */
void
activatetarget(struct target *t)
{
	struct target *result;

	HASH_FIND(hh, hash, &t->sa, sizeof(union addr), result);
	if (result == t)
		; /* nothing, already active in hash */
	else if (result)
		t->duplicate = result;
	else
		HASH_ADD(hh, hash, sa, sizeof(union addr), t);
	t->resolved = 1;
}

/*
 * Remove a target (t) from the hash table if the target is the currently
 * active for the address. Secondly first target (t1) which was duplicate
 * of target (t) is activated, and other duplicates will refer of that
 * one (t) instead.
 */
void
deactivatetarget(struct target *t)
{
	struct target *tmp, *t1;

	t->resolved = 0;
	HASH_FIND(hh, hash, &t->sa, sizeof(union addr), tmp);
	if (tmp == t) {
		HASH_DELETE(hh, hash, t);
		t1 = NULL;
		DL_FOREACH(list, tmp) {
			if (tmp->duplicate == t) {
				if (t1 == NULL) {
					t1 = tmp;
					t1->duplicate = NULL;
					activatetarget(t1);
				} else {
					tmp->duplicate = t1;
				}
			}
		}
	}
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
 * Mark a target and sequence with given symbol
 */
void
marktarget(int af, void *address, int seq, int ch)
{
	struct target *t;

	t = findtarget(af, address);
	if (t == NULL)
		return; /* reply from unknown src */

	t->res[seq % NUM] = ch;
	if (a_flag && ch == '.') {
		if (a_flag == 1)
			write(STDOUT_FILENO, "\a", 1);
		else if (a_flag >=2 &&
		    t->res[(seq-3) % NUM] != '.' &&
		    t->res[(seq-2) % NUM] != '.' &&
		    t->res[(seq-1) % NUM] == '.' &&
		    t->res[(seq-0) % NUM] == '.')
			write(STDOUT_FILENO, "\a", 1);
	}

	update(t);
}

/*
 * Sends out a DNS query for target through evdns. Called by the
 * per target ev_resolve event. Scheduled once for each target at
 * startup, * then repeated periodically for each unresolved host
 * and if tracking (-T) when TTL expires.
 */
void
resolvetarget(int fd, short what, void *thunk)
{
	struct target *t = thunk;

	if (!v4_flag) {
		t->evdns_type = DNS_IPv6_AAAA;
		evdns_base_resolve_ipv6(dns, t->host, 0,
		    resolved_host, t);
	} else {
		t->evdns_type = DNS_IPv4_A;
		evdns_base_resolve_ipv4(dns, t->host, 0,
		    resolved_host, t);
	}
}

void
usage(const char *whine)
{
	if (whine != NULL) {
		fprintf(stderr, "%s\n", whine);
	}
	fprintf(stderr,
	    "usage: xping [-46ACTVah] [-c count] [-i interval] host [host [...]]\n"
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
	char buf[BUFSIZ];
	struct timeval tv;
	struct target *t;
	struct event *ev;
	char *end;
	int i;
	int len;
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
	while ((ch = getopt(argc, argv, "46ACTac:i:hV")) != -1) {
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
			a_flag++;
			break;
		case 'A':
			A_flag++;
			break;
		case 'C':
			C_flag = 1;
			break;
		case 'c':
			c_count = strtol(optarg, &end, 10);
			break;
		case 'T':
			T_flag = 1;
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

	/* Prepare statistics and datapacket */
	tv_interval.tv_sec = i_interval / 1000;
	tv_interval.tv_usec = i_interval % 1000 * 1000;
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

	/* Read targets from program arguments and/or stdin. */
	list = NULL;
	for (i=0; i<argc; i++) {
		if (newtarget(argv[i]) == NULL) {
			perror("malloc");
			return 1;
		}
	}
	if (!isatty(STDIN_FILENO) || argc < 1) {
		while(fgets(buf, sizeof(buf), stdin) != NULL) {
			if ((end = strchr(buf, '#')) != NULL)
				*end = '\0';
			for (len = strlen(buf) - 1; len > 0; len--) {
				if (strchr(" \t\n", buf[len]) == NULL)
					break;
				buf[len] = '\0';
			}
			if (buf[0] == '#' || len < 1)
				continue;
			if (newtarget(buf) == NULL) {
				perror("malloc");
			}
		}
	}
	if (!isatty(STDOUT_FILENO)) {
		init = report_init;
		update = report_update;
		cleanup = report_cleanup;
	}
	if (list == NULL) {
		usage("no arguments");
	}

	/* Initial scheduling with increasing delay, distributes
	 * transmissions across the interval and gives a cascading effect. */
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	DL_FOREACH(list, t) {
		if (sa(t)->sa_family == AF_INET6) {
			t->ev_write = event_new(ev_base, fd6, 0,
			    write_first_packet, t);
		} else {
			t->ev_write = event_new(ev_base, fd4, 0,
			    write_first_packet, t);
		}
		event_add(t->ev_write, &tv);
		tv.tv_usec += 100*1000; /* target spacing: 100ms */
		tv.tv_sec += (tv.tv_usec >= 1000000 ? 1 : 0);
		tv.tv_usec -= (tv.tv_usec >= 1000000 ? 1000000 : 0);
	}

	/* Startup UI and probing */
	signal(SIGINT, sigint);
	signal(SIGTERM, sigint);
	init();
	event_base_dispatch(ev_base);
	cleanup();

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
