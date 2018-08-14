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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <event2/event.h>
#include "xping.h"

#define ICMP6_MINLEN sizeof(struct icmp6_hdr)

struct probe {
	char		host[MAXHOST];
	int		resolved;
	union addr	sa;
	struct probe	*duplicate;
	int		last_seq;
	UT_hash_handle	hh;
	void		*dnstask;
	void		*owner;
};

struct event *ev_read4;
struct event *ev_read6;
struct probe *hash = NULL;
char	outpacket[IP_MAXPACKET];
char	outpacket6[IP_MAXPACKET];
int	datalen = 56;
int	ident;

/*
 * From the original ping.c by Mike Muus...
 *
 * in_cksum --
 *      Checksum routine for Internet Protocol family headers (C Version)
 */
static u_short
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

/*
 * Insert a new target into the hash table. Mark as a duplicate if the
 * key already exists.
 */
void
activate(struct probe *prb)
{
	struct probe *result;

	HASH_FIND(hh, hash, &prb->sa, sizeof(union addr), result);
	if (result == prb)
		; /* nothing, already active in hash */
	else if (result)
		prb->duplicate = result;
	else
		HASH_ADD(hh, hash, sa, sizeof(union addr), prb);
}

/*
 * Remove a probe (prb) from the hash table if the probe is the currently
 * active for the address. Secondly first probe (t1) which was duplicate
 * of probe (prb) is activated, and other duplicates will refer of that
 * one (prb) instead.
 */
void
deactivate(struct probe *prb)
{
	struct probe *tmp, *tmp2, *t1;

	HASH_FIND(hh, hash, &prb->sa, sizeof(union addr), tmp);
	if (tmp == NULL)
		return; /* already inactive, i.e. not in hash */
	HASH_DELETE(hh, hash, prb);
	t1 = NULL;
	HASH_ITER(hh, hash, tmp, tmp2) {
		if (tmp->duplicate == prb) {
			if (t1 == NULL) {
				t1 = tmp;
				t1->duplicate = NULL;
				activate(t1);
			} else {
				tmp->duplicate = t1;
			}
		}
	}
}

/*
 * Lookup target in the hash table
 */
struct probe *
find(int af, void *address)
{
	struct probe *result;
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
 * Send out icmp packet for target.
 */
static int
write_packet4(struct sockaddr *sa, unsigned short seq)
{
	struct icmp *icp;
	int len;

	len = ICMP_MINLEN + datalen;
	icp = (struct icmp *)outpacket;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_cksum = 0;
	icp->icmp_seq = htons(seq);
	icp->icmp_id = htons(ident);
	icp->icmp_cksum = in_cksum((u_short *)icp, len);

	return sendto(fd4, outpacket, len, 0, sa,
	    sizeof(struct sockaddr_in));
}

/*
 * Send out icmp6 packet for target.
 */
static int
write_packet6(struct sockaddr *sa, unsigned short seq)
{
	struct icmp6_hdr *icmp6h;
	int len;

	len = ICMP6_MINLEN + datalen;
	icmp6h = (struct icmp6_hdr *)outpacket6;
	icmp6h->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_cksum = 0;
	icmp6h->icmp6_seq = htons(seq);
	icmp6h->icmp6_id = htons(ident);
	return sendto(fd6, outpacket6, len, 0, sa,
	    sizeof(struct sockaddr_in6));
}

/*
 * Find probe target from address and expand truncated icmp_seq from
 * last sent sequence number.
 */
static void
find_marktarget(int af, void *address, int seq, int ch)
{
	struct probe *prb;
	int npkts;

	prb = find(af, address);
	if (prb == NULL)
		return; /* unknown source address */
	npkts = prb->last_seq;
	if ((npkts & 0xffff) < seq)
	    npkts -= 1<<16;
	target_mark(prb->owner, (npkts & ~0xffff) | seq, ch);
}

/*
 * Receive packet from IPv4 socket, parse it and associate result with
 * an active target via find_marktarget.
 */
static void
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
		return;
	}

	ip = (struct ip *)inpacket;
	hlen = ip->ip_hl << 2;
	if (ip->ip_p != IPPROTO_ICMP) {
		return;
	}
	if (n < hlen + ICMP_MINLEN) {
		return;
	}

	icp = (struct icmp *)(inpacket + hlen);
	if (icp->icmp_type == ICMP_ECHOREPLY) {
		if (icp->icmp_id != htons(ident))
			return; /*  skip other ping sessions */

		seq = ntohs(icp->icmp_seq);
		find_marktarget(AF_INET, &sin.sin_addr, seq, '.');
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
			find_marktarget(AF_INET, &oip->ip_dst, seq, '#');
		else
			find_marktarget(AF_INET, &oip->ip_dst, seq, '%');
	}
}

/*
 * Receive packet from IPv6 socket, parse it and associate with an active
 * target via find_marktarget.
 */
static void
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
		return;
	}
	if (n < ICMP6_MINLEN) {
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
		find_marktarget(AF_INET6, &sin6.sin6_addr, seq, '.');
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
			find_marktarget(AF_INET6, &oip6->ip6_dst, seq, '#');
		else
			find_marktarget(AF_INET6, &oip6->ip6_dst, seq, '%');
	}
}

/*
 * Handle DNS lookups for targets.
 */
static void
resolved(int af, void *address, void *thunk)
{
	struct probe *prb = thunk;
	if (af == AF_INET6) {
		sin6(prb)->sin6_family = AF_INET6;
		memmove(&sin6(prb)->sin6_addr, (struct in6_addr *)address,
		    sizeof(sin6(prb)->sin6_addr));
		activate(prb);
		prb->resolved = 1;
	} else if (af == AF_INET) {
		sin(prb)->sin_family = AF_INET;
		memmove(&sin(prb)->sin_addr, (struct in_addr *)address,
		    sizeof(sin(prb)->sin_addr));
		activate(prb);
		prb->resolved = 1;
	} else if (af == 0) {
		prb->resolved = 0;
		deactivate(prb);
	}
	target_resolved(prb->owner, af, address);
}

/*
 * Prepare datastructures and events needed for probe
 */
void
probe_setup()
{
	int i;

	if (fd4 < 0) {
		errno = fd4errno;
		perror("socket (IPv4)");
		exit(1);
	}
	if (fd6 < 0) {
		errno = fd6errno;
		perror("socket (IPv6)");
		exit(1);
	}

	/* Prepare datapacket */
	ident = getpid() & 0xffff;
	for (i=0; i<datalen; i++) {
		outpacket[ICMP_MINLEN + i] = '0' + i;
		outpacket6[ICMP6_MINLEN + i] = '0' + i;
	}

	evutil_make_socket_nonblocking(fd4);
	ev_read4 = event_new(ev_base, fd4, EV_READ|EV_PERSIST, read_packet4, NULL);
	event_add(ev_read4, NULL);
	evutil_make_socket_nonblocking(fd6);
	ev_read6 = event_new(ev_base, fd6, EV_READ|EV_PERSIST, read_packet6, NULL);
	event_add(ev_read6, NULL);
}

void
probe_cleanup()
{

	HASH_CLEAR(hh, hash);
	if (ev_read4)
		event_free(ev_read4);
	if (ev_read6)
		event_free(ev_read6);
}

/*
 * Allocate structure for a new target and insert into list of all
 * our targets.
 */
struct probe *
probe_new(const char *line, void *owner)
{
	union addr sa;
	struct probe *prb;
	int salen;

	prb = calloc(1, sizeof(*prb));
	if (prb == NULL) {
		perror("malloc");
		return (prb);
	}
	prb->owner = owner;
	strncat(prb->host, line, sizeof(prb->host) - 1);

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
		activate(prb);
	} else {
		prb->dnstask = dnstask_new(prb->host, resolved, prb);
		if (prb->dnstask == NULL) {
			free(prb);
			return NULL;
		}
	}
	return (prb);
}

void
probe_free(struct probe *prb)
{

	if (prb->dnstask)
		dnstask_free(prb->dnstask);
	deactivate(prb);
	free(prb);
}

/*
 * Send out a single probe for a target.
 */
void
probe_send(struct probe *prb, int seq)
{
	int len;
	int n;

	prb->last_seq = seq;
	if (!prb->resolved) {
		target_mark(prb->owner, seq, '@');
		return;
	}

	if (prb->duplicate) {
		target_mark(prb->owner, seq, '"'); /* transmit error */
		return;
	}

	if (sa(prb)->sa_family == AF_INET6) {
		n = write_packet6(sa(prb), seq & 0xffff);
		len = ICMP6_MINLEN + datalen;
	} else {
		n = write_packet4(sa(prb), seq & 0xffff);
		len = ICMP_MINLEN + datalen;
	}

	if (n < 0) {
		target_mark(prb->owner, seq, '!'); /* transmit error */
	} else if (n != len) {
		target_mark(prb->owner, seq, '$'); /* partial transmit */
	}
}
