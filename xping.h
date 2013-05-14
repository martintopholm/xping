#ifndef XPING_H
#define XPING_H

#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include "uthash.h"
#include "utlist.h"

#define ICMP6_MINLEN sizeof(struct icmp6_hdr)
#define NUM 300

extern struct target *list;
extern int C_flag;
extern int numtargets;

union addr {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

struct target {
	char		host[64];
	int		resolved;
	int		evdns_type;

	union addr	sa;
	int		npkts;
	char		res[NUM+1];

	struct event	*ev_resolve;
	struct event	*ev_write;
	struct target	*duplicate;

	UT_hash_handle	hh;
	struct target	*prev, *next;
};

struct statistics {
	int		transmitted;
	int		received;

	int		sendto_err;
	int		recvfrom_err;
	int		runt;
	int		other;
} statistics, *stats;

#define sa(x) ((struct sockaddr *)(&x->sa))
#define sin(x) ((struct sockaddr_in *)(&x->sa))
#define sin6(x) ((struct sockaddr_in6 *)(&x->sa))

/* from "version.c" */
extern const char version[];
extern const char built[];

/* from termio.c */
void termio_init(void);
void termio_update(void);
void termio_cleanup(void);

/* from report.c */
void report_init(void);
void report_update(void);
void report_cleanup(void);

#endif /* !XPING_H */
