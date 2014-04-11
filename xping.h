#ifndef XPING_H
#define XPING_H

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <assert.h>
#include <event2/event.h>

#include "uthash.h"
#include "utlist.h"

#define NUM 300

extern struct event_base *ev_base;
extern struct target *list;
extern int C_flag;
extern int i_interval;
extern int numtargets;
extern int fd4, fd4errno;
extern int fd6, fd6errno;

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

	int		row;

	/* icmp-unpriv. */
	int		pid;
	int		fd;
	int		seqdelta;
	int		seqlast;
	struct evbuffer	*evbuf;

	/* http */
	unsigned short	port;
	char		query[64];

	UT_hash_handle	hh;
	struct target	*prev, *next;
};

#define sa(x) ((struct sockaddr *)(&x->sa))
#define sin(x) ((struct sockaddr_in *)(&x->sa))
#define sin6(x) ((struct sockaddr_in6 *)(&x->sa))

void target_mark(struct target *, int, int);
void target_unmark(struct target *, int);

/* from "version.c" */
extern const char version[];
extern const char built[];

/* from termio.c */
void termio_init(void);
void termio_update(struct target *);
void termio_cleanup(void);

/* from report.c */
void report_init(void);
void report_update(struct target *);
void report_cleanup(void);

/* from dummy.c */
void dummy_init(void);
void dummy_update(struct target *);
void dummy_cleanup(void);

/* from icmp.c */
void probe_setup();
struct target *probe_add(const char *);
void probe_resolved(struct target *, int, void *);
void probe_send(struct target *, int);

#endif /* !XPING_H */
