#ifndef XPING_H
#define XPING_H

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <event2/event.h>

#include "uthash.h"
#include "utlist.h"

#define NUM 300
#define MAXHOST 64

extern struct event_base *ev_base;
extern struct target *list;
extern int B_flag;
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
	int		npkts;
	char		res[NUM+1];

	struct probe	*prb;
	struct event	*ev_write;

	int		row;
	int		af;

	struct target	*prev, *next;
};

#define sa(x) ((struct sockaddr *)(&x->sa))
#define sin(x) ((struct sockaddr_in *)(&x->sa))
#define sin6(x) ((struct sockaddr_in6 *)(&x->sa))

void target_mark(struct target *, int, int);
void target_unmark(struct target *, int);
void target_resolved(struct target *, int, void *);

/* from "version.c" */
extern const char version[];

/* from termio.c */
void termio_init(void);
void termio_update(struct target *);
void termio_cleanup(void);

/* from report.c */
void report_init(void);
void report_update(struct target *);
void report_cleanup(void);

/* from icmp.c */
void probe_setup();
void probe_cleanup();
struct probe *probe_new(const char *, void *);
void probe_free(struct probe *);
void probe_send(struct probe *, int);

/* from dnstask.c */
typedef void (*dnstask_cb_type)(int, void *, void *);
struct dnstask *dnstask_new(const char *, dnstask_cb_type, void *);
void dnstask_free(struct dnstask *);

#endif /* !XPING_H */
