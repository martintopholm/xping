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
struct	timeval tv_interval;
int	numtargets = 0;
int	numcomplete = 0;

struct target *hash = NULL;
struct target *list = NULL;

void target_activate(struct target *);
void target_deactivate(struct target *);

void (*ui_init)(void) = termio_init;
void (*ui_update)(struct target *) = termio_update;
void (*ui_cleanup)(void) = termio_cleanup;

/*
 * Signal to catch program termination
 */
void
sigint(int sig)
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
static void
target_is_resolved(int result, char type, int count, int ttl, void *addresses,
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
			    target_is_resolved, t);
		} else {
			evutil_timerclear(&tv);
			tv.tv_sec = 60; /* neg-TTL might be search domain's */
			event_add(t->ev_resolve, &tv);
			target_deactivate(t);
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
	target_activate(t);

	/* Schedule new request, if tracking domain name */
	if (T_flag) {
		evutil_timerclear(&tv);
		tv.tv_sec = MAX(ttl, 1); /* enforce min-TTL */
		event_add(t->ev_resolve, &tv);
	}
}

/*
 * Sends out a DNS query for target through evdns. Called by the
 * per target ev_resolve event. Scheduled once for each target at
 * startup, * then repeated periodically for each unresolved host
 * and if tracking (-T) when TTL expires.
 */
static void
target_resolve(int fd, short what, void *thunk)
{
	struct target *t = thunk;

	if (!v4_flag) {
		t->evdns_type = DNS_IPv6_AAAA;
		evdns_base_resolve_ipv6(dns, t->host, 0,
		    target_is_resolved, t);
	} else {
		t->evdns_type = DNS_IPv4_A;
		evdns_base_resolve_ipv4(dns, t->host, 0,
		    target_is_resolved, t);
	}
}

/*
 * Register status for send and "timed out" requests and send appropriate
 * request for target. Reschedules transmision if socket and address
 * family mismatches.
 */
static void
target_probe(int fd, short what, void *thunk)
{
	struct target *t = thunk;

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
		ui_update(t);
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
		ui_update(t);
	}

	/* Transmit request */
	probe_send(t);
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
		    target_probe, t);
		event_add(t->ev_write, &tv_interval);
	}

	ui_update(t);
}

/*
 * Does the scheduling of periodic transmissions.
 */
static void
target_probe_sched(int fd, short what, void *thunk)
{
	struct target *t = thunk;

	t->ev_write = event_new(ev_base, fd, EV_PERSIST, target_probe, t);
	event_add(t->ev_write, &tv_interval);
	target_probe(fd, what, thunk);
}

/*
 * Insert a new target into the hash table. Mark as a duplicate if the
 * key already exists.
 */
void
target_activate(struct target *t)
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
target_deactivate(struct target *t)
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
					target_activate(t1);
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
target_find(int af, void *address)
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
target_mark(struct target *t, int seq, int ch)
{
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

	ui_update(t);
}

/*
 * Create a new a probe target, apply resolver if needed.
 */
static int
target_add(const char *line)
{
	struct target *t;
	struct timeval tv;

	t = probe_add(line);
	if (t == NULL)
		return -1;
	if (t->resolved)
		target_activate(t);
	else {
		t->ev_resolve = event_new(ev_base, -1, 0, target_resolve, t);
		evutil_timerclear(&tv);
		event_add(t->ev_resolve, &tv);
	}
	numtargets++;
	return 0;
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

	tv_interval.tv_sec = i_interval / 1000;
	tv_interval.tv_usec = i_interval % 1000 * 1000;

	/* Prepare event system and inbound socket */
	ev_base = event_base_new();
	dns = evdns_base_new(ev_base, 1);
	probe_setup();

	/* Read targets from program arguments and/or stdin. */
	list = NULL;
	for (i=0; i<argc; i++) {
		if (target_add(argv[i]) < 0) {
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
			if (target_add(buf) < 0) {
				perror("malloc");
				return 1;
			}
		}
	}
	if (!isatty(STDOUT_FILENO)) {
		ui_init = report_init;
		ui_update = report_update;
		ui_cleanup = report_cleanup;
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
			    target_probe_sched, t);
		} else {
			t->ev_write = event_new(ev_base, fd4, 0,
			    target_probe_sched, t);
		}
		event_add(t->ev_write, &tv);
		tv.tv_usec += 100*1000; /* target spacing: 100ms */
		tv.tv_sec += (tv.tv_usec >= 1000000 ? 1 : 0);
		tv.tv_usec -= (tv.tv_usec >= 1000000 ? 1000000 : 0);
	}

	/* Startup UI and probing */
	signal(SIGINT, sigint);
	signal(SIGTERM, sigint);
	ui_init();
	event_base_dispatch(ev_base);
	ui_cleanup();

	close(fd4);
	close(fd6);
	return 0;
}
