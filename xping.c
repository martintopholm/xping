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

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <event2/event.h>
#include <event2/dns.h>

#include "xping.h"

#define SETRES(t,i,r) t->res[(t->npkts+i) % NUM] = r
#define GETRES(t,i) t->res[(t->npkts+i) % NUM]

/* Option flags */
int	i_interval = 1000;
int	a_flag = 0;
int	c_count = 0;
int	A_flag = 0;
int	C_flag = 0;
int	T_flag = 0;
int	v4_flag = 0;
int	v6_flag = 0;
int	w_width = 20;

/* Global structures */
int	fd4, fd4errno;
int	fd6, fd6errno;
struct	event_base *ev_base;
struct	evdns_base *dns;
struct	timeval tv_interval;
int	numtargets = 0;
int	numcomplete = 0;

struct target *list = NULL;

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
			probe_resolved(t, 0, NULL);
			ui_update(NULL);
		}
		return;
	}

	/* Lookup succeeded, set address in record */
	if (t->evdns_type == DNS_IPv6_AAAA)
		probe_resolved(t, AF_INET6, addresses);
	else if (t->evdns_type == DNS_IPv4_A)
		probe_resolved(t, AF_INET, addresses);
	ui_update(NULL);

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
 * Register status for send and "timed out" requests and send a probe.
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
		t->npkts++;
		target_mark(t, t->npkts - 1, '@');
		return;
	}

	/* Missed request */
	if (t->npkts > 0 && GETRES(t, -1) != '.') {
		if (GETRES(t, -1) == ' ')
			target_mark(t, t->npkts - 1, '?');
		if (A_flag == 1)
			write(STDOUT_FILENO, "\a", 1);
		else if (A_flag >= 2 &&
		    GETRES(t, -4) == '.' &&
		    GETRES(t, -3) == '.' &&
		    GETRES(t, -2) != '.' &&
		    GETRES(t, -1) != '.')
			write(STDOUT_FILENO, "\a", 1);
	}

	/* Transmit request */
	probe_send(t, t->npkts);
	t->npkts++;

	ui_update(t);
}

/*
 * Does the scheduling of periodic transmissions.
 */
static void
target_probe_sched(int fd, short what, void *thunk)
{
	struct target *t = thunk;

	t->ev_write = event_new(ev_base, -1, EV_PERSIST, target_probe, t);
	event_add(t->ev_write, &tv_interval);
	target_probe(fd, what, thunk);
}

/*
 * Mark a target and sequence with given symbol
 */
void
target_mark(struct target *t, int seq, int ch)
{
	if (ch == '.' && t->res[seq % NUM] != ' ')
		t->res[seq % NUM] = ':';
	else
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

	if (seq == t->npkts - 1)
		ui_update(t);
	else
		ui_update(NULL); /* this is a late reply, need full update to redraw this */
}

/*
 * Clear a mark, used before sending a new probe
 */
void
target_unmark(struct target *t, int seq)
{
	t->res[seq % NUM] = ' ';
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
	if (!t->resolved) {
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
	    "usage: xping [-46ACTVah] [-c count] [-i interval] [-w width] host [host [...]]\n"
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

#ifdef DO_SOCK_RAW
	/* Open RAW-socket and drop root-privs */
	fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	fd4errno = errno;
	fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	fd6errno = errno;
	setuid(getuid());
#else /* !DO_SOCK_RAW */
	fd4 = -1;
	fd4errno = EAFNOSUPPORT;
	fd6 = -1;
	fd6errno = EAFNOSUPPORT;
#endif /* DO_SOCK_RAW */

	/* Parse command line options */
	while ((ch = getopt(argc, argv, "46ACTac:i:w:hV")) != -1) {
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
			if (*optarg != '\0' && *end != '\0')
				usage("Invalid count");
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
		case 'w':
			w_width = strtol(optarg, &end, 10);
			if (*optarg != '\0' && *end != '\0')
				usage("Invalid width");
			if (w_width < 0)
				usage("Invalid width");
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
		t->ev_write = event_new(ev_base, -1, 0, target_probe_sched, t);
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
