/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mph@hoth.dk> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Martin Topholm
 * ----------------------------------------------------------------------------
 */

#include <sys/param.h>
#include <sys/socket.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>
#include <event2/dns.h>

#include "xping.h"

#define MAXHOST 64

extern int v4_flag;
extern int v6_flag;
extern int T_flag;
extern struct event_base *ev_base;
extern struct evdns_base *dns;

struct dnstask {
	dnstask_cb_type	cb;
	void		*thunk;
	char		host[MAXHOST];
	struct event	*ev_resolve;
};

/*
 * Reschedule a DNS request.
 */
static void
reschedule(struct event *ev_resolve, int seconds)
{
	struct timeval tv;

	evutil_timerclear(&tv);
	tv.tv_sec = seconds;
	event_add(ev_resolve, &tv);
}

/*
 * Callback for A-records resolver results. When failed (NXDOMAIN,
 * SERVFAIL, at al), reschedule a new request.
 */
static void
response_ipv4(int result, char type, int count, int ttl, void *addresses,
    void *thunk)
{
	struct dnstask *task = thunk;

	if (result == DNS_ERR_NONE && count > 0) {
		task->cb(AF_INET, addresses, task->thunk);
		/* Schedule new request, enforce a lower bound on ttl. */
		if (T_flag)
			reschedule(task->ev_resolve, MAX(ttl, 1));
	} else {
		task->cb(0, NULL, task->thunk);
		/* neg-TTL might be search domain's */
		reschedule(task->ev_resolve, 60);
	}
}

/*
 * Callback for AAAA-records resolver results. When failed (NXDOMAIN,
 * SERVFAIL, at al), retry for A-record. Otherwise reschedule a new
 * request. All diagnostics about the failed request are useless, since
 * they might refer to a search domain request, which is done transparently
 * after the real request.
 */
static void
response_ipv6(int result, char type, int count, int ttl, void *addresses,
    void *thunk)
{
	struct dnstask *task = thunk;

	if (result == DNS_ERR_NONE && count > 0) {
		task->cb(AF_INET6, addresses, task->thunk);
		/* Schedule new request, enforce a lower bound on ttl. */
		if (T_flag)
			reschedule(task->ev_resolve, MAX(ttl, 1));
	} else {
		if (!v6_flag) {
			evdns_base_resolve_ipv4(dns, task->host, 0,
			    response_ipv4, thunk);
		} else {
			/* neg-TTL might be search domain's */
			reschedule(task->ev_resolve, 60);
			task->cb(0, NULL, task->thunk);
		}
	}
}

/*
 * Send DNS request using evdns. Try IPv6 first unless IPv4 is
 * forced. Missing AAAA-records are handled in response_ipv6.
 */
static void
sendquery(int fd, short what, void *thunk)
{
	struct dnstask *task = thunk;
	if (!v4_flag) {
		evdns_base_resolve_ipv6(dns, task->host, 0,
		    response_ipv6, task);
	} else {
		evdns_base_resolve_ipv4(dns, task->host, 0,
		    response_ipv4, task);
	}

}

/*
 * Set up a dnstask for resolving a given hostname and schedule
 * initial resolving.
 */
struct dnstask *
dnstask_new(const char *hostname, dnstask_cb_type cb, void *thunk)
{
	struct dnstask *task;
	struct timeval tv;

	task = calloc(1, sizeof(*task));
	if (task == NULL)
		return NULL;
	assert(strlen(hostname) + 1 <= sizeof(task->host));
	strncat(task->host, hostname, sizeof(task->host) - 1);
	task->cb = cb;
	task->thunk = thunk;
	task->ev_resolve = event_new(ev_base, -1, 0, sendquery, task);
	if (task->ev_resolve == NULL) {
		free(task);
		return NULL;
	}
	evutil_timerclear(&tv);
	event_add(task->ev_resolve, &tv);
	return task;
}

/*
 * Remove and free a previous dnstask.
 */
void
dnstask_free(struct dnstask *task)
{
	event_free(task->ev_resolve);
	free(task);
}
