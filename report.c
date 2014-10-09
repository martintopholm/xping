/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mph@hoth.dk> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Martin Topholm
 * ----------------------------------------------------------------------------
 */

#include <sys/param.h>

#include <stdio.h>

#include "xping.h"

extern int w_width;

void report_init()
{
}

void report_update(struct target *t)
{
}

void report_cleanup()
{
	struct target *t;
	int i, imax, ifirst, ilast;

	t = list;
	if (t == NULL)
		return;

	imax = MIN(t->npkts, NUM);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	DL_FOREACH(list, t) {
		fprintf(stdout, "%*.*s", w_width, w_width, t->host);
		if (w_width)
			fputc(' ', stdout);
		for (i=ifirst; i<ilast; i++) {
			if (i < t->npkts) fputc(t->res[i % NUM], stdout);
			else fputc(' ', stdout);
		}
		fputc('\n', stdout);
	}
}

