/*-
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <mph@hoth.dk> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Martin Topholm
 * ----------------------------------------------------------------------------
 */

#include <sys/param.h>
#include <sys/ioctl.h>

#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#ifndef NCURSES
#define stdscr
#else /* NCURSES */
#include <ncurses.h>
#endif /* !NCURSES */

#include "xping.h"

#ifndef NCURSES
int
getmaxx(void)
{
	struct winsize wsz;
	char *p;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &wsz) != -1 &&
	    wsz.ws_col > 0)
		return (wsz.ws_col);
	else if ((p = getenv("COLUMNS")) != NULL && *p != '\0')
		return atoi(p);
	else
		return 0;
}

int
getmaxy(void)
{
	struct winsize wsz;
	char *p;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &wsz) != -1 &&
	    wsz.ws_row > 0)
		return (wsz.ws_row);
	else if ((p = getenv("ROWS")) != NULL && *p != '\0')
		return atoi(p);
	else
		return 0;
}
void
move(int row, int col)
{
	fprintf(stdout, "%c[u", 0x1b);
	if (row > 0)
		fprintf(stdout, "%c[%dB", 0x1b, row);
	if (col > 0)
		fprintf(stdout, "%c[%dC", 0x1b, col);
}

static void
clrtobot(void)
{
	fprintf(stdout, "%c[J", 0x1b);
}

static void
clrtoeol(void)
{
	fprintf(stdout, "%c[K", 0x1b);
}

static void
addch(int ch)
{
	fputc(ch, stdout);
}

static void
mvprintw(int row, int col, const char *fmt, ...)
{
	va_list ap;

	move(row, col);
	fprintf(stdout, "%c[K", 0x1b);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

static void
refresh(void)
{
	fflush(stdout);
}
#endif

/*
 * Prepares the terminal for drawing
 */
void
termio_init(void)
{
#ifndef NCURSES
	int y;
	y = getmaxy();
	for (y = getmaxy(); y > 0; y--)
		fprintf(stdout, "%cD", 0x1b);
	fprintf(stdout, "%c[H", 0x1b);
	fprintf(stdout, "%c[s", 0x1b);
	clrtobot();
#else /* NCURSES */
	initscr();
#endif /* !NCURSES */
}

/*
 * Draws the recorded replies on the terminal.
 */
void
termio_update(void)
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
		if (C_flag && t->evdns_type && sa(t)->sa_family == AF_INET6)
			mvprintw(y, 0, "%c[2;32m%19.19s%c[0m ",
			    0x1b, t->host, 0x1b);
		else if (C_flag && t->evdns_type && sa(t)->sa_family == AF_INET)
			mvprintw(y, 0, "%c[2;31m%19.19s%c[0m ",
			    0x1b, t->host, 0x1b);
		else
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
	mvprintw(y++, 0, "Legend  . echo-reply   ? timeout      # unreach    "
	    "%%=other");
	mvprintw(y++, 0, "        @ resolving    ! send-error");
	if (C_flag)
		mvprintw(y-1, 38, "%c[2;32mIPv6%c[0m/%c[2;31mIPv4%c[0m",
		    0x1b, 0x1b, 0x1b, 0x1b);
#ifdef STATS
	y++;
	mvprintw(y++, 0, "Sent: %d", stats->transmitted);
	mvprintw(y++, 0, "Recv: %d", stats->received);
	mvprintw(y++, 0, "ErrO: %d", stats->sendto_err);
	mvprintw(y++, 0, "ErrI: %d", stats->recvfrom_err);
	mvprintw(y++, 0, "Runt: %d", stats->runt);
	mvprintw(y++, 0, "Othr: %d", stats->other);
#endif /* STATS */
	move(y++, 0);
	clrtobot();

	refresh();
}

/*
 * Clean up screen and restore old modes
 */
void
termio_cleanup(void)
{
#ifndef NCURSES
#else /* NCURSES */
	endwin();
#endif /* !NCURSES */
}
