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
#include <sys/socket.h>

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#ifndef NCURSES
#define stdscr
#else /* NCURSES */
#include <ncurses.h>
#endif /* !NCURSES */

#include "xping.h"

static int cursor_y;
static int ifirst_state;

#ifndef NCURSES
static char *scrbuffer;
struct termios oterm;

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

static void
scrollup(int n)
{
	int i;

	for (i=0; i < n; i++)
		fprintf(stdout, "%cM", 0x1b);
}

static void
scrolldown(int n)
{
	int i;

	for (i=0; i < n; i++)
		fprintf(stdout, "%cD", 0x1b);
}
#endif

/*
 * Window changed: move up from current line to the "first" line, clear
 * screen and redraw. XXX: we may continue in the middle of an update,
 * so we should probably just make a new reference point and schedule an
 * immediate update after signal processing.
 */
#ifndef NCURSES
void
sigwinch(int sig)
{
	scrollup(cursor_y);
	cursor_y = 0;
	fprintf(stdout, "%c[2K\r", 0x1b);
	clrtobot();
	termio_update(NULL); /* XXX: this is probably a bad idea */
}
#endif /* !NCURSES */

static void
updatesingle(int ifirst, struct target *selective)
{
	struct target *t;
	int i;

	i = 0;
	DL_FOREACH(list, t) {
		if (t == selective) {
			move(cursor_y = i, 20+(t->npkts-1-ifirst));
			addch(t->res[(t->npkts-1) % NUM]);
		}
		i++;
	}
	move(cursor_y = i, 0);
}

static void
updatefull(int ifirst, int ilast)
{
	struct target *t;
	int i;

	cursor_y = 0;
	move(cursor_y, 0);
	DL_FOREACH(list, t) {
		if (C_flag && t->ev_resolve && sa(t)->sa_family == AF_INET6)
			mvprintw(cursor_y, 0, "%c[2;32m%19.19s%c[0m ",
			    0x1b, t->host, 0x1b);
		else if (C_flag && t->ev_resolve && sa(t)->sa_family == AF_INET)
			mvprintw(cursor_y, 0, "%c[2;31m%19.19s%c[0m ",
			    0x1b, t->host, 0x1b);
		else
			mvprintw(cursor_y, 0, "%19.19s ", t->host);
		if (t->duplicate != NULL)
			mvprintw(cursor_y, 20, "(duplicate of %s)", t->duplicate->host);
		else {
			for (i=ifirst; i<ilast; i++) {
				if (i < t->npkts)
					addch(t->res[i % NUM]);
				else
					addch(' ');
			}
		}
		move(++cursor_y, 0);
	}
}

/*
 * Prepares the terminal for drawing
 */
void
termio_init(void)
{
	ifirst_state = -1;
#ifndef NCURSES
	struct termios term;
	struct target *t;
	int x, y;

	signal(SIGWINCH, sigwinch);
	x = getmaxx();
	y = getmaxy();
	scrbuffer = malloc(x * y);
	if (scrbuffer != NULL)
		setvbuf(stdout, scrbuffer, _IOFBF, x * y);
	else
		perror("malloc");

	/* Reserve space on terminal */
	DL_FOREACH(list, t)
		cursor_y++;
#ifdef STATS
	cursor_y += 7;
#endif
	scrolldown(cursor_y);

	fprintf(stdout, "%c[7l", 0x1b); /* disable wrapping */

	if (isatty(STDOUT_FILENO) && tcgetattr(STDOUT_FILENO, &oterm) == 0) {
		memcpy(&term, &oterm, sizeof(term));
		term.c_lflag &= ~(ECHO | ECHONL);
		tcsetattr(STDOUT_FILENO, TCSAFLUSH, &term);
	}
#else /* NCURSES */
	initscr();
#endif /* !NCURSES */
}

/*
 * Draws the recorded replies on the terminal.
 */
void
termio_update(struct target *selective)
{
	struct target *t;
	int col;

	int imax, ifirst, ilast;
#ifndef NCURSES
	int i;

	/* Establish reference point on "first" output line */
	for (i=0; i < cursor_y; i++)
		fprintf(stdout, "%cM", 0x1b);
	fprintf(stdout, "\r%c[s", 0x1b);
#endif /* !NCURSES */

	t = list;
	if (t == NULL)
		return;

	col = getmaxx(stdscr);
	imax = MIN(t->npkts, col - 20);
	imax = MIN(imax, NUM);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	if (selective != NULL && ifirst == ifirst_state) {
		updatesingle(ifirst, selective);
	} else {
		updatefull(ifirst, ilast);
		ifirst_state = ifirst;
	}
	clrtoeol();
#ifdef STATS
	mvprintw(++cursor_y, 0, "Sent: %d", stats->transmitted);
	mvprintw(++cursor_y, 0, "Recv: %d", stats->received);
	mvprintw(++cursor_y, 0, "ErrO: %d", stats->sendto_err);
	mvprintw(++cursor_y, 0, "ErrI: %d", stats->recvfrom_err);
	mvprintw(++cursor_y, 0, "Runt: %d", stats->runt);
	mvprintw(++cursor_y, 0, "Othr: %d", stats->other);
	move(++cursor_y, 0);
#endif /* STATS */
#ifdef NCURSES
	mvprintw(++cursor_y, 0, "NCURSES");
	move(++cursor_y, 0);
#endif /* NCURSES */
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
	setvbuf(stdout, NULL, _IONBF, 0);
	if (scrbuffer)
		free(scrbuffer);
	if (isatty(STDIN_FILENO))
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &oterm); // XXX: TCASOFT? see openssh
#else /* NCURSES */
	endwin();
#endif /* !NCURSES */
}
