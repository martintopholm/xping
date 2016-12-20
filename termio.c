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

static int ifirst_state = -1;
static int holding_row = 0;
static int labelwidth;

extern int w_width;

#ifndef NCURSES
static int cursor_y;
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
	cursor_y = row;
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
printw(const char *fmt, ...)
{
	va_list ap;

	fprintf(stdout, "%c[K", 0x1b);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
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
 * Window changed: move up from current line (cursor_y) to the "first"
 * line to the origin row (cursor_y = 0), clear screen and redraw.
 * We may continue in the middle of an update, but even so the rest of the
 * interrupted update will use the new reference point for its move().
 */
#ifndef NCURSES
void
sigwinch(int sig)
{
	if (cursor_y > 0)
		fprintf(stdout, "%c[%dA\r", 0x1b, cursor_y);
	fprintf(stdout, "\r%c[s", 0x1b);
	cursor_y = 0;
	fprintf(stdout, "%c[2K\r", 0x1b);
	clrtobot();
	termio_update(NULL); /* XXX: this is probably a bad idea */
}
#endif /* !NCURSES */


/*
 * Return a color based on success/failure
*/
static char *
getcolor(int ch)
{

	switch(ch) {
	case '.':
		return "\x1b[2;34m"; /* blue */
	case ':':
		return "\x1b[6;33m"; /* yellow */
	case '?':
	case '#':
		return "\x1b[1;31m"; /* red */
	case '%':
		return "\x1b[2;35m"; /* magenta */
	case '@':
		return "\x1b[5;32m"; /* green */
	case '!':
		return "\x1b[3;31m"; /* red */
	case '"':
		return "\x1b[5;33m"; /* yellow */
	}
	return "";
}

static void
drawchar(int ch)
{


	if (!B_flag) {
		addch(ch);
	} else {
		printw("%s%c\x1b[0m", getcolor(ch), ch);
	}
}

/*
 * Update a single reponse with redrawing entire output. Initial move
 * compensates for labelwidth (plus space) and move into the current
 * packet position.
 */
static void
updatesingle(int ifirst, struct target *t)
{
	move(t->row, labelwidth+(t->npkts-1-ifirst));
	drawchar(t->res[(t->npkts-1) % NUM]);
	move(holding_row, 0);
}

static void
updatefull(int ifirst, int ilast)
{
	struct target *t;
	int row;
	int i;

	row = 0;
	DL_FOREACH(list, t) {
		t->row = row; /* cache for selective updates */
		if (C_flag && t->af == AF_INET6)
			mvprintw(row, 0, "%c[2;32m%*.*s%c[0m",
			    0x1b, w_width, w_width, t->host, 0x1b);
		else if (C_flag && t->af == AF_INET)
			mvprintw(row, 0, "%c[2;31m%*.*s%c[0m",
			    0x1b, w_width, w_width, t->host, 0x1b);
		else
			mvprintw(row, 0, "%*.*s", w_width, w_width, t->host);
		if (w_width)
			drawchar(' ');
		for (i=ifirst; i<ilast; i++) {
			if (i < t->npkts)
				drawchar(t->res[i % NUM]);
			else
				drawchar(' ');
		}
		move(++row, 0);
	}
	holding_row = row;
}

/*
 * Prepares the terminal for drawing. For !NCURSES this means handling
 * window resize, output buffering, scroll issues and other output mangling.
 */
void
termio_init(void)
{
#ifndef NCURSES
	struct termios term;
	struct target *t;
	int x, y;

	signal(SIGWINCH, sigwinch);
	x = getmaxx();
	y = getmaxy();
	if (x > 0 && y > 0) {
	scrbuffer = malloc(x * y);
	if (scrbuffer != NULL)
		setvbuf(stdout, scrbuffer, _IOFBF, x * y);
	else
		perror("malloc");
	} else {
		scrbuffer = NULL;
	}

	/* Reserve space on terminal */
	cursor_y = 0;
	DL_FOREACH(list, t) {
		cursor_y++;
		scrolldown(1);
	}
	scrollup(cursor_y);

	/* Establish reference point for move() */
	fprintf(stdout, "\r%c[s", 0x1b);
	cursor_y = 0;

	/* Avoid mangling output by disabling input echo and wrapping */
	fprintf(stdout, "%c[7l", 0x1b);
	if (isatty(STDOUT_FILENO) && tcgetattr(STDOUT_FILENO, &oterm) == 0) {
		memcpy(&term, &oterm, sizeof(term));
		term.c_lflag &= ~(ECHO | ECHONL);
		tcsetattr(STDOUT_FILENO, TCSAFLUSH, &term);
	}
#else /* NCURSES */
	initscr();
#endif /* !NCURSES */
	labelwidth = (w_width > 0 ? w_width + 1 : 0);
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

	t = list;
	if (t == NULL)
		return;

	col = getmaxx(stdscr);
	imax = MIN(t->npkts, col - labelwidth);
	imax = MIN(imax, NUM);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	if (selective != NULL && ifirst == ifirst_state) {
		updatesingle(ifirst, selective);
	} else {
#ifndef NCURSES
		/* Re-establish the reference point for move() */
		if (cursor_y > 0)
			fprintf(stdout, "%c[%dA\r", 0x1b, cursor_y);
		fprintf(stdout, "\r%c[s", 0x1b);
		cursor_y = 0;
#endif /* !NCURSES */
		updatefull(ifirst, ilast);
		ifirst_state = ifirst;
		clrtoeol();
		clrtobot();
	}
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
	struct target *t;
	int col, i;
	int imax, ifirst, ilast;

	t = list;
	if (t == NULL)
		return;

	col = getmaxx(stdscr);
	imax = MIN(t->npkts, col - labelwidth);
	imax = MIN(imax, NUM);
	ifirst = (t->npkts > imax ? t->npkts - imax : 0);
	ilast = t->npkts;

	endwin();
	DL_FOREACH(list, t) {
		if (C_flag && t->af == AF_INET6)
			fprintf(stdout, "%c[2;32m%*.*s%c[0m",
			    0x1b, w_width, w_width, t->host, 0x1b);
		else if (C_flag && t->af == AF_INET)
			fprintf(stdout, "%c[2;31m%*.*s%c[0m",
			    0x1b, w_width, w_width, t->host, 0x1b);
		else
			fprintf(stdout, "%*.*s", w_width, w_width, t->host);
		if (w_width)
			fputc(' ', stdout);
		for (i=ifirst; i<ilast; i++) {
			if (i < t->npkts)
				fputc(t->res[i % NUM], stdout);
			else
				fputc(' ', stdout);
		}
		fputc('\n', stdout);
	}
#endif /* !NCURSES */
}
