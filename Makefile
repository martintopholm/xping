#
# PMake
#

LIBEVENT=libevent-2.0.18-stable

PREFIX=/usr/local
SBINPATH=$(PREFIX)/bin
MANPATH=$(PREFIX)/man
CFLAGS=-Wall -Werror -I./$(LIBEVENT) -I./$(LIBEVENT)/include
LDFLAGS=-L./$(LIBEVENT)/.libs
LIBS=libevent.a -lrt -lcurses

all: xping xping.8.gz

libevent.a:
	test -f $(LIBEVENT).tar.gz || wget https://github.com/downloads/libevent/libevent/$(LIBEVENT).tar.gz
	test -d $(LIBEVENT) || tar -xzvf $(LIBEVENT).tar.gz
	cd $(LIBEVENT) && ./configure && make
	cp ./$(LIBEVENT)/.libs/libevent.a .
	size libevent.a

curses.so:
	printf "#include <ncurses.h>\nint main() { initscr(); return 0; }" | \
            gcc -x c -o /dev/null - -lcurses && touch curses.so

xping: libevent.a curses.so xping.o version.o
	$(CC) $(LDFLAGS) -g -o xping xping.o version.o $(LIBS)

xping.8.gz: xping.8
	gzip < xping.8 > xping.8.gz

xping.8.txt: xping.8
	groff -mman -Tascii xping.8 | sed 's/.//g' > xping.8.txt

xping.8.html: xping.8
	-groff -mman -Thtml xping.8 > xping.8.html

install:
	mkdir -p $(SBINPATH)
	mkdir -p $(MANPATH)/man8
	install -m 4555 xping $(SBINPATH)/
	install -m 444 xping.8.gz $(MANPATH)/man8/

clean:
	rm -f xping xping.o xping.8.gz xping.8.txt xping.8.html version.o curses.so
