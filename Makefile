#
# PMake
#

LIBEVENT=libevent-2.0.18-stable

PREFIX=/usr/local
SBINPATH=$(PREFIX)/bin
MANPATH=$(PREFIX)/man
CFLAGS=-Wall -Werror -I./$(LIBEVENT) -I./$(LIBEVENT)/include
LDFLAGS=-L./$(LIBEVENT)/.libs
LIBS=-lcurses libevent.a -lrt

all: xping xping.8.gz

ncurses-dev:
	sudo aptitude install ncurses-dev

libevent.a:
	test -f $(LIBEVENT).tar.gz || wget https://github.com/downloads/libevent/libevent/$(LIBEVENT).tar.gz
	test -d $(LIBEVENT) || tar -xzvf $(LIBEVENT).tar.gz
	cd $(LIBEVENT) && ./configure && make
	cp ./$(LIBEVENT)/.libs/libevent.a .
	size libevent.a

xping: libevent.a xping.o
	gcc $(LDFLAGS) -g -o xping xping.o $(LIBS)

xping.8.gz: xping.8
	cat xping.8 | gzip > xping.8.gz

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
	rm -f xping xping.o xping.8.gz xping.8.txt xping.8.html
