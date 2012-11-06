#
# PMake
#

LIBEVENT=libevent-2.0.18-stable

PREFIX=/usr/local
SBINPATH=$(PREFIX)/bin
MANPATH=$(PREFIX)/man
CFLAGS=-Wall -Werror -I./$(LIBEVENT) -I./$(LIBEVENT)/include
LDFLAGS=-L./$(LIBEVENT)/.libs
LIBS=libevent.a -lrt
VERSION="`git describe --tags --always --dirty=+ 2>/dev/null || date +snapshot-%Y%m%dT%H%M%S`"
TIMESTAMP="`date +%Y%m%dT%H%M%S`"

#CFLAGS+=-DNCURSES
#LIBS+=-lcurses

.PHONY: version.o

all: xping xping.8.gz

libevent.a:
	test -f $(LIBEVENT).tar.gz || wget https://github.com/downloads/libevent/libevent/$(LIBEVENT).tar.gz
	test -d $(LIBEVENT) || tar -xzvf $(LIBEVENT).tar.gz
	cd $(LIBEVENT) && ./configure && make
	cp ./$(LIBEVENT)/.libs/libevent.a .
	size libevent.a

version.o:
	(printf "const char version[] = \"%s\";\n" $(VERSION); \
	 printf "const char built[] = \"%s\";\n" $(TIMESTAMP)) | \
	 gcc -x c -c -o version.o -

xping: libevent.a xping.o termio.o version.o
	$(CC) $(LDFLAGS) -g -o xping xping.o termio.o version.o $(LIBS)

xping.8.gz: xping.8
	gzip < xping.8 > xping.8.gz

install:
	mkdir -p $(SBINPATH)
	mkdir -p $(MANPATH)/man8
	install -m 4555 xping $(SBINPATH)/
	install -m 444 xping.8.gz $(MANPATH)/man8/

clean:
	rm -f xping xping.o xping.8.gz termio.o version.o
