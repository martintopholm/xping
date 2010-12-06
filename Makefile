#
# PMake
#

SBINPATH=/usr/local/bin
MANPATH=/usr/local/man
CFLAGS=-Wall -Werror -I./libevent-2.0.9-rc -I./libevent-2.0.9-rc/include
LDFLAGS=-L./libevent-2.0.9-rc/.libs
LIBS=-lcurses libevent.a -lrt

all: xping xping.8.gz

ncurses-dev:
	sudo aptitude install ncurses-dev

libevent2:
	wget http://monkey.org/~provos/libevent-2.0.9-rc.tar.gz
	tar -xzvf libevent-2.0.9-rc.tar.gz
	cd libevent-2.0.9-rc && ./configure && make
	cp ./libevent-2.0.9-rc/.libs/libevent.a .
	size libevent.a
	
xping: xping.o
	gcc $(LDFLAGS) -g -o xping xping.o $(LIBS)

xping.8.gz: xping.8
	gzip -k -f xping.8

xping.8.txt: xping.8
	groff -mman -Tascii xping.8 | sed 's/.//g' > xping.8.txt

xping.8.html: xping.8
	-groff -mman -Thtml xping.8 > xping.8.html

install:
	mkdir -p $(SBINPATH)
	mkdir -p $(MANPATH)/man8
	sudo install -m 4555 xping $(SBINPATH)/
	sudo install -m 444 xping.8.gz $(MANPATH)/man8/

clean:
	rm -f xping xping.o xping.8.gz xping.8.txt xping.8.html
