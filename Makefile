#
# PMake
#

CFLAGS=-Wall -Werror -I./libevent-2.0.9-rc -I./libevent-2.0.9-rc/include
LDFLAGS=-L./libevent-2.0.9-rc/.libs
LIBS=-lcurses libevent.a -lrt

all: xping

ncurses-dev:
	sudo aptitude install ncurses-dev

libevent2:
	wget http://monkey.org/~provos/libevent-2.0.9-rc.tar.gz
	tar -xzvf libevent-2.0.9-rc.tar.gz
	cd libevent-2.0.9-rc && ./configure && make
	size ./libevent-2.0.9-rc/.libs/libevent.so
	cp ./libevent-2.0.9-rc/.libs/libevent.a .
	
xping: xping.o
	gcc $(LDFLAGS) -g -o xping $< $(LIBS)

install:
	sudo install -m 4555 xping /usr/local/sbin/xping

clean:
	rm -f xping xping.o
