#
# PMake
#

CFLAGS=-I./libevent-2.0.9-rc -I./libevent-2.0.9-rc/include
LDFLAGS=-L./libevent-2.0.9-rc/.libs -static
LIBS=-levent -lcurses

all: rping

libevent.so: ./libevent-2.0.9-rc/.libs/libevent.so
	cp ./libevent-2.0.9-rc/.libs/libevent.so .
	sudo install -m 444 libevent.so /usr/local/lib/libevent-2.0.so.5

rping: rping.o libevent.so
	gcc -g -o rping $> $(LDFLAGS) $(LIBS)

install:
	sudo install -m 4555 rping /usr/local/sbin/rping
