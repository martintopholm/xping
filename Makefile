#
# Makefile for xping
#

LIBEVENT=libevent-2.0.22-stable
LIBEVENTDIR=release-2.0.22-stable

PREFIX?=/usr/local
BINPATH=$(PREFIX)/bin
MANPATH=$(PREFIX)/man
CFLAGS+=-Wall -Werror -Wpedantic -I/usr/local/include
LDFLAGS+=-L/usr/local/lib -L/usr/local/lib/event2
COVFLAGS=-fprofile-instr-generate -fcoverage-mapping
DEPS+=check-libevent.c
OBJS+=termio.o report.o version.o dnstask.o
LIBS+=-levent
VERSION="`git describe --tags --always --dirty=+ 2>/dev/null || echo v1.4.2`"

# Link with ncurses
#DEPS+=check-curses.c
#CFLAGS+=-DNCURSES
#LIBS+=-lcurses

# Dynamic libevent_openssl linking
# (OSX may need -Wno-deprecated-declarations)
#CFLAGS+=-Wno-deprecated-declarations
DEPS+=check-openssl.c
CFLAGS+=-DWITH_SSL
LIBS+=-levent_openssl -lssl

# Static libevent linking (OSX doesn't use -lrt)
#CFLAGS+=-I./$(LIBEVENT)/include
#DEPS=libevent.a
#LIBS=-lrt
# Static libevent_openssl linking
#DEPS+=check-openssl.c libevent_openssl.a
#CFLAGS+=-DWITH_SSL
#LIBS+=-lssl -lcrypto

.PHONY: version.o all install test test_coverage clean

all: xping xping.8.gz xping-unpriv xping-http

check-libevent.c:
	@/bin/echo -n 'Checking for libevent... '; \
	 (echo '#include <stdio.h>'; \
	  echo '#include <event2/event.h>'; \
	  echo 'int main()'; \
	  echo '{ printf("%s\\n", event_get_version()); return 0; }' \
	 ) | $(CC) $(CFLAGS) $(LDFLAGS) -x c -o /dev/null - -levent >/dev/null 2>/dev/null && echo yes || \
	 (echo no; \
	  echo ""; \
	  echo "libevent not available in usual locations"; \
	  echo "adjust CFLAGS and LDFLAGS appropriately"; \
	  echo ""; false)
	@touch $@

check-curses.c:
	@/bin/echo -n 'Checking for libcurses... '; \
	 (echo '#include <stdio.h>'; \
	  echo '#include <curses.h>'; \
	  echo 'int main()'; \
	  echo '{ initscr(); return 0; }' \
	 ) | $(CC) $(CFLAGS) -x c -o /dev/null - -lcurses >/dev/null 2>/dev/null && echo yes || \
	 (echo no; \
	  echo ""; \
	  echo "libcurses not available in usual locations"; \
	  echo "adjust CFLAGS and LDFLAGS appropriately"; \
	  echo ""; false)
	@touch $@

check-openssl.c:
	@/bin/echo -n 'Checking for openssl... '; \
	 (echo '#include <stdio.h>'; \
	  echo '#include <openssl/ssl.h>'; \
	  echo 'int main()'; \
	  echo '{ printf("%d\\n", SSL_library_init()); return 0; }' \
	 ) | $(CC) $(CFLAGS) $(LDFLAGS) -x c -o /dev/null - -lssl >/dev/null 2>/dev/null && echo yes || \
	 (echo no; \
	  echo ""; \
	  echo "openssl not available in usual locations"; \
	  echo "adjust CFLAGS and LDFLAGS appropriately"; \
	  echo ""; false)
	@touch $@

$(LIBEVENT)/.libs:
	test -f $(LIBEVENT).tar.gz || \
		wget https://github.com/libevent/libevent/releases/download/$(LIBEVENTDIR)/$(LIBEVENT).tar.gz || \
	    wget https://sourceforge.net/projects/levent/files/libevent/libevent-2.0/$(LIBEVENT).tar.gz
	test -d $(LIBEVENT) || tar -xzvf $(LIBEVENT).tar.gz
	test -f ./$(LIBEVENT)/.libs/$@ || cd $(LIBEVENT) && ./configure && make

libevent.a libevent_openssl.a: $(LIBEVENT)
	cp ./$(LIBEVENT)/.libs/$@ .
	size $@

version.o:
	printf "const char version[] = \"%s\";\n" $(VERSION) | \
	    $(CC) -x c -c -o $@ -

xping-raw.o: xping.c
	$(CC) $(CFLAGS) -DDO_SOCK_RAW -c -o $@ $^$>

xping: xping-raw.o icmp.o $(OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^$> $(LIBS)

xping-unpriv: xping.o icmp-unpriv.o $(OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^$> $(LIBS)

xping-http: xping.o http.o $(OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^$> $(LIBS)

xping.8.gz: xping.8
	gzip -9 -c $^$> > $@

install:
	mkdir -p $(BINPATH)
	mkdir -p $(MANPATH)/man8
	install -m 4555 xping $(BINPATH)/
	install -m 555 xping-http $(BINPATH)/
	install -m 444 xping.8.gz $(MANPATH)/man8/
	ln -f $(MANPATH)/man8/xping.8.gz $(MANPATH)/man8/xping-http.8.gz

clean:
	make -C test clean
	rm -f xping xping.8.gz xping-http xping-unpriv \
	      xping.o xping-raw.o http.o icmp.o icmp-unpriv.o \
	      $(OBJS) $(DEPS)

test:
	make -C test test

test_coverage:
	env CFLAGS="$$CFLAGS $(COVFLAGS)" LDFLAGS="$$LDFLAGS $(COVFLAGS)" \
	    make -C . clean all
	make -C test test coverage

# Object dependencies (gcc -MM *.c)
dnstask.o: dnstask.c xping.h uthash.h utlist.h
http.o: http.c xping.h uthash.h utlist.h
icmp.o: icmp.c xping.h uthash.h utlist.h
icmp-unpriv.o: icmp-unpriv.c xping.h uthash.h utlist.h
report.o: report.c xping.h uthash.h utlist.h
termio.o: termio.c xping.h uthash.h utlist.h
xping.o: xping.c xping.h uthash.h utlist.h
