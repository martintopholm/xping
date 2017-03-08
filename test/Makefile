CFLAGS+=-Wall -Wpedantic -I..

PROFDATA=xping.profdata xping-unpriv.profdata xping-http.profdata

.PHONY: all test $(PROFDATA) coverage clean

test: tinytest
	test ! -O ../xping || sudo chown root ../xping
	test -u ../xping || sudo chmod 4750 ../xping
	./tinytest || (find test/test.?????? -type f -print0 | xargs -0 head -50; exit 123)

tinytest: check_blackbox.c tests.c tinytest.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^$>

$(PROFDATA):
	rm -f $@
	llvm-profdata merge -o $@ test.??????/$$(basename $@ .profdata).profraw

coverage: $(PROFDATA)
	@for X in $(PROFDATA); do \
	    B=$$(basename $$X .profdata); \
	    printf "%-.20s:" $$B; \
	    echo -n "$$(git log --date=short --pretty="format:%ad%x20%h" -1) "; \
	    llvm-cov report -instr-profile $$X ../$$B | \
		sed -nE '/TOTAL/s/TOTAL *[0-9]* *[0-9]* * ([0-9\.]*)%.*/\1/p'; \
	done

clean:
	rm -rf test.??????
	rm -f tinytest *.profdata
