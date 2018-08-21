/*
 * Memory tracing in LD_PRELOAD
 * from https://stackoverflow.com/questions/2593284/enable-mtrace-malloc-trace-for-binary-program
 * fetched at 2018-07-18
 *
 * Usage:
 *     gcc mtrace.c  -fPIC -shared  -o libmmtrace.so
 *     MALLOC_TRACE=echo LD_PRELOAD=./libmmtrace.so /bin/echo 42
 */
#include <mcheck.h>
#include <stdlib.h>


void __mtracer_on(void) __attribute__((constructor));
/*
 * Avoid deactivating tracer to actually catch libc free()'s as well.
 * void __mtracer_off(void) __attribute__((destructor));
 */

void __mtracer_on(void)
{
	char *p=getenv("MALLOC_TRACE");
	if(!p)
		return;
	/*
	 * Avoid deactivating tracer to actually catch libc free()'s as well.
	 * atexit(&__mtracer_off);
	 */
	mtrace();
}

void __mtracer_off(void)
{
	muntrace();
}
