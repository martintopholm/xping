#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <event2/event.h>

#include "tinytest.h"
#include "tinytest_macros.h"


#define BLACKBOX_OUTDIRS_MAX 3
char blackbox_outdirs[3][16] = { {0}, {0}, {0} };

struct context {
	const struct testcase_t	*testcase;
	char			path[FILENAME_MAX];
	char			name[FILENAME_MAX];
};

#define EXEC_MTRACE		0x01
#define EXEC_UNREACH		0x02
#define EXEC_FDSLIM_MASK	0xf0
#define EXEC_FDSLIM_SHIFT	4

static pid_t
exec_wd(int flags, char *file, ...)
{
	va_list ap;
	char *argv[128];
	int i;
	pid_t pid;
	struct rlimit rlim;

	if (flags & EXEC_MTRACE && flags & EXEC_UNREACH)
		return 1;
	va_start(ap, file);
	argv[0] = file;
	for (i = 1; i < sizeof(argv)/sizeof(char *); i ++) {
		argv[i] = va_arg(ap, char *);
		if (argv[i] == NULL)
			break;
	}
	va_end(ap);
	switch (pid = fork()) {
	case -1:
		return -1;
	case 0:
		freopen("stdout", "w+", stdout);
		freopen("stderr", "w+", stderr);
		if (flags & EXEC_MTRACE) {
			setenv("MALLOC_TRACE", "trace", 1);
			setenv("LD_PRELOAD", "../mmtrace.so", 1);
		}
		if (flags & EXEC_UNREACH) {
			setenv("LD_PRELOAD", "../unreach.so", 1);
		}
		if (flags & EXEC_FDSLIM_MASK) {
			rlim.rlim_cur = rlim.rlim_max = (flags & EXEC_FDSLIM_MASK) >> EXEC_FDSLIM_SHIFT;
			if (setrlimit(RLIMIT_NOFILE, &rlim) < 0)
				abort();
		}
		execvp(file, argv);
		perror("execvp");
		abort();
	default:
		return pid;
	}
}

static int
sock_listen(unsigned short *port)
{
	struct sockaddr_in sin;
	socklen_t sa_len;
	int fd;

	memset(&sin, 0, sizeof(sin));
	if (inet_pton(AF_INET, "127.0.0.1",
	    (struct sockaddr *)&sin.sin_addr) == 0)
		return -1;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(*port);
	fd = socket(sin.sin_family, SOCK_STREAM, 6);
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
		goto err;
	sa_len = sizeof(sin);
	if (getsockname(fd, (struct sockaddr *)&sin, &sa_len) < 0)
		goto err;
	*port = ntohs(sin.sin_port);
	if (listen(fd, 8) < 0)
		goto err;
	return fd;
err:
	close(fd);
	return -1;
}

static int
regex(char *filename, const char *regex)
{
	char buf[4096];
	int fd;
	ssize_t len;
	regex_t preg;
	int n;

	fd = open(filename, O_RDONLY);
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len < 0)
		return -1;
	buf[len] = '\0';

	if (regcomp(&preg, regex, REG_EXTENDED | REG_NOSUB) != 0)
		return -1;
	n = regexec(&preg, buf, 0, NULL, 0);
	regfree(&preg);
	if (n != 0)
		return -1;
	regfree(&preg);
	return 0;

}

static int
has_dots(char *filename)
{

	if (regex(filename, "\\.{4}") < 0)
		return 0;
	return 1;
}

static int
exists(char *filename)
{
	struct stat st;

	if (stat(filename, &st) != 0)
		return 0;
	return 1;
}

static void
test_xping_localhost(void *ctx_)
{
	struct context *ctx = ctx_;
	int wstatus;
	pid_t pid;

	strcpy(ctx->name, "xping");
	pid = exec_wd(0, "../../xping", "-c", "4", "127.0.0.1", NULL);
	tt_uint_op(pid, >, 0);
	waitpid(pid, &wstatus, 0);
	tt_assert(WIFEXITED(wstatus));
	tt_assert(WEXITSTATUS(wstatus) == 0);
	tt_assert(has_dots("stdout"));

end:
	;
}

static void
test_xping_unpriv_localhost(void *ctx_)
{
	struct context *ctx = ctx_;
	int wstatus;
	pid_t pid;

	strcpy(ctx->name, "xping-unpriv");
	pid = exec_wd(0, "../../xping-unpriv", "-c", "4", "127.0.0.1", NULL);
	tt_uint_op(pid, >, 0);
	waitpid(pid, &wstatus, 0);
	tt_assert(WEXITSTATUS(wstatus) == 0);
	tt_assert(has_dots("stdout"));

end:
	;
}

static void
test_xping_http_localhost(void *ctx_)
{
	struct context *ctx = ctx_;
	char url[32];
	char buf[4096];
	char response[] = "HTTP/1.0 200 OK\r\n\r\n";
	unsigned short listen_port;
	struct timeval tv = {2, 0};
	int wstatus;
	pid_t pid;
	int fd_srv;
	int fd;
	ssize_t n;
	int max_req;
	int exec_flags;

	listen_port = 0;
	fd_srv = sock_listen(&listen_port);
	tt_assert(fd_srv >= 0);
	snprintf(url, sizeof(url), "http://127.0.0.1:%hu", listen_port);

	strcpy(ctx->name, "xping-http");
	exec_flags = 0;
	if (strcmp(ctx->testcase->name, "xping-http-localhost") == 0) {
		strcpy(blackbox_outdirs[2], ctx->path);
		if (exists("../mmtrace.so"))
			exec_flags |= EXEC_MTRACE;
	} else if (strcmp(ctx->testcase->name, "connect-unreach-http") == 0) {
		if (!exists("../unreach.so"))
			tt_skip();
		exec_flags |= EXEC_UNREACH;
	} else if (strcmp(ctx->testcase->name, "fd-leakage-http") == 0) {
		exec_flags |= 10 << EXEC_FDSLIM_SHIFT;
	}
	pid = exec_wd(exec_flags, "../../xping-http", "-c", "4", url, NULL);
	tt_assert(pid > 0);
	tt_assert(setsockopt(fd_srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
	for (max_req = 4; max_req > 0; max_req--) {
		fd = accept(fd_srv, NULL, 0);
		if (fd < 0)
			break;
		n = read(fd, buf, sizeof(buf));
		if (n < 1)
			break;
		write(fd, response, strlen(response));
		close(fd);
	}
	waitpid(pid, &wstatus, 0);
	tt_assert(WIFEXITED(wstatus));
	tt_assert(WEXITSTATUS(wstatus) == 0);
	if (strcmp(ctx->testcase->name, "connect-unreach-http") == 0)
		tt_assert(regex("stdout", "[!#]{4}") == 0)
	else
		tt_assert(has_dots("stdout"));

end:
	close(fd_srv);
	;
}

static void
test_memory_leakage(void *ctx_)
{
	char path[FILENAME_MAX];
	int i;
	pid_t pid;
	int wstatus;

	if (!exists("../mmtrace.so") || LIBEVENT_VERSION_NUMBER < 0x02010001 )
		tt_skip();
	for (i=0; i<BLACKBOX_OUTDIRS_MAX; i++) {
		if (blackbox_outdirs[i][0] == '\0')
			continue;
		snprintf(path, sizeof(path), "../%s/trace", blackbox_outdirs[i]);
		if (!exists(path)) {
			tt_fail_msg("mtrace output missing");
			continue;
		}
		pid = exec_wd(0, "mtrace", "../../xping-http", path, NULL);
		waitpid(pid, &wstatus, 0);
		tt_want_msg(WEXITSTATUS(wstatus) == 0, "mtrace reported leaks");
	}

end:
	;
}


static int
cleanup(const struct testcase_t *testcase, void *ctx_)
{
	struct context *ctx = ctx_;
	char buf[FILENAME_MAX];

	snprintf(buf, sizeof(buf), "%.128s.profraw", ctx->name);
	rename("default.profraw", buf);
	if (ctx->path[0])
		if (chdir("..") < 0)
			return 0;
	free(ctx);
	return 1;
}

static void *
setup(const struct testcase_t *testcase)
{
	char buf[512];
	struct context *ctx;
	int fd;

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	ctx->testcase = testcase;
	strcpy(buf, "test.XXXXXX");
	if (mkdtemp(buf) == NULL)
		goto err;
	if (chdir(buf) < 0)
		goto err;
	fd = open("default.profraw", O_WRONLY | O_CREAT, 0666);
	close(fd);
	strcpy(ctx->path, buf);
	return ctx;
err:
	cleanup(testcase, ctx);
	return NULL;
}

static struct testcase_setup_t tc_setup = {setup, cleanup};

struct testcase_t tc_blackbox[] = {
	{"xping-localhost", test_xping_localhost, 0, &tc_setup},
	{"xping-unpriv-localhost", test_xping_unpriv_localhost,
	    TT_OFF_BY_DEFAULT, &tc_setup},
	{"xping-http-localhost", test_xping_http_localhost, 0, &tc_setup},
	{"fd-leakage-http", test_xping_http_localhost, 0, &tc_setup},
	{"connect-unreach-http", test_xping_http_localhost, 0, &tc_setup},
	{"memory-leakage", test_memory_leakage, 0, &tc_setup},
	END_OF_TESTCASES
};
