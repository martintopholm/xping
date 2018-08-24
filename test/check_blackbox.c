#include <sys/types.h>
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

#include "tinytest.h"
#include "tinytest_macros.h"


#define BLACKBOX_OUTDIRS_MAX 3
char blackbox_outdirs[3][16] = { {0}, {0}, {0} };

struct context {
	char		path[FILENAME_MAX];
	char		name[FILENAME_MAX];
};

static pid_t
exec_wd(char *wd, char *file, ...)
{
	va_list ap;
	char *argv[128];
	int i;
	pid_t pid;

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
		if (wd != NULL && chdir(wd) != 0) {
			perror("chdir");
			abort();
		}
		freopen("stdout", "w+", stdout);
		freopen("stderr", "w+", stderr);
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
	if (len < 1)
		return 0;
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
	pid = exec_wd(NULL, "../../xping", "-c", "4", "127.0.0.1", NULL);
	tt_uint_op(pid, >, 0);
	waitpid(pid, &wstatus, 0);
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
	pid = exec_wd(NULL, "../../xping-unpriv", "-c", "4", "127.0.0.1", NULL);
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
	struct timeval tv = {15, 0};
	int wstatus;
	pid_t pid;
	int fd_srv;
	int fd;
	ssize_t n;
	int max_req;

	strcpy(blackbox_outdirs[2], ctx->path);
	listen_port = 0;
	fd_srv = sock_listen(&listen_port);
	tt_assert(fd_srv >= 0);
	snprintf(url, sizeof(url), "http://127.0.0.1:%hu", listen_port);

	strcpy(ctx->name, "xping-http");
	setenv("MALLOC_TRACE", "trace", 1);
	if (exists("../mmtrace.so"))
		setenv("LD_PRELOAD", "../mmtrace.so", 1);
	pid = exec_wd(NULL, "../../xping-http", "-c", "4", url, NULL);
	unsetenv("MALLOC_TRACE");
	unsetenv("LD_PRELOAD");
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
	close(fd_srv);
	waitpid(pid, &wstatus, 0);
	tt_assert(WEXITSTATUS(wstatus) == 0);
	tt_assert(has_dots("stdout"));

end:
	;
}

static void
test_memory_leakage(void *ctx_)
{
	char path[FILENAME_MAX];
	int i;
	pid_t pid;
	int wstatus;

	if (!exists("../mmtrace.so"))
		tt_skip();
	for (i=0; i<BLACKBOX_OUTDIRS_MAX; i++) {
		if (blackbox_outdirs[i][0] == '\0')
			continue;
		snprintf(path, sizeof(path), "../%s/trace", blackbox_outdirs[i]);
		if (!exists(path)) {
			tt_fail_msg("mtrace output missing");
			continue;
		}
		pid = exec_wd(NULL, "mtrace", "../../xping-http", path, NULL);
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

	snprintf(buf, sizeof(buf), "%s.profraw", ctx->name);
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
	{"memory-leakage", test_memory_leakage, 0, &tc_setup},
	END_OF_TESTCASES
};
