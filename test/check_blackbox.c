#include <sys/types.h>
#include <sys/socket.h>
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
	ssize_t n;
	regex_t preg;

	fd = open(filename, O_RDONLY);
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 1)
		return 0;
	buf[n] = '\0';

	if (regcomp(&preg, regex, REG_EXTENDED | REG_NOSUB) != 0)
		return -1;
	if (regexec(&preg, buf, 0, NULL, 0) != 0)
		return -1;
	return 0;

}

static int
has_10_dots(char *filename)
{

	if (regex(filename, "\\.{10}") < 0)
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
	pid = exec_wd(NULL, "../../xping", "-c", "10", "127.0.0.1", NULL);
	tt_uint_op(pid, >, 0);
	waitpid(pid, &wstatus, 0);
	tt_assert(WEXITSTATUS(wstatus) == 0);
	tt_assert(has_10_dots("stdout"));

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
	pid = exec_wd(NULL, "../../xping-unpriv", "-c", "10", "127.0.0.1", NULL);
	tt_uint_op(pid, >, 0);
	waitpid(pid, &wstatus, 0);
	tt_assert(WEXITSTATUS(wstatus) == 0);
	tt_assert(has_10_dots("stdout"));

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

	listen_port = 0;
	fd_srv = sock_listen(&listen_port);
	snprintf(url, sizeof(url), "http://127.0.0.1:%hu", listen_port);

	strcpy(ctx->name, "xping-http");
	pid = exec_wd(NULL, "../../xping-http", "-c", "10", url, NULL);
	tt_assert(pid > 0);
	tt_assert(setsockopt(fd_srv, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0);
	for (max_req = 10; max_req > 0; max_req--) {
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
	tt_assert(has_10_dots("stdout"));

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
	END_OF_TESTCASES
};
