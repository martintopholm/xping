#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <openssl/ssl.h>

struct event_base *ev_base;
struct evdns_base *dns;

SSL_CTX *ssl_ctx;
SSL_CTX *ssl_ctx2;

int seq;

struct state {
	char		remote[64];
	struct bufferevent *bev_device;
	struct bufferevent *bev_webmail;
	int		seq;

	FILE		*fp_device;
	FILE		*fp_webmail;
};

void webmail_read(struct bufferevent *bev, void *arg)
{
	struct state *st = arg;
	char data[8192];
	size_t n;

	n = bufferevent_read(bev, data, sizeof(data)-1);
	bufferevent_write(st->bev_device, data, n);
	fwrite(data, n, 1, st->fp_webmail);
}

void device_read(struct bufferevent *bev, void *arg)
{
	struct state *st = arg;
	char data[8192];
	size_t n;

	// bufferevent_get_input
	//if (evbuffer_find(bev->input, "\r\n\r\n", 4) == NULL) {
	//	return;
	//}

	n = bufferevent_read(bev, data, sizeof(data));
	bufferevent_write(st->bev_webmail, data, n);
	fwrite(data, n, 1, st->fp_device);
}

void event(struct bufferevent *bev, short what, void *arg)
{
	struct state *st = arg;
	char buf[512];

	if (what & BEV_EVENT_CONNECTED) {
		printf("%s: connected to %s (fd=%d)\n", st->remote,
		    bev == st->bev_device ? "device" : "webmail",
		    bufferevent_getfd(bev));
	} else if (what & BEV_EVENT_EOF) {
		printf("%s: eof from %s\n", st->remote,
		    bev == st->bev_device ? "device" : "webmail");
		SSL_shutdown(bufferevent_openssl_get_ssl(st->bev_device));
		SSL_shutdown(bufferevent_openssl_get_ssl(st->bev_webmail));
		bufferevent_free(st->bev_device);
		bufferevent_free(st->bev_webmail);
		fclose(st->fp_device);
		fclose(st->fp_webmail);
		free(st);
	} else {
		printf("%s: exception what=%x from %s\n", st->remote, what,
		    bev == st->bev_device ? "device" : "webmail");
		ERR_error_string(bufferevent_get_openssl_error(bev), buf);
		printf("--: %s\n", buf);
		SSL_shutdown(bufferevent_openssl_get_ssl(st->bev_device));
		SSL_shutdown(bufferevent_openssl_get_ssl(st->bev_webmail));
		bufferevent_free(st->bev_device);
		bufferevent_free(st->bev_webmail);
		fclose(st->fp_device);
		fclose(st->fp_webmail);
		free(st);
	}
}

void accept_new(int fd, short what, void *ev)
{
	char fn[512];
	struct state *st;
	struct sockaddr_in sa;
	socklen_t salen;
	struct timeval tv;
	SSL *ssl;
	int s;
	int rc;

	tv.tv_sec = 300;
	tv.tv_usec = 0;

	/* Accept device-facing connection */
	st = (struct state *)malloc(sizeof(*st));
	if (st == NULL) {
                printf("accept: %s\n", strerror(errno));
                exit(1);
	}
	memset(st, 0, sizeof(*st));
	st->seq = seq++;

	salen = sizeof(sa);
	if ((s = accept(fd, (struct sockaddr *)&sa, &salen)) < 0) {
                fprintf(stderr, "accept: %s\n", strerror(errno));
                return;
	}
	evutil_format_sockaddr_port(&sa, st->remote, sizeof(st->remote));
	evutil_make_socket_nonblocking(s);
	printf("Accepted: %s on %d\n", st->remote, s);

	/* Prepare device-facing side */
	ssl = SSL_new(ssl_ctx);
	st->bev_device = bufferevent_openssl_socket_new(ev_base, s, ssl,
	    BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(st->bev_device, device_read, NULL, event, st);
	bufferevent_set_timeouts(st->bev_device, &tv, NULL);

	/* Prepare Exchange-facing side */
	ssl = SSL_new(ssl_ctx2);
	st->bev_webmail = bufferevent_openssl_socket_new(ev_base, -1, ssl,
	    BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(st->bev_webmail, webmail_read, NULL, event, st);
	bufferevent_set_timeouts(st->bev_webmail, &tv, NULL);

	rc = bufferevent_socket_connect_hostname(st->bev_webmail, dns,
	    AF_INET, "webmail.cxnet.dk", 443);
	if (rc < 0) {
                fprintf(stderr, "socket_connect: %s\n", strerror(errno));
	}

	sprintf(fn, "/tmp/%s.device.txt", st->remote);
	st->fp_device = fopen(fn, "a");
	sprintf(fn, "/tmp/%s.webmail.txt", st->remote);
	st->fp_webmail = fopen(fn, "a");

	bufferevent_enable(st->bev_device, EV_READ);
	bufferevent_enable(st->bev_webmail, EV_READ);
}

int main(int argc, char **argv)
{

	struct event *ev;
	struct sockaddr_in sa;
	int one;
	int s;
	int rc;

        /* Prepare network communication */
        if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
                fprintf(stderr, "socket: %s\n", strerror(errno));
                return (1);
        }
	one = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one)) < 0) {
                fprintf(stderr, "setsockopt: %s\n", strerror(errno));
                return (1);
	}
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons(2002);
        if (INADDR_ANY) sa.sin_addr.s_addr = INADDR_ANY;
        if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
                fprintf(stderr, "bind: %s\n", strerror(errno));
                return (1);
        }
	if (listen(s, 5) < 0) {
                fprintf(stderr, "listen: %s\n", strerror(errno));
                return (1);
	}

        SSL_library_init();
        ssl_ctx = SSL_CTX_new(SSLv23_method());
        ssl_ctx2 = SSL_CTX_new(SSLv3_method());

        rc = SSL_CTX_use_certificate_file(ssl_ctx, "host.cert", SSL_FILETYPE_PEM);
        if (rc != 1) {
                 errx(EXIT_FAILURE, "Could not load certificate file");
        }
        rc = SSL_CTX_use_PrivateKey_file(ssl_ctx, "host.key", SSL_FILETYPE_PEM);
        if (rc != 1) {
                 errx(EXIT_FAILURE, "Could not load private key file");
        }
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify(ssl_ctx2, SSL_VERIFY_NONE, NULL);

	seq = 0;
	event_init();
        ev_base = event_base_new();
        dns = evdns_base_new(ev_base, 1);

        if (evutil_make_socket_nonblocking(s) < 0 ) {
                fprintf(stderr, "evutil_make_socket_nonblocking: %s\n", strerror(errno));
                return (1);
	}
	ev = event_new(ev_base, s, EV_READ|EV_PERSIST, accept_new, NULL);
	event_add(ev, NULL);

	printf("fd: %d\n", s);
	printf("Method: %d\n", event_get_method());
	event_base_dispatch(ev_base);
	
	return 0;
}
