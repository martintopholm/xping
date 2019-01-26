/*
 * Usage:
 *     gcc unreach.c  -fPIC -shared  -o libunreach.so
 */
#include <sys/socket.h>
#include <errno.h>

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

	errno = ENETUNREACH;
	return -1;
}
