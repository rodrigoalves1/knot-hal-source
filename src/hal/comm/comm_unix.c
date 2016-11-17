/*
 * Copyright (c) 2016, CESAR.
 * All rights reserved.
 *
 * This software may be modified and distributed under the terms
 * of the BSD license. See the LICENSE file for details.
 *
 */

#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <include/comm.h>

#define THING_TO_NRFD_UNIX_SOCKET	":thing:nrfd"

static int probe_unix(const char *spi, uint8_t tx_pwr)
{
	return 0;
}

static void remove_unix(void)
{
}

static int hal_comm_init(const char *pathname)
{
	struct sockaddr_un addr;
	int err, sock;

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -errno;

	/* Represents unix socket from thing to nrfd */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path + 1, THING_TO_NRFD_UNIX_SOCKET,
					strlen(THING_TO_NRFD_UNIX_SOCKET));
	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		err = -errno;
		return err;
	}

	return sock;
}

static int hal_comm_listen(int sockfd)
{
	int err;

	if (listen(sockfd, 1) == -1) {
		err = -errno;
		return err;
	}

	return sockfd;
}

static int hal_comm_connect(int sockfd, uint64_t *to_addr)
{
	struct sockaddr_un addr;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path + 1, THING_TO_NRFD_UNIX_SOCKET,
					strlen(THING_TO_NRFD_UNIX_SOCKET));

	if (connect(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == -1)
		return -errno;

	return sockfd;
}

static int hal_comm_accept(int sockfd, uint64_t *to_addr)
{
	return accept(sockfd, NULL, NULL);
}

static ssize_t recv_unix(int sock, void *buffer, size_t len)
{
	return read(sock, buffer, len);
}

static ssize_t send_unix(int sock, const void *buffer, size_t len)
{
	return write(sock, buffer, len);
}

static void close_unix(int sock)
{
	close(sock);
}
