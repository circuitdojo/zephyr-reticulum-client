/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RET_TCP_H_
#define RET_TCP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/net/socket.h>

#define RET_TCP_MAX_ADDRS 4

struct ret_tcp_addrs {
	int count;
	int family[RET_TCP_MAX_ADDRS];
	socklen_t len[RET_TCP_MAX_ADDRS];
	struct sockaddr_storage addr[RET_TCP_MAX_ADDRS];
};

/**
 * Resolve @p host to up to RET_TCP_MAX_ADDRS addresses, in resolver
 * order. Blocks for the DNS lookup.
 */
int ret_tcp_resolve(const char *host, uint16_t port, struct ret_tcp_addrs *out);

/**
 * Open a TCP socket with the configured send timeout and keepalive and
 * start a non-blocking connect to address @p i of @p addrs. A socket
 * option the stack rejects fails the attempt rather than being skipped.
 *
 * @param in_progress set when the connect is still pending: wait for
 *                    POLLOUT, then call ret_tcp_connect_finish()
 * @return fd, or -errno
 */
int ret_tcp_connect_start(const struct ret_tcp_addrs *addrs, int i, bool *in_progress);

/** Complete a connect (SO_ERROR) and switch the socket back to blocking. */
int ret_tcp_connect_finish(int fd);

/** Send all of @p buf, retrying partial writes. */
int ret_tcp_send_all(int fd, const uint8_t *buf, size_t len);

#endif /* RET_TCP_H_ */
