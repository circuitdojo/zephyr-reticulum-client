/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>

#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>

#include "ret_tcp.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

int ret_tcp_connect(const char *host, uint16_t port)
{
	struct zsock_addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	struct zsock_addrinfo *res = NULL;
	char port_str[6];
	int fd = -EHOSTUNREACH;
	int err;

	snprintf(port_str, sizeof(port_str), "%u", port);
	err = zsock_getaddrinfo(host, port_str, &hints, &res);
	if (err) {
		LOG_WRN("getaddrinfo(%s) failed: %d", host, err);
		return -EHOSTUNREACH;
	}

	for (struct zsock_addrinfo *ai = res; ai != NULL; ai = ai->ai_next) {
		int s = zsock_socket(ai->ai_family, ai->ai_socktype, IPPROTO_TCP);

		if (s < 0) {
			fd = -errno;
			continue;
		}
		if (zsock_connect(s, ai->ai_addr, ai->ai_addrlen) == 0) {
			fd = s;
			break;
		}
		fd = -errno;
		zsock_close(s);
	}

	zsock_freeaddrinfo(res);
	return fd;
}

int ret_tcp_send_all(int fd, const uint8_t *buf, size_t len)
{
	size_t sent = 0;

	while (sent < len) {
		ssize_t n = zsock_send(fd, &buf[sent], len - sent, 0);

		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			}
			return -errno;
		}
		sent += (size_t)n;
	}
	return 0;
}
