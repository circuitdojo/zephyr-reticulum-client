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

static int set_opt(int s, int level, int name, const void *val, socklen_t len, const char *what)
{
	if (zsock_setsockopt(s, level, name, val, len) < 0) {
		int err = -errno;

		LOG_ERR("setsockopt %s failed: %d", what, err);
		return err;
	}
	return 0;
}

static int configure(int s)
{
	struct zsock_timeval tv = {
		.tv_sec = CONFIG_RET_SEND_TIMEOUT_MS / 1000,
		.tv_usec = (CONFIG_RET_SEND_TIMEOUT_MS % 1000) * 1000,
	};
	int err = set_opt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv), "SO_SNDTIMEO");

#if defined(CONFIG_RET_TCP_KEEPALIVE)
	int on = 1;
	int idle = CONFIG_RET_TCP_KEEPALIVE_IDLE_S;
	int intvl = CONFIG_RET_TCP_KEEPALIVE_INTERVAL_S;
	int cnt = CONFIG_RET_TCP_KEEPALIVE_COUNT;

	if (!err) {
		err = set_opt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on), "SO_KEEPALIVE");
	}
	if (!err) {
		err = set_opt(s, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle), "TCP_KEEPIDLE");
	}
	if (!err) {
		err = set_opt(s, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl),
			      "TCP_KEEPINTVL");
	}
	if (!err) {
		err = set_opt(s, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt), "TCP_KEEPCNT");
	}
#endif
	return err;
}

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
		err = configure(s);
		if (err) {
			zsock_close(s);
			fd = err;
			break;
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
			if (errno == EINTR) {
				continue;
			}
			/* The socket is blocking: EAGAIN means SO_SNDTIMEO fired. */
			return (errno == EAGAIN || errno == EWOULDBLOCK) ? -ETIMEDOUT : -errno;
		}
		sent += (size_t)n;
	}
	return 0;
}
