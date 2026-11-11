/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/sys/fdtable.h>

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

static int configure(int s, const struct ret_tcp_opts *opts)
{
	struct zsock_timeval tv = {
		.tv_sec = opts->send_timeout_ms / 1000,
		.tv_usec = (opts->send_timeout_ms % 1000) * 1000,
	};
	int err = set_opt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv), "SO_SNDTIMEO");
	int on = 1;
	int idle = opts->keepalive_idle_s;
	int intvl = opts->keepalive_interval_s;
	int cnt = opts->keepalive_count;

	if (!opts->keepalive) {
		return err;
	}
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
	return err;
}

int ret_tcp_resolve(const char *host, uint16_t port, struct ret_tcp_addrs *out)
{
	struct zsock_addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	struct zsock_addrinfo *res = NULL;
	char port_str[6];
	int err;

	snprintf(port_str, sizeof(port_str), "%u", port);
	err = zsock_getaddrinfo(host, port_str, &hints, &res);
	if (err) {
		LOG_WRN("getaddrinfo(%s) failed: %d", host, err);
		return -EHOSTUNREACH;
	}

	out->count = 0;
	for (struct zsock_addrinfo *ai = res; ai != NULL && out->count < RET_TCP_MAX_ADDRS;
	     ai = ai->ai_next) {
		if (ai->ai_addrlen > sizeof(out->addr[0])) {
			continue;
		}
		out->family[out->count] = ai->ai_family;
		out->len[out->count] = ai->ai_addrlen;
		memcpy(&out->addr[out->count], ai->ai_addr, ai->ai_addrlen);
		out->count++;
	}
	zsock_freeaddrinfo(res);
	return out->count > 0 ? 0 : -EHOSTUNREACH;
}

static int set_nonblocking(int s, bool on)
{
	int flags = zsock_fcntl(s, ZVFS_F_GETFL, 0);

	if (flags < 0) {
		return -errno;
	}
	flags = on ? (flags | ZVFS_O_NONBLOCK) : (flags & ~ZVFS_O_NONBLOCK);
	return zsock_fcntl(s, ZVFS_F_SETFL, flags) < 0 ? -errno : 0;
}

int ret_tcp_connect_start(const struct ret_tcp_addrs *addrs, int i,
			  const struct ret_tcp_opts *opts, bool *in_progress)
{
	int s = zsock_socket(addrs->family[i], SOCK_STREAM, IPPROTO_TCP);
	int err;

	if (s < 0) {
		return -errno;
	}
	err = configure(s, opts);
	if (!err) {
		err = set_nonblocking(s, true);
	}
	if (err) {
		zsock_close(s);
		return err;
	}

	*in_progress = false;
	if (zsock_connect(s, (const struct sockaddr *)&addrs->addr[i], addrs->len[i]) == 0) {
		err = set_nonblocking(s, false);
		if (err) {
			zsock_close(s);
			return err;
		}
		return s;
	}
	if (errno == EINPROGRESS) {
		*in_progress = true;
		return s;
	}
	err = -errno;
	zsock_close(s);
	return err;
}

int ret_tcp_connect_finish(int fd)
{
	int so_err = 0;
	socklen_t len = sizeof(so_err);

	if (zsock_getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0) {
		return -errno;
	}
	if (so_err != 0) {
		return -so_err;
	}
	return set_nonblocking(fd, false);
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
