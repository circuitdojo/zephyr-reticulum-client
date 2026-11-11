/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * The uplink: an HDLC-framed TCP connection to a stock rnsd
 * TCPServerInterface, as RNS's TCPClientInterface makes. This thread
 * connects (with backoff), reads and posts frames; the transport thread
 * sends through uplink_send().
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>

#include "gateway.h"
#include "ret_crypto.h"
#include "ret_hdlc.h"
#include "ret_tcp.h"

LOG_MODULE_REGISTER(uplink, LOG_LEVEL_INF);

BUILD_ASSERT(sizeof(CONFIG_RET_GATEWAY_HOST) > 1,
	     "set CONFIG_RET_GATEWAY_HOST (see env/example.conf)");

#define STACK_SIZE         3072
#define CONNECT_TIMEOUT_MS 15000
#define SEND_TIMEOUT_MS    10000
/* A connection that lasted this long resets the backoff. */
#define STABLE_MS          60000

static K_THREAD_STACK_DEFINE(stack, STACK_SIZE);
static struct k_thread thread;

static K_MUTEX_DEFINE(lock);
static int sock = -1;
static uint8_t tx_buf[RET_HDLC_MAX_ENCODED(RET_TRANSPORT_FRAME_MAX)];

static const struct ret_tcp_opts tcp_opts = {
	.send_timeout_ms = SEND_TIMEOUT_MS,
#if defined(CONFIG_NET_NATIVE_OFFLOADED_SOCKETS)
	/* A dead connection is otherwise only noticed when a send stalls. */
	.keepalive = true,
	.keepalive_idle_s = 60,
	.keepalive_interval_s = 10,
	.keepalive_count = 3,
#endif
};

void uplink_iface_hash(uint8_t hash[RET_HASH_LEN])
{
	char name[96];
	int n = snprintf(name, sizeof(name), "TCPInterface[RET uplink/%s:%d]",
			 CONFIG_RET_GATEWAY_HOST, CONFIG_RET_GATEWAY_PORT);
	const struct ret_iov iov = { name, (size_t)MIN(n, (int)sizeof(name) - 1) };

	(void)ret_sha256(&iov, 1, hash);
}

int uplink_send(const uint8_t *frame, size_t len)
{
	int err = -ENOTCONN;
	int n;

	k_mutex_lock(&lock, K_FOREVER);
	if (sock >= 0) {
		n = ret_hdlc_encode(frame, len, tx_buf, sizeof(tx_buf));
		err = n < 0 ? n : ret_tcp_send_all(sock, tx_buf, (size_t)n);
		if (err) {
			/* The reader sees the connection end and reconnects. */
			LOG_WRN("uplink send failed: %d", err);
			zsock_shutdown(sock, ZSOCK_SHUT_RDWR);
		}
	}
	k_mutex_unlock(&lock);
	return err;
}

static int connect_hub(void)
{
	static struct ret_tcp_addrs addrs;
	int err = ret_tcp_resolve(CONFIG_RET_GATEWAY_HOST, CONFIG_RET_GATEWAY_PORT, &addrs);

	if (err) {
		return err;
	}
	for (int i = 0; i < addrs.count; i++) {
		bool in_progress;
		int fd = ret_tcp_connect_start(&addrs, i, &tcp_opts, &in_progress);

		if (fd < 0) {
			err = fd;
			continue;
		}
		if (in_progress) {
			struct zsock_pollfd pfd = { .fd = fd, .events = ZSOCK_POLLOUT };
			int ready = zsock_poll(&pfd, 1, CONNECT_TIMEOUT_MS);

			err = ready == 1 ? ret_tcp_connect_finish(fd) : -ETIMEDOUT;
			if (err) {
				zsock_close(fd);
				continue;
			}
		}
		return fd;
	}
	return err;
}

static void on_frame(const uint8_t *frame, size_t len, void *user)
{
	ARG_UNUSED(user);
	(void)gw_post(GW_FRAME_UPLINK, frame, len, K_FOREVER);
}

static void serve(int fd)
{
	static uint8_t chunk[256];
	static uint8_t frame[RET_TRANSPORT_FRAME_MAX];
	static struct ret_hdlc_decoder decoder;

	ret_hdlc_decoder_init(&decoder, frame, sizeof(frame));
	for (;;) {
		ssize_t n = zsock_recv(fd, chunk, sizeof(chunk), 0);

		if (n > 0) {
			ret_hdlc_feed(&decoder, chunk, (size_t)n, on_frame, NULL);
		} else if (n == 0 || errno != EINTR) {
			return;
		}
	}
}

static void uplink_thread(void *a, void *b, void *c)
{
	uint32_t backoff_s = 1;

	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	for (;;) {
		int fd = connect_hub();
		int64_t up_at;

		if (fd < 0) {
			LOG_WRN("uplink connect failed: %d, retrying in %u s", fd, backoff_s);
			k_sleep(K_SECONDS(backoff_s));
			backoff_s = MIN(backoff_s * 2, CONFIG_RET_GATEWAY_RECONNECT_MAX_S);
			continue;
		}
		k_mutex_lock(&lock, K_FOREVER);
		sock = fd;
		k_mutex_unlock(&lock);
		LOG_INF("uplink connected to %s:%d", CONFIG_RET_GATEWAY_HOST,
			CONFIG_RET_GATEWAY_PORT);
		up_at = k_uptime_get();
		(void)gw_post(GW_UPLINK_UP, NULL, 0, K_FOREVER);

		serve(fd);

		(void)gw_post(GW_UPLINK_DOWN, NULL, 0, K_FOREVER);
		k_mutex_lock(&lock, K_FOREVER);
		sock = -1;
		zsock_close(fd);
		k_mutex_unlock(&lock);
		if (k_uptime_get() - up_at >= STABLE_MS) {
			backoff_s = 1;
		}
		LOG_WRN("uplink down, reconnecting in %u s", backoff_s);
		k_sleep(K_SECONDS(backoff_s));
		backoff_s = MIN(backoff_s * 2, CONFIG_RET_GATEWAY_RECONNECT_MAX_S);
	}
}

int uplink_start(void)
{
	k_thread_create(&thread, stack, K_THREAD_STACK_SIZEOF(stack), uplink_thread, NULL, NULL,
			NULL, K_PRIO_PREEMPT(8), 0, K_NO_WAIT);
	k_thread_name_set(&thread, "uplink");
	return 0;
}
