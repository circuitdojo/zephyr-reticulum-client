/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Client thread: one TCP connection to rnsd, polled together with an
 * eventfd that wakes the loop when the application queues a send. All
 * protocol state (HDLC decoder, destinations, receipts) is owned by this
 * thread.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/zvfs/eventfd.h>

#include <ret/ret_client.h>

#include "ret_announce.h"
#include "ret_crypto.h"
#include "ret_destinations.h"
#include "ret_hdlc.h"
#include "ret_identity.h"
#include "ret_packet.h"
#include "ret_receipt.h"
#include "ret_tcp.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

BUILD_ASSERT(RET_MAX_PAYLOAD == RET_ENCRYPTED_MDU);
BUILD_ASSERT(RET_DEST_HASH_LEN == RET_TRUNC_HASH_LEN);
BUILD_ASSERT(RET_PACKET_HASH_LEN == RET_HASH_LEN);

struct send_req {
	uint8_t dest_hash[RET_DEST_HASH_LEN];
	uint16_t len;
	uint8_t data[RET_MAX_PAYLOAD];
	ret_receipt_cb_t cb;
	void *user;
};

struct ret_client {
	struct ret_client_config cfg;
	const char *host;
	uint16_t port;
	enum ret_client_state state;
	bool started;
	int sock;
	int efd;
	struct ret_hdlc_decoder hdlc;
	uint8_t rx_frame[RET_MTU];
	uint8_t rx_chunk[256];
	uint8_t tx_raw[RET_MTU];
	uint8_t tx_frame[RET_HDLC_MAX_ENCODED(RET_MTU)];
	struct send_req req;
};

K_MSGQ_DEFINE(ret_send_q, sizeof(struct send_req), CONFIG_RET_TX_QUEUE_DEPTH, 4);
K_THREAD_STACK_DEFINE(ret_stack, CONFIG_RET_THREAD_STACK_SIZE);

static struct ret_client client = {
	.sock = -1,
	.efd = -1,
};
static struct k_thread ret_thread;

static const char *state_str(enum ret_client_state s)
{
	switch (s) {
	case RET_STATE_DISCONNECTED:
		return "DISCONNECTED";
	case RET_STATE_CONNECTING:
		return "CONNECTING";
	case RET_STATE_CONNECTED:
		return "CONNECTED";
	case RET_STATE_RECONNECTING:
		return "RECONNECTING";
	}
	return "?";
}

static void set_state(struct ret_client *c, enum ret_client_state s)
{
	if (c->state == s) {
		return;
	}
	LOG_INF("state %s -> %s", state_str(c->state), state_str(s));
	c->state = s;
	if (c->cfg.on_state != NULL) {
		c->cfg.on_state(s, c->cfg.user);
	}
}

static void handle_announce(struct ret_client *c, const struct ret_packet *pkt)
{
	struct ret_announce a;
	const struct ret_destination *d;
	int err;

	err = ret_announce_validate(pkt, &a);
	if (err) {
		LOG_WRN("announce for %02x%02x%02x%02x.. rejected: %d", pkt->dest_hash[0],
			pkt->dest_hash[1], pkt->dest_hash[2], pkt->dest_hash[3], err);
		return;
	}

	err = ret_destinations_update(pkt, &a, k_uptime_get(), &d);
	if (err) {
		LOG_WRN("announce rejected: public key changed for known destination");
		return;
	}

	LOG_DBG("announce valid, hops %u%s%s", d->hops, d->has_ratchet ? ", ratchet" : "",
		d->has_transport_id ? ", via transport" : "");
	LOG_HEXDUMP_DBG(d->dest_hash, RET_TRUNC_HASH_LEN, "dest");

	if (c->cfg.on_announce != NULL) {
		struct ret_announce_info info = {
			.hops = d->hops,
			.has_ratchet = d->has_ratchet,
			.app_data = a.app_data,
			.app_data_len = a.app_data_len,
		};

		memcpy(info.dest_hash, d->dest_hash, RET_TRUNC_HASH_LEN);
		memcpy(info.identity_hash, d->identity_hash, RET_TRUNC_HASH_LEN);
		memcpy(info.name_hash, d->name_hash, RET_NAME_HASH_LEN);
		c->cfg.on_announce(&info, c->cfg.user);
	}
}

static void on_frame(const uint8_t *frame, size_t len, void *user)
{
	struct ret_client *c = user;
	struct ret_packet pkt;
	int err;

	err = ret_packet_unpack(frame, len, &pkt);
	if (err) {
		LOG_DBG("dropping %zu byte frame: %d", len, err);
		return;
	}

	LOG_DBG("rx type %u hdr %u hops %u ctx 0x%02x len %zu", pkt.packet_type,
		pkt.header_type + 1, pkt.hops, pkt.context, pkt.data_len);

	switch (pkt.packet_type) {
	case RET_PKT_ANNOUNCE:
		handle_announce(c, &pkt);
		break;
	case RET_PKT_PROOF:
		err = ret_receipts_handle_proof(&pkt, k_uptime_get());
		if (err == -EBADMSG) {
			LOG_WRN("invalid proof for pending packet");
		}
		break;
	default:
		/* No local destinations yet: DATA and link traffic is not for us. */
		break;
	}
}

static void fail_req(const struct send_req *r, enum ret_receipt_status status)
{
	static const uint8_t zero_hash[RET_HASH_LEN];

	if (r->cb != NULL) {
		r->cb(zero_hash, status, 0, r->user);
	}
}

static int transmit(struct ret_client *c, const struct send_req *r)
{
	const struct ret_destination *d = ret_destinations_find(r->dest_hash);
	uint8_t token[RET_TOKEN_LEN(RET_MAX_PAYLOAD)];
	uint8_t hash[RET_HASH_LEN];
	struct ret_packet pkt = {
		.dest_type = RET_DEST_SINGLE,
		.packet_type = RET_PKT_DATA,
		.context = RET_CONTEXT_NONE,
	};
	int len;
	int err;

	if (d == NULL) {
		LOG_WRN("send to unknown destination");
		return -ENOENT;
	}

	len = ret_identity_encrypt(d->has_ratchet ? d->ratchet : d->pub, d->identity_hash,
				   r->data, r->len, token, sizeof(token));
	if (len < 0) {
		LOG_ERR("encrypt failed: %d", len);
		return len;
	}

	ret_destinations_address(d, &pkt);
	pkt.data = token;
	pkt.data_len = (size_t)len;

	len = ret_packet_pack(&pkt, c->tx_raw, sizeof(c->tx_raw));
	if (len < 0) {
		return len;
	}
	err = ret_packet_hash(c->tx_raw, (size_t)len, hash);
	if (err) {
		return err;
	}

	int flen = ret_hdlc_encode(c->tx_raw, (size_t)len, c->tx_frame, sizeof(c->tx_frame));

	if (flen < 0) {
		return flen;
	}

	/* Register before sending so a fast proof cannot beat the receipt. */
	err = ret_receipts_add(hash, &d->pub[RET_X25519_LEN], k_uptime_get(),
			       CONFIG_RET_RECEIPT_TIMEOUT_MS, r->cb, r->user);
	if (err) {
		LOG_WRN("receipt table full");
		return err;
	}

	err = ret_tcp_send_all(c->sock, c->tx_frame, (size_t)flen);
	if (err) {
		/* The receipt will be failed with the rest on disconnect. */
		LOG_WRN("send failed: %d", err);
		return -ECONNRESET;
	}

	LOG_DBG("tx DATA %d bytes, hdr %u", len, pkt.header_type + 1);
	LOG_HEXDUMP_DBG(hash, RET_HASH_LEN, "packet hash");
	return 0;
}

static void drain_eventfd(struct ret_client *c)
{
	zvfs_eventfd_t v;

	(void)zvfs_eventfd_read(c->efd, &v);
}

/** @return false if the connection must be dropped. */
static bool process_queue(struct ret_client *c)
{
	while (k_msgq_get(&ret_send_q, &c->req, K_NO_WAIT) == 0) {
		int err;

		if (c->state != RET_STATE_CONNECTED) {
			fail_req(&c->req, RET_RECEIPT_FAILED);
			continue;
		}
		err = transmit(c, &c->req);
		if (err == -ECONNRESET) {
			return false;
		}
		if (err) {
			fail_req(&c->req, RET_RECEIPT_FAILED);
		}
	}
	return true;
}

static void disconnect(struct ret_client *c)
{
	if (c->sock >= 0) {
		zsock_close(c->sock);
		c->sock = -1;
	}
	ret_hdlc_decoder_reset(&c->hdlc);
	ret_receipts_fail_all(RET_RECEIPT_DISCONNECTED, k_uptime_get());
}

static int poll_timeout_ms(int64_t until_ms)
{
	int64_t now = k_uptime_get();

	if (until_ms == INT64_MAX) {
		return -1;
	}
	if (until_ms <= now) {
		return 0;
	}
	return (int)MIN(until_ms - now, INT32_MAX);
}

static void run_connected(struct ret_client *c)
{
	struct zsock_pollfd fds[2] = {
		{ .fd = c->sock, .events = ZSOCK_POLLIN },
		{ .fd = c->efd, .events = ZSOCK_POLLIN },
	};

	for (;;) {
		int n = zsock_poll(fds, ARRAY_SIZE(fds), poll_timeout_ms(ret_receipts_next_deadline()));

		if (n < 0) {
			LOG_ERR("poll failed: %d", errno);
			return;
		}

		if (fds[0].revents & (ZSOCK_POLLERR | ZSOCK_POLLNVAL)) {
			LOG_WRN("socket error");
			return;
		}
		if (fds[0].revents & (ZSOCK_POLLIN | ZSOCK_POLLHUP)) {
			ssize_t r = zsock_recv(c->sock, c->rx_chunk, sizeof(c->rx_chunk), 0);

			if (r <= 0) {
				LOG_WRN("connection closed (%d)", r < 0 ? -errno : 0);
				return;
			}
			ret_hdlc_feed(&c->hdlc, c->rx_chunk, (size_t)r, on_frame, c);
		}

		if (fds[1].revents & ZSOCK_POLLIN) {
			drain_eventfd(c);
			if (!process_queue(c)) {
				return;
			}
		}

		ret_receipts_expire(k_uptime_get());
	}
}

/** Sleep for @p ms while failing any sends queued meanwhile. */
static void backoff(struct ret_client *c, int ms)
{
	struct zsock_pollfd pfd = { .fd = c->efd, .events = ZSOCK_POLLIN };
	int64_t until = k_uptime_get() + ms;

	while (k_uptime_get() < until) {
		if (zsock_poll(&pfd, 1, poll_timeout_ms(until)) > 0) {
			drain_eventfd(c);
			(void)process_queue(c);
		}
	}
}

static void client_thread(void *p1, void *p2, void *p3)
{
	struct ret_client *c = p1;
	int delay_s = 1;

	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	for (;;) {
		set_state(c, c->state == RET_STATE_DISCONNECTED ? RET_STATE_CONNECTING
								 : RET_STATE_RECONNECTING);
		LOG_INF("connecting to %s:%u", c->host, c->port);

		c->sock = ret_tcp_connect(c->host, c->port);
		if (c->sock < 0) {
			LOG_WRN("connect failed: %d, retry in %d s", c->sock, delay_s);
			c->sock = -1;
			backoff(c, delay_s * MSEC_PER_SEC);
			delay_s = MIN(delay_s * 2, CONFIG_RET_RECONNECT_BACKOFF_MAX_S);
			continue;
		}

		delay_s = 1;
		set_state(c, RET_STATE_CONNECTED);
		run_connected(c);
		disconnect(c);
		set_state(c, RET_STATE_RECONNECTING);
		backoff(c, MSEC_PER_SEC);
	}
}

struct ret_client *ret_client_create(const struct ret_client_config *cfg)
{
	if (client.started) {
		return &client;
	}
	if (cfg != NULL) {
		client.cfg = *cfg;
	}
	client.host = client.cfg.host != NULL ? client.cfg.host : CONFIG_RET_SERVER_HOST;
	client.port = client.cfg.port != 0 ? client.cfg.port : CONFIG_RET_SERVER_PORT;
	client.state = RET_STATE_DISCONNECTED;
	return &client;
}

int ret_client_start(struct ret_client *c)
{
	int err;

	if (c->started) {
		return -EALREADY;
	}

	err = ret_crypto_init();
	if (err) {
		return err;
	}

	c->efd = zvfs_eventfd(0, ZVFS_EFD_NONBLOCK);
	if (c->efd < 0) {
		LOG_ERR("eventfd failed: %d", errno);
		return -errno;
	}

	ret_hdlc_decoder_init(&c->hdlc, c->rx_frame, sizeof(c->rx_frame));
	ret_destinations_clear();
	ret_receipts_clear();

	k_thread_create(&ret_thread, ret_stack, K_THREAD_STACK_SIZEOF(ret_stack), client_thread,
			c, NULL, NULL, CONFIG_RET_THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&ret_thread, "ret_client");
	c->started = true;
	return 0;
}

int ret_client_send(struct ret_client *c, const uint8_t dest_hash[RET_DEST_HASH_LEN],
		    const uint8_t *data, size_t len, ret_receipt_cb_t cb, void *user)
{
	struct send_req r = {
		.len = (uint16_t)len,
		.cb = cb,
		.user = user,
	};

	if (!c->started) {
		return -ENOTCONN;
	}
	if (len > RET_MAX_PAYLOAD) {
		return -EMSGSIZE;
	}

	memcpy(r.dest_hash, dest_hash, RET_DEST_HASH_LEN);
	memcpy(r.data, data, len);
	if (k_msgq_put(&ret_send_q, &r, K_NO_WAIT) != 0) {
		return -EAGAIN;
	}
	(void)zvfs_eventfd_write(c->efd, 1);
	return 0;
}

int ret_client_name_hash(const char *full_name, uint8_t out[10])
{
	return ret_name_hash(full_name, out);
}

enum ret_client_state ret_client_state(const struct ret_client *c)
{
	return c->state;
}
