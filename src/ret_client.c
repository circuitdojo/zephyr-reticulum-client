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

/* A connection up this long counts as healthy for backoff purposes. */
#define STABLE_CONNECTION_MS (10 * MSEC_PER_SEC)

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

/* A send waiting for a path to its destination. */
struct held_send {
	bool used;
	int64_t deadline_ms;
	int64_t next_request_ms;
	struct send_req req;
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
	/** Valid packets received on the current connection. */
	uint32_t rx_packets;
	int64_t last_rx_ms;
	int consecutive_timeouts;
	/** Set from inside frame handling when a send broke the connection. */
	bool conn_broken;
	struct held_send held[CONFIG_RET_MAX_HELD_SENDS];
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

static void release_held(struct ret_client *c, const uint8_t dest_hash[RET_TRUNC_HASH_LEN]);

static void handle_announce(struct ret_client *c, const struct ret_packet *pkt)
{
	struct ret_announce a;
	const struct ret_destination *d;
	bool fresh;
	int err;

	err = ret_announce_validate(pkt, &a);
	if (err) {
		LOG_WRN("announce for %02x%02x%02x%02x.. rejected: %d", pkt->dest_hash[0],
			pkt->dest_hash[1], pkt->dest_hash[2], pkt->dest_hash[3], err);
		return;
	}

	err = ret_destinations_update(pkt, &a, k_uptime_get(), &d, &fresh);
	if (err) {
		LOG_WRN("announce rejected: public key changed for known destination");
		return;
	}

	/* Any announce that (re)validated the path releases waiting sends,
	 * including a repeat of one already seen.
	 */
	if (d->path_valid) {
		release_held(c, d->dest_hash);
	}

	if (!fresh) {
		/* Same announce again, e.g. rebroadcast plus path response. */
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
	c->rx_packets++;

	LOG_DBG("rx type %u hdr %u hops %u ctx 0x%02x len %zu", pkt.packet_type,
		pkt.header_type + 1, pkt.hops, pkt.context, pkt.data_len);

	switch (pkt.packet_type) {
	case RET_PKT_ANNOUNCE:
		handle_announce(c, &pkt);
		break;
	case RET_PKT_PROOF: {
		uint8_t proved[RET_TRUNC_HASH_LEN];

		err = ret_receipts_handle_proof(&pkt, k_uptime_get(), proved);
		if (err == 0) {
			c->consecutive_timeouts = 0;
			ret_destinations_mark_proves(proved);
		} else if (err == -EBADMSG) {
			LOG_WRN("invalid proof for pending packet");
		}
		break;
	}
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

static int send_frame(struct ret_client *c, size_t raw_len)
{
	int flen = ret_hdlc_encode(c->tx_raw, raw_len, c->tx_frame, sizeof(c->tx_frame));
	int err;

	if (flen < 0) {
		return flen;
	}
	err = ret_tcp_send_all(c->sock, c->tx_frame, (size_t)flen);
	if (err) {
		LOG_WRN("send failed: %d", err);
		return -ECONNRESET;
	}
	return 0;
}

static int send_path_request(struct ret_client *c, const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	uint8_t tag[RET_PATH_REQUEST_TAG_LEN];
	int len;
	int err;

	err = ret_random(tag, sizeof(tag));
	if (err) {
		return err;
	}
	len = ret_path_request_build(dest_hash, tag, c->tx_raw, sizeof(c->tx_raw));
	if (len < 0) {
		return len;
	}
	err = send_frame(c, (size_t)len);
	if (!err) {
		LOG_INF("path request for %02x%02x%02x%02x..", dest_hash[0], dest_hash[1],
			dest_hash[2], dest_hash[3]);
	}
	return err;
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

	if (d == NULL || !d->path_valid) {
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

	if (ret_receipts_full()) {
		LOG_WRN("receipt table full");
		return -ENOMEM;
	}

	err = send_frame(c, (size_t)len);
	if (err) {
		return err;
	}

	/* Registering after the send is safe: proofs are only read by this
	 * thread, after transmit() returns. RTT is measured from here.
	 */
	err = ret_receipts_add(hash, &d->pub[RET_X25519_LEN], d->dest_hash, d->proves,
			       k_uptime_get(), CONFIG_RET_RECEIPT_TIMEOUT_MS, r->cb, r->user);
	if (err) {
		return err; /* not reachable: checked above, same thread */
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

static void free_held(struct held_send *h, enum ret_receipt_status status, bool notify)
{
	if (notify) {
		fail_req(&h->req, status);
	}
	ret_wipe(&h->req, sizeof(h->req));
	h->used = false;
}

/** Hold @p r until a path to its destination arrives. */
static int hold(struct ret_client *c, const struct send_req *r)
{
	int64_t now = k_uptime_get();
	struct held_send *slot = NULL;
	int64_t next_request = now;

	for (size_t i = 0; i < ARRAY_SIZE(c->held); i++) {
		struct held_send *h = &c->held[i];

		if (!h->used) {
			slot = slot != NULL ? slot : h;
		} else if (memcmp(h->req.dest_hash, r->dest_hash, RET_DEST_HASH_LEN) == 0) {
			/* A request for this destination is already scheduled. */
			next_request = h->next_request_ms;
		}
	}
	if (slot == NULL) {
		LOG_WRN("no slot to hold a send while its path is requested");
		return -ENOMEM;
	}

	slot->used = true;
	slot->req = *r;
	slot->deadline_ms = now + CONFIG_RET_PATH_REQUEST_TIMEOUT_MS;
	slot->next_request_ms = next_request;
	return 0;
}

/**
 * Fail held sends past their deadline and, when connected, send the path
 * requests that are due (one per destination).
 *
 * @return false if the connection must be dropped.
 */
static bool service_held(struct ret_client *c)
{
	int64_t now = k_uptime_get();
	bool connected = c->state == RET_STATE_CONNECTED;

	for (size_t i = 0; i < ARRAY_SIZE(c->held); i++) {
		struct held_send *h = &c->held[i];

		if (!h->used) {
			continue;
		}
		if (h->deadline_ms <= now) {
			LOG_WRN("no path to %02x%02x%02x%02x.. in time", h->req.dest_hash[0],
				h->req.dest_hash[1], h->req.dest_hash[2], h->req.dest_hash[3]);
			free_held(h, RET_RECEIPT_FAILED, true);
			continue;
		}
		if (!connected || h->next_request_ms > now) {
			continue;
		}

		int err = send_path_request(c, h->req.dest_hash);

		if (err == -ECONNRESET) {
			return false;
		}
		/* Reschedule every send held for this destination. */
		for (size_t j = 0; j < ARRAY_SIZE(c->held); j++) {
			if (c->held[j].used && memcmp(c->held[j].req.dest_hash, h->req.dest_hash,
						      RET_DEST_HASH_LEN) == 0) {
				c->held[j].next_request_ms = now + CONFIG_RET_PATH_REQUEST_INTERVAL_MS;
			}
		}
	}
	return true;
}

static int64_t held_next_event(const struct ret_client *c)
{
	int64_t next = INT64_MAX;

	for (size_t i = 0; i < ARRAY_SIZE(c->held); i++) {
		const struct held_send *h = &c->held[i];

		if (h->used) {
			next = MIN(next, h->deadline_ms);
			if (c->state == RET_STATE_CONNECTED) {
				next = MIN(next, h->next_request_ms);
			}
		}
	}
	return next;
}

static void release_held(struct ret_client *c, const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(c->held); i++) {
		struct held_send *h = &c->held[i];
		int err;

		if (!h->used || memcmp(h->req.dest_hash, dest_hash, RET_DEST_HASH_LEN) != 0) {
			continue;
		}
		err = c->conn_broken ? -ECONNRESET : transmit(c, &h->req);
		free_held(h, RET_RECEIPT_FAILED, err != 0);
		if (err == -ECONNRESET) {
			c->conn_broken = true;
		}
	}
}

/** @return false if the connection must be dropped. */
static bool process_queue(struct ret_client *c)
{
	while (k_msgq_get(&ret_send_q, &c->req, K_NO_WAIT) == 0) {
		int err;

		if (c->state != RET_STATE_CONNECTED) {
			err = -ENOTCONN;
		} else {
			err = transmit(c, &c->req);
			if (err == -ENOENT) {
				/* No current path: hold it and ask for one. */
				err = hold(c, &c->req);
			}
		}
		if (err) {
			fail_req(&c->req, RET_RECEIPT_FAILED);
		}
		ret_wipe(c->req.data, sizeof(c->req.data));
		if (err == -ECONNRESET) {
			/* The eventfd was drained already: re-arm it so requests
			 * still queued are failed by backoff() rather than stranded.
			 */
			(void)zvfs_eventfd_write(c->efd, 1);
			return false;
		}
	}
	return service_held(c);
}

static void disconnect(struct ret_client *c)
{
	if (c->sock >= 0) {
		zsock_close(c->sock);
		c->sock = -1;
	}
	ret_hdlc_decoder_reset(&c->hdlc);
	ret_receipts_fail_all(RET_RECEIPT_DISCONNECTED, k_uptime_get());

	/* Held sends survive until their deadline; ask again on reconnect. */
	for (size_t i = 0; i < ARRAY_SIZE(c->held); i++) {
		c->held[i].next_request_ms = 0;
	}
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

static int64_t silence_deadline(const struct ret_client *c)
{
	if (CONFIG_RET_RX_SILENCE_TIMEOUT_S == 0) {
		return INT64_MAX;
	}
	return c->last_rx_ms + (int64_t)CONFIG_RET_RX_SILENCE_TIMEOUT_S * MSEC_PER_SEC;
}

/** @return true if a watchdog decided the connection is dead. */
static bool watchdog(struct ret_client *c)
{
	int64_t now = k_uptime_get();

	c->consecutive_timeouts += ret_receipts_expire(now);
	if (CONFIG_RET_RECONNECT_AFTER_TIMEOUTS > 0 &&
	    c->consecutive_timeouts >= CONFIG_RET_RECONNECT_AFTER_TIMEOUTS) {
		LOG_WRN("%d receipts in a row timed out, reconnecting", c->consecutive_timeouts);
		c->consecutive_timeouts = 0;
		return true;
	}
	if (now >= silence_deadline(c)) {
		LOG_WRN("nothing received for %d s, reconnecting", CONFIG_RET_RX_SILENCE_TIMEOUT_S);
		return true;
	}
	return false;
}

static void run_connected(struct ret_client *c)
{
	struct zsock_pollfd fds[2] = {
		{ .fd = c->sock, .events = ZSOCK_POLLIN },
		{ .fd = c->efd, .events = ZSOCK_POLLIN },
	};

	c->last_rx_ms = k_uptime_get();
	c->conn_broken = false;
	c->consecutive_timeouts = 0;

	/* Paths learned on an earlier connection are stale (rnsd may have
	 * restarted with a new transport ID); held sends re-request them.
	 */
	ret_destinations_invalidate_paths();
	if (!service_held(c)) {
		return;
	}

	for (;;) {
		int64_t next = MIN(MIN(ret_receipts_next_deadline(), held_next_event(c)),
				   silence_deadline(c));
		int n = zsock_poll(fds, ARRAY_SIZE(fds), poll_timeout_ms(next));

		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
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
			c->last_rx_ms = k_uptime_get();
			ret_hdlc_feed(&c->hdlc, c->rx_chunk, (size_t)r, on_frame, c);
			if (c->conn_broken) {
				return;
			}
		}

		if (fds[1].revents & ZSOCK_POLLIN) {
			drain_eventfd(c);
			if (!process_queue(c)) {
				return;
			}
		}

		if (!service_held(c) || watchdog(c)) {
			return;
		}
	}
}

/** Sleep for @p ms while failing any sends queued meanwhile. */
static void backoff(struct ret_client *c, int ms)
{
	struct zsock_pollfd pfd = { .fd = c->efd, .events = ZSOCK_POLLIN };
	int64_t until = k_uptime_get() + ms;

	while (k_uptime_get() < until) {
		int64_t next = MIN(until, held_next_event(c));

		if (zsock_poll(&pfd, 1, poll_timeout_ms(next)) > 0) {
			drain_eventfd(c);
			(void)process_queue(c);
		}
		(void)service_held(c);
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

		c->rx_packets = 0;
		int64_t connected_at = k_uptime_get();

		set_state(c, RET_STATE_CONNECTED);
		run_connected(c);
		disconnect(c);
		set_state(c, RET_STATE_RECONNECTING);

		/* Only a connection that was established for real resets the
		 * backoff (it received packets or stayed up), so a server that
		 * accepts and immediately closes is not hammered.
		 */
		if (c->rx_packets > 0 ||
		    k_uptime_get() - connected_at >= STABLE_CONNECTION_MS) {
			delay_s = 1;
		}
		LOG_INF("reconnecting in %d s", delay_s);
		backoff(c, delay_s * MSEC_PER_SEC);
		delay_s = MIN(delay_s * 2, CONFIG_RET_RECONNECT_BACKOFF_MAX_S);
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
	int err;

	if (!c->started) {
		return -ENOTCONN;
	}
	if (len > RET_MAX_PAYLOAD) {
		return -EMSGSIZE;
	}

	memcpy(r.dest_hash, dest_hash, RET_DEST_HASH_LEN);
	memcpy(r.data, data, len);
	err = k_msgq_put(&ret_send_q, &r, K_NO_WAIT);
	ret_wipe(r.data, len);
	if (err != 0) {
		return -EAGAIN;
	}
	(void)zvfs_eventfd_write(c->efd, 1);
	return 0;
}

int ret_client_name_hash(const char *full_name, uint8_t out[10])
{
	int err = ret_crypto_init();

	return err ? err : ret_name_hash(full_name, out);
}

enum ret_client_state ret_client_state(const struct ret_client *c)
{
	return c->state;
}
