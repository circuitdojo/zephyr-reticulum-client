/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Link driver, run on the client thread. The packet formats live in
 * ret_link.c.
 *
 * The client opens at most one link itself (struct link_out, initiator):
 *
 *   NONE -> WAIT_PATH (no current path: path request) -> PENDING
 *   (LINKREQUEST sent) -> ACTIVE (proof valid, RTT sent) <-> STALE
 *   -> NONE (closed, failed, or the connection dropped)
 *
 * Other nodes may open links to the client's destination (struct link in[],
 * responder), as RNS's Link.validate_request() does:
 *
 *   LINKREQUEST -> HANDSHAKE (proof sent) -> ACTIVE (initiator's RTT
 *   received) <-> STALE -> NONE
 *
 * What every link shares (sending, closing, stale timers, receiving a
 * Resource) works on struct link, whichever side opened it.
 *
 * One Resource (ret_resource.c) at a time uses the client's buffers: one
 * arriving on any link (a response too large for one packet, or data,
 * LXMF DIRECT, too large for one packet on an inbound link), or one we
 * send on the outbound link (LXMF DIRECT). The outbound link also carries
 * single packets whose proof is awaited; one such send is in flight at a
 * time.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/__assert.h>

#include "ret_client_internal.h"
#include "ret_crypto.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

/* Link.py: establishment timeout per hop, and the grace after going stale
 * (rtt * KEEPALIVE_TIMEOUT_FACTOR + STALE_GRACE).
 */
#define ESTABLISH_PER_HOP_MS 6000
#define STALE_FACTOR         4
#define STALE_GRACE_MS       5000
/* Link.request: rtt * 6 + 10 * 1.125 s. */
#define REQUEST_TIMEOUT_EXTRA_MS 11250
/* Resource.py receiver watchdog: retries, and the wait for the sender
 * (rtt * PART_TIMEOUT_FACTOR + RETRY_GRACE_TIME + PER_RETRY_DELAY per retry
 * used). The extra second covers a window of parts in flight, which RNS
 * estimates from the measured rate.
 */
#define RESOURCE_MAX_RETRIES     16
#define RESOURCE_TIMEOUT_FACTOR  4
#define RESOURCE_GRACE_MS        1250
#define RESOURCE_PER_RETRY_MS    500
/* Link.validate_request: establishment timeout per hop + KEEPALIVE (360 s). */
#define IN_ESTABLISH_EXTRA_MS 360000
/* However parts trickle in, one resource holds the buffers at most this
 * long: a peer must not keep them (and so the sync and other senders) for
 * as long as it likes.
 */
#define RESOURCE_MAX_MS 180000
/* A link still in handshake is only replaced once it is this old: fresh
 * link requests must not evict a real handshake still waiting for its RTT.
 */
#define IN_EVICT_MIN_AGE_MS 10000
/* PacketReceipt on a link: rtt * TRAFFIC_TIMEOUT_FACTOR. The grace covers
 * the receiver's own work (RNS's floor is 5 ms).
 */
#define TRAFFIC_TIMEOUT_FACTOR 6
#define PACKET_PROOF_GRACE_MS  1000
/* Resource.py, sending: advertisement retries (each waits rtt *
 * TRAFFIC_TIMEOUT_FACTOR + PROCESSING_GRACE), the wait for part requests
 * (rtt * factor * MAX_RETRIES + SENDER_GRACE_TIME + the receiver's retry
 * delays, sum((r + 1) * 0.5 s) over 16 retries = 68 s), and the proof wait
 * (rtt * PROOF_TIMEOUT_FACTOR + SENDER_GRACE_TIME), 3 times.
 */
#define TX_MAX_ADV_RETRIES   4
#define TX_PROCESSING_GRACE_MS 1000
#define TX_SENDER_GRACE_MS   10000
#define TX_RETRY_DELAYS_MS   68000
#define TX_PROOF_TIMEOUT_FACTOR 3
#define TX_PROOF_RETRIES     3
/* Fresh random hashes tried when map hashes collide (Resource remaps
 * until they do not; a collision among 18 parts is already ~1e-8).
 */
#define TX_REMAP_TRIES 8

static struct link_out *link_out_of(struct link *l)
{
	__ASSERT(l->role == LINK_OUT, "not the outbound link");
	return CONTAINER_OF(l, struct link_out, l);
}

static bool link_up(const struct link *l)
{
	return l->state == LINK_ACTIVE || l->state == LINK_STALE;
}

static void request_done(struct link_request *q, int err, const uint8_t *resp, size_t len)
{
	ret_link_response_cb_t cb = q->cb;
	void *user = q->user;

	q->used = false;
	q->receiving = false;
	if (cb != NULL) {
		cb(err, resp, len, user);
	}
}

/* Forget the incoming resource; returns the request it was answering. */
static struct link_request *resource_end(struct ret_client *c)
{
	struct link_resource *res = &c->res;
	struct link_request *q = res->req;

	res->state = RES_IDLE;
	res->link = NULL;
	res->req = NULL;
	ret_wipe(res->plain, sizeof(res->plain));
	return q;
}

/* The outbound link's send is over: report @p status once. */
static void send_done(struct ret_client *c, struct link_out *o, int status)
{
	link_sent_cb_t cb = o->sent_cb;
	uint32_t rtt = (uint32_t)MAX(0, k_uptime_get() - o->send_ms);

	if (o->send == OUT_SEND_NONE) {
		return;
	}
	if (o->send == OUT_SEND_RESOURCE && c->res.state == RES_SENDING) {
		(void)resource_end(c);
	}
	o->send = OUT_SEND_NONE;
	o->sent_cb = NULL;
	if (cb != NULL) {
		cb(c, status, rtt);
	}
}

/* End link @p l: its resource, its requests (outbound), its key. */
static void link_end(struct ret_client *c, struct link *l, enum ret_link_event ev, int reason)
{
	ret_link_cb_t cb = NULL;
	void *user = NULL;

	if (c->res.state != RES_IDLE && c->res.link == l) {
		(void)resource_end(c);
	}
	if (l->role == LINK_OUT) {
		struct link_out *o = link_out_of(l);

		/* A send in flight fails first: its owner learns the link went
		 * before the link callback says so.
		 */
		send_done(c, o, -ECONNRESET);

		for (size_t i = 0; i < ARRAY_SIZE(o->req); i++) {
			if (o->req[i].used) {
				request_done(&o->req[i], -ECONNRESET, NULL, 0);
			}
		}
		ret_wipe(&o->keys, sizeof(o->keys));
		cb = o->cb;
		user = o->user;
		o->cb = NULL;
	}
	ret_wipe(l->key, sizeof(l->key));
	l->state = LINK_NONE;
	if (cb != NULL) {
		cb(ev, reason, user);
	}
}

/* Send the link packet of length @p n (or error) built in c->tx_raw. */
static int send_built(struct ret_client *c, struct link *l, int n, uint8_t hash_out[RET_HASH_LEN])
{
	int err;

	if (n < 0) {
		return n;
	}
	if (hash_out != NULL) {
		err = ret_packet_hash(c->tx_raw, (size_t)n, hash_out);
		if (err) {
			return err;
		}
	}
	err = ret_client_send_frame(c, (size_t)n);
	if (err == -ECONNRESET) {
		c->conn_broken = true;
	} else if (!err) {
		l->last_tx_ms = k_uptime_get();
	}
	return err;
}

/* Encrypt (with the link key) and send one link packet. */
static int send_link(struct ret_client *c, struct link *l, uint8_t context, const uint8_t *pt,
		     size_t len, bool encrypt, uint8_t hash_out[RET_HASH_LEN])
{
	return send_built(c, l,
			  ret_link_packet_build(l->id, encrypt ? l->key : NULL, context, pt, len,
						c->tx_raw, sizeof(c->tx_raw)),
			  hash_out);
}

/* LINKCLOSE (it carries the link_id, encrypted), then end the link. */
static void link_close(struct ret_client *c, struct link *l, enum ret_link_event ev, int reason)
{
	(void)send_link(c, l, RET_CTX_LINKCLOSE, l->id, RET_TRUNC_HASH_LEN, true, NULL);
	link_end(c, l, ev, reason);
}

/* --- Outbound link (initiator) --------------------------------------- */

static void send_link_request(struct ret_client *c, const struct ret_destination *d)
{
	struct link_out *o = &c->out;
	struct link *l = &o->l;
	uint8_t data[RET_LINK_REQUEST_LEN];
	struct ret_packet pkt = {
		.dest_type = RET_DEST_SINGLE,
		.packet_type = RET_PKT_LINKREQUEST,
		.context = RET_CONTEXT_NONE,
		.data = data,
		.data_len = sizeof(data),
	};
	int n;
	int err;

	err = ret_link_keys_generate(&o->keys);
	if (err) {
		link_end(c, l, RET_LINK_EVT_FAILED, err);
		return;
	}
	ret_link_request_data(&o->keys, data);
	memcpy(o->dest_sig_pub, &d->pub[RET_X25519_LEN], RET_ED25519_PUB_LEN);
	ret_destinations_address(d, &pkt);

	n = ret_packet_pack(&pkt, c->tx_raw, sizeof(c->tx_raw));
	err = n < 0 ? n : ret_link_id_from_request(c->tx_raw, (size_t)n, l->id);
	if (!err) {
		err = ret_client_send_frame(c, (size_t)n);
	}
	if (err) {
		if (err == -ECONNRESET) {
			c->conn_broken = true;
		}
		link_end(c, l, RET_LINK_EVT_FAILED, err);
		return;
	}

	l->state = LINK_PENDING;
	l->opened_ms = k_uptime_get();
	l->last_tx_ms = l->opened_ms;
	l->deadline_ms = l->opened_ms + ESTABLISH_PER_HOP_MS +
			 (int64_t)ESTABLISH_PER_HOP_MS * MAX(1, d->hops);
	LOG_INF("link request to %02x%02x%02x%02x.. (link %02x%02x%02x%02x..)", d->dest_hash[0],
		d->dest_hash[1], d->dest_hash[2], d->dest_hash[3], l->id[0], l->id[1], l->id[2],
		l->id[3]);
}

void ret_link_drv_open(struct ret_client *c, const struct send_req *r)
{
	struct link_out *o = &c->out;
	const struct ret_destination *d;

	if (o->l.state != LINK_NONE) {
		if (r->link_cb != NULL) {
			r->link_cb(RET_LINK_EVT_FAILED, -EBUSY, r->user);
		}
		return;
	}

	memset(o, 0, sizeof(*o));
	o->l.role = LINK_OUT;
	memcpy(o->dest, r->dest_hash, RET_TRUNC_HASH_LEN);
	o->cb = r->link_cb;
	o->user = r->user;

	d = ret_destinations_find(o->dest);
	if (d != NULL && d->path_valid) {
		send_link_request(c, d);
		return;
	}

	/* No keys or no current path: ask for one; the announce in reply
	 * continues in ret_link_drv_on_path().
	 */
	o->l.state = LINK_WAIT_PATH;
	o->l.deadline_ms = k_uptime_get() + CONFIG_RET_PATH_REQUEST_TIMEOUT_MS;
	o->next_path_request_ms = 0;
}

void ret_link_drv_on_path(struct ret_client *c, const struct ret_destination *d)
{
	struct link_out *o = &c->out;

	if (o->l.state == LINK_WAIT_PATH &&
	    memcmp(o->dest, d->dest_hash, RET_TRUNC_HASH_LEN) == 0) {
		send_link_request(c, d);
	}
}

static void on_proof(struct ret_client *c, struct link_out *o, const struct ret_packet *pkt)
{
	struct link *l = &o->l;
	uint8_t plain[16];
	uint16_t mtu;
	int64_t now = k_uptime_get();
	int n;
	int err;

	if (l->state != LINK_PENDING) {
		return;
	}
	err = ret_link_proof_validate(l->id, o->dest_sig_pub, &o->keys, pkt, l->key, &mtu);
	if (err == -EBADMSG) {
		/* Anyone who saw the cleartext link request knows the link_id:
		 * an unauthenticated proof must not end the handshake. Keep
		 * waiting until the establishment deadline, as RNS does.
		 */
		LOG_WRN("ignoring invalid link proof");
		return;
	}
	if (err) {
		LOG_WRN("link proof for an unsupported mode");
		link_end(c, l, RET_LINK_EVT_FAILED, err);
		return;
	}
	/* The ephemeral private keys only served to derive the link key. */
	ret_wipe(&o->keys, sizeof(o->keys));

	if (mtu != RET_MTU) {
		/* A transport clamped it below 500 (or the peer confirmed
		 * something we never signalled): requests are sized for 500.
		 */
		LOG_WRN("link MTU %u not supported", mtu);
		link_end(c, l, RET_LINK_EVT_FAILED, -EMSGSIZE);
		return;
	}

	l->rtt_ms = (uint32_t)MAX(1, now - l->opened_ms);
	l->keepalive_ms = ret_link_keepalive_ms(l->rtt_ms);
	l->last_rx_ms = now;
	o->last_keepalive_ms = now;

	/* The responder ignores requests until it has the RTT. */
	n = ret_link_rtt_plain((double)l->rtt_ms / 1000.0, plain, sizeof(plain));
	err = n < 0 ? n : send_link(c, l, RET_CTX_LRRTT, plain, (size_t)n, true, NULL);
	if (err) {
		link_end(c, l, RET_LINK_EVT_FAILED, err);
		return;
	}

	l->state = LINK_ACTIVE;
	LOG_INF("link active, rtt %u ms", l->rtt_ms);
	if (o->cb != NULL) {
		o->cb(RET_LINK_EVT_ACTIVE, 0, o->user);
	}
}

static void on_response(struct link_out *o, const uint8_t *plain, size_t len)
{
	uint8_t id[RET_TRUNC_HASH_LEN];
	const uint8_t *resp;
	size_t resp_len;

	if (ret_link_response_parse(plain, len, id, &resp, &resp_len) != 0) {
		LOG_WRN("malformed link response");
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(o->req); i++) {
		struct link_request *q = &o->req[i];

		if (q->used && !q->receiving && memcmp(q->id, id, RET_TRUNC_HASH_LEN) == 0) {
			request_done(q, 0, resp, resp_len);
			return;
		}
	}
	LOG_DBG("response for an unknown request");
}

/* --- Resources ------------------------------------------------------- */

/* Refuse a resource on @p l (RESOURCE_RCL carries its hash). */
static void send_rcl(struct ret_client *c, struct link *l, const uint8_t h[RET_SHA256_LEN])
{
	(void)send_link(c, l, RET_CTX_RESOURCE_RCL, h, RET_SHA256_LEN, true, NULL);
}

static void resource_touch(struct ret_client *c)
{
	struct link_resource *res = &c->res;

	res->deadline_ms = k_uptime_get() +
			   (int64_t)res->link->rtt_ms * RESOURCE_TIMEOUT_FACTOR + RESOURCE_GRACE_MS +
			   (int64_t)(RESOURCE_MAX_RETRIES - res->retries) * RESOURCE_PER_RETRY_MS;
}

static void resource_request(struct ret_client *c)
{
	struct link_resource *res = &c->res;
	uint8_t buf[1 + RET_RESOURCE_MAPHASH_LEN + RET_SHA256_LEN +
		    RET_RESOURCE_WINDOW_MAX * RET_RESOURCE_MAPHASH_LEN];
	int n = ret_resource_rx_request(&res->rx, buf, sizeof(buf));

	if (n > 0) {
		(void)send_link(c, res->link, RET_CTX_RESOURCE_REQ, buf, (size_t)n, true, NULL);
	}
	resource_touch(c);
}

/* Give up on the resource; a response's request fails with @p err.
 * A delivery is not refused (RCL makes LXMF reject the message for good)
 * when it failed in transit: its link is closed instead, so the sender
 * retries.
 */
static void resource_fail(struct ret_client *c, int err, bool refuse)
{
	struct link_request *q;
	struct link *l = c->res.link;

	if (c->res.purpose == RES_DELIVERY) {
		(void)resource_end(c);
		link_close(c, l, RET_LINK_EVT_CLOSED, err);
		return;
	}
	if (refuse) {
		send_rcl(c, l, c->res.rx.h);
	}
	q = resource_end(c);
	if (q != NULL) {
		request_done(q, err, NULL, 0);
	}
}

/* Start receiving @p adv on @p l. @return 0, or the reason it was refused. */
static int resource_start(struct ret_client *c, struct link *l, const struct ret_resource_adv *adv,
			  enum res_purpose purpose, struct link_request *q)
{
	struct link_resource *res = &c->res;
	int err = ret_resource_rx_init(&res->rx, adv, res->stream, sizeof(res->stream));

	if (err) {
		return err;
	}
	res->state = RES_RECEIVING;
	res->purpose = purpose;
	res->link = l;
	res->req = q;
	res->retries = RESOURCE_MAX_RETRIES;
	res->give_up_ms = k_uptime_get() + RESOURCE_MAX_MS;
	if (q != NULL) {
		q->receiving = true;
	}
	resource_request(c);
	return 0;
}

/* An advertisement on the outbound link: a response to one of its requests. */
static void on_response_adv(struct ret_client *c, struct link_out *o,
			    const struct ret_resource_adv *adv)
{
	struct link_resource *res = &c->res;
	struct link_request *q = NULL;
	int err;

	if (adv->q != NULL) {
		for (size_t i = 0; i < ARRAY_SIZE(o->req); i++) {
			if (o->req[i].used && !o->req[i].receiving &&
			    memcmp(o->req[i].id, adv->q, RET_TRUNC_HASH_LEN) == 0) {
				q = &o->req[i];
				break;
			}
		}
	}
	if (q == NULL) {
		LOG_WRN("refusing unsolicited resource");
		send_rcl(c, &o->l, adv->h);
		return;
	}
	if (res->state != RES_IDLE || !(adv->f & RET_RESOURCE_F_RESPONSE)) {
		/* For a pending request, but not receivable: fail it now rather
		 * than leave it to its deadline.
		 */
		LOG_WRN("refusing response resource: %s",
			res->state != RES_IDLE ? "another one is arriving"
					       : "not marked as a response");
		send_rcl(c, &o->l, adv->h);
		request_done(q, res->state != RES_IDLE ? -EBUSY : -EBADMSG, NULL, 0);
		return;
	}

	err = resource_start(c, &o->l, adv, RES_RESPONSE, q);
	if (err) {
		LOG_WRN("refusing response resource (%u bytes, flags 0x%02x): %d",
			(uint32_t)adv->t, (uint32_t)adv->f, err);
		send_rcl(c, &o->l, adv->h);
		request_done(q, err, NULL, 0);
		return;
	}
	LOG_INF("receiving response: %u bytes in %u parts", res->rx.t, res->rx.n);
}

static void on_resource_adv(struct ret_client *c, struct link *l, const uint8_t *plain, size_t len)
{
	struct link_resource *res = &c->res;
	struct ret_resource_adv adv;

	if (ret_resource_adv_parse(plain, len, &adv) != 0) {
		LOG_WRN("malformed resource advertisement");
		return;
	}
	if (res->state == RES_RECEIVING && res->link == l &&
	    memcmp(res->rx.h, adv.h, RET_SHA256_LEN) == 0) {
		/* Advertised again: the sender never saw our request. */
		resource_request(c);
		return;
	}
	if (l->role == LINK_OUT) {
		on_response_adv(c, link_out_of(l), &adv);
		return;
	}

	/* An inbound link: data sent to us, as LXMF DIRECT sends a packed
	 * message too large for one packet.
	 */
	if (adv.q != NULL || (adv.f & (RET_RESOURCE_F_REQUEST | RET_RESOURCE_F_RESPONSE))) {
		LOG_WRN("refusing request/response resource on an inbound link");
		send_rcl(c, l, adv.h);
		return;
	}
	if (c->cfg.on_lxmf == NULL) {
		LOG_WRN("refusing resource on an inbound link: no LXMF");
		send_rcl(c, l, adv.h);
		return;
	}
	if (res->state != RES_IDLE) {
		/* RESOURCE_RCL makes LXMF reject the message for good; a closed
		 * link makes it retry later.
		 */
		LOG_WRN("resource buffers busy: closing the inbound link so the sender retries");
		link_close(c, l, RET_LINK_EVT_CLOSED, -EBUSY);
		return;
	}

	int err = resource_start(c, l, &adv, RES_DELIVERY, NULL);

	if (err) {
		/* Too large or compressed: it can never be received. */
		LOG_WRN("refusing delivery resource (%u bytes, flags 0x%02x): %d", (uint32_t)adv.t,
			(uint32_t)adv.f, err);
		send_rcl(c, l, adv.h);
		return;
	}
	LOG_INF("receiving delivery: %u bytes in %u parts", res->rx.t, res->rx.n);
}

static void resource_complete(struct ret_client *c)
{
	struct link_resource *res = &c->res;
	struct link *l = res->link;
	struct link_request *q;
	uint8_t proof[RET_RESOURCE_PROOF_LEN];
	uint8_t id[RET_TRUNC_HASH_LEN];
	const uint8_t *resp;
	size_t resp_len;
	int n;
	int err;

	n = ret_resource_rx_assemble(&res->rx, l->key, res->plain, sizeof(res->plain));
	if (n < 0) {
		LOG_WRN("resource corrupt: %d", n);
		resource_fail(c, n, true); /* RCL: the sender stops waiting for a proof */
		return;
	}
	res->state = RES_DELIVERING;

	/* Prove it whatever it holds: the sender is done either way. */
	err = ret_resource_proof(&res->rx, res->plain, (size_t)n, proof);
	if (!err) {
		err = send_built(c, l,
				 ret_link_resource_proof_build(l->id, proof, c->tx_raw,
							       sizeof(c->tx_raw)),
				 NULL);
	}
	if (err) {
		LOG_WRN("resource proof not sent: %d", err);
	}

	if (res->purpose == RES_DELIVERY) {
		LOG_INF("delivery resource complete: %u bytes", (uint32_t)n);
		ret_client_on_link_data(c, res->plain, (size_t)n);
		(void)resource_end(c);
		return;
	}

	q = res->req;
	err = ret_link_response_parse(res->plain, (size_t)n, id, &resp, &resp_len);
	if (err || memcmp(id, q->id, RET_TRUNC_HASH_LEN) != 0) {
		LOG_WRN("malformed response resource");
		request_done(resource_end(c), -EBADMSG, NULL, 0);
		return;
	}
	LOG_INF("response resource complete: %u bytes", (uint32_t)n);
	/* resp points into res->plain: deliver, then wipe. */
	request_done(q, 0, resp, resp_len);
	(void)resource_end(c);
}

static void on_resource_part(struct ret_client *c, struct link *l, const uint8_t *data, size_t len)
{
	struct link_resource *res = &c->res;

	if (res->state != RES_RECEIVING || res->link != l) {
		return;
	}
	switch (ret_resource_rx_part(&res->rx, data, len)) {
	case RET_RESOURCE_PART_IGNORED:
		return;
	case RET_RESOURCE_PART_ACCEPTED:
		res->retries = RESOURCE_MAX_RETRIES;
		resource_touch(c);
		return;
	case RET_RESOURCE_PART_WINDOW:
		res->retries = RESOURCE_MAX_RETRIES;
		if (res->rx.waiting_hmu) {
			resource_touch(c); /* the hashmap update triggers the next request */
		} else {
			resource_request(c);
		}
		return;
	case RET_RESOURCE_PART_COMPLETE:
		resource_complete(c);
		return;
	}
}

static void on_resource_hmu(struct ret_client *c, struct link *l, const uint8_t *plain, size_t len)
{
	struct link_resource *res = &c->res;

	if (res->state != RES_RECEIVING || res->link != l || len < RET_SHA256_LEN ||
	    memcmp(plain, res->rx.h, RET_SHA256_LEN) != 0) {
		return;
	}
	if (ret_resource_rx_hmu(&res->rx, plain, len) != 0) {
		LOG_WRN("bad hashmap update");
		return;
	}
	res->retries = RESOURCE_MAX_RETRIES;
	resource_request(c);
}

static void on_resource_icl(struct ret_client *c, struct link *l, const uint8_t *plain, size_t len)
{
	struct link_resource *res = &c->res;

	if (res->state == RES_RECEIVING && res->link == l && len == RET_SHA256_LEN &&
	    memcmp(plain, res->rx.h, RET_SHA256_LEN) == 0) {
		LOG_WRN("sender cancelled the resource");
		resource_fail(c, -ECANCELED, false);
	}
}

/* --- Sending on the outbound link ------------------------------------- */

int ret_link_drv_send_packet(struct ret_client *c, const uint8_t *data, size_t len,
			     link_sent_cb_t cb)
{
	struct link_out *o = &c->out;
	int err;

	if (!link_up(&o->l)) {
		return -ENOTCONN;
	}
	if (o->send != OUT_SEND_NONE) {
		return -EBUSY;
	}
	err = send_link(c, &o->l, RET_CONTEXT_NONE, data, len, true, o->send_hash);
	if (err) {
		return err;
	}
	o->send = OUT_SEND_PACKET;
	o->sent_cb = cb;
	o->send_ms = k_uptime_get();
	o->send_deadline_ms = o->send_ms + (int64_t)o->l.rtt_ms * TRAFFIC_TIMEOUT_FACTOR +
			      PACKET_PROOF_GRACE_MS;
	return 0;
}

static int send_adv(struct ret_client *c)
{
	struct link_resource *res = &c->res;
	uint8_t adv[RET_LINK_MDU];
	int n = ret_resource_tx_adv(&res->tx, adv, sizeof(adv));

	if (n < 0) {
		return n;
	}
	res->tx_adv_ms = k_uptime_get();
	res->tx_activity_ms = res->tx_adv_ms;
	return send_link(c, res->link, RET_CTX_RESOURCE_ADV, adv, (size_t)n, true, NULL);
}

int ret_link_drv_send_resource(struct ret_client *c, const uint8_t *data, size_t len,
			       link_sent_cb_t cb)
{
	struct link_out *o = &c->out;
	struct link_resource *res = &c->res;
	uint8_t iv[RET_AES_BLOCK_LEN];
	uint8_t prefix[RET_RESOURCE_RANDOM_LEN];
	uint8_t r[RET_RESOURCE_RANDOM_LEN];
	int err;

	if (!link_up(&o->l)) {
		return -ENOTCONN;
	}
	if (o->send != OUT_SEND_NONE || res->state != RES_IDLE) {
		return -EBUSY;
	}
	err = ret_random(iv, sizeof(iv));
	if (!err) {
		err = ret_random(prefix, sizeof(prefix));
	}
	if (!err) {
		err = ret_resource_tx_init(&res->tx, o->l.key, iv, prefix, data, len, res->stream,
					   sizeof(res->stream));
	}
	for (int i = 0; !err; i++) {
		err = ret_random(r, sizeof(r));
		if (!err) {
			err = ret_resource_tx_map(&res->tx, data, len, r);
		}
		if (err != -EAGAIN) {
			break;
		}
		if (i + 1 == TX_REMAP_TRIES) {
			err = -EIO;
		} else {
			err = 0;
		}
	}
	if (err) {
		return err;
	}

	res->state = RES_SENDING;
	res->link = &o->l;
	res->req = NULL;
	res->tx_phase = RES_TX_ADVERTISED;
	res->retries = TX_MAX_ADV_RETRIES;
	res->tx_rtt_ms = 0;
	res->give_up_ms = INT64_MAX;
	o->send = OUT_SEND_RESOURCE;
	o->sent_cb = cb;
	o->send_ms = k_uptime_get();
	err = send_adv(c);
	if (err) {
		o->send = OUT_SEND_NONE;
		o->sent_cb = NULL;
		(void)resource_end(c);
		return err;
	}
	LOG_INF("sending resource: %u bytes in %u parts", res->tx.d, res->tx.n);
	return 0;
}

/* Resource.cancel() on the sender: RESOURCE_ICL carries its hash. */
static void tx_cancel(struct ret_client *c, int status)
{
	(void)send_link(c, c->res.link, RET_CTX_RESOURCE_ICL, c->res.tx.h, RET_SHA256_LEN, true,
			NULL);
	send_done(c, &c->out, status);
}

static void tx_on_request(struct ret_client *c, const uint8_t *plain, size_t len)
{
	/* static: client thread only, and kept off its stack. */
	static struct ret_resource_tx_req req;
	struct link_resource *res = &c->res;
	int64_t now = k_uptime_get();
	int err;

	err = ret_resource_tx_request(&res->tx, plain, len, &req);
	if (err == -EBADMSG) {
		return; /* another resource's */
	}
	if (err) {
		LOG_WRN("resource request out of sequence: cancelled");
		tx_cancel(c, err);
		return;
	}
	if (res->tx_phase == RES_TX_ADVERTISED) {
		res->tx_rtt_ms = (uint32_t)MAX(1, now - res->tx_adv_ms);
	}
	res->tx_phase = RES_TX_TRANSFERRING;
	res->tx_activity_ms = now;

	for (size_t i = 0; i < req.n_parts; i++) {
		size_t plen;
		const uint8_t *part = ret_resource_tx_part(&res->tx, req.parts[i], &plen);

		/* A slice of the encrypted stream: no link token. */
		err = send_link(c, res->link, RET_CTX_RESOURCE, part, plen, false, NULL);
		if (err) {
			return; /* the connection is gone: teardown follows */
		}
		res->tx_last_part_ms = k_uptime_get();
	}
	if (req.hmu) {
		uint8_t hmu[RET_LINK_MDU];
		int n = ret_resource_tx_hmu(&res->tx, req.hmu_segment, hmu, sizeof(hmu));

		if (n < 0) {
			tx_cancel(c, -EPROTO);
			return;
		}
		if (send_link(c, res->link, RET_CTX_RESOURCE_HMU, hmu, (size_t)n, true, NULL)) {
			return;
		}
	}
	if (ret_resource_tx_all_sent(&res->tx)) {
		res->tx_phase = RES_TX_AWAITING_PROOF;
		res->retries = TX_PROOF_RETRIES;
		res->tx_last_part_ms = k_uptime_get();
	}
}

/* A PROOF on the outbound link: of our packet, or of our resource. */
static void out_on_proof(struct ret_client *c, struct link_out *o, const struct ret_packet *pkt)
{
	struct link_resource *res = &c->res;

	if (pkt->context == RET_CTX_RESOURCE_PRF) {
		if (o->send == OUT_SEND_RESOURCE && res->state == RES_SENDING &&
		    ret_resource_tx_proof_valid(&res->tx, pkt->data, pkt->data_len)) {
			LOG_INF("resource proved: %u bytes delivered", res->tx.d);
			send_done(c, o, 0);
		}
		return;
	}
	if (o->send != OUT_SEND_PACKET) {
		return;
	}
	switch (ret_link_packet_proof_validate(o->dest_sig_pub, o->l.id, o->send_hash, pkt)) {
	case 0:
		send_done(c, o, 0);
		break;
	case -EBADMSG:
		/* Anyone on the path can see the link_id: keep waiting. */
		LOG_WRN("invalid link packet proof: ignored");
		break;
	default:
		break;
	}
}

/* --- Packets for a link ----------------------------------------------- */

struct link *ret_link_drv_find(struct ret_client *c, const uint8_t id[RET_TRUNC_HASH_LEN])
{
	if (c->out.l.state != LINK_NONE && memcmp(c->out.l.id, id, RET_TRUNC_HASH_LEN) == 0) {
		return &c->out.l;
	}
#if CONFIG_RET_INBOUND_LINKS > 0
	for (size_t i = 0; i < ARRAY_SIZE(c->in); i++) {
		if (c->in[i].state != LINK_NONE &&
		    memcmp(c->in[i].id, id, RET_TRUNC_HASH_LEN) == 0) {
			return &c->in[i];
		}
	}
#endif
	return NULL;
}

/* --- Inbound links (responder) ---------------------------------------- */

void ret_link_drv_on_request(struct ret_client *c, const struct ret_packet *pkt,
			     const uint8_t *raw, size_t raw_len)
{
#if CONFIG_RET_INBOUND_LINKS == 0
	ARG_UNUSED(c);
	ARG_UNUSED(pkt);
	ARG_UNUSED(raw);
	ARG_UNUSED(raw_len);
	LOG_DBG("link request dropped: inbound links disabled");
#else
	struct ret_link_peer_request req;
	uint8_t id[RET_TRUNC_HASH_LEN];
	uint8_t prv[RET_X25519_LEN];
	uint8_t pub[RET_X25519_LEN];
	struct link *l = NULL;
	struct link *oldest = NULL;
	int64_t now = k_uptime_get();
	int err;

	err = ret_link_request_parse(pkt, &req);
	if (err) {
		LOG_WRN("link request refused: %s", err == -EPROTO ? "unsupported mode" : "malformed");
		return;
	}
	if (req.mtu == 0) {
		req.mtu = RET_MTU; /* Link.validate_request: "... or MTU" */
	}
	if (req.mtu < RET_MTU) {
		/* Resource parts are sized for 500 (SDU 464). */
		LOG_WRN("link request refused: MTU %u below %u", req.mtu, RET_MTU);
		return;
	}
	uint8_t hash[RET_HASH_LEN];

	if (ret_link_id_from_request(raw, raw_len, id) != 0 ||
	    ret_packet_hash(raw, raw_len, hash) != 0) {
		return;
	}
	/* A replayed request (RNS drops repeats in its packet filter), or one
	 * for a link already open.
	 */
	if (ret_client_seen_packet(c, hash) || ret_link_drv_find(c, id) != NULL) {
		LOG_DBG("repeated link request ignored");
		return;
	}
	ret_client_remember_packet(c, hash);

	for (size_t i = 0; i < ARRAY_SIZE(c->in); i++) {
		struct link *x = &c->in[i];

		if (x->state == LINK_NONE) {
			l = x;
			break;
		}
		if (x->state == LINK_HANDSHAKE && now - x->opened_ms >= IN_EVICT_MIN_AGE_MS &&
		    (oldest == NULL || x->opened_ms < oldest->opened_ms)) {
			oldest = x;
		}
	}
	if (l == NULL && oldest != NULL) {
		/* A replayed or spoofed request must not hold every slot. */
		LOG_WRN("inbound links full: replacing one still in handshake");
		link_end(c, oldest, RET_LINK_EVT_CLOSED, -ENOSPC);
		l = oldest;
	}
	if (l == NULL) {
		LOG_WRN("inbound links full: link request dropped");
		return;
	}

	memset(l, 0, sizeof(*l));
	l->role = LINK_IN;
	memcpy(l->id, id, sizeof(l->id));

	/* An ephemeral X25519 key: it only serves to derive the link key. */
	err = ret_random(prv, sizeof(prv));
	if (!err) {
		ret_x25519_public_key(pub, prv);
		err = ret_link_derive_key(prv, req.x25519_pub, id, l->key);
	}
	ret_wipe(prv, sizeof(prv));
	if (!err) {
		/* Confirm 500 whatever was signalled: the initiator adopts it. */
		err = send_built(c, l,
				 ret_link_proof_build(&c->id, id, pub, RET_MTU, c->tx_raw,
						      sizeof(c->tx_raw)),
				 NULL);
	}
	if (err) {
		LOG_WRN("link request not answered: %d", err);
		link_end(c, l, RET_LINK_EVT_FAILED, err);
		return;
	}

	/* Timed from the proof leaving, as RNS sets request_time after
	 * prove(): our own crypto time is not part of the round trip.
	 */
	now = k_uptime_get();
	l->state = LINK_HANDSHAKE;
	l->opened_ms = now;
	l->deadline_ms = now + (int64_t)ESTABLISH_PER_HOP_MS * MAX(1, pkt->hops + 1) +
			 IN_ESTABLISH_EXTRA_MS;
	LOG_INF("inbound link %02x%02x%02x%02x.. accepted", id[0], id[1], id[2], id[3]);
#endif
}

/*
 * HANDSHAKE: only the initiator's RTT (or a close) is taken. RNS would
 * process anything once the proof is out, but its initiator always sends
 * the RTT first and the path keeps order; this keeps resource and
 * keepalive timing from running without an RTT.
 */
static void in_handshake(struct ret_client *c, struct link *l, const struct ret_packet *pkt)
{
	int64_t now = k_uptime_get();
	uint32_t rtt_ms;
	int n;

	if (pkt->packet_type != RET_PKT_DATA ||
	    (pkt->context != RET_CTX_LRRTT && pkt->context != RET_CTX_LINKCLOSE)) {
		LOG_DBG("inbound link in handshake: context 0x%02x dropped", pkt->context);
		return;
	}
	n = ret_token_decrypt(l->key, pkt->data, pkt->data_len, c->rx_plain, sizeof(c->rx_plain));
	if (pkt->context == RET_CTX_LINKCLOSE) {
		if (n == RET_TRUNC_HASH_LEN && memcmp(c->rx_plain, l->id, RET_TRUNC_HASH_LEN) == 0) {
			LOG_INF("inbound link closed by peer");
			link_end(c, l, RET_LINK_EVT_CLOSED, 0);
		}
	} else if (n < 0) {
		/* Not from the initiator (anyone who saw the request knows the
		 * link_id): ignored, as Link.rtt_packet ignores what does not
		 * decrypt.
		 */
		LOG_WRN("undecryptable RTT on an inbound link: ignored");
	} else if (ret_link_rtt_parse(c->rx_plain, (size_t)n, &rtt_ms) != 0) {
		/* Link.rtt_packet tears the link down when unpacking fails. */
		LOG_WRN("bad RTT on an inbound link: closed");
		link_end(c, l, RET_LINK_EVT_FAILED, -EBADMSG);
	} else {
		l->rtt_ms = MAX(1U, MAX((uint32_t)(now - l->opened_ms), rtt_ms));
		l->keepalive_ms = ret_link_keepalive_ms(l->rtt_ms);
		l->last_rx_ms = now;
		l->state = LINK_ACTIVE;
		LOG_INF("inbound link %02x%02x%02x%02x.. active, rtt %u ms", l->id[0], l->id[1],
			l->id[2], l->id[3], l->rtt_ms);
	}
	if (n > 0) {
		ret_wipe(c->rx_plain, (size_t)n);
	}
}

/* DATA on an inbound link: deliver (once), then always prove, as RNS does
 * for a destination with PROVE_ALL.
 */
static void in_data(struct ret_client *c, struct link *l, const struct ret_packet *pkt,
		    const uint8_t *raw, size_t raw_len)
{
	uint8_t hash[RET_HASH_LEN];
	int n;

	if (ret_packet_hash(raw, raw_len, hash) != 0) {
		return;
	}
	if (ret_client_seen_packet(c, hash)) {
		LOG_DBG("repeated link packet, proving again");
	} else {
		n = ret_token_decrypt(l->key, pkt->data, pkt->data_len, c->rx_plain,
				      sizeof(c->rx_plain));
		if (n < 0) {
			LOG_WRN("undecryptable link packet: %d", n);
			return; /* only what decrypted earns a proof */
		}
		ret_client_remember_packet(c, hash);
		ret_client_on_link_data(c, c->rx_plain, (size_t)n);
		ret_wipe(c->rx_plain, (size_t)n);
		if (l->state == LINK_NONE || c->conn_broken) {
			return;
		}
	}
	(void)send_built(c, l,
			 ret_link_packet_proof_build(&c->id, l->id, hash, c->tx_raw,
						     sizeof(c->tx_raw)),
			 NULL);
}

void ret_link_drv_on_packet(struct ret_client *c, struct link *l, const struct ret_packet *pkt,
			    const uint8_t *raw, size_t raw_len)
{
	int n;

	if (l->role == LINK_OUT && pkt->packet_type == RET_PKT_PROOF &&
	    pkt->context == RET_CTX_LRPROOF) {
		on_proof(c, link_out_of(l), pkt);
		return;
	}
	if (l->state == LINK_HANDSHAKE) {
		in_handshake(c, l, pkt);
		return;
	}
	if (!link_up(l)) {
		return;
	}

	l->last_rx_ms = k_uptime_get();
	if (l->state == LINK_STALE) {
		l->state = LINK_ACTIVE;
	}

	if (pkt->packet_type == RET_PKT_PROOF) {
		/* Proofs of what we send: only the outbound link sends any. */
		if (l->role == LINK_OUT) {
			out_on_proof(c, link_out_of(l), pkt);
		}
		return;
	}
	if (pkt->packet_type != RET_PKT_DATA) {
		return;
	}

	switch (pkt->context) {
	case RET_CTX_KEEPALIVE:
		/* Unencrypted. The responder answers 0xFF with 0xFE when it
		 * sent nothing for a keepalive interval; the initiator ignores
		 * answers (any inbound already refreshed last_rx).
		 */
		if (l->role == LINK_IN && pkt->data_len == 1 && pkt->data[0] == 0xFF &&
		    k_uptime_get() >= l->last_tx_ms + l->keepalive_ms) {
			const uint8_t ka = 0xFE;

			(void)send_link(c, l, RET_CTX_KEEPALIVE, &ka, 1, false, NULL);
		}
		return;
	case RET_CONTEXT_NONE:
		if (l->role == LINK_IN) {
			in_data(c, l, pkt, raw, raw_len);
		}
		return;
	case RET_CTX_RESOURCE:
		/* A slice of the already encrypted stream: no link token. */
		on_resource_part(c, l, pkt->data, pkt->data_len);
		return;
	case RET_CTX_RESPONSE:
	case RET_CTX_LINKCLOSE:
	case RET_CTX_RESOURCE_ADV:
	case RET_CTX_RESOURCE_HMU:
	case RET_CTX_RESOURCE_ICL:
	case RET_CTX_RESOURCE_REQ:
	case RET_CTX_RESOURCE_RCL:
		break;
	default:
		LOG_DBG("unhandled link context 0x%02x", pkt->context);
		return;
	}

	n = ret_token_decrypt(l->key, pkt->data, pkt->data_len, c->rx_plain, sizeof(c->rx_plain));
	if (n < 0) {
		LOG_WRN("undecryptable link packet: %d", n);
		return;
	}

	switch (pkt->context) {
	case RET_CTX_RESPONSE:
		if (l->role == LINK_OUT) {
			on_response(link_out_of(l), c->rx_plain, (size_t)n);
		}
		break;
	case RET_CTX_RESOURCE_ADV:
		on_resource_adv(c, l, c->rx_plain, (size_t)n);
		break;
	case RET_CTX_RESOURCE_HMU:
		on_resource_hmu(c, l, c->rx_plain, (size_t)n);
		break;
	case RET_CTX_RESOURCE_ICL:
		on_resource_icl(c, l, c->rx_plain, (size_t)n);
		break;
	case RET_CTX_RESOURCE_REQ:
		if (c->res.state == RES_SENDING && c->res.link == l) {
			uint8_t hash[RET_HASH_LEN];

			/* Link.receive drops a request it saw before
			 * (req_hashlist): a repeat would resend its parts.
			 */
			if (ret_packet_hash(raw, raw_len, hash) == 0 &&
			    !ret_client_seen_packet(c, hash)) {
				ret_client_remember_packet(c, hash);
				tx_on_request(c, c->rx_plain, (size_t)n);
			}
		}
		break;
	case RET_CTX_RESOURCE_RCL:
		if (c->res.state == RES_SENDING && c->res.link == l && n == RET_SHA256_LEN &&
		    memcmp(c->rx_plain, c->res.tx.h, RET_SHA256_LEN) == 0) {
			LOG_WRN("receiver refused our resource");
			send_done(c, link_out_of(l), -EPERM);
		}
		break;
	default: /* LINKCLOSE */
		if (n == RET_TRUNC_HASH_LEN && memcmp(c->rx_plain, l->id, RET_TRUNC_HASH_LEN) == 0) {
			LOG_INF("%slink closed by peer", l->role == LINK_IN ? "inbound " : "");
			link_end(c, l, RET_LINK_EVT_CLOSED, 0);
		}
		break;
	}
	ret_wipe(c->rx_plain, (size_t)n);
}

/* --- Outbound link API (queued requests) ------------------------------ */

void ret_link_drv_request(struct ret_client *c, const struct send_req *r)
{
	struct link_out *o = &c->out;
	struct link_request *slot = NULL;
	uint8_t plain[RET_LINK_MDU];
	uint8_t hash[RET_HASH_LEN];
	int n;
	int err;

	if (!link_up(&o->l)) {
		if (r->response_cb != NULL) {
			r->response_cb(-ENOTCONN, NULL, 0, r->user);
		}
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(o->req); i++) {
		if (!o->req[i].used) {
			slot = &o->req[i];
			break;
		}
	}
	if (slot == NULL) {
		if (r->response_cb != NULL) {
			r->response_cb(-ENOMEM, NULL, 0, r->user);
		}
		return;
	}

	/* RNS stamps requests with time.time(); with no wall clock, uptime.
	 * Handlers receive it as requested_at; the LXMF /get handler ignores it.
	 */
	n = ret_link_request_plain((double)k_uptime_get() / 1000.0, r->path,
				   r->len > 0 ? r->data : NULL, r->len, plain, sizeof(plain));
	err = n < 0 ? n : send_link(c, &o->l, RET_CTX_REQUEST, plain, (size_t)n, true, hash);
	ret_wipe(plain, sizeof(plain));
	if (err) {
		if (r->response_cb != NULL) {
			r->response_cb(err, NULL, 0, r->user);
		}
		return;
	}

	slot->used = true;
	memcpy(slot->id, hash, RET_TRUNC_HASH_LEN);
	slot->deadline_ms = k_uptime_get() + (int64_t)o->l.rtt_ms * 6 + REQUEST_TIMEOUT_EXTRA_MS;
	slot->cb = r->response_cb;
	slot->user = r->user;
}

void ret_link_drv_identify(struct ret_client *c)
{
	struct link_out *o = &c->out;
	uint8_t plain[RET_LINK_IDENTIFY_LEN];

	if (!link_up(&o->l) || !c->has_local) {
		return;
	}
	ret_link_identify_plain(&c->id, o->l.id, plain);
	(void)send_link(c, &o->l, RET_CTX_LINKIDENTIFY, plain, sizeof(plain), true, NULL);
	LOG_INF("identified on link");
}

void ret_link_drv_close(struct ret_client *c)
{
	struct link *l = &c->out.l;

	if (link_up(l)) {
		link_close(c, l, RET_LINK_EVT_CLOSED, 0);
	} else if (l->state != LINK_NONE) {
		link_end(c, l, RET_LINK_EVT_CLOSED, 0);
	}
}

/* --- Every link at once ------------------------------------------------ */

void ret_link_drv_teardown(struct ret_client *c)
{
	struct link *l = &c->out.l;
	enum link_state st = l->state;

	if (st != LINK_NONE) {
		/* CLOSED only for a link that was ACTIVE; one still being set
		 * up FAILED, as the API promises.
		 */
		link_end(c, l, link_up(l) ? RET_LINK_EVT_CLOSED : RET_LINK_EVT_FAILED, -ECONNRESET);
	}
#if CONFIG_RET_INBOUND_LINKS > 0
	for (size_t i = 0; i < ARRAY_SIZE(c->in); i++) {
		if (c->in[i].state != LINK_NONE) {
			link_end(c, &c->in[i], RET_LINK_EVT_CLOSED, -ECONNRESET);
		}
	}
#endif
}

void ret_link_drv_close_all(struct ret_client *c)
{
	if (link_up(&c->out.l)) {
		link_close(c, &c->out.l, RET_LINK_EVT_CLOSED, 0);
	}
#if CONFIG_RET_INBOUND_LINKS > 0
	/* An inbound link has its key from the request on: RNS accepts the
	 * close even in handshake.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(c->in); i++) {
		if (c->in[i].state == LINK_NONE) {
			continue;
		}
		LOG_INF("closing inbound link %02x%02x%02x%02x..", c->in[i].id[0], c->in[i].id[1],
			c->in[i].id[2], c->in[i].id[3]);
		if (c->conn_broken) {
			link_end(c, &c->in[i], RET_LINK_EVT_CLOSED, 0);
		} else {
			link_close(c, &c->in[i], RET_LINK_EVT_CLOSED, 0);
		}
	}
#endif
}

/* --- Timers ------------------------------------------------------------ */

static int64_t stale_close_at(const struct link *l)
{
	return l->stale_since_ms + (int64_t)l->rtt_ms * STALE_FACTOR + STALE_GRACE_MS;
}

/* Shared by both roles: ACTIVE -> STALE without traffic, then closed. */
static void service_stale(struct ret_client *c, struct link *l, int64_t now)
{
	if (l->state == LINK_ACTIVE && now - l->last_rx_ms >= 2 * (int64_t)l->keepalive_ms) {
		l->state = LINK_STALE;
		l->stale_since_ms = now;
		LOG_WRN("link stale");
	} else if (l->state == LINK_STALE && now >= stale_close_at(l)) {
		LOG_WRN("link timed out");
		link_close(c, l, RET_LINK_EVT_CLOSED, -ETIMEDOUT);
	}
}

static int64_t stale_next(const struct link *l)
{
	return l->state == LINK_ACTIVE ? l->last_rx_ms + 2 * (int64_t)l->keepalive_ms
				       : stale_close_at(l);
}

static int64_t keepalive_due(const struct link_out *o)
{
	const struct link *l = &o->l;

	return MIN(l->last_tx_ms, MAX(l->last_rx_ms, o->last_keepalive_ms)) + l->keepalive_ms;
}

static void service_out(struct ret_client *c, int64_t now)
{
	struct link_out *o = &c->out;
	struct link *l = &o->l;

	switch (l->state) {
	case LINK_NONE:
	case LINK_HANDSHAKE:
		return;
	case LINK_WAIT_PATH:
		if (now >= l->deadline_ms) {
			LOG_WRN("no path for link");
			link_end(c, l, RET_LINK_EVT_FAILED, -EHOSTUNREACH);
		} else if (now >= o->next_path_request_ms) {
			if (ret_client_send_path_request(c, o->dest) == -ECONNRESET) {
				c->conn_broken = true;
			}
			o->next_path_request_ms = now + CONFIG_RET_PATH_REQUEST_INTERVAL_MS;
		}
		return;
	case LINK_PENDING:
		if (now >= l->deadline_ms) {
			LOG_WRN("no link proof in time");
			link_end(c, l, RET_LINK_EVT_FAILED, -ETIMEDOUT);
		}
		return;
	case LINK_ACTIVE:
	case LINK_STALE:
		break;
	}

	for (size_t i = 0; i < ARRAY_SIZE(o->req); i++) {
		struct link_request *q = &o->req[i];

		if (q->used && !q->receiving && now >= q->deadline_ms) {
			request_done(q, -ETIMEDOUT, NULL, 0);
		}
	}
	if (o->send == OUT_SEND_PACKET && now >= o->send_deadline_ms) {
		LOG_WRN("no proof for link packet");
		send_done(c, o, -ETIMEDOUT);
	}

	/* The initiator keeps the link alive (the responder only answers):
	 * a keepalive when nothing was sent for a keepalive interval, or when
	 * nothing was received for one (at most one per interval).
	 */
	if (now >= keepalive_due(o)) {
		const uint8_t ka = 0xFF;

		o->last_keepalive_ms = now;
		(void)send_link(c, l, RET_CTX_KEEPALIVE, &ka, 1, false, NULL);
	}
	service_stale(c, l, now);
}

/* When the sending resource's watchdog fires next (Resource.py). */
static int64_t tx_deadline(const struct link_resource *res)
{
	uint32_t rtt = res->tx_rtt_ms != 0 ? res->tx_rtt_ms : res->link->rtt_ms;

	switch (res->tx_phase) {
	case RES_TX_ADVERTISED:
		return res->tx_adv_ms + (int64_t)res->link->rtt_ms * TRAFFIC_TIMEOUT_FACTOR +
		       TX_PROCESSING_GRACE_MS;
	case RES_TX_TRANSFERRING:
		return res->tx_activity_ms +
		       (int64_t)rtt * TRAFFIC_TIMEOUT_FACTOR * RESOURCE_MAX_RETRIES +
		       TX_SENDER_GRACE_MS + TX_RETRY_DELAYS_MS;
	default:
		return res->tx_last_part_ms + (int64_t)rtt * TX_PROOF_TIMEOUT_FACTOR +
		       TX_SENDER_GRACE_MS;
	}
}

static void service_tx(struct ret_client *c, int64_t now)
{
	struct link_resource *res = &c->res;

	if (now < tx_deadline(res)) {
		return;
	}
	switch (res->tx_phase) {
	case RES_TX_ADVERTISED:
		if (res->retries == 0) {
			LOG_WRN("resource advertisement unanswered");
			tx_cancel(c, -ETIMEDOUT);
		} else {
			res->retries--;
			(void)send_adv(c);
		}
		break;
	case RES_TX_TRANSFERRING:
		LOG_WRN("no part requests for our resource");
		tx_cancel(c, -ETIMEDOUT);
		break;
	default:
		/* RNS queries the network cache for the proof here; there is
		 * none to ask: wait again.
		 */
		if (res->retries == 0) {
			LOG_WRN("no proof for our resource");
			tx_cancel(c, -ETIMEDOUT);
		} else {
			res->retries--;
			res->tx_last_part_ms = now;
		}
		break;
	}
}

static void service_resource(struct ret_client *c, int64_t now)
{
	struct link_resource *res = &c->res;

	if (res->state == RES_SENDING) {
		service_tx(c, now);
		return;
	}
	if (res->state != RES_RECEIVING) {
		return;
	}
	if (now >= res->give_up_ms) {
		LOG_WRN("resource took too long: given up");
		resource_fail(c, -ETIMEDOUT, true);
		return;
	}
	if (now < res->deadline_ms) {
		return;
	}
	if (res->retries == 0) {
		LOG_WRN("resource timed out");
		resource_fail(c, -ETIMEDOUT, true);
	} else {
		res->retries--;
		ret_resource_rx_timeout(&res->rx);
		resource_request(c);
	}
}

static void service_in(struct ret_client *c, int64_t now)
{
#if CONFIG_RET_INBOUND_LINKS > 0
	for (size_t i = 0; i < ARRAY_SIZE(c->in); i++) {
		struct link *l = &c->in[i];

		if (l->state == LINK_HANDSHAKE && now >= l->deadline_ms) {
			LOG_WRN("inbound link: no RTT from the initiator");
			link_end(c, l, RET_LINK_EVT_FAILED, -ETIMEDOUT);
		} else if (link_up(l)) {
			/* The responder sends no keepalives of its own. */
			service_stale(c, l, now);
		}
	}
#else
	ARG_UNUSED(c);
	ARG_UNUSED(now);
#endif
}

void ret_link_drv_service(struct ret_client *c)
{
	int64_t now = k_uptime_get();

	service_resource(c, now);
	service_out(c, now);
	service_in(c, now);
}

static int64_t next_in(const struct ret_client *c)
{
	int64_t next = INT64_MAX;

#if CONFIG_RET_INBOUND_LINKS > 0
	for (size_t i = 0; i < ARRAY_SIZE(c->in); i++) {
		const struct link *l = &c->in[i];

		if (l->state == LINK_HANDSHAKE) {
			next = MIN(next, l->deadline_ms);
		} else if (link_up(l)) {
			next = MIN(next, stale_next(l));
		}
	}
#else
	ARG_UNUSED(c);
#endif
	return next;
}

int64_t ret_link_drv_next_event(const struct ret_client *c)
{
	const struct link_out *o = &c->out;
	const struct link *l = &o->l;
	int64_t next = next_in(c);

	if (c->res.state == RES_RECEIVING) {
		next = MIN(next, MIN(c->res.deadline_ms, c->res.give_up_ms));
	} else if (c->res.state == RES_SENDING) {
		next = MIN(next, tx_deadline(&c->res));
	}
	switch (l->state) {
	case LINK_NONE:
	case LINK_HANDSHAKE:
		return next;
	case LINK_WAIT_PATH:
		return MIN(next, MIN(l->deadline_ms, o->next_path_request_ms));
	case LINK_PENDING:
		return MIN(next, l->deadline_ms);
	case LINK_ACTIVE:
	case LINK_STALE:
		break;
	}
	for (size_t i = 0; i < ARRAY_SIZE(o->req); i++) {
		if (o->req[i].used && !o->req[i].receiving) {
			next = MIN(next, o->req[i].deadline_ms);
		}
	}
	if (o->send == OUT_SEND_PACKET) {
		next = MIN(next, o->send_deadline_ms);
	}
	next = MIN(next, keepalive_due(o));
	return MIN(next, stale_next(l));
}

uint8_t *ret_link_drv_scratch(struct ret_client *c, size_t *cap)
{
	if (c->res.state == RES_RECEIVING || c->res.state == RES_SENDING) {
		*cap = 0;
		return NULL;
	}
	*cap = sizeof(c->res.stream);
	return c->res.stream;
}
