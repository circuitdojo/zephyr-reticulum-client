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
 * What every link shares (sending, closing, stale timers, receiving a
 * Resource) works on struct link, whichever side opened it.
 *
 * A Resource (ret_resource.c) arrives at most one at a time, on any link,
 * into the client's buffers: a response too large for one packet.
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

/* Give up on the resource; a response's request fails with @p err. */
static void resource_fail(struct ret_client *c, int err, bool refuse)
{
	struct link_request *q;

	if (refuse) {
		send_rcl(c, c->res.link, c->res.rx.h);
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
	} else {
		LOG_WRN("refusing resource on an inbound link");
		send_rcl(c, l, adv.h);
	}
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

/* --- Packets for a link ----------------------------------------------- */

struct link *ret_link_drv_find(struct ret_client *c, const uint8_t id[RET_TRUNC_HASH_LEN])
{
	if (c->out.l.state != LINK_NONE && memcmp(c->out.l.id, id, RET_TRUNC_HASH_LEN) == 0) {
		return &c->out.l;
	}
	return NULL;
}

void ret_link_drv_on_packet(struct ret_client *c, struct link *l, const struct ret_packet *pkt,
			    const uint8_t *raw, size_t raw_len)
{
	int n;

	ARG_UNUSED(raw);
	ARG_UNUSED(raw_len);

	if (l->role == LINK_OUT && pkt->packet_type == RET_PKT_PROOF &&
	    pkt->context == RET_CTX_LRPROOF) {
		on_proof(c, link_out_of(l), pkt);
		return;
	}
	if (!link_up(l)) {
		return;
	}

	l->last_rx_ms = k_uptime_get();
	if (l->state == LINK_STALE) {
		l->state = LINK_ACTIVE;
	}

	if (pkt->packet_type != RET_PKT_DATA) {
		return; /* packet proofs: nothing sent by us asks for them */
	}

	switch (pkt->context) {
	case RET_CTX_KEEPALIVE:
		return; /* unencrypted; any inbound already refreshed last_rx */
	case RET_CTX_RESOURCE:
		/* A slice of the already encrypted stream: no link token. */
		on_resource_part(c, l, pkt->data, pkt->data_len);
		return;
	case RET_CTX_RESPONSE:
	case RET_CTX_LINKCLOSE:
	case RET_CTX_RESOURCE_ADV:
	case RET_CTX_RESOURCE_HMU:
	case RET_CTX_RESOURCE_ICL:
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
	default: /* LINKCLOSE */
		if (n == RET_TRUNC_HASH_LEN && memcmp(c->rx_plain, l->id, RET_TRUNC_HASH_LEN) == 0) {
			LOG_INF("link closed by peer");
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
}

void ret_link_drv_close_all(struct ret_client *c)
{
	if (link_up(&c->out.l)) {
		link_close(c, &c->out.l, RET_LINK_EVT_CLOSED, 0);
	}
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

static void service_resource(struct ret_client *c, int64_t now)
{
	struct link_resource *res = &c->res;

	if (res->state != RES_RECEIVING || now < res->deadline_ms) {
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

void ret_link_drv_service(struct ret_client *c)
{
	int64_t now = k_uptime_get();

	service_resource(c, now);
	service_out(c, now);
}

int64_t ret_link_drv_next_event(const struct ret_client *c)
{
	const struct link_out *o = &c->out;
	const struct link *l = &o->l;
	int64_t next = INT64_MAX;

	if (c->res.state == RES_RECEIVING) {
		next = MIN(next, c->res.deadline_ms);
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
	next = MIN(next, keepalive_due(o));
	return MIN(next, stale_next(l));
}

uint8_t *ret_link_drv_scratch(struct ret_client *c, size_t *cap)
{
	if (c->res.state == RES_RECEIVING) {
		*cap = 0;
		return NULL;
	}
	*cap = sizeof(c->res.stream);
	return c->res.stream;
}
