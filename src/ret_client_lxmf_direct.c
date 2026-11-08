/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * LXMF DIRECT delivery, as LXMRouter sends a message with method DIRECT:
 * a link to the recipient's lxmf.delivery destination, then the whole
 * packed message (destination included) as one link packet when it fits
 * the link MDU, otherwise as a Resource. The packet's proof, or the
 * resource's, confirms delivery.
 *
 * ret_lxmf_send() packs and signs on the caller's thread straight into
 * the pool; the client thread sends the queue head over the outbound link
 * when it is free (no application link, no sync), keeps the link a while
 * for the next message to the same recipient, and retries a failed
 * attempt on a new link (LXMRouter.DELIVERY_RETRY_WAIT). A message the
 * recipient refused (RESOURCE_RCL, final in LXMF too) is not retried.
 *
 * Link callbacks and send outcomes only record what happened;
 * ret_lxmf_direct_drv_service(), from the client loop, acts on it.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "ret_client_internal.h"
#include "ret_crypto.h"
#include "ret_lxmf.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

/* LXMRouter.DELIVERY_RETRY_WAIT. */
#define RETRY_WAIT_MS 10000
/* The link stays up this long after a delivery, for the next message. */
#define IDLE_LINK_MS 10000
/* The head message fails after waiting this long for the link (held by
 * the application or a sync) or for the resource buffers (a delivery
 * arriving). Its own attempts and retry waits do not count.
 */
#define QUEUE_WAIT_MS 300000
/* How often a blocked head re-checks while the link stays up for it. */
#define BLOCKED_POLL_MS 1000

static void direct_link(enum ret_link_event ev, int reason, void *user);

static bool owns_link(const struct ret_client *c)
{
	return c->out.l.state != LINK_NONE && c->out.cb == direct_link;
}

void ret_lxmf_direct_drv_init(struct ret_client *c)
{
	k_mutex_init(&c->direct.lock);
}

bool ret_lxmf_direct_drv_owns_link(const struct ret_client *c)
{
	return owns_link(c);
}

/* Remove the head message and report @p status for it. */
static void pop(struct ret_client *c, enum ret_receipt_status status, uint32_t rtt_ms)
{
	struct lxmf_direct *d = &c->direct;
	struct lxmf_direct_msg m;

	k_mutex_lock(&d->lock, K_FOREVER);
	if (d->n == 0) {
		k_mutex_unlock(&d->lock);
		return;
	}
	m = d->q[0];
	ret_wipe(d->pool, m.len);
	memmove(d->pool, &d->pool[m.len], d->pool_used - m.len);
	d->pool_used -= m.len;
	/* The moved bytes' old copy: signed plaintext. */
	ret_wipe(&d->pool[d->pool_used], m.len);
	memmove(&d->q[0], &d->q[1], (d->n - 1) * sizeof(d->q[0]));
	d->n--;
	k_mutex_unlock(&d->lock);

	d->attempts = 0;
	d->next_attempt_ms = 0;
	d->blocked_since_ms = 0;
	LOG_INF("DIRECT message %02x%02x%02x%02x..: %s", m.hash[0], m.hash[1], m.hash[2],
		m.hash[3],
		status == RET_RECEIPT_DELIVERED  ? "delivered"
		: status == RET_RECEIPT_REJECTED ? "rejected"
						 : "failed");
	if (m.cb != NULL) {
		m.cb(m.hash, status, rtt_ms, m.user);
	}
}

/* The head message, copied out under the lock (its bytes stay put: only
 * the client thread pops).
 */
static bool head(struct ret_client *c, struct lxmf_direct_msg *m)
{
	struct lxmf_direct *d = &c->direct;
	bool any;

	k_mutex_lock(&d->lock, K_FOREVER);
	any = d->n > 0;
	if (any) {
		*m = d->q[0];
	}
	k_mutex_unlock(&d->lock);
	return any;
}

void ret_lxmf_direct_drv_fail_all(struct ret_client *c, enum ret_receipt_status status)
{
	struct lxmf_direct *d = &c->direct;
	struct lxmf_direct_msg m;

	/* Called with every link gone (suspended): nothing is in flight. */
	d->step = DIRECT_IDLE;
	d->have_result = false;
	d->link_up = false;
	d->link_gone = false;
	d->blocked_since_ms = 0;
	while (head(c, &m)) {
		pop(c, status, 0);
	}
}

static void direct_link(enum ret_link_event ev, int reason, void *user)
{
	struct ret_client *c = user;
	struct lxmf_direct *d = &c->direct;

	if (ev == RET_LINK_EVT_ACTIVE) {
		d->link_up = true;
		return;
	}
	if (ev == RET_LINK_EVT_FAILED) {
		LOG_WRN("DIRECT: no link to the recipient: %d", reason);
	}
	d->link_gone = true;
}

static void direct_sent(struct ret_client *c, int status, uint32_t rtt_ms)
{
	struct lxmf_direct *d = &c->direct;

	d->have_result = true;
	d->result = status;
	d->result_rtt_ms = rtt_ms;
}

/* This attempt failed: try again on a new link, or give up. */
static void attempt_failed(struct ret_client *c, int err)
{
	struct lxmf_direct *d = &c->direct;

	d->attempts++;
	if (d->attempts >= CONFIG_RET_LXMF_DIRECT_ATTEMPTS) {
		pop(c, err == -ETIMEDOUT ? RET_RECEIPT_TIMEOUT : RET_RECEIPT_FAILED, 0);
		return;
	}
	LOG_WRN("DIRECT attempt %u failed (%d): retrying in %d s", d->attempts, err,
		RETRY_WAIT_MS / 1000);
	d->next_attempt_ms = k_uptime_get() + RETRY_WAIT_MS;
}

/* A message larger than one link packet needs the resource buffers, which
 * an arriving resource may hold for a while.
 */
static bool sendable(const struct ret_client *c, const struct lxmf_direct_msg *m)
{
	return m->len <= RET_LINK_MDU || c->res.state == RES_IDLE;
}

/* The head waits on someone else: give up once that lasted too long. */
static bool blocked_too_long(struct ret_client *c, int64_t now)
{
	struct lxmf_direct *d = &c->direct;

	if (d->blocked_since_ms == 0) {
		d->blocked_since_ms = now;
	}
	if (now - d->blocked_since_ms < QUEUE_WAIT_MS) {
		return false;
	}
	LOG_WRN("DIRECT: the link or the resource buffers stayed busy too long");
	pop(c, RET_RECEIPT_FAILED, 0);
	return true;
}

static void send_head(struct ret_client *c)
{
	struct lxmf_direct *d = &c->direct;
	struct lxmf_direct_msg m;
	int err;

	if (!head(c, &m)) {
		return;
	}
	if (!sendable(c, &m)) {
		/* A delivery arriving holds the buffers: keep the link and
		 * wait, without spending an attempt.
		 */
		d->step = DIRECT_READY;
		d->idle_until_ms = k_uptime_get() + IDLE_LINK_MS;
		return;
	}
	d->blocked_since_ms = 0;
	/* The head's bytes start the pool. LXMessage: a packed message that
	 * fits the link MDU goes as one packet, a larger one as a Resource.
	 */
	if (m.len <= RET_LINK_MDU) {
		err = ret_link_drv_send_packet(c, d->pool, m.len, direct_sent);
	} else {
		err = ret_link_drv_send_resource(c, d->pool, m.len, direct_sent);
	}
	if (err) {
		LOG_WRN("DIRECT send failed: %d", err);
		d->step = DIRECT_CLOSING;
		ret_link_drv_close(c);
		attempt_failed(c, err);
		return;
	}
	d->step = DIRECT_SENDING;
	LOG_INF("DIRECT message %02x%02x%02x%02x.. sent as %s (%u bytes)", m.hash[0], m.hash[1],
		m.hash[2], m.hash[3], m.len <= RET_LINK_MDU ? "a packet" : "a resource", m.len);
}

static void on_result(struct ret_client *c)
{
	struct lxmf_direct *d = &c->direct;
	int status = d->result;

	d->have_result = false;
	if (status == 0) {
		pop(c, RET_RECEIPT_DELIVERED, d->result_rtt_ms);
	} else if (status == -EPERM) {
		/* The recipient refused it (too large for it): final, as in
		 * LXMF, where a rejected resource fails the message.
		 */
		pop(c, RET_RECEIPT_REJECTED, 0);
	} else {
		/* LXMRouter tears the link down when a delivery times out. */
		if (d->step != DIRECT_IDLE) {
			d->step = DIRECT_CLOSING;
			ret_link_drv_close(c);
		}
		attempt_failed(c, status);
		return;
	}
	if (d->step == DIRECT_SENDING) {
		d->step = DIRECT_READY;
		d->idle_until_ms = k_uptime_get() + IDLE_LINK_MS;
	}
}

static void open_link(struct ret_client *c, const struct lxmf_direct_msg *m)
{
	struct lxmf_direct *d = &c->direct;
	/* static: client thread only, and kept off its stack. */
	static struct send_req open = { .kind = REQ_LINK_OPEN, .link_cb = direct_link };

	memcpy(open.dest_hash, m->dest, RET_DEST_HASH_LEN);
	open.user = c;
	memcpy(d->link_dest, m->dest, RET_TRUNC_HASH_LEN);
	d->link_up = false;
	d->link_gone = false;
	d->step = DIRECT_LINKING;
	LOG_INF("DIRECT: linking to %02x%02x%02x%02x..", m->dest[0], m->dest[1], m->dest[2],
		m->dest[3]);
	ret_link_drv_open(c, &open);
}

void ret_lxmf_direct_drv_service(struct ret_client *c)
{
	struct lxmf_direct *d = &c->direct;
	struct lxmf_direct_msg m;
	int64_t now = k_uptime_get();
	bool any;

	if (d->have_result) {
		on_result(c);
	}
	if (d->link_gone) {
		d->link_gone = false;
		d->link_up = false;
		enum direct_step was = d->step;

		d->step = DIRECT_IDLE;
		if (was == DIRECT_LINKING) {
			attempt_failed(c, -EHOSTUNREACH);
		}
		/* SENDING: the send failed first (-ECONNRESET), handled above. */
	}
	if (d->step == DIRECT_LINKING && d->link_up) {
		d->link_up = false;
		send_head(c);
	}

	any = head(c, &m);
	switch (d->step) {
	case DIRECT_READY:
		if (any && memcmp(m.dest, d->link_dest, RET_TRUNC_HASH_LEN) == 0 &&
		    !ret_lxmf_sync_drv_waiting(c)) {
			if (sendable(c, &m)) {
				send_head(c);
			} else if (!blocked_too_long(c, now)) {
				break; /* the link stays up while the buffers are busy */
			}
		} else if (any || now >= d->idle_until_ms || ret_lxmf_sync_drv_waiting(c)) {
			/* Another recipient, a waiting sync, or idle long enough. */
			d->step = DIRECT_CLOSING;
			ret_link_drv_close(c);
		}
		break;
	case DIRECT_IDLE:
		if (!any) {
			break;
		}
		if (now < d->next_attempt_ms) {
			break; /* between attempts */
		}
		if (c->out.l.state == LINK_NONE && !c->sync.active && sendable(c, &m)) {
			d->blocked_since_ms = 0;
			open_link(c, &m);
		} else {
			(void)blocked_too_long(c, now);
		}
		break;
	default:
		break;
	}
}

int64_t ret_lxmf_direct_drv_next_event(const struct ret_client *c)
{
	const struct lxmf_direct *d = &c->direct;

	if (d->have_result || d->link_gone || (d->step == DIRECT_LINKING && d->link_up)) {
		return 0;
	}
	switch (d->step) {
	case DIRECT_READY:
		if (ret_lxmf_sync_drv_waiting(c)) {
			return 0;
		}
		if (d->n > 0) {
			/* Waiting for the buffers re-checks now and then. */
			return d->blocked_since_ms != 0 ? k_uptime_get() + BLOCKED_POLL_MS : 0;
		}
		return d->idle_until_ms;
	case DIRECT_IDLE:
		if (d->n == 0) {
			return INT64_MAX;
		}
		/* Waiting for the link to be free wakes on its own events;
		 * re-check at least every retry interval for the queue limit.
		 */
		return d->blocked_since_ms == 0 ? d->next_attempt_ms
						: k_uptime_get() + BLOCKED_POLL_MS;
	default:
		return INT64_MAX;
	}
}

/* --- API (any thread) -------------------------------------------------- */

int ret_lxmf_direct_queue(struct ret_client *c, const uint8_t dest[RET_DEST_HASH_LEN],
			  double timestamp, const uint8_t *title, size_t title_len,
			  const uint8_t *content, size_t content_len, ret_receipt_cb_t cb,
			  void *user)
{
	struct lxmf_direct *d = &c->direct;
	struct lxmf_direct_msg *m;
	uint8_t hash[RET_SHA256_LEN];
	int n;

	k_mutex_lock(&d->lock, K_FOREVER);
	if (d->n == ARRAY_SIZE(d->q)) {
		k_mutex_unlock(&d->lock);
		return -EAGAIN;
	}
	m = &d->q[d->n];
	/* Packed in place at the pool's end; the client thread only reads
	 * the head and only moves the pool under this lock.
	 */
	n = ret_lxmf_pack(&c->id, c->local_dest, dest, timestamp, title, title_len, content,
			  content_len, &d->pool[d->pool_used], sizeof(d->pool) - d->pool_used,
			  hash);
	if (n < 0) {
		/* Whatever the pack wrote before running out: signed plaintext. */
		ret_wipe(&d->pool[d->pool_used], sizeof(d->pool) - d->pool_used);
		k_mutex_unlock(&d->lock);
		/* Fits an empty pool (checked by the caller): wait for room. */
		return n == -ENOBUFS ? -EAGAIN : n;
	}
	if (RET_RESOURCE_STREAM_LEN((size_t)n) > CONFIG_RET_RESOURCE_MAX_SIZE) {
		ret_wipe(&d->pool[d->pool_used], (size_t)n);
		k_mutex_unlock(&d->lock);
		return -EMSGSIZE;
	}
	memcpy(m->dest, dest, RET_TRUNC_HASH_LEN);
	memcpy(m->hash, hash, sizeof(hash));
	m->len = (uint32_t)n;
	m->cb = cb;
	m->user = user;
	d->pool_used += (size_t)n;
	d->n++;
	k_mutex_unlock(&d->lock);
	LOG_DBG("DIRECT message %02x%02x%02x%02x.. queued (%d bytes)", hash[0], hash[1], hash[2],
		hash[3], n);
	return 0;
}
