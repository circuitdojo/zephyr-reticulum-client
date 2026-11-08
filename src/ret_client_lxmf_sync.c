/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * LXMF propagation sync (the client side of LXMRouter's "/get" handler):
 *
 *   link to the node's lxmf.propagation destination, identify with our
 *   identity (the node serves the lxmf.delivery address it derives)
 *   -> /get [nil, nil]                 list of transient ids
 *   -> /get [wants (<= 10), [], limit] messages: dest | SINGLE token
 *   -> /get [nil, haves]               acknowledge: the node deletes them
 *   ... until the list is done, then close.
 *
 * A transient id is SHA256 of the item exactly as served. The node fills
 * a batch up to the transfer limit (cumulatively, in the order asked),
 * so a batch can come back short: what it left out is asked for again.
 * Only a batch that serves nothing marks its first, smallest, id as too
 * large for the limit.
 *
 * Runs on the client thread. Link callbacks only record the next step;
 * ret_lxmf_sync_drv_service(), from the client loop, performs it through
 * the link driver directly. No step goes through the request queue, so a
 * full queue cannot strand a sync, and while a sync owns the link the
 * application's link requests are refused (ret_client.c).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <mpack.h>

#include "ret_client_internal.h"
#include "ret_crypto.h"
#include "ret_lxmf.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

#define GET_PATH "/get"
/* LXMPeer error codes answered instead of a list. */
#define ERROR_NO_IDENTITY 0xf0
#define ERROR_NO_ACCESS   0xf1
/* Times one request is sent again after a delivery held the resource. */
#define SYNC_BUSY_RETRIES 3

/* Each request must fit one link packet (no outgoing resources). */
BUILD_ASSERT(1 + 1 + RET_LXMF_SYNC_BATCH * (2 + RET_SHA256_LEN) + 1 + 9 <= RET_LINK_MDU - 32);
/* Every batch must be receivable as a resource. */
BUILD_ASSERT(CONFIG_RET_LXMF_SYNC_LIMIT_KB * 1000 + 1024 <= CONFIG_RET_RESOURCE_MAX_SIZE,
	     "RET_LXMF_SYNC_LIMIT_KB does not fit RET_RESOURCE_MAX_SIZE");

static void sync_response(int status, const uint8_t *resp, size_t len, void *user);
static void sync_link(enum ret_link_event ev, int reason, void *user);

/* The link is the sync's while its callback is ours. */
static bool owns_link(const struct ret_client *c)
{
	return c->out.l.state != LINK_NONE && c->out.cb == sync_link;
}

/* End with @p err: close the link if it is still up; the link callback
 * reports the outcome.
 */
static void fail(struct ret_client *c, int err)
{
	struct lxmf_sync *s = &c->sync;

	if (s->status == 0) {
		s->status = err;
	}
	s->pending = SYNC_PEND_CLOSE;
}

static void queue_request(struct ret_client *c, enum sync_phase phase, size_t len)
{
	c->sync.phase = phase;
	c->sync.req_len = len;
	c->sync.pending = SYNC_PEND_REQUEST;
}

static void request_list(struct ret_client *c)
{
	static const uint8_t nil_nil[] = { 0x92, 0xc0, 0xc0 };

	memcpy(c->sync.req, nil_nil, sizeof(nil_nil));
	c->sync.acked_since_list = 0;
	queue_request(c, SYNC_LISTING, sizeof(nil_nil));
}

static void finish_list(struct ret_client *c)
{
	struct lxmf_sync *s = &c->sync;

	if (s->list_truncated && s->acked_since_list > 0) {
		request_list(c); /* what we fetched is gone from the node now */
		return;
	}
	if (s->list_truncated) {
		/* A whole pass over a truncated list moved nothing. */
		LOG_WRN("sync: messages left at the node are all over the transfer limit");
	}
	s->phase = SYNC_CLOSING;
	s->pending = SYNC_PEND_CLOSE;
}

static void request_next(struct ret_client *c)
{
	struct lxmf_sync *s = &c->sync;
	mpack_writer_t w;
	size_t k = MIN(s->n_ids - s->next, (size_t)RET_LXMF_SYNC_BATCH);

	if (k == 0) {
		finish_list(c);
		return;
	}

	mpack_writer_init(&w, (char *)s->req, sizeof(s->req));
	mpack_start_array(&w, 3);
	mpack_start_array(&w, (uint32_t)k);
	for (size_t i = 0; i < k; i++) {
		mpack_write_bin(&w, (const char *)s->ids[s->next + i], RET_SHA256_LEN);
	}
	mpack_finish_array(&w);
	mpack_start_array(&w, 0);
	mpack_finish_array(&w);
	mpack_write_uint(&w, CONFIG_RET_LXMF_SYNC_LIMIT_KB);
	mpack_finish_array(&w);

	size_t used = mpack_writer_buffer_used(&w);

	if (mpack_writer_destroy(&w) != mpack_ok) {
		fail(c, -ENOBUFS);
		return;
	}
	s->wanted = k;
	queue_request(c, SYNC_FETCHING, used);
}

static void request_ack(struct ret_client *c)
{
	struct lxmf_sync *s = &c->sync;
	mpack_writer_t w;

	mpack_writer_init(&w, (char *)s->req, sizeof(s->req));
	mpack_start_array(&w, 2);
	mpack_write_nil(&w);
	mpack_start_array(&w, (uint32_t)s->n_acks);
	for (size_t i = 0; i < s->n_acks; i++) {
		mpack_write_bin(&w, (const char *)s->acks[i], RET_SHA256_LEN);
	}
	mpack_finish_array(&w);
	mpack_finish_array(&w);

	size_t used = mpack_writer_buffer_used(&w);

	if (mpack_writer_destroy(&w) != mpack_ok) {
		fail(c, -ENOBUFS);
		return;
	}
	queue_request(c, SYNC_ACKING, used);
}

static bool skipped(const struct lxmf_sync *s, const uint8_t *id)
{
	for (size_t i = 0; i < s->n_skipped; i++) {
		if (memcmp(s->skipped[i], id, RET_SHA256_LEN) == 0) {
			return true;
		}
	}
	return false;
}

/* An LXMPeer error code instead of the expected array. */
static int node_error(mpack_reader_t *r)
{
	uint64_t code = mpack_expect_u64(r);

	if (mpack_reader_error(r) != mpack_ok) {
		return -EBADMSG;
	}
	LOG_WRN("propagation node refused: error 0x%02x", (unsigned int)code);
	return (code == ERROR_NO_IDENTITY || code == ERROR_NO_ACCESS) ? -EACCES : -EPROTO;
}

static int on_list(struct ret_client *c, const uint8_t *resp, size_t len)
{
	struct lxmf_sync *s = &c->sync;
	mpack_reader_t r;
	uint32_t count;
	int err = 0;

	mpack_reader_init_data(&r, (const char *)resp, len);
	if (mpack_peek_tag(&r).type == mpack_type_uint) {
		err = node_error(&r);
		mpack_reader_destroy(&r);
		return err;
	}
	count = mpack_expect_array(&r);
	s->n_ids = 0;
	s->next = 0;
	s->list_truncated = false;
	for (uint32_t i = 0; i < count && mpack_reader_error(&r) == mpack_ok; i++) {
		uint32_t n = mpack_expect_bin(&r);
		const char *id = mpack_read_bytes_inplace(&r, n);

		mpack_done_bin(&r);
		if (mpack_reader_error(&r) != mpack_ok || n != RET_SHA256_LEN) {
			err = -EBADMSG;
			break;
		}
		if (skipped(s, (const uint8_t *)id)) {
			continue;
		}
		if (s->n_ids == ARRAY_SIZE(s->ids)) {
			s->list_truncated = true;
			continue;
		}
		memcpy(s->ids[s->n_ids++], id, RET_SHA256_LEN);
	}
	if (mpack_reader_destroy(&r) != mpack_ok && !err) {
		err = -EBADMSG;
	}
	if (!err) {
		LOG_INF("propagation node holds %u message(s) for us, %u to fetch now", count,
			(unsigned int)s->n_ids);
	}
	return err;
}

/* One served item: dest | SINGLE token of packed[16:]. */
static void on_item(struct ret_client *c, const uint8_t *item, size_t len)
{
	struct lxmf_sync *s = &c->sync;
	const struct ret_iov iov = { item, len };
	uint8_t id[RET_SHA256_LEN];
	size_t cap;
	uint8_t *plain = ret_link_drv_scratch(c, &cap);
	int n;

	if (plain == NULL) {
		/* A resource is arriving on another link, so this response came
		 * in one packet: its items fit a link MDU.
		 */
		plain = s->item_plain;
		cap = sizeof(s->item_plain);
	}

	if (ret_sha256(&iov, 1, id) != 0) {
		return;
	}
	/* Acknowledged (deleted at the node) whatever it holds: an item
	 * that is not ours, undecryptable, refused or badly signed will not
	 * get any better, and would otherwise be fetched forever.
	 */
	if (s->n_acks < ARRAY_SIZE(s->acks)) {
		memcpy(s->acks[s->n_acks++], id, RET_SHA256_LEN);
	}
	for (size_t i = 0; i < s->wanted; i++) {
		if (memcmp(s->ids[s->next + i], id, RET_SHA256_LEN) == 0) {
			s->served |= BIT(i);
		}
	}

	if (len <= RET_LXMF_ADDR_LEN || memcmp(item, c->local_dest, RET_LXMF_ADDR_LEN) != 0) {
		LOG_WRN("propagated item not addressed to us: dropped");
		return;
	}
	n = ret_local_identity_decrypt(&c->id, &item[RET_LXMF_ADDR_LEN], len - RET_LXMF_ADDR_LEN,
				       plain, cap);
	if (n < 0) {
		if (n == -ENOBUFS) {
			LOG_ERR("propagated message larger than its buffer: dropped");
		} else {
			LOG_WRN("propagated message undecryptable (%d): dropped", n);
		}
		return;
	}
	if (ret_lxmf_drv_deliver(c, plain, (size_t)n) == LXMF_DELIVERED) {
		s->received++;
	}
	ret_wipe(plain, (size_t)n);
}

/* Drop what the batch served from the working list; keep the rest in
 * order to be asked for again. A batch that served nothing means its
 * first (smallest) id alone is over the limit: skip that one.
 */
static void settle_batch(struct lxmf_sync *s)
{
	size_t keep = 0;

	if (s->served == 0) {
		/* The list is in ascending size order: everything from here on
		 * is over the limit as well. Remember them, end the pass.
		 */
		LOG_WRN("%u propagated message(s) exceed RET_LXMF_SYNC_LIMIT_KB: left at the node",
			(unsigned int)(s->n_ids - s->next));
		for (size_t i = s->next; i < s->n_ids && s->n_skipped < ARRAY_SIZE(s->skipped);
		     i++) {
			memcpy(s->skipped[s->n_skipped++], s->ids[i], RET_SHA256_LEN);
		}
		s->next = s->n_ids;
	} else {
		for (size_t i = 0; i < s->wanted; i++) {
			if (!(s->served & BIT(i))) {
				memmove(s->ids[s->next + keep], s->ids[s->next + i],
					RET_SHA256_LEN);
				keep++;
			}
		}
		/* Close the gap the served ids leave behind. */
		size_t tail = s->n_ids - (s->next + s->wanted);

		memmove(s->ids[s->next + keep], s->ids[s->next + s->wanted],
			tail * RET_SHA256_LEN);
		s->n_ids = s->next + keep + tail;
	}
	s->wanted = 0;
	s->served = 0;
}

static int on_messages(struct ret_client *c, const uint8_t *resp, size_t len)
{
	struct lxmf_sync *s = &c->sync;
	mpack_reader_t r;
	uint32_t count;
	int err = 0;

	mpack_reader_init_data(&r, (const char *)resp, len);
	if (mpack_peek_tag(&r).type == mpack_type_uint) {
		err = node_error(&r);
		mpack_reader_destroy(&r);
		return err;
	}
	count = mpack_expect_array(&r);
	s->n_acks = 0;
	s->served = 0;
	for (uint32_t i = 0; i < count && mpack_reader_error(&r) == mpack_ok; i++) {
		uint32_t n = mpack_expect_bin(&r);
		const char *item = mpack_read_bytes_inplace(&r, n);

		mpack_done_bin(&r);
		if (mpack_reader_error(&r) != mpack_ok) {
			break;
		}
		on_item(c, (const uint8_t *)item, n);
	}
	if (mpack_reader_destroy(&r) != mpack_ok) {
		err = -EBADMSG;
	}
	settle_batch(s);
	return err;
}

static void sync_response(int status, const uint8_t *resp, size_t len, void *user)
{
	struct ret_client *c = user;
	struct lxmf_sync *s = &c->sync;
	int err;

	if (!s->active) {
		return;
	}
	if (status == -EBUSY && s->busy_retries < SYNC_BUSY_RETRIES) {
		/* A delivery resource on an inbound link held the buffers. /get
		 * is idempotent (nothing is deleted until acknowledged): send
		 * the same request again once the resource is done.
		 */
		s->busy_retries++;
		LOG_INF("sync: resource buffers busy, request again when free");
		s->pending = SYNC_PEND_REQUEST;
		return;
	}
	if (status != 0) {
		LOG_WRN("sync request failed: %d", status);
		fail(c, status);
		return;
	}
	s->busy_retries = 0;

	switch (s->phase) {
	case SYNC_LISTING:
		err = on_list(c, resp, len);
		if (err) {
			fail(c, err);
		} else {
			request_next(c);
		}
		break;
	case SYNC_FETCHING:
		err = on_messages(c, resp, len);
		if (err) {
			fail(c, err);
			break;
		}
		if (s->n_acks > 0) {
			request_ack(c);
		} else {
			request_next(c);
		}
		break;
	case SYNC_ACKING:
		s->acked_since_list += s->n_acks;
		s->n_acks = 0;
		request_next(c);
		break;
	default:
		break;
	}
}

static void sync_link(enum ret_link_event ev, int reason, void *user)
{
	struct ret_client *c = user;
	struct lxmf_sync *s = &c->sync;

	if (!s->active) {
		return;
	}
	if (ev == RET_LINK_EVT_ACTIVE) {
		LOG_INF("sync: link to the propagation node is up");
		s->pending = SYNC_PEND_IDENTIFY;
		return;
	}

	/* CLOSED or FAILED: the sync ends here. */
	int status = s->status;

	if (status == 0 && (ev == RET_LINK_EVT_FAILED || s->phase != SYNC_CLOSING)) {
		status = reason != 0 ? reason : -ECONNRESET;
	}
	ret_lxmf_sync_cb_t cb = s->cb;
	void *cb_user = s->user;
	unsigned int received = s->received;

	memset(s, 0, sizeof(*s));
	LOG_INF("sync done: %d, %u message(s)", status, received);
	if (cb != NULL) {
		cb(status, received, cb_user);
	}
}

void ret_lxmf_sync_drv_start(struct ret_client *c, const struct send_req *r)
{
	struct lxmf_sync *s = &c->sync;
	struct send_req open = { .kind = REQ_LINK_OPEN, .link_cb = sync_link, .user = c };
	int err = 0;

	if (s->active) {
		err = -EALREADY;
	} else if (c->state != RET_STATE_CONNECTED || c->connecting) {
		err = -ENOTCONN;
	} else if (c->out.l.state != LINK_NONE) {
		err = -EBUSY;
	}
	if (err) {
		if (r->sync_cb != NULL) {
			r->sync_cb(err, 0, r->user);
		}
		return;
	}

	memset(s, 0, sizeof(*s));
	s->active = true;
	s->cb = r->sync_cb;
	s->user = r->user;
	s->phase = SYNC_LINKING;
	memcpy(open.dest_hash, r->dest_hash, RET_DEST_HASH_LEN);
	/* Not inside a link callback: the driver can be called directly. */
	ret_link_drv_open(c, &open);
}

void ret_lxmf_sync_drv_service(struct ret_client *c)
{
	struct lxmf_sync *s = &c->sync;
	/* static: client thread only, and kept off its stack. */
	static struct send_req req = {
		.kind = REQ_LINK_REQUEST,
		.path = GET_PATH,
		.response_cb = sync_response,
	};
	enum sync_pending p = s->pending;

	if (!s->active || p == SYNC_PEND_NONE) {
		return;
	}
	s->pending = SYNC_PEND_NONE;

	if (!owns_link(c)) {
		return; /* gone: its callback ends (or ended) the sync */
	}
	if (p == SYNC_PEND_REQUEST && c->res.state != RES_IDLE) {
		s->pending = p; /* its response could not be received yet */
		return;
	}
	switch (p) {
	case SYNC_PEND_IDENTIFY:
		ret_link_drv_identify(c);
		request_list(c);
		break;
	case SYNC_PEND_REQUEST:
		req.user = c;
		req.len = (uint16_t)s->req_len;
		memcpy(req.data, s->req, s->req_len);
		ret_link_drv_request(c, &req);
		break;
	case SYNC_PEND_CLOSE:
		ret_link_drv_close(c);
		break;
	default:
		break;
	}
}

int64_t ret_lxmf_sync_drv_next_event(const struct ret_client *c)
{
	const struct lxmf_sync *s = &c->sync;

	if (!s->active || s->pending == SYNC_PEND_NONE) {
		return INT64_MAX;
	}
	/* A request waits for the resource buffers: the resource's own
	 * deadlines and packets wake the loop.
	 */
	return (s->pending == SYNC_PEND_REQUEST && c->res.state != RES_IDLE) ? INT64_MAX : 0;
}

bool ret_lxmf_sync_drv_owns_link(const struct ret_client *c)
{
	return c->sync.active;
}
