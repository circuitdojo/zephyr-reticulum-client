/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * LXMF on the client: the lxmf.delivery destination, inbound messages
 * (parsed and verified on the client thread, where the announced keys
 * live) and opportunistic sends. The message format is in ret_lxmf.c.
 */

#include <errno.h>
#include <string.h>
#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/clock.h>

#include "ret_client_internal.h"
#include "ret_crypto.h"
#include "ret_lxmf.h"
#include "ret_lxmf_seen.h"
#include "ret_storage.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

BUILD_ASSERT(RET_LXMF_MAX_CONTENT == RET_LXMF_OPPORTUNISTIC_MAX);

/* 2020-01-01: anything earlier means the wall clock was never set. */
#define WALL_CLOCK_VALID_S 1577836800LL

int ret_lxmf_drv_setup(struct ret_client *c)
{
	int n;

	if (c->cfg.dest_name != NULL || c->cfg.announce_app_data != NULL ||
	    c->cfg.on_data != NULL) {
		return -EINVAL;
	}
	n = ret_lxmf_app_data(c->cfg.lxmf_display_name, c->lxmf_app_data,
			      sizeof(c->lxmf_app_data));
	if (n < 0) {
		return -EMSGSIZE;
	}
	c->dest_name = RET_LXMF_APP_NAME;
	c->app_data = c->lxmf_app_data;
	c->app_data_len = (size_t)n;
	return 0;
}

/* Wall-clock seconds, or 0 when the clock was never set. */
static int64_t wall_now(void)
{
	struct timespec now;

	if (sys_clock_gettime(SYS_CLOCK_REALTIME, &now) != 0 || now.tv_sec < WALL_CLOCK_VALID_S) {
		return 0;
	}
	return (int64_t)now.tv_sec;
}

int ret_lxmf_drv_load(struct ret_client *c)
{
	c->lxmf_seen = (struct ret_lxmf_seen){
		.entries = c->lxmf_seen_entries,
		.count = ARRAY_SIZE(c->lxmf_seen_entries),
		.max_age_s = CONFIG_RET_LXMF_MAX_AGE_DAYS * 86400U,
		.max_future_s = CONFIG_RET_LXMF_MAX_FUTURE_S,
	};
	return ret_storage_load_lxmf_seen(&c->lxmf_seen);
}

enum lxmf_outcome ret_lxmf_drv_deliver(struct ret_client *c, const uint8_t *body, size_t len)
{
	struct ret_lxmf_msg m;
	const struct ret_destination *d;
	const uint8_t *sig_pub;
	bool verified = false;
	bool floor_raised;
	int64_t now_s = wall_now();
	size_t slot;

	/* body = packed[16:]: the destination is our own address. */
	if (ret_lxmf_unpack(c->local_dest, body, len, &m) != 0) {
		LOG_WRN("malformed LXMF message");
		return LXMF_MALFORMED;
	}
	switch (ret_lxmf_seen_check(&c->lxmf_seen, m.hash, m.timestamp, now_s)) {
	case RET_LXMF_SEEN_DUPLICATE:
		LOG_DBG("repeated LXMF message");
		return LXMF_DUPLICATE;
	case RET_LXMF_SEEN_TOO_OLD:
		/* Older than any node keeps one, or than what we forgot. */
		LOG_WRN("refusing LXMF message from %.0f: too old to tell from a replay",
			m.timestamp);
		return LXMF_TOO_OLD;
	case RET_LXMF_SEEN_BAD_TIME:
		LOG_WRN("refusing LXMF message with timestamp %.0f: in the future", m.timestamp);
		return LXMF_TOO_OLD;
	case RET_LXMF_SEEN_NEW:
		break;
	}

	if (memcmp(m.src, c->local_dest, RET_LXMF_ADDR_LEN) == 0) {
		sig_pub = &c->id.pub[RET_X25519_LEN];
	} else {
		d = ret_destinations_find(m.src);
		sig_pub = d != NULL ? &d->pub[RET_X25519_LEN] : NULL;
	}
	if (sig_pub != NULL) {
		if (!ret_lxmf_verify(&m, sig_pub)) {
			LOG_WRN("dropping LXMF message with an invalid signature");
			return LXMF_BAD_SIGNATURE;
		}
		verified = true;
	} else {
		/* Its announce brings the key for later messages. At most one
		 * such path request per interval: source addresses cost a
		 * sender nothing.
		 */
		int64_t now = k_uptime_get();

		LOG_INF("LXMF message from an unknown sender: unverified");
		if (c->lxmf_last_path_request_ms == 0 ||
		    now - c->lxmf_last_path_request_ms >= CONFIG_RET_PATH_REQUEST_INTERVAL_MS) {
			c->lxmf_last_path_request_ms = now;
			if (ret_client_send_path_request(c, m.src) == -ECONNRESET) {
				c->conn_broken = true;
			}
		}
	}

	/* Remembered (and persisted) before delivery: a crash in between
	 * loses the message rather than delivering it twice. If the save
	 * fails it is still delivered (remembered in RAM until reboot):
	 * losing mail is worse than a replay window after a flash fault.
	 */
	slot = ret_lxmf_seen_add(&c->lxmf_seen, m.hash, m.timestamp, now_s, verified,
				 &floor_raised);
	if (slot != RET_LXMF_SEEN_NOT_STORED) {
		(void)ret_storage_save_lxmf_seen(&c->lxmf_seen, slot, floor_raised);
	}

	struct ret_lxmf_message out = {
		.timestamp = m.timestamp,
		.title = m.title,
		.title_len = m.title_len,
		.content = m.content,
		.content_len = m.content_len,
		.fields = m.fields,
		.fields_len = m.fields_len,
		.verified = verified,
	};

	memcpy(out.source, m.src, sizeof(out.source));
	memcpy(out.hash, m.hash, sizeof(out.hash));
	c->cfg.on_lxmf(&out, c->cfg.user);
	return LXMF_DELIVERED;
}

void ret_lxmf_drv_on_data(struct ret_client *c, const uint8_t *plain, size_t len)
{
	(void)ret_lxmf_drv_deliver(c, plain, len);
}

int ret_lxmf_send(struct ret_client *c, const uint8_t dest_hash[RET_DEST_HASH_LEN],
		  const uint8_t *title, size_t title_len, const uint8_t *content,
		  size_t content_len, ret_receipt_cb_t cb, void *user)
{
	uint8_t packed[RET_LXMF_ADDR_LEN + RET_MAX_PAYLOAD];
	uint8_t hash[RET_SHA256_LEN];
	struct timespec now;
	int n;
	int err;

	if (!c->started) {
		return -ENOTCONN;
	}
	if (c->cfg.on_lxmf == NULL || !c->has_local) {
		return -EINVAL;
	}
	if (title_len > RET_LXMF_MAX_CONTENT || content_len > RET_LXMF_MAX_CONTENT - title_len) {
		return -EMSGSIZE;
	}
	if (sys_clock_gettime(SYS_CLOCK_REALTIME, &now) != 0 || now.tv_sec < WALL_CLOCK_VALID_S) {
		LOG_WRN("LXMF send refused: wall clock not set (SYS_CLOCK_REALTIME)");
		return -ENODATA;
	}

	/* The identity and address are fixed once the client started, so
	 * signing here, off the client thread, reads no changing state.
	 */
	n = ret_lxmf_pack(&c->id, c->local_dest, dest_hash,
			  (double)now.tv_sec + (double)now.tv_nsec / 1e9, title, title_len, content,
			  content_len, packed, sizeof(packed), hash);
	if (n < 0) {
		return n == -ENOBUFS ? -EMSGSIZE : n;
	}
	LOG_DBG("LXMF message %02x%02x%02x%02x.. to %02x%02x%02x%02x..", hash[0], hash[1], hash[2],
		hash[3], dest_hash[0], dest_hash[1], dest_hash[2], dest_hash[3]);

	err = ret_client_send(c, dest_hash, &packed[RET_LXMF_ADDR_LEN],
			      (size_t)n - RET_LXMF_ADDR_LEN, cb, user);
	ret_wipe(packed, sizeof(packed));
	return err;
}
