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

static bool seen(const struct ret_client *c, const uint8_t hash[RET_SHA256_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(c->lxmf_recent); i++) {
		if (memcmp(c->lxmf_recent[i], hash, RET_SHA256_LEN) == 0) {
			return true;
		}
	}
	return false;
}

void ret_lxmf_drv_on_data(struct ret_client *c, const uint8_t *plain, size_t len)
{
	struct ret_lxmf_msg m;
	const struct ret_destination *d;
	const uint8_t *sig_pub;
	bool verified = false;

	/* Opportunistic delivery: the packet holds packed[16:], the
	 * destination being our own address.
	 */
	if (ret_lxmf_unpack(c->local_dest, plain, len, &m) != 0) {
		LOG_WRN("malformed LXMF message");
		return;
	}
	if (seen(c, m.hash)) {
		LOG_DBG("repeated LXMF message");
		return;
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
			return;
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

	memcpy(c->lxmf_recent[c->lxmf_recent_next], m.hash, RET_SHA256_LEN);
	c->lxmf_recent_next = (c->lxmf_recent_next + 1) % ARRAY_SIZE(c->lxmf_recent);

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
