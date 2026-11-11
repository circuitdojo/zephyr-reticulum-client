/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
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

BUILD_ASSERT(RET_LXMF_OPPORTUNISTIC_MAX_CONTENT == RET_LXMF_OPPORTUNISTIC_MAX);
/* DIRECT carries more than one opportunistic packet, or it has no point. */
BUILD_ASSERT(CONFIG_RET_LXMF_DIRECT_POOL == 0 ||
		     RET_LXMF_DIRECT_MAX_CONTENT > RET_LXMF_OPPORTUNISTIC_MAX_CONTENT,
	     "RET_LXMF_DIRECT_POOL / RET_RESOURCE_MAX_SIZE too small for DIRECT");

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

/* The lxmf.delivery address a public key gives. */
static bool address_matches(const struct ret_client *c, const uint8_t dest[RET_TRUNC_HASH_LEN],
			    const uint8_t pub[RET_PUBKEY_LEN])
{
	uint8_t id_hash[RET_TRUNC_HASH_LEN];
	uint8_t want[RET_TRUNC_HASH_LEN];

	return ret_identity_hash(pub, id_hash) == 0 &&
	       ret_dest_hash(c->local_name_hash, id_hash, want) == 0 &&
	       memcmp(want, dest, RET_TRUNC_HASH_LEN) == 0;
}

static int load_known(struct ret_client *c)
{
	static struct ret_storage_known stored[CONFIG_RET_LXMF_KNOWN_SENDERS];
	int err = ret_storage_load_known(stored, ARRAY_SIZE(stored));

	memset(c->lxmf_known, 0, sizeof(c->lxmf_known));
	c->lxmf_known_seq = 0;
	for (size_t i = 0; !err && i < ARRAY_SIZE(stored); i++) {
		struct lxmf_known *k = &c->lxmf_known[i];

		if (stored[i].seq == 0) {
			continue;
		}
		/* The address binds the key: a record that disagrees is junk. */
		if (!address_matches(c, stored[i].dest, stored[i].pub)) {
			LOG_WRN("stored LXMF sender %u does not match its key: ignored",
				(unsigned int)i);
			continue;
		}
		k->used = true;
		memcpy(k->dest, stored[i].dest, sizeof(k->dest));
		memcpy(k->pub, stored[i].pub, sizeof(k->pub));
		k->seq = stored[i].seq;
		c->lxmf_known_seq = MAX(c->lxmf_known_seq, k->seq);
	}
	return err;
}

int ret_lxmf_drv_load(struct ret_client *c)
{
	int err;

	c->lxmf_seen = (struct ret_lxmf_seen){
		.entries = c->lxmf_seen_entries,
		.count = ARRAY_SIZE(c->lxmf_seen_entries),
		.max_age_s = CONFIG_RET_LXMF_MAX_AGE_DAYS * 86400U,
		.max_future_s = CONFIG_RET_LXMF_MAX_FUTURE_S,
	};
	err = ret_storage_load_lxmf_seen(&c->lxmf_seen);
	return err ? err : load_known(c);
}

static struct lxmf_known *known_find(struct ret_client *c, const uint8_t *dest)
{
	for (size_t i = 0; i < ARRAY_SIZE(c->lxmf_known); i++) {
		if (c->lxmf_known[i].used &&
		    memcmp(c->lxmf_known[i].dest, dest, RET_TRUNC_HASH_LEN) == 0) {
			return &c->lxmf_known[i];
		}
	}
	return NULL;
}

/* A verified message from a known sender: it goes to the back of the
 * eviction order (in RAM only: no flash write per message; the stored
 * order applies again after a reboot).
 */
static void known_touch(struct ret_client *c, const uint8_t *dest)
{
	struct lxmf_known *k = known_find(c, dest);

	if (k != NULL) {
		k->seq = ++c->lxmf_known_seq;
	}
}

/* Keep a sender's key across reboots (once: the address binds the key). */
static void known_store(struct ret_client *c, const uint8_t *dest, const uint8_t *pub)
{
	size_t slot = 0;

	if (known_find(c, dest) != NULL) {
		known_touch(c, dest);
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(c->lxmf_known); i++) {
		if (!c->lxmf_known[i].used) {
			slot = i;
			break;
		}
		if (c->lxmf_known[i].seq < c->lxmf_known[slot].seq) {
			slot = i;
		}
	}

	struct lxmf_known *k = &c->lxmf_known[slot];
	struct ret_storage_known rec = { .seq = ++c->lxmf_known_seq };

	k->used = true;
	memcpy(k->dest, dest, sizeof(k->dest));
	memcpy(k->pub, pub, sizeof(k->pub));
	k->seq = rec.seq;
	memcpy(rec.dest, k->dest, sizeof(rec.dest));
	memcpy(rec.pub, k->pub, sizeof(rec.pub));
	(void)ret_storage_save_known(slot, &rec);
	LOG_INF("keeping the key of LXMF sender %02x%02x%02x%02x..", dest[0], dest[1], dest[2],
		dest[3]);
}

void ret_lxmf_drv_on_announce(struct ret_client *c, const struct ret_destination *d)
{
	if (memcmp(d->name_hash, c->local_name_hash, RET_NAME_HASH_LEN) != 0) {
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(c->lxmf_wanted); i++) {
		if (memcmp(c->lxmf_wanted[i], d->dest_hash, RET_TRUNC_HASH_LEN) == 0) {
			memset(c->lxmf_wanted[i], 0, RET_TRUNC_HASH_LEN);
			known_store(c, d->dest_hash, d->pub);
		}
	}
}

enum lxmf_outcome ret_lxmf_drv_deliver(struct ret_client *c, const uint8_t *body, size_t len)
{
	struct ret_lxmf_msg m;
	const struct ret_destination *d = NULL;
	const uint8_t *sig_pub;
	bool verified = false;
	bool floor_raised;
	int64_t now_s = ret_client_wall_now();
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
		struct lxmf_known *k = NULL;

		/* Announced this session, else kept from an earlier one. */
		d = ret_destinations_find(m.src);
		if (d == NULL) {
			k = known_find(c, m.src);
		}
		sig_pub = d != NULL ? &d->pub[RET_X25519_LEN]
			  : k != NULL ? &k->pub[RET_X25519_LEN]
				      : NULL;
	}
	if (sig_pub != NULL) {
		if (!ret_lxmf_verify(&m, sig_pub)) {
			LOG_WRN("dropping LXMF message with an invalid signature");
			return LXMF_BAD_SIGNATURE;
		}
		verified = true;
		if (d != NULL) {
			known_store(c, m.src, d->pub);
		} else {
			known_touch(c, m.src);
		}
	} else {
		/* Keep its key when the announce in reply to our request comes. */
		bool waiting = false;

		for (size_t i = 0; i < ARRAY_SIZE(c->lxmf_wanted); i++) {
			waiting |= memcmp(c->lxmf_wanted[i], m.src, RET_TRUNC_HASH_LEN) == 0;
		}
		if (!waiting) {
			memcpy(c->lxmf_wanted[c->lxmf_wanted_next], m.src, RET_TRUNC_HASH_LEN);
			c->lxmf_wanted_next = (c->lxmf_wanted_next + 1) % ARRAY_SIZE(c->lxmf_wanted);
		}

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

void ret_lxmf_drv_on_direct(struct ret_client *c, const uint8_t *packed, size_t len)
{
	/* DIRECT carries the whole packed message, destination included. */
	if (len <= RET_LXMF_ADDR_LEN || memcmp(packed, c->local_dest, RET_LXMF_ADDR_LEN) != 0) {
		LOG_WRN("DIRECT LXMF message for another destination: dropped");
		return;
	}
	(void)ret_lxmf_drv_deliver(c, &packed[RET_LXMF_ADDR_LEN], len - RET_LXMF_ADDR_LEN);
}

void ret_lxmf_drv_on_data(struct ret_client *c, const uint8_t *plain, size_t len)
{
	(void)ret_lxmf_drv_deliver(c, plain, len);
}

static bool fits(size_t title_len, size_t content_len, size_t max)
{
	return title_len <= max && content_len <= max - title_len;
}

int ret_lxmf_send_method(struct ret_client *c, const uint8_t dest_hash[RET_DEST_HASH_LEN],
			 enum ret_lxmf_method method, const uint8_t *title, size_t title_len,
			 const uint8_t *content, size_t content_len, ret_receipt_cb_t cb,
			 void *user)
{
	uint8_t packed[RET_LXMF_ADDR_LEN + RET_MAX_PAYLOAD];
	uint8_t hash[RET_SHA256_LEN];
	struct timespec now;
	double timestamp;
	int n;
	int err;

	if (!c->started) {
		return -ENOTCONN;
	}
	if (c->cfg.on_lxmf == NULL || !c->has_local || method > RET_LXMF_METHOD_DIRECT) {
		return -EINVAL;
	}
	if (method == RET_LXMF_METHOD_AUTO) {
		/* LXMessage: opportunistic falls back to DIRECT when the
		 * content does not fit one packet.
		 */
		method = fits(title_len, content_len, RET_LXMF_OPPORTUNISTIC_MAX_CONTENT)
				 ? RET_LXMF_METHOD_OPPORTUNISTIC
				 : RET_LXMF_METHOD_DIRECT;
		if (method == RET_LXMF_METHOD_DIRECT && CONFIG_RET_LXMF_DIRECT_POOL == 0) {
			return -EMSGSIZE;
		}
	} else if (method == RET_LXMF_METHOD_DIRECT && CONFIG_RET_LXMF_DIRECT_POOL == 0) {
		return -ENOTSUP;
	}
	if (!fits(title_len, content_len,
		  method == RET_LXMF_METHOD_OPPORTUNISTIC ? RET_LXMF_OPPORTUNISTIC_MAX_CONTENT
							  : RET_LXMF_DIRECT_MAX_CONTENT)) {
		return -EMSGSIZE;
	}
	if (sys_clock_gettime(SYS_CLOCK_REALTIME, &now) != 0 || now.tv_sec < RET_WALL_CLOCK_VALID_S) {
		LOG_WRN("LXMF send refused: wall clock not set (SYS_CLOCK_REALTIME)");
		return -ENODATA;
	}
	timestamp = (double)now.tv_sec + (double)now.tv_nsec / 1e9;

	/* The identity and address are fixed once the client started, so
	 * signing here, off the client thread, reads no changing state.
	 */
	if (method == RET_LXMF_METHOD_DIRECT) {
		err = ret_lxmf_direct_queue(c, dest_hash, timestamp, title, title_len, content,
					    content_len, cb, user);
		if (!err) {
			ret_client_wake(c);
		}
		return err;
	}

	n = ret_lxmf_pack(&c->id, c->local_dest, dest_hash, timestamp, title, title_len, content,
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

int ret_lxmf_send(struct ret_client *c, const uint8_t dest_hash[RET_DEST_HASH_LEN],
		  const uint8_t *title, size_t title_len, const uint8_t *content,
		  size_t content_len, ret_receipt_cb_t cb, void *user)
{
	return ret_lxmf_send_method(c, dest_hash, RET_LXMF_METHOD_AUTO, title, title_len, content,
				    content_len, cb, user);
}
