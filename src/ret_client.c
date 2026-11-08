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
#include <time.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/clock.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/socket.h>
#include <zephyr/zvfs/eventfd.h>

#include <ret/ret_client.h>

#include "ret_announce.h"
#include "ret_client_internal.h"
#include "ret_crypto.h"
#include "ret_destinations.h"
#include "ret_hdlc.h"
#include "ret_identity.h"
#include "ret_packet.h"
#include "ret_receipt.h"
#include "ret_storage.h"
#include "ret_tcp.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

/* A connection up this long counts as healthy for backoff purposes. */
#define STABLE_CONNECTION_MS (10 * MSEC_PER_SEC)

BUILD_ASSERT(RET_MAX_PAYLOAD == RET_ENCRYPTED_MDU);
BUILD_ASSERT(RET_DEST_HASH_LEN == RET_TRUNC_HASH_LEN);
BUILD_ASSERT(RET_PACKET_HASH_LEN == RET_HASH_LEN);
BUILD_ASSERT(RET_MAX_PAYLOAD <= RET_LINK_MDU);

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
	case RET_STATE_SUSPENDED:
		return "SUSPENDED";
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
		ret_link_drv_on_path(c, d);
	}
	if (c->cfg.on_lxmf != NULL) {
		ret_lxmf_drv_on_announce(c, d);
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


int64_t ret_client_wall_now(void)
{
	struct timespec now;

	if (sys_clock_gettime(SYS_CLOCK_REALTIME, &now) != 0 ||
	    now.tv_sec < RET_WALL_CLOCK_VALID_S) {
		return 0;
	}
	return (int64_t)now.tv_sec;
}

#if defined(CONFIG_RET_RATCHETS)
static void log_ratchet(const char *what, const uint8_t id[RET_RATCHET_ID_LEN])
{
	char hex[2 * RET_RATCHET_ID_LEN + 1];

	bin2hex(id, RET_RATCHET_ID_LEN, hex, sizeof(hex));
	LOG_INF("%s ratchet %s", what, hex);
}

static bool ratchet_key_used(const struct ret_client *c, uint16_t key)
{
	for (size_t i = 0; i < c->n_ratchets; i++) {
		if (c->ratchets[i].key == key) {
			return true;
		}
	}
	return false;
}

/**
 * Make a new newest ratchet, created at @p now (0: clock not set). It is
 * stored before anything uses it, so no announce ever carries a ratchet
 * a reboot could lose: senders keep encrypting to the last one they
 * heard. When the set is full it replaces the oldest, in place.
 */
static int ratchet_add(struct ret_client *c, int64_t now)
{
	struct ret_storage_ratchet r = {
		.created = (uint64_t)now,
		.seq = c->n_ratchets > 0 ? c->ratchets[0].seq + 1 : 1,
	};
	uint8_t pub[RET_RATCHET_LEN];
	uint8_t id[RET_RATCHET_ID_LEN];
	size_t keep = MIN(c->n_ratchets, (size_t)CONFIG_RET_RATCHET_COUNT - 1);
	int err = ret_random(r.prv, sizeof(r.prv));

	if (!err) {
		ret_x25519_public_key(pub, r.prv);
		err = ret_ratchet_id(pub, id);
	}
	if (!err) {
		if (keep < c->n_ratchets) {
			r.key = c->ratchets[keep].key;
		} else {
			/* The smallest record number not in use. */
			while (ratchet_key_used(c, r.key)) {
				r.key++;
			}
		}
		err = ret_storage_save_ratchet(&r);
	}
	if (err) {
		ret_wipe(&r, sizeof(r));
		return err;
	}

	if (keep < c->n_ratchets) {
		ret_wipe(&c->ratchets[keep], sizeof(c->ratchets[keep]));
	}
	memmove(&c->ratchets[1], &c->ratchets[0], keep * sizeof(c->ratchets[0]));
	memmove(&c->ratchet_ids[1], &c->ratchet_ids[0], keep * sizeof(c->ratchet_ids[0]));
	c->ratchets[0] = r;
	memcpy(c->ratchet_ids[0], id, sizeof(id));
	memcpy(c->ratchet_pub, pub, sizeof(pub));
	c->n_ratchets = keep + 1;
	ret_wipe(&r, sizeof(r));
	log_ratchet("new", id);
	return 0;
}

/**
 * Rotate when the newest ratchet is older than RET_RATCHET_INTERVAL_S.
 * Only with the wall clock set: a ratchet made before it was (created 0)
 * is rotated once it is. A clock a little behind the newest ratchet's
 * time rotates nothing until it passes it; one more than an interval
 * behind means that time was bogus (a wrong clock reading), which would
 * otherwise stop rotation for good, so it rotates.
 */
static int ratchet_rotate(struct ret_client *c)
{
	uint64_t now = (uint64_t)ret_client_wall_now();
	uint64_t newest = c->ratchets[0].created;
	uint64_t interval = CONFIG_RET_RATCHET_INTERVAL_S;

	if (now == 0) {
		return 0;
	}
	if (newest != 0 && now < newest) {
		if (newest - now <= interval) {
			return 0;
		}
		LOG_WRN("newest ratchet dated %llu s ahead of the clock: rotating",
			(unsigned long long)(newest - now));
	} else if (newest != 0 && now - newest < interval) {
		return 0;
	}
	return ratchet_add(c, (int64_t)now);
}

/** Load the stored ratchets, or make the first one. */
static int ratchets_setup(struct ret_client *c)
{
	uint8_t pub[RET_RATCHET_LEN];
	int err = ret_storage_load_ratchets(c->ratchets, CONFIG_RET_RATCHET_COUNT,
					    &c->n_ratchets);

	if (err) {
		LOG_ERR("stored ratchets unreadable: %d", err);
		return err;
	}
	if (c->n_ratchets == 0) {
		return ratchet_add(c, ret_client_wall_now());
	}
	for (size_t i = 0; i < c->n_ratchets && !err; i++) {
		ret_x25519_public_key(pub, c->ratchets[i].prv);
		err = ret_ratchet_id(pub, c->ratchet_ids[i]);
		if (i == 0) {
			memcpy(c->ratchet_pub, pub, sizeof(pub));
		}
	}
	if (!err) {
		log_ratchet("current", c->ratchet_ids[0]);
	}
	return err;
}
#endif /* CONFIG_RET_RATCHETS */

int ret_client_decrypt(struct ret_client *c, const uint8_t *token, size_t len, uint8_t *out,
		       size_t cap)
{
#if defined(CONFIG_RET_RATCHETS)
	/* At most 32 (Kconfig range): 128 bytes of stack on nRF. */
	const uint8_t *keys[CONFIG_RET_RATCHET_COUNT];
	int used = -1;
	int n;

	for (size_t i = 0; i < c->n_ratchets; i++) {
		keys[i] = c->ratchets[i].prv;
	}
	n = ret_local_identity_decrypt_ratchets(&c->id, keys, c->n_ratchets, token, len, out, cap,
						&used);
	if (n >= 0 && used >= 0) {
		char hex[2 * RET_RATCHET_ID_LEN + 1];

		bin2hex(c->ratchet_ids[used], RET_RATCHET_ID_LEN, hex, sizeof(hex));
		LOG_DBG("decrypted with ratchet %s", hex);
	} else if (n >= 0) {
		LOG_DBG("decrypted with the identity key");
	}
	return n;
#else
	return ret_local_identity_decrypt(&c->id, token, len, out, cap);
#endif
}

/**
 * Announce the client's destination. The announce clock is persisted
 * before use: an announce that is not newer than the last one a node has
 * seen is ignored, so a clock that went backwards over a reboot would
 * make the client unreachable until that node's path expired.
 */
static int send_announce(struct ret_client *c, uint8_t context)
{
	uint8_t random_hash[RET_RANDOM_HASH_LEN];
	const uint8_t *ratchet = NULL;
	uint64_t emitted = c->aclk + 1;
	int len;
	int err;

	/* Reschedule first, so a failure cannot make the loop spin on it. */
	if (CONFIG_RET_ANNOUNCE_INTERVAL_S > 0) {
		c->next_announce_ms =
			k_uptime_get() + (int64_t)CONFIG_RET_ANNOUNCE_INTERVAL_S * MSEC_PER_SEC;
	}

#if defined(CONFIG_RET_RATCHETS)
	/* A rotation that failed (the new ratchet could not be stored)
	 * changed nothing: announce the current one, which is stored, and
	 * try again next time. Only the rotation waits.
	 */
	err = ratchet_rotate(c);
	if (err) {
		LOG_ERR("ratchet rotation failed (%d): announcing the current one", err);
	}
	ratchet = c->ratchet_pub;
#endif

	if (emitted > c->aclk_reserved) {
		uint64_t reserve = emitted + CONFIG_RET_ANNOUNCE_CLOCK_BLOCK - 1;

		err = ret_storage_save_aclk(reserve);
		if (err) {
			return err;
		}
		c->aclk_reserved = reserve;
	}
	c->aclk = emitted;

	err = ret_random(random_hash, 5);
	if (err) {
		return err;
	}
	for (int i = 9; i >= 5; i--) {
		random_hash[i] = (uint8_t)emitted;
		emitted >>= 8;
	}

	len = ret_announce_build(&c->id, c->local_name_hash, c->local_dest, random_hash,
				 ratchet, c->app_data, c->app_data_len, context,
				 c->tx_raw, sizeof(c->tx_raw));
	if (len < 0) {
		return len;
	}
	err = ret_client_send_frame(c, (size_t)len);
	if (!err) {
		LOG_INF("announced own destination%s",
			context == RET_CONTEXT_PATH_RESPONSE ? " (path response)" : "");
	}
	return err;
}

bool ret_client_seen_packet(const struct ret_client *c, const uint8_t hash[RET_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(c->recent); i++) {
		if (memcmp(c->recent[i], hash, RET_HASH_LEN) == 0) {
			return true;
		}
	}
	return false;
}

void ret_client_remember_packet(struct ret_client *c, const uint8_t hash[RET_HASH_LEN])
{
	memcpy(c->recent[c->recent_next], hash, RET_HASH_LEN);
	c->recent_next = (c->recent_next + 1) % ARRAY_SIZE(c->recent);
}

/** DATA for the client's own destination: decrypt, deliver, prove. */
static void handle_inbound(struct ret_client *c, const struct ret_packet *pkt,
			   const uint8_t *frame, size_t len)
{
	uint8_t hash[RET_HASH_LEN];
	int n;
	int err;

	if (pkt->context != RET_CONTEXT_NONE) {
		LOG_DBG("ignoring DATA with context 0x%02x", pkt->context);
		return;
	}
	if (ret_packet_hash(frame, len, hash) != 0) {
		return;
	}

	if (ret_client_seen_packet(c, hash)) {
		/* Delivered already; prove again in case our proof was lost. */
		LOG_DBG("duplicate packet, proving again");
	} else {
		n = ret_client_decrypt(c, pkt->data, pkt->data_len, c->rx_plain,
				       sizeof(c->rx_plain));
		if (n < 0) {
			LOG_WRN("undecryptable packet for own destination: %d", n);
			return;
		}
		/* Only packets that decrypted count as seen: a forged packet
		 * must not earn a proof by being repeated.
		 */
		ret_client_remember_packet(c, hash);
		if (c->cfg.on_lxmf != NULL) {
			ret_lxmf_drv_on_data(c, c->rx_plain, (size_t)n);
		} else if (c->cfg.on_data != NULL) {
			c->cfg.on_data(c->rx_plain, (size_t)n, c->cfg.user);
		}
		ret_wipe(c->rx_plain, (size_t)n);
	}

	n = ret_proof_build(&c->id, hash, c->tx_raw, sizeof(c->tx_raw));
	err = n < 0 ? n : ret_client_send_frame(c, (size_t)n);
	if (err == -ECONNRESET) {
		c->conn_broken = true;
	} else if (err) {
		LOG_WRN("proof not sent: %d", err);
	}
}

/** A path request for the client's own destination: announce in reply. */
static void handle_path_request(struct ret_client *c, const struct ret_packet *pkt)
{
	const uint8_t *tag;
	size_t tag_len;
	int64_t now = k_uptime_get();

	if (pkt->data_len < RET_TRUNC_HASH_LEN ||
	    memcmp(pkt->data, c->local_dest, RET_TRUNC_HASH_LEN) != 0) {
		return;
	}

	/* Tag position as path_request_handler reads it: after the
	 * requesting transport ID if one is present. Tagless requests are
	 * ignored, as RNS does.
	 */
	if (pkt->data_len > 2 * RET_TRUNC_HASH_LEN) {
		tag = &pkt->data[2 * RET_TRUNC_HASH_LEN];
		tag_len = pkt->data_len - 2 * RET_TRUNC_HASH_LEN;
	} else if (pkt->data_len > RET_TRUNC_HASH_LEN) {
		tag = &pkt->data[RET_TRUNC_HASH_LEN];
		tag_len = pkt->data_len - RET_TRUNC_HASH_LEN;
	} else {
		return;
	}
	tag_len = MIN(tag_len, RET_PATH_REQUEST_TAG_LEN);

	uint8_t key[RET_PATH_REQUEST_TAG_LEN] = { 0 };

	memcpy(key, tag, tag_len);
	for (size_t i = 0; i < ARRAY_SIZE(c->path_request_tags); i++) {
		if (memcmp(c->path_request_tags[i], key, sizeof(key)) == 0) {
			return;
		}
	}
	if (c->last_path_response_ms != 0 &&
	    now - c->last_path_response_ms < CONFIG_RET_PATH_RESPONSE_INTERVAL_MS) {
		LOG_DBG("path request for own destination rate-limited");
		return;
	}

	memcpy(c->path_request_tags[c->path_request_tag_next], key, sizeof(key));
	c->path_request_tag_next = (c->path_request_tag_next + 1) % ARRAY_SIZE(c->path_request_tags);
	c->last_path_response_ms = now;

	if (send_announce(c, RET_CONTEXT_PATH_RESPONSE) == -ECONNRESET) {
		c->conn_broken = true;
	}
}

static void on_frame(const uint8_t *frame, size_t len, void *user)
{
	struct ret_client *c = user;
	struct ret_packet pkt;
	int err;

	if (c->conn_broken) {
		/* A send failed earlier in this read; the connection is gone. */
		return;
	}

	err = ret_packet_unpack(frame, len, &pkt);
	if (err) {
		LOG_DBG("dropping %zu byte frame: %d", len, err);
		return;
	}
	c->rx_packets++;

	if (pkt.dest_type == RET_DEST_LINK) {
		struct link *l = ret_link_drv_find(c, pkt.dest_hash);

		if (l != NULL) {
			ret_link_drv_on_packet(c, l, &pkt, frame, len);
			return;
		}
	}

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
	case RET_PKT_DATA:
		if (!c->has_local) {
			break;
		}
		if (pkt.dest_type == RET_DEST_SINGLE &&
		    memcmp(pkt.dest_hash, c->local_dest, RET_TRUNC_HASH_LEN) == 0) {
			handle_inbound(c, &pkt, frame, len);
		} else if (pkt.dest_type == RET_DEST_PLAIN &&
			   memcmp(pkt.dest_hash, c->path_request_dest, RET_TRUNC_HASH_LEN) == 0) {
			handle_path_request(c, &pkt);
		}
		break;
	case RET_PKT_LINKREQUEST:
		if (c->has_local && pkt.dest_type == RET_DEST_SINGLE &&
		    memcmp(pkt.dest_hash, c->local_dest, RET_TRUNC_HASH_LEN) == 0) {
			ret_link_drv_on_request(c, &pkt, frame, len);
		}
		break;
	default:
		break;
	}
}

void ret_client_on_link_data(struct ret_client *c, const uint8_t *data, size_t len)
{
	if (c->cfg.on_lxmf != NULL) {
		ret_lxmf_drv_on_direct(c, data, len);
	} else if (c->cfg.on_data != NULL) {
		c->cfg.on_data(data, len, c->cfg.user);
	}
}

static void fail_req(const struct send_req *r, enum ret_receipt_status status)
{
	static const uint8_t zero_hash[RET_HASH_LEN];

	if (r->cb != NULL) {
		r->cb(zero_hash, status, 0, r->user);
	}
}

int ret_client_send_frame(struct ret_client *c, size_t raw_len)
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

int ret_client_send_path_request(struct ret_client *c, const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
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
	err = ret_client_send_frame(c, (size_t)len);
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

	err = ret_client_send_frame(c, (size_t)len);
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

		int err = ret_client_send_path_request(c, h->req.dest_hash);

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

/* Link operations need a live connection; while connecting or
 * disconnected they fail immediately and the caller retries.
 */
static void process_link_req(struct ret_client *c, const struct send_req *r)
{
	int err = 0;

	if (c->state != RET_STATE_CONNECTED || c->connecting) {
		err = -ENOTCONN;
	} else if (ret_lxmf_sync_drv_owns_link(c) || ret_lxmf_direct_drv_owns_link(c)) {
		/* A sync or a DIRECT delivery drives the link itself; nothing
		 * queued is theirs.
		 */
		err = -EBUSY;
	}
	if (err) {
		if (r->kind == REQ_LINK_OPEN && r->link_cb != NULL) {
			r->link_cb(RET_LINK_EVT_FAILED, err, r->user);
		} else if (r->kind == REQ_LINK_REQUEST && r->response_cb != NULL) {
			r->response_cb(err, NULL, 0, r->user);
		}
		return;
	}
	switch (r->kind) {
	case REQ_LINK_OPEN:
		ret_link_drv_open(c, r);
		break;
	case REQ_LINK_REQUEST:
		ret_link_drv_request(c, r);
		break;
	case REQ_LINK_IDENTIFY:
		ret_link_drv_identify(c);
		break;
	case REQ_LINK_CLOSE:
		ret_link_drv_close(c);
		break;
	default:
		break;
	}
}

/** @return false if the connection must be dropped. */
static bool process_queue(struct ret_client *c)
{
	while (k_msgq_get(&ret_send_q, &c->req, K_NO_WAIT) == 0) {
		int err;

		switch (c->req.kind) {
		case REQ_ANNOUNCE:
			if (c->state == RET_STATE_CONNECTED &&
			    send_announce(c, RET_CONTEXT_NONE) == -ECONNRESET) {
				(void)zvfs_eventfd_write(c->efd, 1);
				return false;
			}
			continue;
		case REQ_LXMF_SYNC:
			ret_lxmf_sync_drv_start(c, &c->req);
			if (c->conn_broken) {
				(void)zvfs_eventfd_write(c->efd, 1);
				return false;
			}
			continue;
		case REQ_LINK_OPEN:
		case REQ_LINK_REQUEST:
		case REQ_LINK_IDENTIFY:
		case REQ_LINK_CLOSE:
			process_link_req(c, &c->req);
			ret_wipe(c->req.data, sizeof(c->req.data));
			if (c->conn_broken) {
				(void)zvfs_eventfd_write(c->efd, 1);
				return false;
			}
			continue;
		default:
			break;
		}
		if (c->connecting) {
			/* Released (path request included) once connected, or
			 * failed at the held-send deadline.
			 */
			err = hold(c, &c->req);
		} else if (c->state != RET_STATE_CONNECTED) {
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
	ret_link_drv_teardown(c);

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
	if (c->has_local) {
		int err = send_announce(c, RET_CONTEXT_NONE);

		if (err == -ECONNRESET) {
			return;
		}
		if (err) {
			LOG_ERR("announce failed: %d", err);
		}
	}

	for (;;) {
		int64_t next = MIN(MIN(ret_receipts_next_deadline(), held_next_event(c)),
				   MIN(silence_deadline(c), c->next_announce_ms));

		next = MIN(next, ret_link_drv_next_event(c));
		next = MIN(next, ret_lxmf_sync_drv_next_event(c));
		next = MIN(next, ret_lxmf_direct_drv_next_event(c));
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
			if (atomic_get(&c->want_suspended)) {
				/* Tell the peers established links are going, rather
				 * than let them go stale. One still being set up just
				 * fails (disconnect() tears it down).
				 */
				ret_link_drv_close_all(c);
				return;
			}
		}

		if (!service_held(c) || watchdog(c)) {
			return;
		}
		ret_link_drv_service(c);
		ret_lxmf_sync_drv_service(c);
		ret_lxmf_direct_drv_service(c);
		if (c->conn_broken) {
			return;
		}
		if (c->has_local && k_uptime_get() >= c->next_announce_ms &&
		    send_announce(c, RET_CONTEXT_NONE) == -ECONNRESET) {
			return;
		}
	}
}

/** Sleep for @p ms while failing any sends queued meanwhile. */
static void backoff(struct ret_client *c, int ms)
{
	struct zsock_pollfd pfd = { .fd = c->efd, .events = ZSOCK_POLLIN };
	int64_t until = k_uptime_get() + ms;

	while (k_uptime_get() < until && !atomic_get(&c->want_suspended)) {
		int64_t next = MIN(until, held_next_event(c));

		if (zsock_poll(&pfd, 1, poll_timeout_ms(next)) > 0) {
			drain_eventfd(c);
			(void)process_queue(c);
		}
		(void)service_held(c);
	}
}

/**
 * Connect to the server without blocking the thread: wait for each
 * non-blocking connect alongside the eventfd and the held-send deadlines,
 * so queued sends are answered and held sends expire on time even while
 * a connect over LTE takes tens of seconds. Tries each resolved address
 * in turn (an IPv6 result may be unreachable on an IPv4-only bearer).
 *
 * @return connected fd, or -errno
 */
static int connect_serviced_inner(struct ret_client *c);

static int connect_serviced(struct ret_client *c)
{
	int fd;

	c->connecting = true;
	fd = connect_serviced_inner(c);
	c->connecting = false;
	return fd;
}

static int connect_serviced_inner(struct ret_client *c)
{
	static struct ret_tcp_addrs addrs;
	int err = ret_tcp_resolve(c->host, c->port, &addrs);

	if (err) {
		return err;
	}

	for (int i = 0; i < addrs.count; i++) {
		bool in_progress;
		int fd = ret_tcp_connect_start(&addrs, i, &in_progress);
		int64_t deadline = k_uptime_get() + CONFIG_RET_CONNECT_TIMEOUT_MS;

		if (fd < 0) {
			err = fd;
			continue;
		}
		/* An earlier address's failure must not condemn this attempt,
		 * which may already have connected.
		 */
		err = 0;

		while (in_progress) {
			struct zsock_pollfd fds[2] = {
				{ .fd = fd, .events = ZSOCK_POLLOUT },
				{ .fd = c->efd, .events = ZSOCK_POLLIN },
			};
			int n = zsock_poll(fds, ARRAY_SIZE(fds),
					   poll_timeout_ms(MIN(deadline, held_next_event(c))));

			if (n < 0 && errno != EINTR) {
				err = -errno;
				break;
			}
			if (n > 0 && (fds[1].revents & ZSOCK_POLLIN)) {
				drain_eventfd(c);
				(void)process_queue(c); /* holds sends until connected */
			}
			(void)service_held(c);
			if (atomic_get(&c->want_suspended)) {
				zsock_close(fd);
				return -ECANCELED;
			}

			if (n > 0 && (fds[0].revents & (ZSOCK_POLLOUT | ZSOCK_POLLERR |
							ZSOCK_POLLHUP))) {
				err = ret_tcp_connect_finish(fd);
				in_progress = false;
			} else if (k_uptime_get() >= deadline) {
				err = -ETIMEDOUT;
				in_progress = false;
			}
		}
		if (err == 0) {
			return fd;
		}
		zsock_close(fd);
		LOG_DBG("address %d of %d failed: %d", i + 1, addrs.count, err);
	}
	return err;
}

/* Suspended: no socket, no timers. Waiting sends cannot complete, so they
 * fail now; requests that arrive fail as they come (not connected).
 */
static void suspended(struct ret_client *c)
{
	struct zsock_pollfd pfd = { .fd = c->efd, .events = ZSOCK_POLLIN };

	for (size_t i = 0; i < ARRAY_SIZE(c->held); i++) {
		if (c->held[i].used) {
			free_held(&c->held[i], RET_RECEIPT_DISCONNECTED, true);
		}
	}
	ret_lxmf_sync_drv_abort_waiting(c, -ECONNRESET);
	ret_lxmf_direct_drv_fail_all(c, RET_RECEIPT_DISCONNECTED);
	set_state(c, RET_STATE_SUSPENDED);
	while (atomic_get(&c->want_suspended)) {
		if (zsock_poll(&pfd, 1, -1) > 0) {
			drain_eventfd(c);
			(void)process_queue(c);
			ret_lxmf_direct_drv_fail_all(c, RET_RECEIPT_FAILED);
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
		if (atomic_get(&c->want_suspended)) {
			suspended(c);
			delay_s = 1;
		}
		set_state(c, (c->state == RET_STATE_DISCONNECTED || c->state == RET_STATE_SUSPENDED)
				     ? RET_STATE_CONNECTING
				     : RET_STATE_RECONNECTING);
		LOG_INF("connecting to %s:%u", c->host, c->port);

		c->sock = connect_serviced(c);
		if (c->sock == -ECANCELED) {
			c->sock = -1;
			continue; /* suspended mid-connect */
		}
		if (c->sock < 0) {
			LOG_WRN("connect failed: %d, retry in %d s", c->sock, delay_s);
			c->sock = -1;
			backoff(c, delay_s * MSEC_PER_SEC);
			delay_s = MIN(delay_s * 2, CONFIG_RET_RECONNECT_BACKOFF_MAX_S);
			continue;
		}

		if (atomic_get(&c->want_suspended)) {
			/* Connected at once, but a suspend came meanwhile. */
			zsock_close(c->sock);
			c->sock = -1;
			continue;
		}

		c->rx_packets = 0;
		int64_t connected_at = k_uptime_get();

		set_state(c, RET_STATE_CONNECTED);
		run_connected(c);
		disconnect(c);
		if (atomic_get(&c->want_suspended)) {
			continue;
		}
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

/** Load (or create and store) the identity behind the client's address. */
static int setup_local(struct ret_client *c)
{
	uint8_t prv[RET_PRVKEY_LEN];
	bool have_id;
	int err;

	if (c->app_data_len >
	    RET_MTU - RET_H1_HEADER_LEN - 148 - (IS_ENABLED(CONFIG_RET_RATCHETS) ? RET_RATCHET_LEN : 0)) {
		LOG_ERR("announce_app_data of %zu bytes does not fit an announce",
			c->app_data_len);
		return -EMSGSIZE;
	}

	err = ret_storage_load(prv, &have_id, &c->aclk_reserved);
	if (err) {
		return err;
	}
	/* Every value up to the reservation may have been used already. */
	c->aclk = c->aclk_reserved;
	if (have_id) {
		err = ret_local_identity_load(&c->id, prv);
	} else {
		err = ret_local_identity_generate(&c->id, prv);
		if (!err) {
			/* Ratchets left from an identity that is gone. */
			err = ret_storage_clear_ratchets();
		}
		if (!err) {
			err = ret_storage_save_identity(prv);
		}
		if (!err) {
			LOG_INF("created new identity");
		}
	}
	ret_wipe(prv, sizeof(prv));
	if (!err) {
		err = ret_name_hash(c->dest_name, c->local_name_hash);
	}
	if (!err) {
		err = ret_dest_hash(c->local_name_hash, c->id.hash, c->local_dest);
	}
	if (!err) {
		err = ret_plain_dest_hash("rnstransport.path.request", c->path_request_dest);
	}
#if defined(CONFIG_RET_RATCHETS)
	if (!err) {
		err = ratchets_setup(c);
	}
#endif
	if (err) {
		ret_wipe(&c->id, sizeof(c->id));
#if defined(CONFIG_RET_RATCHETS)
		ret_wipe(c->ratchets, sizeof(c->ratchets));
		c->n_ratchets = 0;
#endif
		return err;
	}

	c->has_local = true;
	LOG_INF("own destination %s: %02x%02x%02x%02x%02x%02x%02x%02x"
		"%02x%02x%02x%02x%02x%02x%02x%02x",
		c->dest_name, c->local_dest[0], c->local_dest[1], c->local_dest[2],
		c->local_dest[3], c->local_dest[4], c->local_dest[5], c->local_dest[6],
		c->local_dest[7], c->local_dest[8], c->local_dest[9], c->local_dest[10],
		c->local_dest[11], c->local_dest[12], c->local_dest[13], c->local_dest[14],
		c->local_dest[15]);
	return 0;
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

	c->next_announce_ms = INT64_MAX;
	c->dest_name = c->cfg.dest_name;
	c->app_data = c->cfg.announce_app_data;
	c->app_data_len = c->cfg.announce_app_data_len;
	if (c->cfg.on_lxmf != NULL) {
		err = ret_lxmf_drv_setup(c);
		if (err) {
			LOG_ERR("LXMF configuration invalid: %d", err);
			zsock_close(c->efd);
			c->efd = -1;
			return err;
		}
	}
	if (c->dest_name != NULL) {
		err = setup_local(c);
		if (!err && c->cfg.on_lxmf != NULL) {
			err = ret_lxmf_drv_load(c);
		}
		if (err) {
			LOG_ERR("own destination setup failed: %d", err);
			zsock_close(c->efd);
			c->efd = -1;
			return err;
		}
	}

	ret_lxmf_direct_drv_init(c);
	k_thread_create(&ret_thread, ret_stack, K_THREAD_STACK_SIZEOF(ret_stack), client_thread,
			c, NULL, NULL, CONFIG_RET_THREAD_PRIORITY, 0, K_NO_WAIT);
	k_thread_name_set(&ret_thread, "ret_client");
	c->started = true;
	return 0;
}

void ret_client_wake(struct ret_client *c)
{
	(void)zvfs_eventfd_write(c->efd, 1);
}

int ret_client_send(struct ret_client *c, const uint8_t dest_hash[RET_DEST_HASH_LEN],
		    const uint8_t *data, size_t len, ret_receipt_cb_t cb, void *user)
{
	struct send_req r = {
		.kind = REQ_SEND,
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

int ret_client_dest_hash(const struct ret_client *c, uint8_t out[RET_DEST_HASH_LEN])
{
	if (!c->started || !c->has_local) {
		return -ENOENT;
	}
	memcpy(out, c->local_dest, RET_DEST_HASH_LEN);
	return 0;
}

int ret_client_announce(struct ret_client *c)
{
	struct send_req r = { .kind = REQ_ANNOUNCE };

	if (!c->started || !c->has_local) {
		return -ENOENT;
	}
	if (k_msgq_put(&ret_send_q, &r, K_NO_WAIT) != 0) {
		return -EAGAIN;
	}
	(void)zvfs_eventfd_write(c->efd, 1);
	return 0;
}

static int queue_req(struct ret_client *c, const struct send_req *r)
{
	if (!c->started) {
		return -ENOTCONN;
	}
	if (k_msgq_put(&ret_send_q, r, K_NO_WAIT) != 0) {
		return -EAGAIN;
	}
	(void)zvfs_eventfd_write(c->efd, 1);
	return 0;
}

int ret_client_link_open(struct ret_client *c, const uint8_t dest_hash[RET_DEST_HASH_LEN],
			 ret_link_cb_t cb, void *user)
{
	struct send_req r = { .kind = REQ_LINK_OPEN, .link_cb = cb, .user = user };

	memcpy(r.dest_hash, dest_hash, RET_DEST_HASH_LEN);
	return queue_req(c, &r);
}

int ret_client_link_request(struct ret_client *c, const char *path, const uint8_t *data_mp,
			    size_t len, ret_link_response_cb_t cb, void *user)
{
	/* Must fit one request packet: [float64, bin16, data] in RET_LINK_MDU. */
	struct send_req r = { .kind = REQ_LINK_REQUEST, .response_cb = cb, .user = user };
	size_t path_len = path != NULL ? strlen(path) : 0;

	if (path_len == 0 || path_len > RET_LINK_PATH_MAX) {
		return -EINVAL;
	}
	if (len > RET_LINK_MDU - 32) {
		return -EMSGSIZE;
	}
	memcpy(r.path, path, path_len + 1);
	if (data_mp != NULL && len > 0) {
		memcpy(r.data, data_mp, len);
		r.len = (uint16_t)len;
	}
	return queue_req(c, &r);
}

int ret_client_link_identify(struct ret_client *c)
{
	struct send_req r = { .kind = REQ_LINK_IDENTIFY };

	if (!c->has_local) {
		return -ENOENT;
	}
	return queue_req(c, &r);
}

int ret_client_link_close(struct ret_client *c)
{
	struct send_req r = { .kind = REQ_LINK_CLOSE };

	return queue_req(c, &r);
}

int ret_lxmf_sync(struct ret_client *c, const uint8_t node_hash[RET_DEST_HASH_LEN],
		  ret_lxmf_sync_cb_t cb, void *user)
{
	struct send_req r = { .kind = REQ_LXMF_SYNC, .sync_cb = cb, .user = user };

	if (!c->started) {
		return -ENOTCONN;
	}
	if (c->cfg.on_lxmf == NULL) {
		return -EINVAL;
	}
	memcpy(r.dest_hash, node_hash, RET_DEST_HASH_LEN);
	return queue_req(c, &r);
}

int ret_client_suspend(struct ret_client *c)
{
	if (!c->started) {
		return -ENOTCONN;
	}
	atomic_set(&c->want_suspended, 1);
	(void)zvfs_eventfd_write(c->efd, 1);
	return 0;
}

int ret_client_resume(struct ret_client *c)
{
	if (!c->started) {
		return -ENOTCONN;
	}
	atomic_set(&c->want_suspended, 0);
	(void)zvfs_eventfd_write(c->efd, 1);
	return 0;
}
