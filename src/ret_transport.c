/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * Transport node behaviour of RNS 1.5.7 (RNS/Transport.py with
 * enable_transport, RNS/Interfaces/Interface.py): comments name the RNS
 * code each part follows. Differences are listed in docs/protocol.md.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "ret_announce.h"
#include "ret_crypto.h"
#include "ret_link.h"
#include "ret_transport.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

#define MS_PER_DAY (24LL * 3600 * 1000)

#define PATHFINDER_M           128
#define PATHFINDER_R           1
#define PATHFINDER_G_MS        5000
#define PATHFINDER_RW_MS       500
#define LOCAL_REBROADCASTS_MAX 2
#define PATHFINDER_E_MS        (7 * MS_PER_DAY)
#define AP_PATH_TIME_MS        MS_PER_DAY
#define ROAMING_PATH_TIME_MS   (6LL * 3600 * 1000)
#define PATH_REQUEST_TIMEOUT_MS 15000
#define PATH_REQUEST_GATE_MS   45000
#define PATH_REQUEST_GRACE_MS  400
#define PATH_REQUEST_RG_MS     1500
#define PATH_REQUEST_MI_MS     20000
#define LINK_TIMEOUT_MS        900000
#define REVERSE_TIMEOUT_MS     480000
#define PER_HOP_TIMEOUT_MS     6000
#define AR_TARGET_MS           3600000
#define AR_GRACE               5
#define AR_PENALTY_MS          0
#define QUEUED_ANNOUNCE_LIFE_MS (3LL * 3600 * 1000)
#define DEFAULT_IFAC_SIZE      16

/* Ingress control (Interface.IC_*), frequencies in mHz. */
#define IC_NEW_TIME_MS         (2LL * 3600 * 1000)
#define IC_BURST_FREQ_NEW      3000
#define IC_BURST_FREQ          10000
#define IC_PR_BURST_FREQ_NEW   3000
#define IC_PR_BURST_FREQ       8000
#define IC_BURST_HOLD_MS       15000
#define IC_BURST_PENALTY_MS    15000
#define IC_HELD_RELEASE_MS     5000
#define IC_DEQUE_MIN_SAMPLE    2
#define FREQ_DECAY_MS          10000

#define JOB_INTERVAL_MS        250
#define ANNOUNCES_CHECK_MS     1000
#define TABLES_CULL_MS         5000
#define IFACE_JOBS_MS          5000
#define DISCOVERY_PR_THROTTLE_MS 500

#define CTX_CACHE_REQUEST 0x08
#define CTX_CHANNEL       0x0E

#define FLAG_IFAC 0x80
#define LINK_MODE_DEFAULT RET_LINK_MODE_AES256_CBC
#define LRPROOF_LEN       (RET_SIG_LEN + RET_X25519_LEN)

/* Bytes before the destination hash: flags, hops and (H2) a transport ID. */
#define H2_PREFIX (2 + RET_TRUNC_HASH_LEN)

/* A packet we originate (Transport._outbound, no-path branch). */
struct outpkt {
	const uint8_t *raw;
	size_t len;
	uint8_t packet_type;
	const uint8_t *dest_hash;
	uint8_t hops;
	/* Interface index, or -1 for all. */
	int attached;
	uint64_t emitted;
};

static void process(struct ret_transport *t, struct ret_transport_iface *iface,
		    const uint8_t *raw, size_t len, bool ingress_limited);

static struct ret_transport_iface *iface_at(struct ret_transport *t, uint8_t idx)
{
	return idx < t->n_ifaces ? t->ifaces[idx] : NULL;
}

static uint32_t rand_below(uint32_t n)
{
	uint32_t r = 0;

	(void)ret_random((uint8_t *)&r, sizeof(r));
	return n ? r % n : 0;
}

static bool hash_eq(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, RET_TRUNC_HASH_LEN) == 0;
}

static bool is_ours(struct ret_transport *t, const uint8_t id[RET_TRUNC_HASH_LEN])
{
	return hash_eq(id, t->identity->hash);
}

/* Time on air of @p len bytes divided by the announce cap (Transport._outbound). */
static int64_t announce_wait_ms(const struct ret_transport_iface *iface, size_t len)
{
	uint64_t cap = iface->announce_cap ? iface->announce_cap : 200;

	if (iface->bitrate == 0) {
		return 0;
	}
	return (int64_t)(((uint64_t)len * 8 * MSEC_PER_SEC * 10000) / ((uint64_t)iface->bitrate * cap));
}

/* Transport.medium_path_timeout(): a round trip for an MTU on the slowest interface. */
static int64_t medium_path_timeout_ms(struct ret_transport *t)
{
	uint32_t lowest = 0;

	for (uint8_t i = 0; i < t->n_ifaces; i++) {
		uint32_t b = t->ifaces[i]->online ? t->ifaces[i]->bitrate : 0;

		if (b && (lowest == 0 || b < lowest)) {
			lowest = b;
		}
	}
	if (lowest == 0) {
		return 0;
	}
	return (int64_t)(2ULL * RET_MTU * 8 * MSEC_PER_SEC / MAX(lowest, 5)) + PER_HOP_TIMEOUT_MS;
}

/* --- Packet hash list and path request tags (two halves, rotated) --- */

static bool hash_seen(struct ret_transport *t, const uint8_t h[RET_TRUNC_HASH_LEN])
{
	for (int k = 0; k < 2; k++) {
		for (uint16_t i = 0; i < t->hash_count[k]; i++) {
			if (hash_eq(t->hashes[k][i], h)) {
				return true;
			}
		}
	}
	return false;
}

static void hash_add(struct ret_transport *t, const uint8_t h[RET_TRUNC_HASH_LEN])
{
	uint8_t cur = t->hash_cur;

	if (hash_seen(t, h)) {
		return;
	}
	if (t->hash_count[cur] == CONFIG_RET_TRANSPORT_HASHLIST) {
		/* packet_hashlist_prev = packet_hashlist; packet_hashlist = set() */
		cur ^= 1;
		t->hash_cur = cur;
		t->hash_count[cur] = 0;
	}
	memcpy(t->hashes[cur][t->hash_count[cur]++], h, RET_TRUNC_HASH_LEN);
}

static bool tag_add(struct ret_transport *t, const uint8_t tag[RET_TRANSPORT_PR_TAG_LEN])
{
	uint8_t cur = t->tag_cur;

	for (int k = 0; k < 2; k++) {
		for (uint16_t i = 0; i < t->tag_count[k]; i++) {
			if (memcmp(t->tags[k][i], tag, RET_TRANSPORT_PR_TAG_LEN) == 0) {
				return false;
			}
		}
	}
	if (t->tag_count[cur] == CONFIG_RET_TRANSPORT_PR_TAGS) {
		cur ^= 1;
		t->tag_cur = cur;
		t->tag_count[cur] = 0;
	}
	memcpy(t->tags[cur][t->tag_count[cur]++], tag, RET_TRANSPORT_PR_TAG_LEN);
	return true;
}

/* --- Paths: RAM cache over the store --- */

/* How long a path lasts, by the mode of the interface it came in on. */
static int64_t path_ttl_ms(int mode)
{
	return mode == RET_IFACE_MODE_ACCESS_POINT ? AP_PATH_TIME_MS
	       : mode == RET_IFACE_MODE_ROAMING    ? ROAMING_PATH_TIME_MS
						   : PATHFINDER_E_MS;
}

/*
 * A path written in another boot: its times mean nothing now. Treat it as
 * just heard, so it lasts its full time again.
 */
static bool normalize(struct ret_transport *t, struct ret_transport_path_meta *m)
{
	if (m->boot == t->boot) {
		return false;
	}
	m->boot = t->boot;
	m->timestamp = t->now;
	m->expires = t->now + path_ttl_ms((int)t->ifaces[m->iface]->mode);
	m->rate_last = t->now;
	m->rate_blocked_until = 0;
	return true;
}

/* Stored metadata is checked before use: flash can be corrupt or from another build. */
static bool meta_valid(const struct ret_transport *t, const struct ret_transport_path_meta *m)
{
	return m->iface < t->n_ifaces && m->n_blobs <= CONFIG_RET_TRANSPORT_RANDOM_BLOBS &&
	       m->hops <= PATHFINDER_M && m->state <= RET_PATH_STATE_RESPONSIVE;
}

static struct ret_transport_path *path_find_ram(struct ret_transport *t,
						const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(t->paths); i++) {
		if (t->paths[i].used && hash_eq(t->paths[i].m.dest_hash, dest_hash)) {
			return &t->paths[i];
		}
	}
	return NULL;
}

static void path_save(struct ret_transport *t, struct ret_transport_path *p, const uint8_t *raw,
		      size_t len)
{
	int err = t->store->save(t->store, &p->m, raw, len);

	if (err) {
		LOG_WRN("transport: path not stored: %d", err);
	}
	p->dirty = false;
}

/*
 * A free RAM slot, else the least recently used. That one stays in the
 * store, updated first if it was used since it was stored.
 */
static struct ret_transport_path *path_slot(struct ret_transport *t)
{
	struct ret_transport_path *lru = &t->paths[0];

	for (size_t i = 0; i < ARRAY_SIZE(t->paths); i++) {
		if (!t->paths[i].used) {
			return &t->paths[i];
		}
		if (t->paths[i].last_used < lru->last_used) {
			lru = &t->paths[i];
		}
	}
	if (lru->dirty) {
		path_save(t, lru, NULL, 0);
	}
	lru->used = false;
	return lru;
}

/*
 * The path to @p dest_hash, from RAM or the store. The pointer is valid
 * until the next lookup of another destination.
 */
static struct ret_transport_path *path_get(struct ret_transport *t,
					   const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_path_meta m;
	struct ret_transport_path *p = path_find_ram(t, dest_hash);
	bool renewed;

	if (p) {
		p->last_used = t->now;
		return p;
	}
	if (t->store->load(t->store, dest_hash, &m, NULL, 0, NULL) != 0) {
		return NULL;
	}
	if (!meta_valid(t, &m) || !hash_eq(m.dest_hash, dest_hash)) {
		LOG_WRN("transport: invalid stored path, removed");
		(void)t->store->remove(t->store, dest_hash);
		return NULL;
	}
	renewed = normalize(t, &m);
	p = path_slot(t);
	p->used = true;
	p->dirty = false;
	p->last_used = t->now;
	p->m = m;
	if (renewed) {
		path_save(t, p, NULL, 0);
	}
	return p;
}

static void path_remove(struct ret_transport *t, struct ret_transport_path *p)
{
	(void)t->store->remove(t->store, p->m.dest_hash);
	p->used = false;
}

/*
 * The store lost a path's announce (its own eviction): without it the path
 * can't be announced, answered or used to check link proofs, so drop it.
 */
static void path_lost(struct ret_transport *t, const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_path *p = path_find_ram(t, dest_hash);

	if (p) {
		LOG_DBG("transport: stored announce gone, path dropped");
		path_remove(t, p);
	}
}

/* The stored announce for @p dest_hash, unpacked into @p pkt (in t->stored). */
static int stored_announce(struct ret_transport *t, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
			   struct ret_packet *pkt)
{
	struct ret_transport_path_meta m;
	size_t len = 0;
	int err;

	err = t->store->load(t->store, dest_hash, &m, t->stored, sizeof(t->stored), &len);
	if (err == -ENOENT) {
		path_lost(t, dest_hash);
	}
	if (err) {
		return err;
	}
	err = ret_packet_unpack(t->stored, len, pkt);
	if (err) {
		return err;
	}
	return pkt->packet_type == RET_PKT_ANNOUNCE && hash_eq(pkt->dest_hash, dest_hash) ? 0
											  : -EBADMSG;
}

static int iface_mode_of_path(struct ret_transport *t, const struct ret_transport_path *p)
{
	struct ret_transport_iface *i = p ? iface_at(t, p->m.iface) : NULL;

	return i ? (int)i->mode : -1;
}

/* --- Small tables --- */

static struct ret_transport_announce *announce_find(struct ret_transport *t,
						    const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(t->announces); i++) {
		if (t->announces[i].used && hash_eq(t->announces[i].dest_hash, dest_hash)) {
			return &t->announces[i];
		}
	}
	return NULL;
}

static struct ret_transport_announce *announce_slot(struct ret_transport *t,
						    const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_announce *a = announce_find(t, dest_hash);
	struct ret_transport_announce *oldest = NULL;

	if (a) {
		return a;
	}
	for (size_t i = 0; i < ARRAY_SIZE(t->announces); i++) {
		a = &t->announces[i];
		if (!a->used) {
			goto fresh;
		}
		if (!oldest || a->e.timestamp < oldest->e.timestamp) {
			oldest = a;
		}
	}
	LOG_DBG("transport: announce table full, dropping the oldest");
	a = oldest;
fresh:
	memset(a, 0, sizeof(*a));
	a->used = true;
	memcpy(a->dest_hash, dest_hash, RET_TRUNC_HASH_LEN);
	return a;
}

static struct ret_transport_link *link_find(struct ret_transport *t,
					    const uint8_t link_id[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(t->links); i++) {
		if (t->links[i].used && hash_eq(t->links[i].link_id, link_id)) {
			return &t->links[i];
		}
	}
	return NULL;
}

static struct ret_transport_link *link_slot(struct ret_transport *t,
					    const uint8_t link_id[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_link *l = link_find(t, link_id);
	struct ret_transport_link *oldest = &t->links[0];

	if (l) {
		return l;
	}
	for (size_t i = 0; i < ARRAY_SIZE(t->links); i++) {
		if (!t->links[i].used) {
			return &t->links[i];
		}
		if (t->links[i].timestamp < oldest->timestamp) {
			oldest = &t->links[i];
		}
	}
	LOG_DBG("transport: link table full, dropping the oldest");
	return oldest;
}

static struct ret_transport_reverse *reverse_find(struct ret_transport *t,
						  const uint8_t hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(t->reverse); i++) {
		if (t->reverse[i].used && hash_eq(t->reverse[i].hash, hash)) {
			return &t->reverse[i];
		}
	}
	return NULL;
}

static void reverse_add(struct ret_transport *t, const uint8_t hash[RET_TRUNC_HASH_LEN],
			uint8_t rcvd, uint8_t out)
{
	struct ret_transport_reverse *r = reverse_find(t, hash);

	for (size_t i = 0; !r && i < ARRAY_SIZE(t->reverse); i++) {
		if (!t->reverse[i].used) {
			r = &t->reverse[i];
		}
	}
	if (!r) {
		r = &t->reverse[0];
		for (size_t i = 1; i < ARRAY_SIZE(t->reverse); i++) {
			if (t->reverse[i].timestamp < r->timestamp) {
				r = &t->reverse[i];
			}
		}
		LOG_DBG("transport: reverse table full, dropping the oldest");
	}
	r->used = true;
	memcpy(r->hash, hash, RET_TRUNC_HASH_LEN);
	r->rcvd_iface = rcvd;
	r->out_iface = out;
	r->timestamp = t->now;
}

static struct ret_transport_pr *pr_find(struct ret_transport_pr *tab, size_t n,
					const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < n; i++) {
		if (tab[i].used && hash_eq(tab[i].dest_hash, dest_hash)) {
			return &tab[i];
		}
	}
	return NULL;
}

static void pr_set(struct ret_transport_pr *tab, size_t n,
		   const uint8_t dest_hash[RET_TRUNC_HASH_LEN], int64_t now)
{
	struct ret_transport_pr *p = pr_find(tab, n, dest_hash);

	for (size_t i = 0; !p && i < n; i++) {
		if (!tab[i].used) {
			p = &tab[i];
		}
	}
	if (!p) {
		p = &tab[0];
		for (size_t i = 1; i < n; i++) {
			if (tab[i].time < p->time) {
				p = &tab[i];
			}
		}
	}
	p->used = true;
	memcpy(p->dest_hash, dest_hash, RET_TRUNC_HASH_LEN);
	p->time = now;
}

#define OWN_PRS(t)  (t)->own_prs, ARRAY_SIZE((t)->own_prs)
#define INFLIGHT(t) (t)->inflight, ARRAY_SIZE((t)->inflight)

static struct ret_transport_discovery *discovery_find(struct ret_transport *t,
						      const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(t->discovery); i++) {
		if (t->discovery[i].used && hash_eq(t->discovery[i].dest_hash, dest_hash)) {
			return &t->discovery[i];
		}
	}
	return NULL;
}

static struct ret_transport_discovery *discovery_slot(struct ret_transport *t,
						      const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_discovery *d = discovery_find(t, dest_hash);

	for (size_t i = 0; !d && i < ARRAY_SIZE(t->discovery); i++) {
		if (!t->discovery[i].used) {
			d = &t->discovery[i];
			memset(d, 0, sizeof(*d));
		}
	}
	if (!d) {
		d = &t->discovery[0];
		for (size_t i = 1; i < ARRAY_SIZE(t->discovery); i++) {
			if (t->discovery[i].timeout < d->timeout) {
				d = &t->discovery[i];
			}
		}
		memset(d, 0, sizeof(*d));
	}
	d->used = true;
	memcpy(d->dest_hash, dest_hash, RET_TRUNC_HASH_LEN);
	return d;
}

/* --- Sending --- */

/* Transport.transmit(): add the access code, hand the frame to the interface. */
static void transmit(struct ret_transport *t, struct ret_transport_iface *iface,
		     const uint8_t *raw, size_t len)
{
	const uint8_t *frame = raw;
	size_t n = len;

	if (iface->ifac) {
		int r = ret_ifac_apply(iface->ifac, raw, len, t->tx, sizeof(t->tx));

		if (r < 0) {
			iface->drops++;
			return;
		}
		frame = t->tx;
		n = (size_t)r;
	}
	if (iface->send(iface, frame, n) == 0) {
		iface->tx_frames++;
	} else {
		iface->drops++;
	}
}

static void add_packet_hash(struct ret_transport *t, const uint8_t *raw, size_t len)
{
	uint8_t h[RET_HASH_LEN];

	if (ret_packet_hash(raw, len, h) == 0) {
		hash_add(t, h);
	}
}

/* Interface.process_announce_queue()'s entry: queue or refresh. */
static void queue_announce(struct ret_transport_iface *iface, const struct outpkt *p, int64_t now)
{
	struct ret_transport_queued_announce *free_slot = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(iface->queue); i++) {
		struct ret_transport_queued_announce *q = &iface->queue[i];

		if (q->used && hash_eq(q->dest_hash, p->dest_hash)) {
			if (p->emitted > q->emitted) {
				q->time = now;
				q->hops = p->hops;
				q->emitted = p->emitted;
				q->len = (uint16_t)p->len;
			}
			return;
		}
		if (!q->used && !free_slot) {
			free_slot = q;
		}
	}
	if (!free_slot) {
		LOG_DBG("transport: %s announce queue full", iface->name);
		return;
	}
	free_slot->used = true;
	memcpy(free_slot->dest_hash, p->dest_hash, RET_TRUNC_HASH_LEN);
	free_slot->time = now;
	free_slot->hops = p->hops;
	free_slot->emitted = p->emitted;
	free_slot->len = (uint16_t)p->len;
}

static bool queue_empty(const struct ret_transport_iface *iface)
{
	for (size_t i = 0; i < ARRAY_SIZE(iface->queue); i++) {
		if (iface->queue[i].used) {
			return false;
		}
	}
	return true;
}

/* Interfaces in Transport.prioritize_interfaces() order: fastest first. */
static void iface_order(struct ret_transport *t, uint8_t order[CONFIG_RET_TRANSPORT_MAX_IFACES])
{
	for (uint8_t i = 0; i < t->n_ifaces; i++) {
		uint8_t j = i;

		while (j > 0 && t->ifaces[order[j - 1]]->bitrate < t->ifaces[i]->bitrate) {
			order[j] = order[j - 1];
			j--;
		}
		order[j] = i;
	}
}

/*
 * Transport._outbound() for packets we originate, which never take the
 * path table branch (announces, and PLAIN path requests and tunnel
 * synthesis): send on the attached interface or on all, applying the mode
 * rules and the announce cap to announces sent on all.
 */
static void outbound(struct ret_transport *t, const struct outpkt *p)
{
	uint8_t order[CONFIG_RET_TRANSPORT_MAX_IFACES];
	bool stored_hash = false;

	if (p->hops > PATHFINDER_M - 1) {
		return;
	}
	iface_order(t, order);
	for (uint8_t k = 0; k < t->n_ifaces; k++) {
		struct ret_transport_iface *iface = t->ifaces[order[k]];
		bool send = true;

		if (!iface->online || (p->attached >= 0 && iface->index != p->attached)) {
			continue;
		}
		if (p->packet_type == RET_PKT_ANNOUNCE && p->attached < 0) {
			int from = iface_mode_of_path(t, path_get(t, p->dest_hash));

			if (from < 0) {
				send = false;
			} else if (iface->mode == RET_IFACE_MODE_ACCESS_POINT) {
				send = false;
			} else if (iface->mode == RET_IFACE_MODE_INTERNAL) {
				send = from != RET_IFACE_MODE_BOUNDARY;
			} else if (iface->mode == RET_IFACE_MODE_ROAMING) {
				send = from != RET_IFACE_MODE_ROAMING && from != RET_IFACE_MODE_BOUNDARY;
			} else if (iface->mode == RET_IFACE_MODE_BOUNDARY) {
				send = from != RET_IFACE_MODE_ROAMING;
			} else if (p->hops > 0) {
				if (queue_empty(iface) && t->now > iface->announce_allowed_at &&
				    iface->bitrate) {
					iface->announce_allowed_at = t->now + announce_wait_ms(iface, p->len);
				} else {
					send = false;
					queue_announce(iface, p, t->now);
				}
			}
		}
		if (send) {
			if (!stored_hash) {
				add_packet_hash(t, p->raw, p->len);
				stored_hash = true;
			}
			transmit(t, iface, p->raw, p->len);
		}
	}
}

/* An announce as a transport node sends it: HEADER_2 with our transport ID. */
static int build_announce(struct ret_transport *t, const struct ret_packet *src, uint8_t hops,
			  uint8_t context)
{
	struct ret_packet p = {
		.header_type = RET_HEADER_2,
		.context_flag = src->context_flag,
		.transport_type = RET_TRANSPORT_TRANSPORT,
		.dest_type = RET_DEST_SINGLE,
		.packet_type = RET_PKT_ANNOUNCE,
		.hops = hops,
		.context = context,
		.data = src->data,
		.data_len = src->data_len,
	};

	memcpy(p.transport_id, t->identity->hash, RET_TRUNC_HASH_LEN);
	memcpy(p.dest_hash, src->dest_hash, RET_TRUNC_HASH_LEN);
	return ret_packet_pack(&p, t->build, sizeof(t->build));
}

static void send_announce(struct ret_transport *t, const struct ret_packet *src, uint8_t hops,
			  uint8_t context, int attached)
{
	int n = build_announce(t, src, hops, context);
	struct outpkt o = {
		.raw = t->build,
		.packet_type = RET_PKT_ANNOUNCE,
		.dest_hash = src->dest_hash,
		.hops = hops,
		.attached = attached,
	};

	if (n < 0) {
		/* Packet.pack() refuses an announce that no longer fits. */
		LOG_DBG("transport: announce too long to rebroadcast");
		return;
	}
	o.len = (size_t)n;
	o.emitted = ret_announce_emitted(&src->data[RET_PUBKEY_LEN + RET_NAME_HASH_LEN]);
	outbound(t, &o);
}

/* Transport.request_path() as a transport node. */
static void request_path(struct ret_transport *t, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
			 int on_iface, const uint8_t *tag, size_t tag_len, bool recursive)
{
	uint8_t data[2 * RET_TRUNC_HASH_LEN + RET_PATH_REQUEST_TAG_LEN];
	struct ret_packet pkt = {
		.header_type = RET_HEADER_1,
		.transport_type = RET_TRANSPORT_BROADCAST,
		.dest_type = RET_DEST_PLAIN,
		.packet_type = RET_PKT_DATA,
		.context = RET_CONTEXT_NONE,
		.data = data,
	};
	struct outpkt o = {
		.raw = t->build,
		.packet_type = RET_PKT_DATA,
		.dest_hash = t->pr_dest,
		.attached = on_iface,
	};
	int n;

	memcpy(data, dest_hash, RET_TRUNC_HASH_LEN);
	memcpy(&data[RET_TRUNC_HASH_LEN], t->identity->hash, RET_TRUNC_HASH_LEN);
	if (tag) {
		tag_len = MIN(tag_len, RET_PATH_REQUEST_TAG_LEN);
		memcpy(&data[2 * RET_TRUNC_HASH_LEN], tag, tag_len);
	} else {
		tag_len = RET_PATH_REQUEST_TAG_LEN;
		if (ret_random(&data[2 * RET_TRUNC_HASH_LEN], tag_len)) {
			return;
		}
	}
	pkt.data_len = 2 * RET_TRUNC_HASH_LEN + tag_len;
	memcpy(pkt.dest_hash, t->pr_dest, RET_TRUNC_HASH_LEN);

	if (on_iface >= 0 && recursive) {
		struct ret_transport_iface *iface = iface_at(t, (uint8_t)on_iface);

		if (!queue_empty(iface) || t->now < iface->announce_allowed_at) {
			return;
		}
		iface->announce_allowed_at =
			t->now + announce_wait_ms(iface, pkt.data_len + RET_H1_HEADER_LEN);
	}
	n = ret_packet_pack(&pkt, t->build, sizeof(t->build));
	if (n < 0) {
		return;
	}
	o.len = (size_t)n;
	pr_set(OWN_PRS(t), dest_hash, t->now);
	outbound(t, &o);
}

/* --- Ingress control (Interface.should_ingress_limit etc.) --- */

static void freq_add(struct ret_transport_freq *f, int64_t now)
{
	f->t[f->head] = now;
	f->head = (f->head + 1) % RET_TRANSPORT_FREQ_SAMPLES;
	if (f->count < RET_TRANSPORT_FREQ_SAMPLES) {
		f->count++;
	}
}

/* Interface.incoming_announce_frequency(), in mHz. */
static uint32_t freq_mhz(struct ret_transport_freq *f, int64_t now)
{
	uint8_t n = f->count;
	int64_t oldest;
	int64_t span;

	if (n <= IC_DEQUE_MIN_SAMPLE) {
		return 0;
	}
	oldest = f->t[(f->head + RET_TRANSPORT_FREQ_SAMPLES - n) % RET_TRANSPORT_FREQ_SAMPLES];
	span = now - oldest;
	if (span > FREQ_DECAY_MS) {
		f->count--;
	}
	if (span <= 0) {
		return 0;
	}
	return (uint32_t)(((uint64_t)n * 1000 * 1000) / (uint64_t)span);
}

static bool iface_new(const struct ret_transport *t, const struct ret_transport_iface *iface)
{
	return t->now - iface->created < IC_NEW_TIME_MS;
}

static bool should_ingress_limit(struct ret_transport *t, struct ret_transport_iface *iface)
{
	uint32_t threshold = iface_new(t, iface) ? IC_BURST_FREQ_NEW : IC_BURST_FREQ;
	uint32_t freq = freq_mhz(&iface->ia_freq, t->now);

	if (iface->ic_burst_active) {
		if (freq < threshold && t->now > iface->ic_burst_activated + IC_BURST_HOLD_MS &&
		    t->now > iface->ic_burst_sustained + IC_BURST_HOLD_MS) {
			if (iface->ia_freq.count >= IC_DEQUE_MIN_SAMPLE) {
				iface->ic_burst_active = false;
			}
		} else if (freq >= threshold) {
			iface->ic_burst_sustained = t->now;
		}
		return true;
	}
	if (freq > threshold) {
		iface->ic_burst_active = true;
		iface->ic_burst_activated = t->now;
		iface->ic_burst_sustained = t->now;
		iface->ic_held_release = t->now + IC_BURST_PENALTY_MS;
		return true;
	}
	return false;
}

static bool should_ingress_limit_pr(struct ret_transport *t, struct ret_transport_iface *iface)
{
	uint32_t threshold = iface_new(t, iface) ? IC_PR_BURST_FREQ_NEW : IC_PR_BURST_FREQ;
	uint32_t freq = freq_mhz(&iface->ip_freq, t->now);

	if (iface->ic_pr_burst_active) {
		if (freq < threshold && t->now > iface->ic_pr_burst_activated + IC_BURST_HOLD_MS &&
		    t->now > iface->ic_pr_burst_sustained + IC_BURST_HOLD_MS) {
			if (iface->ic_pr_burst_cooldown == 0) {
				iface->ic_pr_burst_active = false;
			} else {
				iface->ic_pr_burst_cooldown--;
			}
		} else {
			iface->ic_pr_burst_cooldown = 3;
			if (freq >= threshold) {
				iface->ic_pr_burst_sustained = t->now;
			}
		}
		return true;
	}
	if (freq > threshold) {
		iface->ic_pr_burst_active = true;
		iface->ic_pr_burst_activated = t->now;
		iface->ic_pr_burst_sustained = t->now;
		iface->ic_pr_burst_cooldown = 3;
		return true;
	}
	return false;
}

static void hold_announce(struct ret_transport_iface *iface, const uint8_t *raw, size_t len,
			  const struct ret_packet *pkt)
{
	struct ret_transport_held_announce *slot = NULL;

	if (pkt->hops >= PATHFINDER_M - 1 || len > sizeof(slot->raw)) {
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(iface->held); i++) {
		if (iface->held[i].used && hash_eq(iface->held[i].dest_hash, pkt->dest_hash)) {
			slot = &iface->held[i];
			break;
		}
	}
	for (size_t i = 0; !slot && i < ARRAY_SIZE(iface->held); i++) {
		if (!iface->held[i].used) {
			slot = &iface->held[i];
		}
	}
	if (!slot) {
		return;
	}
	slot->used = true;
	memcpy(slot->dest_hash, pkt->dest_hash, RET_TRUNC_HASH_LEN);
	slot->hops = pkt->hops;
	slot->len = (uint16_t)len;
	memcpy(slot->raw, raw, len);
}

static void process_held_announces(struct ret_transport *t, struct ret_transport_iface *iface)
{
	struct ret_transport_held_announce *pick = NULL;
	uint32_t threshold = iface_new(t, iface) ? IC_BURST_FREQ_NEW : IC_BURST_FREQ;
	uint8_t min_hops = PATHFINDER_M;
	size_t len;

	bool any = false;

	for (size_t i = 0; i < ARRAY_SIZE(iface->held); i++) {
		any |= iface->held[i].used;
	}
	/* Only then the frequency: reading it decays a sample, as in RNS. */
	if (!any || t->now <= iface->ic_held_release ||
	    freq_mhz(&iface->ia_freq, t->now) >= threshold) {
		return;
	}
	for (size_t i = 0; i < ARRAY_SIZE(iface->held); i++) {
		if (iface->held[i].used && iface->held[i].hops < min_hops) {
			min_hops = iface->held[i].hops;
			pick = &iface->held[i];
		}
	}
	if (!pick) {
		return;
	}
	iface->ic_held_release = t->now + IC_HELD_RELEASE_MS;
	len = pick->len;
	memcpy(t->work, pick->raw, len);
	pick->used = false;
	process(t, iface, t->work, len, true);
}

/* --- Forwarding (Transport._inbound) --- */

static void forward_transported(struct ret_transport *t, struct ret_transport_iface *iface,
				const struct ret_packet *pkt, const uint8_t *raw, size_t len,
				const uint8_t hash[RET_HASH_LEN])
{
	struct ret_transport_path *p = path_get(t, pkt->dest_hash);
	struct ret_transport_iface *out;
	uint8_t remaining;
	size_t n;

	if (!p) {
		LOG_DBG("transport: no path for a packet addressed to us");
		return;
	}
	out = iface_at(t, p->m.iface);
	remaining = p->m.hops;

	if (remaining > 1) {
		/* Keep HEADER_2, pointed at the next transport node. */
		memcpy(t->build, raw, len);
		t->build[1] = pkt->hops;
		memcpy(&t->build[2], p->m.next_hop, RET_TRUNC_HASH_LEN);
		n = len;
	} else if (remaining == 1) {
		/* Last hop: HEADER_1 BROADCAST, the flags' low nibble kept. */
		t->build[0] = (uint8_t)((RET_HEADER_1 << 6) | (RET_TRANSPORT_BROADCAST << 4) |
					(raw[0] & 0x0F));
		t->build[1] = pkt->hops;
		memcpy(&t->build[2], &raw[H2_PREFIX], len - H2_PREFIX);
		n = len - RET_TRUNC_HASH_LEN;
	} else {
		memcpy(t->build, raw, len);
		t->build[1] = pkt->hops;
		n = len;
	}

	if (pkt->packet_type == RET_PKT_LINKREQUEST) {
		struct ret_transport_link *l;
		uint8_t link_id[RET_TRUNC_HASH_LEN];
		uint32_t path_mtu = 0;
		uint8_t mode = LINK_MODE_DEFAULT;
		int64_t extra = out->bitrate ? (int64_t)RET_MTU * 8 * MSEC_PER_SEC / out->bitrate : 0;

		if (pkt->data_len == RET_LINK_REQUEST_LEN) {
			const uint8_t *s = &pkt->data[RET_X25519_LEN + RET_ED25519_PUB_LEN];

			path_mtu = (((uint32_t)s[0] << 16) | ((uint32_t)s[1] << 8) | s[2]) &
				   RET_LINK_MTU_MASK;
		}
		if (pkt->data_len > RET_X25519_LEN + RET_ED25519_PUB_LEN) {
			mode = (pkt->data[RET_X25519_LEN + RET_ED25519_PUB_LEN] & 0xE0) >> 5;
		}
		if (path_mtu) {
			if (!out->mtu_signalling) {
				n -= RET_LINK_MTU_SIZE;
			} else if (out->hw_mtu < path_mtu || iface->hw_mtu < path_mtu) {
				if (mode != RET_LINK_MODE_AES256_CBC) {
					/* signalling_bytes() raises for a disabled mode. */
					return;
				}
				ret_link_signalling(MIN(out->hw_mtu, iface->hw_mtu), mode,
						    &t->build[n - RET_LINK_MTU_SIZE]);
			}
		}
		if (ret_link_id_from_request(raw, len, link_id)) {
			return;
		}
		l = link_slot(t, link_id);
		*l = (struct ret_transport_link){
			.used = true,
			.timestamp = t->now,
			.nh_iface = out->index,
			.remaining_hops = remaining,
			.rcvd_iface = iface->index,
			.taken_hops = pkt->hops,
			.proof_timeout =
				t->now + extra + PER_HOP_TIMEOUT_MS * MAX(1, (int)remaining),
		};
		memcpy(l->link_id, link_id, RET_TRUNC_HASH_LEN);
		memcpy(l->next_hop, p->m.next_hop, RET_TRUNC_HASH_LEN);
		memcpy(l->dest_hash, pkt->dest_hash, RET_TRUNC_HASH_LEN);
	} else {
		reverse_add(t, hash, iface->index, out->index);
	}

	transmit(t, out, t->build, n);
	p->m.timestamp = t->now;
	p->dirty = true;
}

static void forward_link(struct ret_transport *t, struct ret_transport_iface *iface,
			 struct ret_transport_link *l, const struct ret_packet *pkt,
			 const uint8_t *raw, size_t len, const uint8_t hash[RET_HASH_LEN])
{
	int out = -1;

	if (!l->validated) {
		LOG_DBG("transport: link packet before link validation");
		return;
	}
	if (l->nh_iface == l->rcvd_iface) {
		if (pkt->hops == l->remaining_hops || pkt->hops == l->taken_hops) {
			out = l->nh_iface;
		}
	} else if (iface->index == l->nh_iface) {
		if (pkt->hops == l->remaining_hops) {
			out = l->rcvd_iface;
		}
	} else if (iface->index == l->rcvd_iface) {
		if (pkt->hops == l->taken_hops) {
			out = l->nh_iface;
		}
	}
	if (out < 0) {
		return;
	}
	hash_add(t, hash);
	memcpy(t->build, raw, len);
	t->build[1] = pkt->hops;
	transmit(t, iface_at(t, (uint8_t)out), t->build, len);
	l->timestamp = t->now;
}

/* An LRPROOF's signature, by the destination's announced key (Transport._inbound). */
static bool lrproof_valid(struct ret_transport *t, const struct ret_transport_link *l,
			  const struct ret_packet *pkt)
{
	struct ret_packet ann;
	const uint8_t *d = pkt->data;
	size_t sig_n = 0;

	if (pkt->data_len != LRPROOF_LEN && pkt->data_len != LRPROOF_LEN + RET_LINK_MTU_SIZE) {
		return false;
	}
	if (pkt->data_len == LRPROOF_LEN + RET_LINK_MTU_SIZE) {
		/* signalling_bytes(mtu, mode) re-encodes the same three bytes,
		 * and raises for a disabled mode.
		 */
		if ((d[LRPROOF_LEN] >> 5) != RET_LINK_MODE_AES256_CBC) {
			return false;
		}
		sig_n = RET_LINK_MTU_SIZE;
	}
	if (stored_announce(t, l->dest_hash, &ann)) {
		return false;
	}

	const struct ret_iov iov[] = {
		{ pkt->dest_hash, RET_TRUNC_HASH_LEN },
		{ &d[RET_SIG_LEN], RET_X25519_LEN },
		{ &ann.data[RET_X25519_LEN], RET_ED25519_PUB_LEN },
		{ &d[LRPROOF_LEN], sig_n },
	};

	return ret_ed25519_verify_iov(d, &ann.data[RET_X25519_LEN], iov, ARRAY_SIZE(iov));
}

static void proof_inbound(struct ret_transport *t, struct ret_transport_iface *iface,
			  const struct ret_packet *pkt, const uint8_t *raw, size_t len)
{
	if (pkt->context == RET_CTX_LRPROOF) {
		struct ret_transport_link *l = link_find(t, pkt->dest_hash);

		if (!l) {
			return;
		}
		if (pkt->hops != l->remaining_hops && iface->index == l->nh_iface &&
		    !l->validated && lrproof_valid(t, l, pkt)) {
			/* The path rebalanced: the proof took a different number of hops. */
			struct ret_transport_path *p = path_get(t, l->dest_hash);

			l->remaining_hops = pkt->hops;
			if (p) {
				p->m.hops = pkt->hops;
				path_save(t, p, NULL, 0);
			}
		}
		if (pkt->hops == l->remaining_hops && iface->index == l->nh_iface) {
			if (!lrproof_valid(t, l, pkt)) {
				LOG_DBG("transport: invalid link request proof");
				return;
			}
			memcpy(t->build, raw, len);
			t->build[1] = pkt->hops;
			l->validated = true;
			transmit(t, iface_at(t, l->rcvd_iface), t->build, len);
		}
		return;
	}
	if (pkt->context == RET_CTX_RESOURCE_PRF) {
		return;
	}

	struct ret_transport_reverse *r = reverse_find(t, pkt->dest_hash);

	if (r) {
		uint8_t rcvd = r->rcvd_iface;
		bool from_out = iface->index == r->out_iface;

		r->used = false;
		if (from_out) {
			memcpy(t->build, raw, len);
			t->build[1] = pkt->hops;
			transmit(t, iface_at(t, rcvd), t->build, len);
		}
	}
}

/* --- Announces (Transport._inbound) --- */

static bool blob_known(const struct ret_transport_path_meta *m, const uint8_t *blob)
{
	for (uint8_t i = 0; i < m->n_blobs; i++) {
		if (memcmp(m->blobs[i], blob, RET_RANDOM_HASH_LEN) == 0) {
			return true;
		}
	}
	return false;
}

static void blob_add(struct ret_transport_path_meta *m, const uint8_t *blob)
{
	if (blob_known(m, blob)) {
		return;
	}
	if (m->n_blobs == ARRAY_SIZE(m->blobs)) {
		memmove(m->blobs[0], m->blobs[1], (ARRAY_SIZE(m->blobs) - 1) * RET_RANDOM_HASH_LEN);
		m->n_blobs--;
	}
	memcpy(m->blobs[m->n_blobs++], blob, RET_RANDOM_HASH_LEN);
}

static bool should_add(struct ret_transport *t, struct ret_transport_path *p,
		       const struct ret_packet *pkt, const uint8_t *blob)
{
	uint64_t emitted = ret_announce_emitted(blob);
	bool known_blob;

	if (!p) {
		return true;
	}
	known_blob = blob_known(&p->m, blob);
	if (pkt->hops <= p->m.hops) {
		uint64_t timebase = 0;

		for (uint8_t i = 0; i < p->m.n_blobs; i++) {
			timebase = MAX(timebase, ret_announce_emitted(p->m.blobs[i]));
		}
		if (!known_blob && emitted > timebase) {
			p->m.state = RET_PATH_STATE_UNKNOWN;
			return true;
		}
		/* Equal emission with more gravity: gravity is always 0 here. */
		return false;
	}

	/* More hops than the known path. RNS stops at the first stored blob
	 * at or after this one's emission time.
	 */
	uint64_t path_emitted = 0;

	for (uint8_t i = 0; i < p->m.n_blobs; i++) {
		path_emitted = MAX(path_emitted, ret_announce_emitted(p->m.blobs[i]));
		if (path_emitted >= emitted) {
			break;
		}
	}
	if (t->now >= p->m.expires) {
		if (!known_blob) {
			p->m.state = RET_PATH_STATE_UNKNOWN;
			return true;
		}
		return false;
	}
	if (emitted > path_emitted) {
		if (!known_blob) {
			p->m.state = RET_PATH_STATE_UNKNOWN;
			return true;
		}
		return false;
	}
	return emitted == path_emitted && p->m.state == RET_PATH_STATE_UNRESPONSIVE;
}

/* Announce rate limiting; true when the rebroadcast is blocked. */
static bool rate_blocked(struct ret_transport *t, struct ret_transport_path_meta *m)
{
	if (!m->rate_known) {
		m->rate_known = true;
		m->rate_last = t->now;
		m->rate_violations = 0;
		m->rate_blocked_until = 0;
		return false;
	}
	if (t->now <= m->rate_blocked_until) {
		return true;
	}
	if (t->now - m->rate_last < AR_TARGET_MS) {
		if (m->rate_violations < UINT8_MAX) {
			m->rate_violations++;
		}
	} else if (m->rate_violations > 0) {
		m->rate_violations--;
	}
	if (m->rate_violations > AR_GRACE) {
		m->rate_blocked_until = m->rate_last + AR_TARGET_MS + AR_PENALTY_MS;
		return true;
	}
	m->rate_last = t->now;
	return false;
}

static void announce_inbound(struct ret_transport *t, struct ret_transport_iface *iface,
			     const struct ret_packet *pkt, const uint8_t *raw, size_t len,
			     const struct ret_announce *a)
{
	struct ret_transport_path *p = path_get(t, pkt->dest_hash);
	struct ret_transport_path_meta m;
	const uint8_t *received_from = pkt->dest_hash;
	bool blocked = false;

	/* Identity.validate_announce(): a known destination keeps its key. */
	if (p) {
		struct ret_packet old;

		if (stored_announce(t, pkt->dest_hash, &old) == 0 &&
		    memcmp(old.data, a->pub, RET_PUBKEY_LEN) != 0) {
			LOG_DBG("transport: announce with a different key for a known destination");
			return;
		}
	}
	/* stored_announce() drops a path whose announce the store lost. */
	p = path_find_ram(t, pkt->dest_hash);

	if (pkt->header_type == RET_HEADER_2) {
		struct ret_transport_announce *ae = announce_find(t, pkt->dest_hash);

		received_from = pkt->transport_id;
		if (ae) {
			struct ret_transport_announce_entry e;

			/* Another node rebroadcast it at our distance. */
			if (pkt->hops - 1 == ae->e.hops) {
				ae->e.local_rebroadcasts++;
				if (ae->e.retries > 0 &&
				    ae->e.local_rebroadcasts >= LOCAL_REBROADCASTS_MAX) {
					ae->used = false;
				}
			}
			e = ae->e;
			/* Our rebroadcast was passed on: no need to repeat it. */
			if (pkt->hops - 1 == e.hops + 1 && e.retries > 0 && t->now < e.retransmit_at) {
				ae->used = false;
			}
		}
	}

	if (pkt->hops >= PATHFINDER_M + 1) {
		return;
	}
	if (!should_add(t, p, pkt, a->random_hash)) {
		return;
	}

	if (p) {
		m = p->m;
	} else {
		memset(&m, 0, sizeof(m));
		memcpy(m.dest_hash, pkt->dest_hash, RET_TRUNC_HASH_LEN);
		m.boot = t->boot;
	}

	if (pkt->context != RET_CONTEXT_PATH_RESPONSE) {
		blocked = rate_blocked(t, &m);
	}

	if (iface->mode == RET_IFACE_MODE_ACCESS_POINT) {
		m.expires = t->now + AP_PATH_TIME_MS;
	} else if (iface->mode == RET_IFACE_MODE_ROAMING) {
		m.expires = t->now + ROAMING_PATH_TIME_MS;
	} else {
		m.expires = t->now + PATHFINDER_E_MS;
	}
	blob_add(&m, a->random_hash);

	if (pkt->context != RET_CONTEXT_PATH_RESPONSE && !blocked) {
		struct ret_transport_announce *ae = announce_slot(t, pkt->dest_hash);

		ae->e = (struct ret_transport_announce_entry){
			.timestamp = t->now,
			.retransmit_at = t->now + rand_below(PATHFINDER_RW_MS),
			.retries = 0,
			.hops = pkt->hops,
			.attached = -1,
		};
	}

	/* Answer path requests waiting for this destination. */
	struct ret_transport_discovery *d = discovery_find(t, pkt->dest_hash);

	if (d) {
		uint8_t ifaces = d->ifaces;

		d->used = false;
		for (uint8_t i = 0; i < t->n_ifaces; i++) {
			if (ifaces & BIT(i)) {
				send_announce(t, pkt, pkt->hops, RET_CONTEXT_PATH_RESPONSE, i);
			}
		}
	}

	memcpy(m.next_hop, received_from, RET_TRUNC_HASH_LEN);
	m.hops = pkt->hops;
	m.iface = iface->index;
	m.timestamp = t->now;
	m.state = RET_PATH_STATE_UNKNOWN;

	/* The lookup above may have been evicted by send_announce()'s. */
	p = path_find_ram(t, pkt->dest_hash);
	if (!p) {
		p = path_slot(t);
	}
	p->used = true;
	p->last_used = t->now;
	p->m = m;
	path_save(t, p, raw, len);

	struct ret_transport_pr *inflight = pr_find(INFLIGHT(t), pkt->dest_hash);

	if (inflight) {
		inflight->used = false;
	}
}

/* --- Path requests (Transport.path_request) --- */

static void path_request(struct ret_transport *t, struct ret_transport_iface *iface,
			 const uint8_t dest_hash[RET_TRUNC_HASH_LEN], const uint8_t *requestor,
			 const uint8_t *tag, size_t tag_len, bool ingress_limited)
{
	struct ret_transport_path *p;
	bool limit = ingress_limited || should_ingress_limit_pr(t, iface);
	bool search = false;
	bool boundary_filter = false;
	bool answered = false;

	switch (iface->mode) {
	case RET_IFACE_MODE_ACCESS_POINT:
	case RET_IFACE_MODE_GATEWAY:
	case RET_IFACE_MODE_ROAMING:
	case RET_IFACE_MODE_INTERNAL:
		search = true;
		break;
	case RET_IFACE_MODE_BOUNDARY:
		search = true;
		boundary_filter = true;
		break;
	default:
		break;
	}

	p = path_get(t, dest_hash);
	if (p) {
		struct ret_packet ann;

		if (stored_announce(t, dest_hash, &ann) != 0) {
			/* Dropped by stored_announce(): search as for an unknown path. */
			p = NULL;
		}
	}
	if (p) {
		answered = true;
		if (iface->mode == RET_IFACE_MODE_ROAMING && iface->index == p->m.iface) {
			/* Not back out the roaming interface it came from. */
		} else if (requestor && hash_eq(requestor, p->m.next_hop)) {
			/* The requestor is our next hop: it knows the path already. */
		} else {
			struct ret_transport_announce *ae = announce_find(t, dest_hash);
			struct ret_transport_announce_entry held = { 0 };
			bool has_held = false;
			int64_t rtx = t->now + PATH_REQUEST_GRACE_MS;

			if (iface->mode == RET_IFACE_MODE_ROAMING) {
				rtx += PATH_REQUEST_RG_MS;
			}
			if (ae) {
				held = ae->e;
				has_held = true;
			}
			ae = announce_slot(t, dest_hash);
			ae->e = (struct ret_transport_announce_entry){
				.timestamp = t->now,
				.retransmit_at = rtx,
				.retries = PATHFINDER_R,
				.hops = p->m.hops,
				.block_rebroadcasts = true,
				.attached = (int8_t)iface->index,
			};
			ae->has_held = has_held;
			ae->held = held;
		}
	} else if (search) {
		struct ret_transport_discovery *d = discovery_find(t, dest_hash);

		if (d && d->engaged) {
			/* Already searching. */
		} else if (limit) {
			return;
		} else {
			uint8_t prev = d ? d->ifaces : 0;
			uint8_t order[CONFIG_RET_TRANSPORT_MAX_IFACES];

			d = discovery_slot(t, dest_hash);
			d->engaged = true;
			d->ifaces = prev | BIT(iface->index);
			d->timeout = t->now + MAX(PATH_REQUEST_TIMEOUT_MS, medium_path_timeout_ms(t));
			iface_order(t, order);
			for (uint8_t k = 0; k < t->n_ifaces; k++) {
				struct ret_transport_iface *o = t->ifaces[order[k]];

				if (boundary_filter && o->mode != RET_IFACE_MODE_BOUNDARY &&
				    o->mode != RET_IFACE_MODE_GATEWAY) {
					continue;
				}
				if (o->online && o != iface) {
					request_path(t, dest_hash, o->index, tag, tag_len, true);
				}
			}
		}
	}

	if (answered) {
		struct ret_transport_pr *inflight = pr_find(INFLIGHT(t), dest_hash);

		if (inflight) {
			inflight->used = false;
		}
	}
}

static void path_request_handler(struct ret_transport *t, struct ret_transport_iface *iface,
				 const struct ret_packet *pkt, bool ingress_limited)
{
	const uint8_t *d = pkt->data;
	size_t n = pkt->data_len;
	const uint8_t *requestor = NULL;
	const uint8_t *tag = NULL;
	size_t tag_len = 0;

	if (n < RET_TRUNC_HASH_LEN) {
		return;
	}
	if (n > 2 * RET_TRUNC_HASH_LEN) {
		requestor = &d[RET_TRUNC_HASH_LEN];
		tag = &d[2 * RET_TRUNC_HASH_LEN];
		tag_len = n - 2 * RET_TRUNC_HASH_LEN;
	} else if (n > RET_TRUNC_HASH_LEN) {
		tag = &d[RET_TRUNC_HASH_LEN];
		tag_len = n - RET_TRUNC_HASH_LEN;
	}
	if (!tag) {
		return;
	}
	path_request(t, iface, d, requestor, tag, MIN(tag_len, RET_PATH_REQUEST_TAG_LEN),
		     ingress_limited);
}

/* --- Inbound (Transport.preprocess_inbound, packet_filter, _inbound) --- */

static bool packet_filter(struct ret_transport *t, const struct ret_packet *pkt,
			  const uint8_t hash[RET_HASH_LEN])
{
	if (pkt->header_type == RET_HEADER_2 && pkt->packet_type != RET_PKT_ANNOUNCE &&
	    !is_ours(t, pkt->transport_id)) {
		return false;
	}
	switch (pkt->context) {
	case RET_CTX_KEEPALIVE:
	case RET_CTX_RESOURCE_REQ:
	case RET_CTX_RESOURCE_PRF:
	case RET_CTX_RESOURCE:
	case CTX_CACHE_REQUEST:
	case CTX_CHANNEL:
		return true;
	default:
		break;
	}
	if (pkt->dest_type == RET_DEST_PLAIN || pkt->dest_type == RET_DEST_GROUP) {
		/* Never transported; announces are SINGLE only. */
		return pkt->packet_type != RET_PKT_ANNOUNCE && pkt->hops <= 1;
	}
	if (!hash_seen(t, hash)) {
		return true;
	}
	/* A repeated announce still counts towards rebroadcast detection. */
	return pkt->packet_type == RET_PKT_ANNOUNCE && pkt->dest_type == RET_DEST_SINGLE;
}

static void inbound(struct ret_transport *t, struct ret_transport_iface *iface,
		    const struct ret_packet *pkt, const uint8_t *raw, size_t len,
		    const uint8_t hash[RET_HASH_LEN], bool ingress_limited,
		    const struct ret_announce *a)
{
	struct ret_transport_link *l = link_find(t, pkt->dest_hash);

	if (!iface->online) {
		return;
	}
	if (!l && !(pkt->packet_type == RET_PKT_PROOF && pkt->context == RET_CTX_LRPROOF)) {
		hash_add(t, hash);
	}

	if (pkt->header_type == RET_HEADER_2 && pkt->packet_type != RET_PKT_ANNOUNCE) {
		forward_transported(t, iface, pkt, raw, len, hash);
		l = link_find(t, pkt->dest_hash);
	}

	if (pkt->packet_type != RET_PKT_ANNOUNCE && pkt->packet_type != RET_PKT_LINKREQUEST &&
	    pkt->context != RET_CTX_LRPROOF && l) {
		forward_link(t, iface, l, pkt, raw, len, hash);
		return;
	}

	switch (pkt->packet_type) {
	case RET_PKT_ANNOUNCE:
		announce_inbound(t, iface, pkt, raw, len, a);
		break;
	case RET_PKT_DATA:
		if (pkt->dest_type == RET_DEST_PLAIN && hash_eq(pkt->dest_hash, t->pr_dest)) {
			path_request_handler(t, iface, pkt, ingress_limited);
		}
		break;
	case RET_PKT_PROOF:
		proof_inbound(t, iface, pkt, raw, len);
		break;
	default:
		/* Link requests for local destinations: we have none. */
		break;
	}
}

static void process(struct ret_transport *t, struct ret_transport_iface *iface,
		    const uint8_t *raw, size_t len, bool ingress_limited)
{
	struct ret_packet pkt;
	struct ret_announce a;
	uint8_t hash[RET_HASH_LEN];
	size_t ifac_size = iface->ifac ? iface->ifac->size : DEFAULT_IFAC_SIZE;

	if (len > (size_t)iface->hw_mtu + ifac_size ||
	    ret_packet_unpack_max(raw, len, RET_TRANSPORT_PACKET_MAX, &pkt) ||
	    ret_packet_hash(raw, len, hash)) {
		iface->drops++;
		return;
	}
	if (!packet_filter(t, &pkt, hash)) {
		return;
	}
	pkt.hops++;

	if (pkt.packet_type == RET_PKT_ANNOUNCE) {
		if (len > RET_MTU || ret_announce_validate(&pkt, &a) != 0) {
			iface->drops++;
			return;
		}
		freq_add(&iface->ia_freq, t->now);
		if (!path_get(t, pkt.dest_hash) && !pr_find(OWN_PRS(t), pkt.dest_hash) &&
		    !discovery_find(t, pkt.dest_hash) && should_ingress_limit(t, iface)) {
			hold_announce(iface, raw, len, &pkt);
			return;
		}
	} else if (hash_eq(pkt.dest_hash, t->pr_dest)) {
		uint8_t unique[RET_TRANSPORT_PR_TAG_LEN] = { 0 };
		size_t n = pkt.data_len;
		size_t off;

		if (n < RET_TRUNC_HASH_LEN) {
			return;
		}
		if (n > 2 * RET_TRUNC_HASH_LEN) {
			off = 2 * RET_TRUNC_HASH_LEN;
		} else if (n > RET_TRUNC_HASH_LEN) {
			off = RET_TRUNC_HASH_LEN;
		} else {
			/* Tagless path request. */
			return;
		}
		memcpy(unique, pkt.data, RET_TRUNC_HASH_LEN);
		memcpy(&unique[RET_TRUNC_HASH_LEN], &pkt.data[off],
		       MIN(n - off, RET_PATH_REQUEST_TAG_LEN));
		if (!tag_add(t, unique)) {
			return;
		}
		freq_add(&iface->ip_freq, t->now);
		if (should_ingress_limit_pr(t, iface)) {
			ingress_limited = true;
		}
		if (!pr_find(INFLIGHT(t), pkt.data)) {
			pr_set(INFLIGHT(t), pkt.data, t->now);
		} else {
			if (!ingress_limited) {
				struct ret_transport_discovery *d = discovery_find(t, pkt.data);

				if (!d) {
					d = discovery_slot(t, pkt.data);
					d->engaged = false;
					d->timeout = t->now + MAX(PATH_REQUEST_TIMEOUT_MS,
								  medium_path_timeout_ms(t));
				}
				d->ifaces |= BIT(iface->index);
			}
			return;
		}
	}

	inbound(t, iface, &pkt, raw, len, hash, ingress_limited, &a);
}

void ret_transport_inbound(struct ret_transport *t, struct ret_transport_iface *iface,
			   const uint8_t *frame, size_t len, int64_t now)
{
	int n;

	t->now = now;
	iface->rx_frames++;
	if (len <= 2 || len > sizeof(t->work)) {
		iface->drops++;
		return;
	}
	if (iface->ifac) {
		if (!(frame[0] & FLAG_IFAC) || len <= 2 + (size_t)iface->ifac->size) {
			goto ifac_fail;
		}
		n = ret_ifac_strip(iface->ifac, frame, len, t->work, sizeof(t->work));
		if (n < 0) {
			goto ifac_fail;
		}
	} else {
		if (frame[0] & FLAG_IFAC) {
			goto ifac_fail;
		}
		memcpy(t->work, frame, len);
		n = (int)len;
	}
	process(t, iface, t->work, (size_t)n, false);
	return;

ifac_fail:
	iface->ifac_drops++;
	iface->drops++;
}

/* --- Jobs (Transport.jobs) --- */

struct rebroadcast {
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	uint8_t hops;
	uint8_t context;
	int8_t attached;
};

static void announce_jobs(struct ret_transport *t)
{
	struct rebroadcast out[CONFIG_RET_TRANSPORT_ANNOUNCES];
	size_t n = 0;

	for (size_t i = 0; i < ARRAY_SIZE(t->announces); i++) {
		struct ret_transport_announce *a = &t->announces[i];
		struct ret_transport_announce_entry *e = &a->e;

		if (!a->used) {
			continue;
		}
		if (e->retries > 0 && e->retries >= LOCAL_REBROADCASTS_MAX) {
			a->used = false;
		} else if (e->retries > PATHFINDER_R) {
			a->used = false;
		} else if (t->now > e->retransmit_at) {
			e->retransmit_at = t->now + PATHFINDER_G_MS + PATHFINDER_RW_MS;
			e->retries++;
			memcpy(out[n].dest_hash, a->dest_hash, RET_TRUNC_HASH_LEN);
			out[n].hops = e->hops;
			out[n].context = e->block_rebroadcasts ? RET_CONTEXT_PATH_RESPONSE
							       : RET_CONTEXT_NONE;
			out[n].attached = e->attached;
			n++;
			if (a->has_held) {
				a->e = a->held;
				a->has_held = false;
			}
		}
	}

	/* Transport.handle_outgoing_announces(): fewest hops first. */
	for (size_t i = 1; i < n; i++) {
		struct rebroadcast r = out[i];
		size_t j = i;

		while (j > 0 && out[j - 1].hops > r.hops) {
			out[j] = out[j - 1];
			j--;
		}
		out[j] = r;
	}
	for (size_t i = 0; i < n; i++) {
		struct ret_packet ann;

		if (stored_announce(t, out[i].dest_hash, &ann) != 0) {
			/* Identity.recall() failed: the entry is done. */
			struct ret_transport_announce *a = announce_find(t, out[i].dest_hash);

			if (a) {
				a->used = false;
			}
			continue;
		}
		send_announce(t, &ann, out[i].hops, out[i].context, out[i].attached);
	}
}

/* Interface.process_announce_queue(). */
static void process_announce_queue(struct ret_transport *t, struct ret_transport_iface *iface)
{
	struct ret_transport_queued_announce *pick = NULL;
	struct ret_packet ann;
	int n;

	for (size_t i = 0; i < ARRAY_SIZE(iface->queue); i++) {
		struct ret_transport_queued_announce *q = &iface->queue[i];

		if (!q->used) {
			continue;
		}
		if (t->now > q->time + QUEUED_ANNOUNCE_LIFE_MS) {
			q->used = false;
			continue;
		}
		if (!pick || q->hops < pick->hops || (q->hops == pick->hops && q->time < pick->time)) {
			pick = q;
		}
	}
	if (!pick) {
		return;
	}
	pick->used = false;
	iface->announce_allowed_at = t->now + announce_wait_ms(iface, pick->len);
	if (stored_announce(t, pick->dest_hash, &ann) != 0) {
		return;
	}
	n = build_announce(t, &ann, pick->hops, RET_CONTEXT_NONE);
	if (n > 0 && iface->online) {
		transmit(t, iface, t->build, (size_t)n);
	}
}

static void pending_pr_push(struct ret_transport *t, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
			    int8_t blocked)
{
	uint8_t idx;

	for (uint8_t i = 0; i < t->pending_count; i++) {
		idx = (t->pending_head + i) % RET_TRANSPORT_PENDING_PRS;
		if (hash_eq(t->pending_prs[idx].dest_hash, dest_hash)) {
			return;
		}
	}
	if (t->pending_count == RET_TRANSPORT_PENDING_PRS) {
		return;
	}
	idx = (t->pending_head + t->pending_count) % RET_TRANSPORT_PENDING_PRS;
	memcpy(t->pending_prs[idx].dest_hash, dest_hash, RET_TRUNC_HASH_LEN);
	t->pending_prs[idx].blocked = blocked;
	t->pending_count++;
}

/* An unproven link timed out: maybe the path broke (Transport.jobs). */
static void link_timed_out(struct ret_transport *t, const struct ret_transport_link *l)
{
	struct ret_transport_pr *last = pr_find(OWN_PRS(t), l->dest_hash);
	bool throttle = last && t->now - last->time < PATH_REQUEST_MI_MS;
	struct ret_transport_path *p = path_get(t, l->dest_hash);
	int8_t blocked = -1;
	bool request = false;

	if (!p) {
		request = true;
	} else if (!throttle && l->taken_hops == 0) {
		request = true;
	} else if (!throttle && (p->m.hops == 1 || l->taken_hops == 1)) {
		struct ret_transport_iface *rcvd = iface_at(t, l->rcvd_iface);

		request = true;
		blocked = (int8_t)l->rcvd_iface;
		if (rcvd && rcvd->mode != RET_IFACE_MODE_BOUNDARY) {
			p->m.state = RET_PATH_STATE_UNRESPONSIVE;
			path_save(t, p, NULL, 0);
		}
	}
	if (request) {
		pending_pr_push(t, l->dest_hash, blocked);
	}
}

static void cull(struct ret_transport *t)
{
	for (size_t i = 0; i < ARRAY_SIZE(t->reverse); i++) {
		if (t->reverse[i].used && t->now > t->reverse[i].timestamp + REVERSE_TIMEOUT_MS) {
			t->reverse[i].used = false;
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(t->links); i++) {
		struct ret_transport_link *l = &t->links[i];

		if (!l->used) {
			continue;
		}
		if (l->validated) {
			if (t->now > l->timestamp + LINK_TIMEOUT_MS) {
				l->used = false;
			}
		} else if (t->now > l->proof_timeout) {
			l->used = false;
			link_timed_out(t, l);
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(t->paths); i++) {
		struct ret_transport_path *p = &t->paths[i];
		int mode;
		int64_t ttl;

		if (!p->used) {
			continue;
		}
		mode = iface_mode_of_path(t, p);
		ttl = path_ttl_ms(mode);
		if (t->now > p->m.timestamp + ttl) {
			path_remove(t, p);
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(t->own_prs); i++) {
		if (t->own_prs[i].used && t->now > t->own_prs[i].time + PATH_REQUEST_GATE_MS) {
			t->own_prs[i].used = false;
		}
		if (t->inflight[i].used && t->now > t->inflight[i].time + PATH_REQUEST_GATE_MS) {
			t->inflight[i].used = false;
		}
		if (t->discovery[i].used && t->now > t->discovery[i].timeout) {
			t->discovery[i].used = false;
		}
	}
}

int64_t ret_transport_jobs(struct ret_transport *t, int64_t now)
{
	int64_t next = now + JOB_INTERVAL_MS;

	t->now = now;
	if (now >= t->announces_checked + ANNOUNCES_CHECK_MS) {
		announce_jobs(t);
		t->announces_checked = now;
	}
	if (now >= t->tables_culled + TABLES_CULL_MS) {
		cull(t);
		t->tables_culled = now;
	}
	if (now >= t->ifaces_checked + IFACE_JOBS_MS) {
		for (uint8_t i = 0; i < t->n_ifaces; i++) {
			struct ret_transport_iface *iface = t->ifaces[i];

			(void)should_ingress_limit(t, iface);
			(void)should_ingress_limit_pr(t, iface);
			process_held_announces(t, iface);
		}
		t->ifaces_checked = now;
	}
	for (uint8_t i = 0; i < t->n_ifaces; i++) {
		struct ret_transport_iface *iface = t->ifaces[i];

		if (queue_empty(iface)) {
			continue;
		}
		if (now >= iface->announce_allowed_at) {
			process_announce_queue(t, iface);
		}
		if (!queue_empty(iface)) {
			next = MIN(next, MAX(iface->announce_allowed_at, now));
		}
	}
	if (t->pending_count && now >= t->pending_pr_at) {
		struct ret_transport_pending_pr pr = t->pending_prs[t->pending_head];

		t->pending_head = (t->pending_head + 1) % RET_TRANSPORT_PENDING_PRS;
		t->pending_count--;
		t->pending_pr_at = now + DISCOVERY_PR_THROTTLE_MS;
		if (pr.blocked < 0) {
			request_path(t, pr.dest_hash, -1, NULL, 0, false);
		} else {
			for (uint8_t i = 0; i < t->n_ifaces; i++) {
				if (i != pr.blocked) {
					request_path(t, pr.dest_hash, i, NULL, 0, false);
				}
			}
		}
	}
	return next;
}

/* --- Setup --- */

struct load_ctx {
	struct ret_transport *t;
	size_t n;
	size_t n_invalid;
	uint8_t invalid[8][RET_TRUNC_HASH_LEN];
};

static int load_path(const struct ret_transport_path_meta *meta, void *user)
{
	struct load_ctx *c = user;
	struct ret_transport_path *p;

	if (c->n == ARRAY_SIZE(c->t->paths)) {
		return 1;
	}
	if (!meta_valid(c->t, meta)) {
		/* Removed after the iteration: a store may not allow changes during it. */
		if (c->n_invalid < ARRAY_SIZE(c->invalid)) {
			memcpy(c->invalid[c->n_invalid++], meta->dest_hash, RET_TRUNC_HASH_LEN);
		}
		return 0;
	}
	p = &c->t->paths[c->n++];
	p->used = true;
	p->last_used = c->t->now;
	p->m = *meta;
	/* Renewed here, written back after the iteration. */
	p->dirty = normalize(c->t, &p->m);
	return 0;
}

int ret_transport_init(struct ret_transport *t, const struct ret_local_identity *identity,
		       struct ret_transport_store *store, struct ret_transport_iface *const *ifaces,
		       size_t n_ifaces, uint32_t boot, int64_t now)
{
	struct load_ctx c = { .t = t };
	int err;

	if (!store || n_ifaces == 0 || n_ifaces > ARRAY_SIZE(t->ifaces)) {
		return -EINVAL;
	}
	memset(t, 0, sizeof(*t));
	t->identity = identity;
	t->store = store;
	t->boot = boot;
	t->now = now;
	t->n_ifaces = (uint8_t)n_ifaces;
	t->announces_checked = now;
	t->tables_culled = now;
	t->ifaces_checked = now;

	for (size_t i = 0; i < n_ifaces; i++) {
		struct ret_transport_iface *iface = ifaces[i];

		if (!iface->send || iface->hw_mtu == 0 || iface->hw_mtu > RET_TRANSPORT_HW_MTU_MAX) {
			return -EINVAL;
		}
		t->ifaces[i] = iface;
		iface->index = (uint8_t)i;
		iface->online = false;
		iface->created = now;
		iface->announce_allowed_at = INT64_MIN;
		memset(iface->queue, 0, sizeof(iface->queue));
		memset(iface->held, 0, sizeof(iface->held));
		memset(&iface->ia_freq, 0, sizeof(iface->ia_freq));
		memset(&iface->ip_freq, 0, sizeof(iface->ip_freq));
		iface->ic_burst_active = false;
		iface->ic_pr_burst_active = false;
		iface->ic_pr_burst_cooldown = 0;
		iface->ic_held_release = 0;
	}

	err = ret_plain_dest_hash("rnstransport.path.request", t->pr_dest);
	if (!err) {
		err = ret_plain_dest_hash("rnstransport.tunnel.synthesize", t->tunnel_dest);
	}
	if (err) {
		return err;
	}
	err = store->foreach(store, load_path, &c);
	if (err < 0) {
		return err;
	}
	for (size_t i = 0; i < c.n; i++) {
		if (t->paths[i].dirty) {
			path_save(t, &t->paths[i], NULL, 0);
		}
	}
	for (size_t i = 0; i < c.n_invalid; i++) {
		LOG_WRN("transport: invalid stored path, removed");
		(void)store->remove(store, c.invalid[i]);
	}
	LOG_INF("transport: %zu paths loaded", c.n);
	return 0;
}

void ret_transport_iface_online(struct ret_transport *t, struct ret_transport_iface *iface,
				bool online, int64_t now)
{
	t->now = now;
	iface->online = online;
}

int ret_transport_synthesize_tunnel(struct ret_transport *t, struct ret_transport_iface *iface,
				    const uint8_t iface_hash[RET_HASH_LEN], int64_t now)
{
	uint8_t data[RET_PUBKEY_LEN + RET_HASH_LEN + RET_TRUNC_HASH_LEN + RET_SIG_LEN];
	const size_t signed_len = RET_PUBKEY_LEN + RET_HASH_LEN + RET_TRUNC_HASH_LEN;
	struct ret_packet pkt = {
		.header_type = RET_HEADER_1,
		.transport_type = RET_TRANSPORT_BROADCAST,
		.dest_type = RET_DEST_PLAIN,
		.packet_type = RET_PKT_DATA,
		.context = RET_CONTEXT_NONE,
		.data = data,
		.data_len = sizeof(data),
	};
	struct outpkt o = {
		.raw = t->build,
		.packet_type = RET_PKT_DATA,
		.dest_hash = t->tunnel_dest,
		.attached = iface->index,
	};
	int n;
	int err;

	t->now = now;
	memcpy(data, t->identity->pub, RET_PUBKEY_LEN);
	memcpy(&data[RET_PUBKEY_LEN], iface_hash, RET_HASH_LEN);
	err = ret_random(&data[RET_PUBKEY_LEN + RET_HASH_LEN], RET_TRUNC_HASH_LEN);
	if (err) {
		return err;
	}
	ret_local_identity_sign(t->identity, data, signed_len, &data[signed_len]);
	memcpy(pkt.dest_hash, t->tunnel_dest, RET_TRUNC_HASH_LEN);
	n = ret_packet_pack(&pkt, t->build, sizeof(t->build));
	if (n < 0) {
		return n;
	}
	o.len = (size_t)n;
	outbound(t, &o);
	return 0;
}

const struct ret_transport_path_meta *ret_transport_path(struct ret_transport *t,
							 const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_path *p = path_get(t, dest_hash);

	return p ? &p->m : NULL;
}
