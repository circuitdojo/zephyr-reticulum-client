/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * ret_transport against RNS: the bytes it sends match vectors built by RNS
 * (tools/rns_peer/gen_vectors.py, transport_vectors()), and its behaviour
 * follows RNS/Transport.py, driven here with a hand-run clock.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/byteorder.h>
#include <zephyr/ztest.h>

#include "ret_announce.h"
#include "ret_crypto.h"
#include "ret_ifac.h"
#include "ret_link.h"
#include "ret_transport.h"
#include "ret_transport_store_ram.h"
#include "vectors_rns.h"

#define NOW0       1000000
#define MAX_FRAMES 16

struct capture {
	uint8_t f[MAX_FRAMES][RET_TRANSPORT_FRAME_MAX];
	size_t len[MAX_FRAMES];
	size_t n;
};

static struct capture caps[2];
#define LORA_TX (&caps[0])
#define TCP_TX  (&caps[1])

static struct ret_transport_iface lora;
static struct ret_transport_iface tcp;
static struct ret_transport_iface *const ifaces[] = { &lora, &tcp };
static struct ret_transport tp;
static struct ret_transport_store_ram store;
static struct ret_transport_store_ram_entry entries[16];
static struct ret_local_identity tid;
static int64_t now;

static int send_cb(struct ret_transport_iface *iface, const uint8_t *frame, size_t len)
{
	struct capture *c = iface->user;

	zassert_true(len <= sizeof(c->f[0]));
	if (c->n < MAX_FRAMES) {
		memcpy(c->f[c->n], frame, len);
		c->len[c->n] = len;
	}
	c->n++;
	return 0;
}

static void clear(void)
{
	memset(caps, 0, sizeof(caps));
}

static void start(uint32_t boot)
{
	zassert_ok(ret_transport_init(&tp, &tid, &store.store, ifaces, ARRAY_SIZE(ifaces), boot,
				      now));
	ret_transport_iface_online(&tp, &lora, true, now);
	ret_transport_iface_online(&tp, &tcp, true, now);
}

static void before(void *f)
{
	ARG_UNUSED(f);
	clear();
	lora = (struct ret_transport_iface){
		.name = "lora",
		.mode = RET_IFACE_MODE_GATEWAY,
		.bitrate = 7031,
		.hw_mtu = 508,
		.mtu_signalling = false,
		.announce_cap = 200,
		.send = send_cb,
		.user = LORA_TX,
	};
	tcp = (struct ret_transport_iface){
		.name = "tcp",
		.mode = RET_IFACE_MODE_FULL,
		.bitrate = 10000000,
		.hw_mtu = 508,
		.mtu_signalling = true,
		.announce_cap = 200,
		.send = send_cb,
		.user = TCP_TX,
	};
	ret_transport_store_ram_init(&store, entries, ARRAY_SIZE(entries));
	zassert_ok(ret_local_identity_load(&tid, v_tp_prv));
	zassert_mem_equal(tid.hash, v_tp_id, sizeof(v_tp_id));
	now = NOW0;
	start(1);
}

static void rx(struct ret_transport_iface *iface, const uint8_t *frame, size_t len)
{
	ret_transport_inbound(&tp, iface, frame, len, now);
}

/* Advance the clock to @p t, running the jobs as a 250 ms loop would. */
static void run_until(int64_t t)
{
	while (now < t) {
		now += 250;
		(void)ret_transport_jobs(&tp, now);
	}
}

static bool sent(const struct capture *c, const uint8_t *frame, size_t len)
{
	for (size_t i = 0; i < MIN(c->n, MAX_FRAMES); i++) {
		if (c->len[i] == len && memcmp(c->f[i], frame, len) == 0) {
			return true;
		}
	}
	return false;
}

#define SENT(c, v) sent(c, v, sizeof(v))

/* A copy of @p v with a new hop count and, if given, transport ID. */
static size_t variant(uint8_t *out, const uint8_t *v, size_t len, uint8_t hops,
		      const uint8_t *transport_id)
{
	memcpy(out, v, len);
	out[1] = hops;
	if (transport_id) {
		memcpy(&out[2], transport_id, RET_TRUNC_HASH_LEN);
	}
	return len;
}

static const uint8_t other_a[RET_TRUNC_HASH_LEN] = { 0xa1, 0xa2, 0xa3 };
static const uint8_t other_b[RET_TRUNC_HASH_LEN] = { 0xb1, 0xb2, 0xb3 };

/* A signed announce from identity @p seed, emitted at @p emitted. */
static size_t make_announce(uint8_t seed, uint64_t emitted, uint8_t *out, uint8_t dest[16])
{
	struct ret_local_identity id;
	uint8_t prv[RET_PRVKEY_LEN];
	uint8_t name_hash[RET_NAME_HASH_LEN];
	uint8_t rh[RET_RANDOM_HASH_LEN] = { seed, 1, 2, 3, 4 };
	int n;

	memset(prv, seed, sizeof(prv));
	zassert_ok(ret_local_identity_load(&id, prv));
	zassert_ok(ret_name_hash("ret.test", name_hash));
	zassert_ok(ret_dest_hash(name_hash, id.hash, dest));
	for (int i = 0; i < 5; i++) {
		rh[5 + i] = (uint8_t)(emitted >> (8 * (4 - i)));
	}
	n = ret_announce_build(&id, name_hash, dest, rh, NULL, (const uint8_t *)"x", 1,
			       RET_CONTEXT_NONE, out, RET_MTU);
	zassert_true(n > 0);
	return (size_t)n;
}

static int64_t cap_wait_ms(const struct ret_transport_iface *iface, size_t len)
{
	return (int64_t)len * 8 * 1000 * 10000 / ((int64_t)iface->bitrate * iface->announce_cap);
}

ZTEST(ret_transport, test_rebroadcast)
{
	const struct ret_transport_path_meta *p;
	int64_t first;

	rx(&lora, v_announce_real, sizeof(v_announce_real));
	p = ret_transport_path(&tp, v_dest_hash);
	zassert_not_null(p);
	zassert_equal(p->hops, 1);
	zassert_equal(p->iface, lora.index);
	zassert_mem_equal(p->next_hop, v_dest_hash, sizeof(v_dest_hash));

	/* Within PATHFINDER_RW, on every interface, the LoRa one included. */
	run_until(now + 1000);
	first = now;
	zassert_true(SENT(LORA_TX, v_tp_rebroadcast));
	zassert_true(SENT(TCP_TX, v_tp_rebroadcast));
	zassert_equal(LORA_TX->n, 1);
	zassert_equal(TCP_TX->n, 1);

	/* Once more after PATHFINDER_G: TCP at once, LoRa when its cap allows. */
	run_until(first + 6500);
	zassert_equal(TCP_TX->n, 2);
	zassert_equal(LORA_TX->n, 1);
	run_until(first + cap_wait_ms(&lora, sizeof(v_tp_rebroadcast)) + 500);
	zassert_equal(LORA_TX->n, 2);
	zassert_mem_equal(LORA_TX->f[1], v_tp_rebroadcast, sizeof(v_tp_rebroadcast));

	/* PATHFINDER_R: that was the last. */
	run_until(now + 30000);
	zassert_equal(TCP_TX->n, 2);
	zassert_equal(LORA_TX->n, 2);
}

ZTEST(ret_transport, test_rebroadcast_passed_on)
{
	uint8_t heard[sizeof(v_tp_rebroadcast)];

	rx(&lora, v_announce_real, sizeof(v_announce_real));
	run_until(now + 1000);
	zassert_equal(TCP_TX->n, 1);

	/* A neighbour repeated ours (one more hop): no retry needed. */
	rx(&lora, heard, variant(heard, v_tp_rebroadcast, sizeof(heard), 2, other_a));
	run_until(now + 20000);
	zassert_equal(TCP_TX->n, 1);
	zassert_equal(LORA_TX->n, 1);
}

ZTEST(ret_transport, test_rebroadcast_local)
{
	uint8_t heard[sizeof(v_tp_rebroadcast)];

	rx(&lora, v_announce_real, sizeof(v_announce_real));
	run_until(now + 1000);

	/* Two others at our distance rebroadcast it after our first send. */
	rx(&lora, heard, variant(heard, v_tp_rebroadcast, sizeof(heard), 1, other_a));
	zassert_not_null(ret_transport_path(&tp, v_dest_hash));
	rx(&lora, heard, variant(heard, v_tp_rebroadcast, sizeof(heard), 1, other_b));
	run_until(now + 20000);
	zassert_equal(TCP_TX->n, 1);
}

ZTEST(ret_transport, test_duplicates_and_age)
{
	uint8_t a[RET_MTU];
	uint8_t dest[16];
	size_t n;

	n = make_announce(7, 100, a, dest);
	rx(&tcp, a, n);
	run_until(now + 30000);
	zassert_equal(TCP_TX->n, 2);
	clear();

	/* The same announce again, then an older one: nothing new. */
	rx(&tcp, a, n);
	n = make_announce(7, 99, a, dest);
	rx(&tcp, a, n);
	run_until(now + 2000);
	zassert_equal(TCP_TX->n, 0);

	/* Newer: rebroadcast. */
	n = make_announce(7, 101, a, dest);
	rx(&tcp, a, n);
	run_until(now + 2000);
	zassert_equal(TCP_TX->n, 1);
}

ZTEST(ret_transport, test_more_hops_ignored)
{
	uint8_t heard[sizeof(v_tp_rebroadcast)];
	const struct ret_transport_path_meta *p;

	rx(&lora, v_announce_real, sizeof(v_announce_real));
	/* The same announce over a longer route keeps the short path. */
	rx(&tcp, heard, variant(heard, v_tp_rebroadcast, sizeof(heard), 3, other_a));
	p = ret_transport_path(&tp, v_dest_hash);
	zassert_equal(p->hops, 1);
	zassert_equal(p->iface, lora.index);
}

ZTEST(ret_transport, test_path_response)
{
	uint8_t pr[RET_PATH_REQUEST_LEN + RET_TRUNC_HASH_LEN];
	const uint8_t tag[16] = { 1, 2, 3 };
	const uint8_t tag2[16] = { 4, 5, 6 };
	int n;

	rx(&lora, v_announce_real, sizeof(v_announce_real));
	run_until(now + 30000);
	clear();

	n = ret_path_request_build(v_dest_hash, tag, pr, sizeof(pr));
	zassert_true(n > 0);
	rx(&tcp, pr, (size_t)n);
	run_until(now + 1500);
	zassert_true(SENT(TCP_TX, v_tp_path_response));
	zassert_equal(TCP_TX->n, 1);
	zassert_equal(LORA_TX->n, 0);

	/* The same request again (same tag): answered once only. */
	rx(&tcp, pr, (size_t)n);
	run_until(now + 3000);
	zassert_equal(TCP_TX->n, 1);

	/* From our next hop (here the destination itself): not answered. */
	n = ret_path_request_build_transport(v_dest_hash, v_dest_hash, tag2, pr, sizeof(pr));
	rx(&tcp, pr, (size_t)n);
	run_until(now + 3000);
	zassert_equal(TCP_TX->n, 1);
}

ZTEST(ret_transport, test_path_discovery)
{
	uint8_t pr[RET_PATH_REQUEST_LEN];
	const uint8_t tag[16] = { 9 };
	int n;

	/* Unknown on a gateway interface: asked upstream with the same tag. */
	n = ret_path_request_build(v_dest_hash, v_tp_pr_tag, pr, sizeof(pr));
	rx(&lora, pr, (size_t)n);
	zassert_equal(TCP_TX->n, 1);
	zassert_true(SENT(TCP_TX, v_tp_path_request));

	/* The answer comes back: the waiting LoRa side hears it at once. */
	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	zassert_equal(LORA_TX->n, 1);
	zassert_true(SENT(LORA_TX, v_tp_path_response));
	clear();

	/* Unknown on a full interface: not searched for. */
	n = ret_path_request_build(other_a, tag, pr, sizeof(pr));
	rx(&tcp, pr, (size_t)n);
	zassert_equal(LORA_TX->n, 0);
}

ZTEST(ret_transport, test_forward_and_proof)
{
	uint8_t ann[sizeof(v_tp_rebroadcast)];
	uint8_t proof[RET_H1_HEADER_LEN + RET_SIG_LEN] = { 0x03, 0x00 };
	uint8_t hash[RET_HASH_LEN];
	const struct ret_transport_path_meta *p;

	/* Two hops away behind the hub, via another transport node. */
	rx(&tcp, ann, variant(ann, v_tp_rebroadcast, sizeof(ann), 1, v_tp_next_hop));
	p = ret_transport_path(&tp, v_dest_hash);
	zassert_equal(p->hops, 2);
	zassert_mem_equal(p->next_hop, v_tp_next_hop, sizeof(v_tp_next_hop));
	clear();

	rx(&lora, v_tp_data_in, sizeof(v_tp_data_in));
	zassert_equal(TCP_TX->n, 1);
	zassert_true(SENT(TCP_TX, v_tp_data_fwd));

	/* Its proof comes back the way the packet went. */
	zassert_ok(ret_packet_hash(v_tp_data_in, sizeof(v_tp_data_in), hash));
	memcpy(&proof[2], hash, RET_TRUNC_HASH_LEN);
	memset(&proof[RET_H1_HEADER_LEN], 0x5a, RET_SIG_LEN);
	rx(&tcp, proof, sizeof(proof));
	zassert_equal(LORA_TX->n, 1);
	zassert_equal(LORA_TX->f[0][1], 1);
	zassert_mem_equal(&LORA_TX->f[0][2], &proof[2], sizeof(proof) - 2);

	/* Only once: the reverse entry is spent. */
	proof[RET_H1_HEADER_LEN] ^= 1;
	rx(&tcp, proof, sizeof(proof));
	zassert_equal(LORA_TX->n, 1);
}

ZTEST(ret_transport, test_forward_last_hop)
{
	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	clear();
	rx(&lora, v_tp_data_in, sizeof(v_tp_data_in));
	zassert_true(SENT(TCP_TX, v_tp_data_last));
}

ZTEST(ret_transport, test_lora_to_lora)
{
	/* Both ends on the radio: forwarded back out the same interface. */
	rx(&lora, v_announce_real, sizeof(v_announce_real));
	clear();
	rx(&lora, v_tp_data_in, sizeof(v_tp_data_in));
	zassert_equal(LORA_TX->n, 1);
	zassert_true(SENT(LORA_TX, v_tp_data_last));
	zassert_equal(TCP_TX->n, 0);
}

ZTEST(ret_transport, test_no_path_dropped)
{
	rx(&lora, v_tp_data_in, sizeof(v_tp_data_in));
	zassert_equal(TCP_TX->n + LORA_TX->n, 0);
}

ZTEST(ret_transport, test_link_relay)
{
	uint8_t proof[sizeof(v_link_lrproof_rns)];
	uint8_t data[sizeof(v_link_data)];

	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	clear();

	/* LoRa to hub: the 262144 MTU is clamped to 508. */
	rx(&lora, v_tp_lr_in, sizeof(v_tp_lr_in));
	zassert_true(SENT(TCP_TX, v_tp_lr_clamp));

	/* A link packet before the proof is not relayed. */
	rx(&lora, v_link_data, sizeof(v_link_data));
	zassert_equal(TCP_TX->n, 1);

	/* The destination's proof goes back to the requester. */
	rx(&tcp, v_link_lrproof_rns, sizeof(v_link_lrproof_rns));
	zassert_equal(LORA_TX->n, 1);
	memcpy(proof, v_link_lrproof_rns, sizeof(proof));
	proof[1] = 1;
	zassert_true(SENT(LORA_TX, proof));

	/* Link traffic both ways. */
	memcpy(data, v_link_data, sizeof(data));
	data[sizeof(data) - 1] ^= 1;
	rx(&lora, data, sizeof(data));
	zassert_equal(TCP_TX->n, 2);
	data[sizeof(data) - 2] ^= 1;
	rx(&tcp, data, sizeof(data));
	zassert_equal(LORA_TX->n, 2);
}

ZTEST(ret_transport, test_link_bad_proof)
{
	uint8_t proof[sizeof(v_link_lrproof_rns)];

	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	rx(&lora, v_tp_lr_in, sizeof(v_tp_lr_in));
	clear();
	memcpy(proof, v_link_lrproof_rns, sizeof(proof));
	proof[RET_H1_HEADER_LEN] ^= 1;
	rx(&tcp, proof, sizeof(proof));
	zassert_equal(LORA_TX->n, 0);
	rx(&lora, v_link_data, sizeof(v_link_data));
	zassert_equal(TCP_TX->n, 0);
}

ZTEST(ret_transport, test_link_onto_rnode)
{
	/* Hub to LoRa: an RNode-like interface gets no MTU signalling. */
	rx(&lora, v_announce_real, sizeof(v_announce_real));
	clear();
	rx(&tcp, v_tp_lr_in, sizeof(v_tp_lr_in));
	zassert_true(SENT(LORA_TX, v_tp_lr_strip));
}

ZTEST(ret_transport, test_ifac)
{
	static struct ret_ifac ifac;
	uint8_t frame[RET_TRANSPORT_FRAME_MAX];
	uint8_t raw[RET_TRANSPORT_FRAME_MAX];
	int n;

	zassert_ok(ret_ifac_init(&ifac, V_IFAC_NETNAME, V_IFAC_PASSPHRASE, 16));
	tcp.ifac = &ifac;

	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	zassert_is_null(ret_transport_path(&tp, v_dest_hash));

	n = ret_ifac_apply(&ifac, v_announce_real, sizeof(v_announce_real), frame, sizeof(frame));
	zassert_true(n > 0);
	rx(&tcp, frame, (size_t)n);
	zassert_not_null(ret_transport_path(&tp, v_dest_hash));

	run_until(now + 1000);
	zassert_equal(TCP_TX->n, 1);
	n = ret_ifac_strip(&ifac, TCP_TX->f[0], TCP_TX->len[0], raw, sizeof(raw));
	zassert_equal(n, sizeof(v_tp_rebroadcast));
	zassert_mem_equal(raw, v_tp_rebroadcast, sizeof(v_tp_rebroadcast));
	zassert_true(SENT(LORA_TX, v_tp_rebroadcast));
}

ZTEST(ret_transport, test_announce_cap)
{
	uint8_t a[RET_MTU];
	uint8_t b[RET_MTU];
	uint8_t dest[16];
	size_t na = make_announce(1, 100, a, dest);
	size_t nb = make_announce(2, 100, b, dest);
	int64_t first;
	int64_t wait;

	rx(&tcp, a, na);
	rx(&tcp, b, nb);
	run_until(now + 1000);
	first = now;
	zassert_equal(LORA_TX->n, 1);
	/* At 10 Mbps the cap holds the second back for milliseconds. */
	run_until(now + 250);
	zassert_equal(TCP_TX->n, 2);

	/* On LoRa it waits for the first's airtime / 2%. */
	wait = cap_wait_ms(&lora, LORA_TX->len[0]);
	run_until(first + wait - 500);
	zassert_equal(LORA_TX->n, 1);
	run_until(first + wait + 500);
	zassert_equal(LORA_TX->n, 2);
}

ZTEST(ret_transport, test_store)
{
	uint8_t a[RET_MTU];
	uint8_t dest[6][16];
	const struct ret_transport_path_meta *p;

	/* More paths than RAM holds: the store keeps them all. */
	for (int i = 0; i < 6; i++) {
		rx(&tcp, a, make_announce(10 + i, 100, a, dest[i]));
		now += 1000;
	}
	for (int i = 0; i < 6; i++) {
		zassert_not_null(ret_transport_path(&tp, dest[i]), "path %d", i);
	}

	/* After a reboot: loaded, with fresh times. */
	now = 50;
	start(2);
	p = ret_transport_path(&tp, dest[0]);
	zassert_not_null(p);
	zassert_equal(p->boot, 2);
	zassert_equal(p->timestamp, 50);
	zassert_not_null(ret_transport_path(&tp, dest[5]));

	/* A path unused for a week is dropped, from the store too. */
	(void)ret_transport_jobs(&tp, now + 8LL * 24 * 3600 * 1000);
	now += 8LL * 24 * 3600 * 1000;
	zassert_is_null(ret_transport_path(&tp, dest[5]));
}

ZTEST(ret_transport, test_ingress_limit)
{
	uint8_t a[RET_MTU];
	uint8_t dest[4][16];

	/* A burst of new destinations on a new interface: the third is held. */
	for (int i = 0; i < 3; i++) {
		rx(&tcp, a, make_announce(20 + i, 100, a, dest[i]));
		now += 100;
	}
	zassert_not_null(ret_transport_path(&tp, dest[0]));
	zassert_is_null(ret_transport_path(&tp, dest[2]));

	/* Released once the burst is over. */
	run_until(now + 120000);
	zassert_not_null(ret_transport_path(&tp, dest[2]));
}

ZTEST(ret_transport, test_tunnel_synthesis)
{
	struct ret_packet pkt;
	const uint8_t iface_hash[RET_HASH_LEN] = { 0x11, 0x22 };

	zassert_ok(ret_transport_synthesize_tunnel(&tp, &tcp, iface_hash, now));
	zassert_equal(TCP_TX->n, 1);
	zassert_equal(LORA_TX->n, 0);
	zassert_ok(ret_packet_unpack(TCP_TX->f[0], TCP_TX->len[0], &pkt));
	zassert_mem_equal(pkt.dest_hash, v_tp_tunnel_dest, sizeof(v_tp_tunnel_dest));
	zassert_equal(pkt.dest_type, RET_DEST_PLAIN);
	zassert_equal(pkt.data_len, 176);
	zassert_mem_equal(pkt.data, tid.pub, RET_PUBKEY_LEN);
	zassert_mem_equal(&pkt.data[RET_PUBKEY_LEN], iface_hash, RET_HASH_LEN);
	zassert_true(ret_ed25519_verify(&pkt.data[112], &tid.pub[RET_X25519_LEN], pkt.data, 112));
}

ZTEST(ret_transport, test_offline_iface)
{
	ret_transport_iface_online(&tp, &tcp, false, now);
	rx(&lora, v_announce_real, sizeof(v_announce_real));
	run_until(now + 1000);
	zassert_equal(TCP_TX->n, 0);
	zassert_equal(LORA_TX->n, 1);
}

ZTEST(ret_transport, test_store_corrupt)
{
	struct ret_transport_path_meta m = { .iface = 0, .hops = 1 };

	/* More random blobs than this build keeps: refused and removed. */
	memcpy(m.dest_hash, v_dest_hash, sizeof(v_dest_hash));
	m.n_blobs = CONFIG_RET_TRANSPORT_RANDOM_BLOBS + 1;
	m.boot = 1;
	zassert_ok(store.store.save(&store.store, &m, v_announce_real, sizeof(v_announce_real)));
	zassert_is_null(ret_transport_path(&tp, v_dest_hash));
	zassert_equal(store.store.load(&store.store, v_dest_hash, &m, NULL, 0, NULL), -ENOENT);

	/* Also when loading at start. */
	m.n_blobs = 0;
	m.iface = 7;
	zassert_ok(store.store.save(&store.store, &m, v_announce_real, sizeof(v_announce_real)));
	start(2);
	zassert_equal(store.store.load(&store.store, v_dest_hash, &m, NULL, 0, NULL), -ENOENT);
}

ZTEST(ret_transport, test_reboot_keeps_path)
{
	uint8_t a[RET_MTU];
	uint8_t fwd[RET_MTU + RET_TRUNC_HASH_LEN];
	uint8_t dest[16];
	size_t n = make_announce(30, 100, a, dest);
	const struct ret_transport_path_meta *p;

	rx(&lora, a, n);
	now += 1000;
	start(2);

	/* An older announce over a longer route doesn't replace it. */
	n = make_announce(30, 99, a, dest);
	fwd[0] = (uint8_t)((RET_HEADER_2 << 6) | (RET_TRANSPORT_TRANSPORT << 4) | (a[0] & 0x0F));
	fwd[1] = 2;
	memcpy(&fwd[2], other_a, RET_TRUNC_HASH_LEN);
	memcpy(&fwd[2 + RET_TRUNC_HASH_LEN], &a[2], n - 2);
	rx(&tcp, fwd, n + RET_TRUNC_HASH_LEN);
	p = ret_transport_path(&tp, dest);
	zassert_not_null(p);
	zassert_equal(p->iface, lora.index);
	zassert_equal(p->hops, 1);
}

ZTEST(ret_transport, test_store_lost_announce)
{
	uint8_t pr[RET_PATH_REQUEST_LEN];
	int n;

	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	run_until(now + 30000);
	clear();

	/* The store dropped it: a request is searched for, not swallowed. */
	zassert_ok(store.store.remove(&store.store, v_dest_hash));
	n = ret_path_request_build(v_dest_hash, v_tp_pr_tag, pr, sizeof(pr));
	rx(&lora, pr, (size_t)n);
	zassert_true(SENT(TCP_TX, v_tp_path_request));
	zassert_is_null(ret_transport_path(&tp, v_dest_hash));
}

ZTEST(ret_transport, test_path_response_holds_rebroadcast)
{
	uint8_t pr[RET_PATH_REQUEST_LEN];
	const uint8_t tag[16] = { 7 };
	int n;

	/* A request arrives while the announce waits for its rebroadcast. */
	rx(&lora, v_announce_real, sizeof(v_announce_real));
	n = ret_path_request_build(v_dest_hash, tag, pr, sizeof(pr));
	rx(&tcp, pr, (size_t)n);

	run_until(now + 1000);
	zassert_true(SENT(TCP_TX, v_tp_path_response));
	/* Then the held rebroadcast still goes out, everywhere. */
	run_until(now + 2000);
	zassert_true(SENT(TCP_TX, v_tp_rebroadcast));
	zassert_true(SENT(LORA_TX, v_tp_rebroadcast));
}

static bool sent_path_request(const struct capture *c, const uint8_t dest[16])
{
	struct ret_packet pkt;

	for (size_t i = 0; i < MIN(c->n, MAX_FRAMES); i++) {
		if (ret_packet_unpack(c->f[i], c->len[i], &pkt) == 0 &&
		    memcmp(pkt.dest_hash, &v_tp_path_request[2], 16) == 0 &&
		    pkt.data_len == 48 && memcmp(pkt.data, dest, 16) == 0 &&
		    memcmp(&pkt.data[16], v_tp_id, 16) == 0) {
			return true;
		}
	}
	return false;
}

ZTEST(ret_transport, test_unproven_link)
{
	rx(&tcp, v_announce_real, sizeof(v_announce_real));
	run_until(now + 30000);
	rx(&lora, v_tp_lr_in, sizeof(v_tp_lr_in));
	clear();

	/* No proof in time: the one-hop path is suspect; ask again elsewhere. */
	run_until(now + 12000);
	zassert_equal(ret_transport_path(&tp, v_dest_hash)->state, RET_PATH_STATE_UNRESPONSIVE);
	zassert_true(sent_path_request(TCP_TX, v_dest_hash));
	zassert_false(sent_path_request(LORA_TX, v_dest_hash));
}

ZTEST(ret_transport, test_rate_limit)
{
	uint8_t a[RET_MTU];
	uint8_t dest[16];

	/* Re-announced far more often than the 3600 s target: after the grace of 5,
	 * the path still updates but the announce is not passed on.
	 */
	for (int i = 0; i < 7; i++) {
		clear();
		rx(&lora, a, make_announce(40, 100 + i, a, dest));
		run_until(now + 2000);
		if (i < 6) {
			zassert_true(TCP_TX->n > 0, "announce %d", i);
		} else {
			zassert_equal(TCP_TX->n, 0);
		}
		run_until(now + 30000);
	}
	zassert_equal(ret_announce_emitted(ret_transport_path(&tp, dest)->blobs[6]), 106);
}

ZTEST(ret_transport, test_oversize_dropped)
{
	static uint8_t frame[508 + 17];
	uint32_t drops = lora.drops;

	memcpy(frame, v_tp_data_in, sizeof(v_tp_data_in));
	rx(&lora, frame, sizeof(frame));
	zassert_equal(lora.drops, drops + 1);
}

ZTEST(ret_transport, test_link_relay_multihop)
{
	uint8_t ann[sizeof(v_tp_rebroadcast)];
	uint8_t proof[sizeof(v_link_lrproof_rns)];
	uint8_t sig[RET_LINK_MTU_SIZE];

	/* The destination is two hops away behind the hub. */
	rx(&tcp, ann, variant(ann, v_tp_rebroadcast, sizeof(ann), 1, v_tp_next_hop));
	clear();
	rx(&lora, v_tp_lr_in, sizeof(v_tp_lr_in));
	zassert_equal(TCP_TX->n, 1);
	zassert_equal(TCP_TX->len[0], sizeof(v_tp_lr_in));
	zassert_mem_equal(&TCP_TX->f[0][2], v_tp_next_hop, sizeof(v_tp_next_hop));
	ret_link_signalling(508, RET_LINK_MODE_AES256_CBC, sig);
	zassert_mem_equal(&TCP_TX->f[0][sizeof(v_tp_lr_in) - 3], sig, sizeof(sig));

	/* The proof comes back with two hops. */
	memcpy(proof, v_link_lrproof_rns, sizeof(proof));
	proof[1] = 1;
	rx(&tcp, proof, sizeof(proof));
	zassert_equal(LORA_TX->n, 1);
	zassert_equal(LORA_TX->f[0][1], 2);
}

ZTEST(ret_transport, test_packet_helpers)
{
	uint8_t pr[RET_PATH_REQUEST_LEN + RET_TRUNC_HASH_LEN];
	uint8_t raw[RET_TRANSPORT_HW_MTU_MAX];
	struct ret_packet pkt;
	int n;

	n = ret_path_request_build_transport(v_dest_hash, v_tp_id, v_tp_pr_tag, pr, sizeof(pr));
	zassert_equal(n, sizeof(v_tp_path_request));
	zassert_mem_equal(pr, v_tp_path_request, sizeof(v_tp_path_request));

	/* An RNode frame can exceed the 500-byte packet MTU. */
	memset(raw, 0, sizeof(raw));
	zassert_ok(ret_packet_unpack_max(raw, sizeof(raw), sizeof(raw), &pkt));
	zassert_equal(ret_packet_unpack(raw, sizeof(raw), &pkt), -EMSGSIZE);
	zassert_equal(ret_packet_unpack_max(raw, sizeof(raw), sizeof(raw) - 1, &pkt), -EMSGSIZE);
	/* Packet.unpack(): hops of 128 or more, or no data, are malformed. */
	raw[1] = 128;
	zassert_equal(ret_packet_unpack_max(raw, sizeof(raw), sizeof(raw), &pkt), -EBADMSG);
	raw[1] = 127;
	zassert_ok(ret_packet_unpack_max(raw, sizeof(raw), sizeof(raw), &pkt));
	zassert_equal(ret_packet_unpack_max(raw, RET_H1_HEADER_LEN, sizeof(raw), &pkt), -EBADMSG);
}

ZTEST_SUITE(ret_transport, NULL, NULL, before, NULL, NULL);
