/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ret_crypto.h"
#include "ret_hdlc.h"
#include "ret_packet.h"
#include "vectors_rns.h"

/* --- HDLC ---------------------------------------------------------- */

struct frames {
	int count;
	size_t len[8];
	uint8_t data[8][RET_MTU];
};

static void collect(const uint8_t *frame, size_t len, void *user)
{
	struct frames *f = user;

	zassert_true(f->count < ARRAY_SIZE(f->len));
	f->len[f->count] = len;
	memcpy(f->data[f->count], frame, len);
	f->count++;
}

static struct frames got;
static uint8_t dec_buf[RET_MTU];
static struct ret_hdlc_decoder dec;

static void hdlc_before(void *fixture)
{
	ARG_UNUSED(fixture);
	memset(&got, 0, sizeof(got));
	ret_hdlc_decoder_init(&dec, dec_buf, sizeof(dec_buf));
}

ZTEST(hdlc, test_encode_escapes)
{
	const uint8_t in[] = { 0x7E, 0x7D, 0x01, 0x5E };
	const uint8_t want[] = { 0x7E, 0x7D, 0x5E, 0x7D, 0x5D, 0x01, 0x5E, 0x7E };
	uint8_t out[16];
	int n = ret_hdlc_encode(in, sizeof(in), out, sizeof(out));

	zassert_equal(n, sizeof(want));
	zassert_mem_equal(out, want, sizeof(want));
}

ZTEST(hdlc, test_encode_too_small)
{
	const uint8_t in[] = { 0x7E, 0x7E };
	uint8_t out[6];

	zassert_equal(ret_hdlc_encode(in, sizeof(in), out, sizeof(out) - 1), -ENOMEM);
	zassert_equal(ret_hdlc_encode(in, sizeof(in), out, sizeof(out)), 6);
}

ZTEST(hdlc, test_roundtrip_bytewise)
{
	uint8_t enc[RET_HDLC_MAX_ENCODED(sizeof(v_announce))];
	int n = ret_hdlc_encode(v_announce, sizeof(v_announce), enc, sizeof(enc));

	zassert_true(n > 0);
	for (int i = 0; i < n; i++) {
		ret_hdlc_feed(&dec, &enc[i], 1, collect, &got);
	}
	zassert_equal(got.count, 1);
	zassert_equal(got.len[0], sizeof(v_announce));
	zassert_mem_equal(got.data[0], v_announce, sizeof(v_announce));
}

ZTEST(hdlc, test_escape_split_across_reads)
{
	/* ESC as the last byte of one read, its partner in the next. */
	const uint8_t a[] = { 0x7E, 0x01, 0x7D };
	const uint8_t b[] = { 0x5E, 0x02, 0x7E };

	ret_hdlc_feed(&dec, a, sizeof(a), collect, &got);
	zassert_equal(got.count, 0);
	ret_hdlc_feed(&dec, b, sizeof(b), collect, &got);
	zassert_equal(got.count, 1);
	zassert_equal(got.len[0], 3);
	zassert_mem_equal(got.data[0], ((uint8_t[]){ 0x01, 0x7E, 0x02 }), 3);
}

ZTEST(hdlc, test_back_to_back_and_shared_flags)
{
	/* Garbage before the first flag, a frame, a doubled flag (empty
	 * frame), then a frame whose opening flag is the previous closer.
	 */
	const uint8_t s[] = { 0xAA, 0xBB, 0x7E, 0x11, 0x22, 0x7E, 0x7E, 0x33, 0x7E, 0x44, 0x7E };

	ret_hdlc_feed(&dec, s, sizeof(s), collect, &got);
	zassert_equal(got.count, 3);
	zassert_equal(got.len[0], 2);
	zassert_equal(got.data[0][0], 0x11);
	zassert_equal(got.len[1], 1);
	zassert_equal(got.data[1][0], 0x33);
	zassert_equal(got.len[2], 1);
	zassert_equal(got.data[2][0], 0x44);
}

ZTEST(hdlc, test_oversize_frame_dropped)
{
	uint8_t big[RET_MTU + 10];
	const uint8_t flag = 0x7E;
	const uint8_t small[] = { 0x55, 0x7E };

	memset(big, 0x42, sizeof(big));
	ret_hdlc_feed(&dec, &flag, 1, collect, &got);
	ret_hdlc_feed(&dec, big, sizeof(big), collect, &got);
	ret_hdlc_feed(&dec, &flag, 1, collect, &got);
	zassert_equal(got.count, 0);
	zassert_equal(dec.dropped, 1);

	/* The decoder recovers for the next frame. */
	ret_hdlc_feed(&dec, small, sizeof(small), collect, &got);
	zassert_equal(got.count, 1);
	zassert_equal(got.data[0][0], 0x55);
}

ZTEST(hdlc, test_mtu_frame_accepted)
{
	static uint8_t pkt[RET_MTU];
	static uint8_t enc[RET_HDLC_MAX_ENCODED(RET_MTU)];
	int n;

	/* All flag bytes: worst-case escaping, exactly the MTU unescaped. */
	memset(pkt, RET_HDLC_FLAG, sizeof(pkt));
	n = ret_hdlc_encode(pkt, sizeof(pkt), enc, sizeof(enc));
	zassert_equal(n, (int)sizeof(enc));
	ret_hdlc_feed(&dec, enc, (size_t)n, collect, &got);
	zassert_equal(got.count, 1);
	zassert_equal(got.len[0], RET_MTU);
	zassert_mem_equal(got.data[0], pkt, RET_MTU);
	zassert_equal(dec.dropped, 0);
}

ZTEST(hdlc, test_esc_before_flag_dropped)
{
	const uint8_t s[] = { 0x7E, 0x01, 0x7D, 0x7E, 0x02, 0x7E };

	ret_hdlc_feed(&dec, s, sizeof(s), collect, &got);
	zassert_equal(got.count, 1);
	zassert_equal(got.len[0], 1);
	zassert_equal(got.data[0][0], 0x02);
	zassert_equal(dec.dropped, 1);
}

ZTEST(hdlc, test_reset_drops_partial)
{
	const uint8_t a[] = { 0x7E, 0x01, 0x02 };
	const uint8_t b[] = { 0x03, 0x7E, 0x04, 0x7E };

	ret_hdlc_feed(&dec, a, sizeof(a), collect, &got);
	ret_hdlc_decoder_reset(&dec);
	ret_hdlc_feed(&dec, b, sizeof(b), collect, &got);
	/* 0x03 arrived before any flag after reset: discarded. */
	zassert_equal(got.count, 1);
	zassert_equal(got.len[0], 1);
	zassert_equal(got.data[0][0], 0x04);
}

ZTEST_SUITE(hdlc, NULL, NULL, hdlc_before, NULL, NULL);

/* --- Packet -------------------------------------------------------- */

static void *packet_setup(void)
{
	zassert_ok(ret_crypto_init());
	return NULL;
}

ZTEST(packet, test_unpack_h1_announce)
{
	struct ret_packet p;

	zassert_ok(ret_packet_unpack(v_announce, sizeof(v_announce), &p));
	zassert_equal(p.header_type, RET_HEADER_1);
	zassert_equal(p.packet_type, RET_PKT_ANNOUNCE);
	zassert_equal(p.dest_type, RET_DEST_SINGLE);
	zassert_equal(p.transport_type, RET_TRANSPORT_BROADCAST);
	zassert_equal(p.context_flag, 0);
	zassert_equal(p.hops, 0);
	zassert_equal(p.context, RET_CONTEXT_NONE);
	zassert_mem_equal(p.dest_hash, v_dest_hash, RET_TRUNC_HASH_LEN);
	zassert_equal(p.data_len, sizeof(v_announce) - RET_H1_HEADER_LEN);
	zassert_equal_ptr(p.data, &v_announce[RET_H1_HEADER_LEN]);
}

ZTEST(packet, test_unpack_h2_announce)
{
	struct ret_packet p;

	zassert_ok(ret_packet_unpack(v_announce_ratchet_h2, sizeof(v_announce_ratchet_h2), &p));
	zassert_equal(p.header_type, RET_HEADER_2);
	zassert_equal(p.transport_type, RET_TRANSPORT_TRANSPORT);
	zassert_equal(p.context_flag, 1);
	zassert_equal(p.hops, 1);
	zassert_mem_equal(p.transport_id, v_transport_id, RET_TRUNC_HASH_LEN);
	zassert_mem_equal(p.dest_hash, v_dest_hash, RET_TRUNC_HASH_LEN);
	zassert_equal(p.data_len, sizeof(v_announce_ratchet_h2) - RET_H2_HEADER_LEN);
}

ZTEST(packet, test_pack_roundtrip)
{
	const uint8_t *vec[] = { v_announce, v_announce_ratchet_h2, v_data_h1, v_data_h2,
				 v_proof_implicit };
	const size_t len[] = { sizeof(v_announce), sizeof(v_announce_ratchet_h2),
			       sizeof(v_data_h1), sizeof(v_data_h2), sizeof(v_proof_implicit) };
	uint8_t out[RET_MTU];

	for (size_t i = 0; i < ARRAY_SIZE(vec); i++) {
		struct ret_packet p;

		zassert_ok(ret_packet_unpack(vec[i], len[i], &p));
		zassert_equal(ret_packet_pack(&p, out, sizeof(out)), (int)len[i], "vector %zu", i);
		zassert_mem_equal(out, vec[i], len[i], "vector %zu", i);
	}
}

ZTEST(packet, test_unpack_rejects)
{
	struct ret_packet p;
	uint8_t raw[RET_MTU + 1] = { 0 };

	zassert_equal(ret_packet_unpack(raw, 1, &p), -EMSGSIZE);
	zassert_equal(ret_packet_unpack(raw, RET_H1_HEADER_LEN - 1, &p), -EMSGSIZE);
	zassert_ok(ret_packet_unpack(raw, RET_H1_HEADER_LEN, &p));
	zassert_equal(ret_packet_unpack(raw, sizeof(raw), &p), -EMSGSIZE);

	raw[0] = 0x40; /* HEADER_2 needs the transport ID too */
	zassert_equal(ret_packet_unpack(raw, RET_H2_HEADER_LEN - 1, &p), -EMSGSIZE);
	zassert_ok(ret_packet_unpack(raw, RET_H2_HEADER_LEN, &p));

	raw[0] = 0x80; /* IFAC */
	zassert_equal(ret_packet_unpack(raw, RET_H1_HEADER_LEN, &p), -ENOTSUP);
}

ZTEST(packet, test_pack_rejects_over_mtu)
{
	static uint8_t data[RET_MTU];
	uint8_t out[RET_MTU + RET_H2_HEADER_LEN];
	struct ret_packet p = { .data = data, .data_len = RET_MTU - RET_H1_HEADER_LEN + 1 };

	zassert_equal(ret_packet_pack(&p, out, sizeof(out)), -EMSGSIZE);
	p.data_len--;
	zassert_equal(ret_packet_pack(&p, out, sizeof(out)), RET_MTU);
	zassert_equal(ret_packet_pack(&p, out, RET_MTU - 1), -EMSGSIZE);
}

ZTEST(packet, test_packet_hash_matches_rns)
{
	uint8_t h[RET_HASH_LEN];

	zassert_ok(ret_packet_hash(v_data_h1, sizeof(v_data_h1), h));
	zassert_mem_equal(h, v_packet_hash, RET_HASH_LEN);

	/* Header rewrite to HEADER_2 leaves the hash unchanged. */
	zassert_ok(ret_packet_hash(v_data_h2, sizeof(v_data_h2), h));
	zassert_mem_equal(h, v_packet_hash, RET_HASH_LEN);
}

ZTEST(packet, test_path_request_matches_rns)
{
	uint8_t out[RET_MTU];
	int n = ret_path_request_build(v_dest_hash, v_path_request_tag, out, sizeof(out));

	zassert_equal(n, RET_PATH_REQUEST_LEN);
	zassert_equal(n, sizeof(v_path_request));
	zassert_mem_equal(out, v_path_request, sizeof(v_path_request));
	zassert_mem_equal(&out[2], v_path_request_dest, RET_TRUNC_HASH_LEN);
	zassert_equal(ret_path_request_build(v_dest_hash, v_path_request_tag, out, n - 1),
		      -EMSGSIZE);
}

ZTEST_SUITE(packet, NULL, packet_setup, NULL, NULL, NULL);
