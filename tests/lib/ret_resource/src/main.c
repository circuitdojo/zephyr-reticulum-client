/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * Resource receiving against vectors laid out as RNS/Resource.py builds
 * them (stream = Token(random4 | data) under the link key, SDU 464 parts,
 * map hashes SHA256(part | r)[:4], hashmap update h | [segment, hashes]).
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ret_crypto.h"
#include "ret_link.h"
#include "ret_resource.h"
#include "vectors_rns.h"

static struct ret_resource_rx rx;
static uint8_t stream[40960];
static uint8_t plain[40960];
static uint8_t req[256];
static struct ret_resource_tx tx;
static struct ret_resource_tx_req txreq;
static uint8_t tx_stream[40960];
static uint8_t tx_data[36000];

static void *setup(void)
{
	zassert_ok(ret_crypto_init());
	return NULL;
}

static void parse_adv(const uint8_t *adv_plain, size_t len, struct ret_resource_adv *adv)
{
	zassert_ok(ret_resource_adv_parse(adv_plain, len, adv));
}

static size_t part_len(const uint8_t *s, size_t total, uint32_t i)
{
	ARG_UNUSED(s);
	size_t off = (size_t)i * RET_RESOURCE_SDU;

	return MIN((size_t)RET_RESOURCE_SDU, total - off);
}

ZTEST(resource, test_adv_parse)
{
	struct ret_resource_adv adv;

	parse_adv(v_res_adv_plain, sizeof(v_res_adv_plain), &adv);
	zassert_equal(adv.t, sizeof(v_res_stream));
	zassert_equal(adv.d, sizeof(v_res_data));
	zassert_equal(adv.n, DIV_ROUND_UP(sizeof(v_res_stream), RET_RESOURCE_SDU));
	zassert_equal(adv.i, 1);
	zassert_equal(adv.l, 1);
	zassert_equal(adv.f, RET_RESOURCE_F_ENCRYPTED | RET_RESOURCE_F_RESPONSE);
	zassert_mem_equal(adv.h, v_res_h, 32);
	zassert_mem_equal(adv.r, v_res_r, 4);
	zassert_not_null(adv.q);
	zassert_mem_equal(adv.q, v_link_request_id, 16);
	zassert_equal(adv.m_len, sizeof(v_res_hashmap));
}

ZTEST(resource, test_adv_packet_decrypts)
{
	struct ret_packet p;
	uint8_t buf[RET_MTU];
	struct ret_resource_adv adv;
	int n;

	zassert_ok(ret_packet_unpack(v_res_adv_packet, sizeof(v_res_adv_packet), &p));
	zassert_equal(p.context, RET_CTX_RESOURCE_ADV);
	n = ret_token_decrypt(v_link_key, p.data, p.data_len, buf, sizeof(buf));
	zassert_equal(n, sizeof(v_res_adv_plain));
	zassert_mem_equal(buf, v_res_adv_plain, n);
	zassert_ok(ret_resource_adv_parse(buf, n, &adv));
}

ZTEST(resource, test_small_transfer)
{
	struct ret_resource_adv adv;
	uint8_t want[1 + 32 + 3 * 4];
	uint8_t proof[RET_RESOURCE_PROOF_LEN];
	int n;

	parse_adv(v_res_adv_plain, sizeof(v_res_adv_plain), &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	zassert_equal(rx.n, 3);

	/* First request: flag 0, hash, all three map hashes (window 4). */
	want[0] = 0x00;
	memcpy(&want[1], v_res_h, 32);
	memcpy(&want[33], v_res_hashmap, 12);
	n = ret_resource_rx_request(&rx, req, sizeof(req));
	zassert_equal(n, sizeof(want));
	zassert_mem_equal(req, want, sizeof(want));

	/* Out of order, with a duplicate and a junk part. */
	static const uint32_t order[] = { 2, 0, 0, 1 };
	static const enum ret_resource_part expect[] = {
		RET_RESOURCE_PART_ACCEPTED, RET_RESOURCE_PART_ACCEPTED, RET_RESOURCE_PART_IGNORED,
		RET_RESOURCE_PART_COMPLETE,
	};

	zassert_equal(ret_resource_rx_part(&rx, (const uint8_t *)"junk", 4),
		      RET_RESOURCE_PART_IGNORED);
	for (size_t k = 0; k < ARRAY_SIZE(order); k++) {
		uint32_t i = order[k];

		zassert_equal(ret_resource_rx_part(&rx, &v_res_stream[i * RET_RESOURCE_SDU],
						   part_len(v_res_stream, sizeof(v_res_stream), i)),
			      expect[k], "step %zu", k);
	}

	n = ret_resource_rx_assemble(&rx, v_link_key, plain, sizeof(plain));
	zassert_equal(n, sizeof(v_res_data));
	zassert_mem_equal(plain, v_res_data, n);
	zassert_ok(ret_resource_proof(&rx, plain, n, proof));
	zassert_mem_equal(proof, v_res_proof, sizeof(proof));
}

ZTEST(resource, test_large_transfer_with_hashmap_update)
{
	struct ret_resource_adv adv;
	uint8_t proof[RET_RESOURCE_PROOF_LEN];
	bool saw_exhausted = false;
	uint32_t rounds = 0;
	int n;

	parse_adv(v_resbig_adv_plain, sizeof(v_resbig_adv_plain), &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	zassert_true(rx.n > RET_RESOURCE_HASHMAP_SEG);
	zassert_equal(rx.hashmap_height, RET_RESOURCE_HASHMAP_SEG);

	for (;;) {
		zassert_true(++rounds < 200, "transfer did not converge");
		n = ret_resource_rx_request(&rx, req, sizeof(req));
		zassert_true(n > 0);

		if (req[0] == 0xFF) {
			/* Hashmap ran out: flag, last known map hash, then the hash. */
			saw_exhausted = true;
			zassert_mem_equal(&req[1], &v_resbig_hashmap[(RET_RESOURCE_HASHMAP_SEG - 1) * 4],
					  4);
			zassert_mem_equal(&req[5], v_resbig_h, 32);
		}

		/* Serve every requested map hash, as the sender would. */
		size_t hoff = req[0] == 0xFF ? 1 + 4 + 32 : 1 + 32;
		enum ret_resource_part st = RET_RESOURCE_PART_IGNORED;

		for (size_t o = hoff; o < (size_t)n; o += 4) {
			uint32_t i;

			for (i = 0; i < rx.n; i++) {
				if (memcmp(&v_resbig_hashmap[i * 4], &req[o], 4) == 0) {
					break;
				}
			}
			zassert_true(i < rx.n);
			st = ret_resource_rx_part(&rx, &v_resbig_stream[i * RET_RESOURCE_SDU],
						  part_len(v_resbig_stream, sizeof(v_resbig_stream),
							   i));
		}
		if (st == RET_RESOURCE_PART_COMPLETE) {
			break;
		}
		if (rx.waiting_hmu && rx.outstanding == 0) {
			zassert_ok(ret_resource_rx_hmu(&rx, v_resbig_hmu_plain,
						       sizeof(v_resbig_hmu_plain)));
		}
	}
	zassert_true(saw_exhausted);
	zassert_equal(rx.window, RET_RESOURCE_WINDOW_MAX);

	n = ret_resource_rx_assemble(&rx, v_link_key, plain, sizeof(plain));
	zassert_true(n > 36000);
	zassert_ok(ret_resource_proof(&rx, plain, n, proof));
	zassert_mem_equal(proof, v_resbig_proof, sizeof(proof));
}

ZTEST(resource, test_proof_packet)
{
	uint8_t pkt[RET_MTU];
	int n = ret_link_resource_proof_build(v_link_id, v_res_proof, pkt, sizeof(pkt));

	zassert_equal(n, sizeof(v_res_proof_packet));
	zassert_mem_equal(pkt, v_res_proof_packet, n);
	zassert_equal(ret_link_resource_proof_build(v_link_id, v_res_proof, pkt, 40), -EMSGSIZE);
}

ZTEST(resource, test_timeout_shrinks_window)
{
	struct ret_resource_adv adv;

	parse_adv(v_res_adv_plain, sizeof(v_res_adv_plain), &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	zassert_equal(rx.window, RET_RESOURCE_WINDOW);
	for (int i = 0; i < 5; i++) {
		ret_resource_rx_timeout(&rx);
	}
	zassert_equal(rx.window, RET_RESOURCE_WINDOW_MIN);

	/* The repeated request still asks for what is missing. */
	zassert_equal(ret_resource_rx_request(&rx, req, sizeof(req)), 1 + 32 + 2 * 4);
}

ZTEST(resource, test_delivery_resource)
{
	/* LXMF DIRECT: an advertisement that is neither request nor response
	 * (no request id), carrying the raw data.
	 */
	struct ret_resource_adv adv;
	uint8_t proof[RET_RESOURCE_PROOF_LEN];
	int n;

	parse_adv(v_resdel_adv_plain, sizeof(v_resdel_adv_plain), &adv);
	zassert_is_null(adv.q);
	zassert_equal(adv.f, RET_RESOURCE_F_ENCRYPTED);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	(void)ret_resource_rx_request(&rx, req, sizeof(req));
	for (uint32_t i = 0; i < rx.n; i++) {
		enum ret_resource_part st = ret_resource_rx_part(
			&rx, &v_resdel_stream[i * RET_RESOURCE_SDU],
			part_len(v_resdel_stream, sizeof(v_resdel_stream), i));

		if (st == RET_RESOURCE_PART_WINDOW) {
			(void)ret_resource_rx_request(&rx, req, sizeof(req));
		}
	}
	n = ret_resource_rx_assemble(&rx, v_link_key, plain, sizeof(plain));
	zassert_equal(n, sizeof(v_resdel_data));
	zassert_mem_equal(plain, v_resdel_data, n);
	zassert_ok(ret_resource_proof(&rx, plain, n, proof));
	zassert_mem_equal(proof, v_resdel_proof, sizeof(proof));
}

ZTEST(resource, test_rejects)
{
	struct ret_resource_adv adv, bad;

	parse_adv(v_res_adv_plain, sizeof(v_res_adv_plain), &adv);

	bad = adv;
	bad.f |= RET_RESOURCE_F_COMPRESSED;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -ENOTSUP);
	bad = adv;
	bad.f |= RET_RESOURCE_F_METADATA;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -ENOTSUP);
	bad = adv;
	bad.l = 2;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -ENOTSUP);
	bad = adv;
	bad.f &= ~RET_RESOURCE_F_ENCRYPTED;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -ENOTSUP);
	zassert_equal(ret_resource_rx_init(&rx, &adv, stream, sizeof(v_res_stream) - 1), -EFBIG);
	bad = adv;
	bad.n = 2;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -EBADMSG);

	/* A corrupted stream fails the HMAC, so assembly refuses it. */
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	for (uint32_t i = 0; i < rx.n; i++) {
		(void)ret_resource_rx_part(&rx, &v_res_stream[i * RET_RESOURCE_SDU],
					   part_len(v_res_stream, sizeof(v_res_stream), i));
	}
	stream[10] ^= 0x01;
	zassert_equal(ret_resource_rx_assemble(&rx, v_link_key, plain, sizeof(plain)), -EBADMSG);

	/* A hashmap update while not waiting for one, or for another resource. */
	zassert_equal(ret_resource_rx_hmu(&rx, v_resbig_hmu_plain, sizeof(v_resbig_hmu_plain)),
		      -EBADMSG);
}

ZTEST(resource, test_rejects_bad_hashmap_and_size)
{
	struct ret_resource_adv adv, bad;
	static uint8_t big_cap_dummy[1];

	parse_adv(v_resbig_adv_plain, sizeof(v_resbig_adv_plain), &adv);

	/* The advertisement must carry the whole first segment (74 hashes). */
	bad = adv;
	bad.m_len = 0;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -EBADMSG);
	bad.m_len = 4 * 10;
	zassert_equal(ret_resource_rx_init(&rx, &bad, stream, sizeof(stream)), -EBADMSG);

	/* Over CONFIG_RET_RESOURCE_MAX_SIZE even with room in the buffer. */
	bad = adv;
	bad.t = CONFIG_RET_RESOURCE_MAX_SIZE + 1;
	bad.n = DIV_ROUND_UP(bad.t, RET_RESOURCE_SDU);
	zassert_equal(ret_resource_rx_init(&rx, &bad, big_cap_dummy, SIZE_MAX), -EFBIG);
}

ZTEST(resource, test_hmu_rejects)
{
	struct ret_resource_adv adv;
	uint8_t hmu[64];
	static const uint8_t empty[] = { 0x92, 0x01, 0xc4, 0x00 };
	static const uint8_t seg2[] = { 0x92, 0x02, 0xc4, 0x04, 1, 2, 3, 4 };
	static const uint8_t huge[] = { 0x92, 0xcf, 0xff, 0xff, 0xff, 0xff, 0xff,
					0xff, 0xff, 0xff, 0xc4, 0x04, 1,    2,
					3,    4 };

	parse_adv(v_resbig_adv_plain, sizeof(v_resbig_adv_plain), &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	rx.waiting_hmu = true;

	memcpy(hmu, v_resbig_h, 32);
	memcpy(&hmu[32], empty, sizeof(empty));
	zassert_equal(ret_resource_rx_hmu(&rx, hmu, 32 + sizeof(empty)), -EBADMSG);
	memcpy(&hmu[32], seg2, sizeof(seg2));
	zassert_equal(ret_resource_rx_hmu(&rx, hmu, 32 + sizeof(seg2)), -EBADMSG);
	memcpy(&hmu[32], huge, sizeof(huge));
	zassert_equal(ret_resource_rx_hmu(&rx, hmu, 32 + sizeof(huge)), -EBADMSG);
	zassert_equal(ret_resource_rx_hmu(&rx, v_resbig_hmu_plain, sizeof(v_resbig_hmu_plain) - 3),
		      -EBADMSG);
	zassert_equal(rx.hashmap_height, RET_RESOURCE_HASHMAP_SEG);
	zassert_ok(ret_resource_rx_hmu(&rx, v_resbig_hmu_plain, sizeof(v_resbig_hmu_plain)));
	zassert_equal(rx.hashmap_height, rx.n);
}

ZTEST(resource, test_short_part_ignored)
{
	struct ret_resource_adv adv;

	parse_adv(v_res_adv_plain, sizeof(v_res_adv_plain), &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	zassert_equal(ret_resource_rx_part(&rx, v_res_stream, RET_RESOURCE_SDU - 1),
		      RET_RESOURCE_PART_IGNORED);
	zassert_equal(rx.received, 0);
}

ZTEST(resource, test_request_stays_in_window)
{
	struct ret_resource_adv adv;
	uint8_t want[1 + 32 + 4];

	/* Parts 1-3 of the first window arrive, part 0 is lost; after the
	 * timeout only part 0 is asked for: later parts would fall outside
	 * the range accepted until part 0 is in (Resource.request_next).
	 */
	parse_adv(v_resbig_adv_plain, sizeof(v_resbig_adv_plain), &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));
	zassert_equal(ret_resource_rx_request(&rx, req, sizeof(req)), 1 + 32 + 4 * 4);
	for (uint32_t i = 1; i < 4; i++) {
		zassert_equal(ret_resource_rx_part(&rx, &v_resbig_stream[i * RET_RESOURCE_SDU],
						   RET_RESOURCE_SDU),
			      RET_RESOURCE_PART_ACCEPTED);
	}
	ret_resource_rx_timeout(&rx);
	want[0] = 0x00;
	memcpy(&want[1], v_resbig_h, 32);
	memcpy(&want[33], v_resbig_hashmap, 4);
	zassert_equal(ret_resource_rx_request(&rx, req, sizeof(req)), sizeof(want));
	zassert_mem_equal(req, want, sizeof(want));
}

ZTEST(resource, test_adv_parse_rejects)
{
	struct ret_resource_adv adv;
	uint8_t trunc[sizeof(v_res_adv_plain)];

	memcpy(trunc, v_res_adv_plain, sizeof(trunc));
	zassert_equal(ret_resource_adv_parse(trunc, sizeof(trunc) - 5, &adv), -EBADMSG);
	zassert_equal(ret_resource_adv_parse((const uint8_t *)"\x90", 1, &adv), -EBADMSG);
}

ZTEST(resource, test_adv_parse_skips_unknown_keys)
{
	struct ret_resource_adv adv;
	uint8_t ext[sizeof(v_res_adv_plain) + 4];

	/* A newer sender's extra key, longer than one character: skipped. */
	zassert_equal(v_res_adv_plain[0] & 0xF0, 0x80, "want a fixmap");
	memcpy(ext, v_res_adv_plain, sizeof(v_res_adv_plain));
	ext[0]++;
	memcpy(&ext[sizeof(v_res_adv_plain)], "\xa2zz\xc0", 4);
	zassert_ok(ret_resource_adv_parse(ext, sizeof(ext), &adv));
	zassert_equal(adv.t, sizeof(v_res_stream));
}

/* --- Sending --------------------------------------------------------- */

static void fill_tx_data(size_t len)
{
	/* gen_vectors.sender_resource_vectors: (i * 11 + 5) & 0xFF. */
	for (size_t i = 0; i < len; i++) {
		tx_data[i] = (uint8_t)((i * 11 + 5) & 0xFF);
	}
}

/* Our receiver against our sender: requests, parts and hashmap updates
 * go back and forth until it is complete; then the proof must satisfy the
 * sender. Returns the hashmap updates sent.
 */
static int loopback(size_t data_len)
{
	struct ret_resource_adv adv;
	uint8_t adv_plain[RET_LINK_MDU];
	uint8_t hmu[RET_LINK_MDU];
	uint8_t proof[RET_RESOURCE_PROOF_LEN];
	int hmus = 0;
	int n;

	n = ret_resource_tx_adv(&tx, adv_plain, sizeof(adv_plain));
	zassert_true(n > 0);
	parse_adv(adv_plain, n, &adv);
	zassert_ok(ret_resource_rx_init(&rx, &adv, stream, sizeof(stream)));

	for (int rounds = 0;; rounds++) {
		enum ret_resource_part st = RET_RESOURCE_PART_IGNORED;

		zassert_true(rounds < 200, "transfer did not converge");
		zassert_false(ret_resource_tx_all_sent(&tx) && rounds > 100);
		n = ret_resource_rx_request(&rx, req, sizeof(req));
		zassert_true(n > 0);
		zassert_ok(ret_resource_tx_request(&tx, req, n, &txreq));
		for (size_t k = 0; k < txreq.n_parts; k++) {
			size_t plen;
			const uint8_t *part = ret_resource_tx_part(&tx, txreq.parts[k], &plen);

			st = ret_resource_rx_part(&rx, part, plen);
		}
		if (txreq.hmu) {
			n = ret_resource_tx_hmu(&tx, txreq.hmu_segment, hmu, sizeof(hmu));
			zassert_true(n > 0);
			zassert_ok(ret_resource_rx_hmu(&rx, hmu, n));
			hmus++;
		}
		if (st == RET_RESOURCE_PART_COMPLETE) {
			break;
		}
	}
	zassert_true(ret_resource_tx_all_sent(&tx));
	n = ret_resource_rx_assemble(&rx, v_link_key, plain, sizeof(plain));
	zassert_equal(n, data_len);
	zassert_mem_equal(plain, tx_data, data_len);
	zassert_ok(ret_resource_proof(&rx, plain, n, proof));
	zassert_true(ret_resource_tx_proof_valid(&tx, proof, sizeof(proof)));
	return hmus;
}

ZTEST(resource, test_tx_matches_rns)
{
	uint8_t adv[RET_LINK_MDU];
	int n;

	fill_tx_data(sizeof(v_restx_data));
	zassert_mem_equal(tx_data, v_restx_data, sizeof(v_restx_data));
	zassert_ok(ret_resource_tx_init(&tx, v_link_key, v_restx_iv, v_restx_prefix, tx_data,
					sizeof(v_restx_data), tx_stream, sizeof(tx_stream)));
	zassert_ok(ret_resource_tx_map(&tx, tx_data, sizeof(v_restx_data), v_restx_r));
	zassert_equal(tx.t, sizeof(v_restx_stream));
	zassert_equal(tx.t, RET_RESOURCE_STREAM_LEN(sizeof(v_restx_data)));
	zassert_mem_equal(tx_stream, v_restx_stream, tx.t);
	zassert_mem_equal(tx.h, v_restx_h, sizeof(tx.h));
	zassert_mem_equal(tx.hashmap, v_restx_hashmap, sizeof(v_restx_hashmap));
	zassert_mem_equal(tx.expected_proof, v_restx_expected_proof, 32);

	n = ret_resource_tx_adv(&tx, adv, sizeof(adv));
	zassert_equal(n, sizeof(v_restx_adv_plain));
	zassert_mem_equal(adv, v_restx_adv_plain, n);
	zassert_equal(ret_resource_tx_adv(&tx, adv, 60), -ENOBUFS);

	zassert_equal(loopback(sizeof(v_restx_data)), 0);
}

ZTEST(resource, test_tx_hashmap_update_matches_rns)
{
	uint8_t adv[RET_LINK_MDU];
	uint8_t hmu[RET_LINK_MDU];
	int n;

	fill_tx_data(36000);
	zassert_ok(ret_resource_tx_init(&tx, v_link_key, v_restxbig_iv, v_restxbig_prefix,
					tx_data, 36000, tx_stream, sizeof(tx_stream)));
	zassert_ok(ret_resource_tx_map(&tx, tx_data, 36000, v_restxbig_r));
	zassert_equal(tx.t, sizeof(v_restxbig_stream));
	zassert_mem_equal(tx_stream, v_restxbig_stream, tx.t);
	zassert_mem_equal(tx.hashmap, v_restxbig_hashmap, sizeof(v_restxbig_hashmap));
	zassert_mem_equal(tx.expected_proof, v_restxbig_expected_proof, 32);
	n = ret_resource_tx_adv(&tx, adv, sizeof(adv));
	zassert_equal(n, sizeof(v_restxbig_adv_plain));
	zassert_mem_equal(adv, v_restxbig_adv_plain, n);

	/* RNS's answer to running out of map hashes after part 73: parts
	 * 70..73, then segment 1.
	 */
	zassert_ok(ret_resource_tx_request(&tx, v_restxbig_req, sizeof(v_restxbig_req), &txreq));
	zassert_equal(txreq.n_parts, 4);
	for (size_t k = 0; k < 4; k++) {
		zassert_equal(txreq.parts[k], 70 + k);
	}
	zassert_true(txreq.hmu);
	zassert_equal(txreq.hmu_segment, 1);
	n = ret_resource_tx_hmu(&tx, 1, hmu, sizeof(hmu));
	zassert_equal(n, sizeof(v_restxbig_hmu_plain));
	zassert_mem_equal(hmu, v_restxbig_hmu_plain, n);
	zassert_equal(tx.min_height, 74 - 1 - RET_RESOURCE_WINDOW_MAX);

	/* The next request is matched from that height: parts 74..77, and a
	 * map hash below it (part 0) is out of scope.
	 */
	uint8_t next[1 + 32 + 5 * 4];

	next[0] = 0x00;
	memcpy(&next[1], v_restxbig_h, 32);
	memcpy(&next[33], &v_restxbig_hashmap[74 * 4], 4 * 4);
	memcpy(&next[33 + 16], &v_restxbig_hashmap[0], 4);
	zassert_ok(ret_resource_tx_request(&tx, next, sizeof(next), &txreq));
	zassert_equal(txreq.n_parts, 4);
	zassert_equal(txreq.parts[0], 74);
	zassert_equal(txreq.parts[3], 77);
	zassert_false(txreq.hmu);
	zassert_true(ret_resource_tx_all_sent(&tx) == false);

	/* From the start, against our receiver. */
	zassert_ok(ret_resource_tx_init(&tx, v_link_key, v_restxbig_iv, v_restxbig_prefix,
					tx_data, 36000, tx_stream, sizeof(tx_stream)));
	zassert_ok(ret_resource_tx_map(&tx, tx_data, 36000, v_restxbig_r));
	zassert_equal(loopback(36000), 1);
}

ZTEST(resource, test_tx_rejects)
{
	uint8_t bad[1 + 32 + 4];
	uint8_t proof[RET_RESOURCE_PROOF_LEN];

	fill_tx_data(36000);
	zassert_equal(ret_resource_tx_init(&tx, v_link_key, v_restx_iv, v_restx_prefix, tx_data,
					   sizeof(v_restx_data), tx_stream, 1000),
		      -EFBIG);
	zassert_equal(ret_resource_tx_init(&tx, v_link_key, v_restx_iv, v_restx_prefix, tx_data,
					   0, tx_stream, sizeof(tx_stream)),
		      -EFBIG);
	zassert_ok(ret_resource_tx_init(&tx, v_link_key, v_restx_iv, v_restx_prefix, tx_data,
					sizeof(v_restx_data), tx_stream, sizeof(tx_stream)));
	zassert_ok(ret_resource_tx_map(&tx, tx_data, sizeof(v_restx_data), v_restx_r));

	/* A request for another resource, or too short. */
	bad[0] = 0x00;
	memset(&bad[1], 0xAA, 32);
	memcpy(&bad[33], v_restx_hashmap, 4);
	zassert_equal(ret_resource_tx_request(&tx, bad, sizeof(bad), &txreq), -EBADMSG);
	zassert_equal(ret_resource_tx_request(&tx, bad, 10, &txreq), -EBADMSG);

	/* Out of map hashes where no segment ends: a sequencing error. */
	uint8_t seq[1 + 4 + 32];

	seq[0] = 0xFF;
	memcpy(&seq[1], v_restx_hashmap, 4);
	memcpy(&seq[5], v_restx_h, 32);
	zassert_equal(ret_resource_tx_request(&tx, seq, sizeof(seq), &txreq), -EPROTO);

	/* A proof must carry the hash and the expected proof. */
	memcpy(proof, v_restx_h, 32);
	memcpy(&proof[32], v_restx_expected_proof, 32);
	zassert_true(ret_resource_tx_proof_valid(&tx, proof, sizeof(proof)));
	zassert_false(ret_resource_tx_proof_valid(&tx, proof, sizeof(proof) - 1));
	proof[40] ^= 1;
	zassert_false(ret_resource_tx_proof_valid(&tx, proof, sizeof(proof)));
	proof[40] ^= 1;
	proof[0] ^= 1;
	zassert_false(ret_resource_tx_proof_valid(&tx, proof, sizeof(proof)));
}

ZTEST_SUITE(resource, NULL, setup, NULL, NULL, NULL);
