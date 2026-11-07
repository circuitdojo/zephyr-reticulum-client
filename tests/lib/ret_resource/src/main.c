/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
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

ZTEST_SUITE(resource, NULL, setup, NULL, NULL, NULL);
