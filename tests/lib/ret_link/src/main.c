/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Link initiator pieces against vectors built with RNS (link_id from
 * RNS.Link.link_id_from_lr_packet, signalling from Link.signalling_bytes,
 * tokens from RNS's Token with pinned IVs).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ret_crypto.h"
#include "ret_link.h"
#include "vectors_rns.h"

static struct ret_link_keys keys;

static void *setup(void)
{
	zassert_ok(ret_crypto_init());
	return NULL;
}

static void before(void *f)
{
	ARG_UNUSED(f);
	ret_link_keys_load(&keys, v_link_x25519_prv, v_link_ed25519_seed);
}

ZTEST(link, test_request_data_and_link_id)
{
	uint8_t data[RET_LINK_REQUEST_LEN];
	uint8_t link_id[RET_TRUNC_HASH_LEN];

	ret_link_request_data(&keys, data);
	zassert_mem_equal(data, &v_link_request[RET_H1_HEADER_LEN], sizeof(data));
	zassert_mem_equal(&data[64], v_link_signalling, 3);

	zassert_ok(ret_link_id_from_request(v_link_request, sizeof(v_link_request), link_id));
	zassert_mem_equal(link_id, v_link_id, sizeof(link_id));
}

ZTEST(link, test_link_id_ignores_signalling_and_transport)
{
	/* Same request without signalling, and rewritten to HEADER_2: same id. */
	uint8_t raw[sizeof(v_link_request) + RET_TRUNC_HASH_LEN];
	uint8_t link_id[RET_TRUNC_HASH_LEN];

	zassert_ok(ret_link_id_from_request(v_link_request, sizeof(v_link_request) - 3, link_id));
	zassert_mem_equal(link_id, v_link_id, sizeof(link_id));

	raw[0] = v_link_request[0] | 0x40 | 0x10;
	raw[1] = 0;
	memset(&raw[2], 0xAB, RET_TRUNC_HASH_LEN);
	memcpy(&raw[2 + RET_TRUNC_HASH_LEN], &v_link_request[2], sizeof(v_link_request) - 2);
	zassert_ok(ret_link_id_from_request(raw, sizeof(raw), link_id));
	zassert_mem_equal(link_id, v_link_id, sizeof(link_id));
}

ZTEST(link, test_proof_validates_and_derives_key)
{
	struct ret_packet p;
	uint8_t key[RET_TOKEN_KEY_LEN];
	uint16_t mtu = 0;

	zassert_ok(ret_packet_unpack(v_link_proof, sizeof(v_link_proof), &p));
	zassert_equal(p.dest_type, RET_DEST_LINK);
	zassert_ok(ret_link_proof_validate(v_link_id, &v_identity_pub[RET_X25519_LEN], &keys, &p,
					   key, &mtu));
	zassert_mem_equal(key, v_link_key, sizeof(key));
	zassert_equal(mtu, 500);
}

ZTEST(link, test_proof_rejects)
{
	uint8_t raw[sizeof(v_link_proof)];
	uint8_t key[RET_TOKEN_KEY_LEN];
	uint16_t mtu;
	struct ret_packet p;
	uint8_t other_id[RET_TRUNC_HASH_LEN];

	/* Flipped signature, peer key, or signalling. */
	const size_t offsets[] = { RET_H1_HEADER_LEN + 3, RET_H1_HEADER_LEN + 70,
				   sizeof(raw) - 1 };

	for (size_t i = 0; i < ARRAY_SIZE(offsets); i++) {
		memcpy(raw, v_link_proof, sizeof(raw));
		raw[offsets[i]] ^= 0x01;
		zassert_ok(ret_packet_unpack(raw, sizeof(raw), &p));
		zassert_equal(ret_link_proof_validate(v_link_id, &v_identity_pub[RET_X25519_LEN],
						      &keys, &p, key, &mtu),
			      -EBADMSG, "offset %zu", offsets[i]);
	}

	/* Proof for a different link, or signed by a different key. */
	zassert_ok(ret_packet_unpack(v_link_proof, sizeof(v_link_proof), &p));
	memcpy(other_id, v_link_id, sizeof(other_id));
	other_id[0] ^= 1;
	zassert_equal(ret_link_proof_validate(other_id, &v_identity_pub[RET_X25519_LEN], &keys,
					      &p, key, &mtu),
		      -EBADMSG);
	zassert_equal(ret_link_proof_validate(v_link_id, &v_link_client_prv[0], &keys, &p, key,
					      &mtu),
		      -EBADMSG);

	/* Wrong length. */
	zassert_ok(ret_packet_unpack(v_link_proof, sizeof(v_link_proof) - 1, &p));
	zassert_equal(ret_link_proof_validate(v_link_id, &v_identity_pub[RET_X25519_LEN], &keys,
					      &p, key, &mtu),
		      -EBADMSG);
}

ZTEST(link, test_proof_without_signalling)
{
	struct ret_packet p;
	uint8_t key[RET_TOKEN_KEY_LEN];
	uint16_t mtu = 0;

	zassert_ok(ret_packet_unpack(v_link_proof_nosig, sizeof(v_link_proof_nosig), &p));
	zassert_ok(ret_link_proof_validate(v_link_id, &v_identity_pub[RET_X25519_LEN], &keys, &p,
					   key, &mtu));
	zassert_mem_equal(key, v_link_key, sizeof(key));
	zassert_equal(mtu, 500);
}

ZTEST(link, test_proof_unsupported_mode)
{
	struct ret_packet p;
	uint8_t key[RET_TOKEN_KEY_LEN];
	uint16_t mtu;

	/* Correctly signed, but for AES-128 mode: a protocol error, not a forgery. */
	zassert_ok(ret_packet_unpack(v_link_proof_mode0, sizeof(v_link_proof_mode0), &p));
	zassert_equal(ret_link_proof_validate(v_link_id, &v_identity_pub[RET_X25519_LEN], &keys,
					      &p, key, &mtu),
		      -EPROTO);
}

ZTEST(link, test_rtt_packet_matches_rns)
{
	uint8_t plain[16];
	uint8_t out[RET_MTU];
	int n = ret_link_rtt_plain(0.25, plain, sizeof(plain));

	zassert_equal(n, 9);
	n = ret_link_packet_build_det(v_link_id, v_link_key, RET_CTX_LRRTT, plain, (size_t)n,
				      v_link_iv_rtt, out, sizeof(out));
	zassert_equal(n, sizeof(v_link_rtt));
	zassert_mem_equal(out, v_link_rtt, sizeof(v_link_rtt));
}

ZTEST(link, test_request_packet_and_id_match_rns)
{
	static const uint8_t ping_mp[] = { 0xc4, 0x04, 'p', 'i', 'n', 'g' };
	uint8_t plain[64];
	uint8_t out[RET_MTU];
	uint8_t hash[RET_HASH_LEN];
	int n = ret_link_request_plain(1800000000.5, "/echo", ping_mp, sizeof(ping_mp), plain,
				       sizeof(plain));

	zassert_equal(n, sizeof(v_link_request_plain));
	zassert_mem_equal(plain, v_link_request_plain, sizeof(v_link_request_plain));

	n = ret_link_packet_build_det(v_link_id, v_link_key, RET_CTX_REQUEST, plain, (size_t)n,
				      v_link_iv_req, out, sizeof(out));
	zassert_equal(n, sizeof(v_link_req));
	zassert_mem_equal(out, v_link_req, sizeof(v_link_req));

	/* request_id: the truncated hash of the packet as sent. */
	zassert_ok(ret_packet_hash(out, (size_t)n, hash));
	zassert_mem_equal(hash, v_link_request_id, RET_TRUNC_HASH_LEN);
}

ZTEST(link, test_response_decrypts_and_parses)
{
	struct ret_packet p;
	uint8_t plain[RET_MTU];
	uint8_t id[RET_TRUNC_HASH_LEN];
	const uint8_t *resp;
	size_t resp_len;
	int n;

	zassert_ok(ret_packet_unpack(v_link_response, sizeof(v_link_response), &p));
	zassert_equal(p.context, RET_CTX_RESPONSE);
	zassert_mem_equal(p.dest_hash, v_link_id, RET_TRUNC_HASH_LEN);
	n = ret_token_decrypt(v_link_key, p.data, p.data_len, plain, sizeof(plain));
	zassert_true(n > 0);
	zassert_ok(ret_link_response_parse(plain, (size_t)n, id, &resp, &resp_len));
	zassert_mem_equal(id, v_link_request_id, sizeof(id));
	zassert_equal(resp_len, 6);
	zassert_mem_equal(resp, ((uint8_t[]){ 0xc4, 0x04, 'p', 'o', 'n', 'g' }), 6);
}

ZTEST(link, test_response_parse_rejects)
{
	uint8_t id[RET_TRUNC_HASH_LEN];
	const uint8_t *resp;
	size_t len;
	/* [bin8 of 15 bytes, nil]: wrong id length. */
	uint8_t bad_id[2 + 2 + 15 + 1] = { 0x92, 0xc4, 15 };
	/* [bin16 id] with no response value. */
	uint8_t no_resp[1 + 2 + 16] = { 0x91, 0xc4, 16 };

	bad_id[sizeof(bad_id) - 1] = 0xc0;
	zassert_equal(ret_link_response_parse(bad_id, sizeof(bad_id), id, &resp, &len), -EBADMSG);
	zassert_equal(ret_link_response_parse(no_resp, sizeof(no_resp), id, &resp, &len),
		      -EBADMSG);
	zassert_equal(ret_link_response_parse(v_link_request_plain, 3, id, &resp, &len), -EBADMSG);
}

ZTEST(link, test_response_nested_and_trailing)
{
	uint8_t id[RET_TRUNC_HASH_LEN];
	const uint8_t *resp;
	size_t len;
	/* [id, [1, {"k": [2, 3]}]]: a nested response is returned whole. */
	uint8_t ok[] = { 0x92, 0xc4, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			 0x92, 0x01, 0x81, 0xa1, 'k', 0x92, 0x02, 0x03 };
	uint8_t trailing[sizeof(ok) + 1];

	zassert_ok(ret_link_response_parse(ok, sizeof(ok), id, &resp, &len));
	zassert_equal(len, 8);
	zassert_mem_equal(resp, &ok[19], 8);

	/* A byte after the response value is rejected. */
	memcpy(trailing, ok, sizeof(ok));
	trailing[sizeof(ok)] = 0xc0;
	zassert_equal(ret_link_response_parse(trailing, sizeof(trailing), id, &resp, &len),
		      -EBADMSG);
}

ZTEST(link, test_response_deep_nesting_rejected)
{
	/* [id, [[[[...]]]]] 400 levels deep: rejected without recursing (a
	 * recursive skip would overflow the client thread's stack).
	 */
	static uint8_t deep[19 + 400 + 1];
	uint8_t id[RET_TRUNC_HASH_LEN];
	const uint8_t *resp;
	size_t len;

	deep[0] = 0x92;
	deep[1] = 0xc4;
	deep[2] = 16;
	memset(&deep[19], 0x91, 400);
	deep[19 + 400] = 0xc0;
	zassert_equal(ret_link_response_parse(deep, sizeof(deep), id, &resp, &len), -EBADMSG);
}

ZTEST(link, test_identify_keepalive_close_match_rns)
{
	struct ret_local_identity client;
	uint8_t plain[RET_LINK_IDENTIFY_LEN];
	uint8_t out[RET_MTU];
	const uint8_t ka = 0xFF;
	int n;

	zassert_ok(ret_local_identity_load(&client, v_link_client_prv));
	ret_link_identify_plain(&client, v_link_id, plain);
	n = ret_link_packet_build_det(v_link_id, v_link_key, RET_CTX_LINKIDENTIFY, plain,
				      sizeof(plain), v_link_iv_ident, out, sizeof(out));
	zassert_equal(n, sizeof(v_link_identify));
	zassert_mem_equal(out, v_link_identify, sizeof(v_link_identify));

	n = ret_link_packet_build(v_link_id, NULL, RET_CTX_KEEPALIVE, &ka, 1, out, sizeof(out));
	zassert_equal(n, sizeof(v_link_keepalive));
	zassert_mem_equal(out, v_link_keepalive, sizeof(v_link_keepalive));

	n = ret_link_packet_build_det(v_link_id, v_link_key, RET_CTX_LINKCLOSE, v_link_id,
				      RET_TRUNC_HASH_LEN, v_link_iv_close, out, sizeof(out));
	zassert_equal(n, sizeof(v_link_close));
	zassert_mem_equal(out, v_link_close, sizeof(v_link_close));
}

ZTEST(link, test_mdu_fits_one_packet)
{
	static uint8_t plain[RET_LINK_MDU + 1];
	uint8_t out[RET_MTU];

	zassert_equal(ret_link_packet_build(v_link_id, v_link_key, RET_CTX_REQUEST, plain,
					    RET_LINK_MDU, out, sizeof(out)),
		      499);
	zassert_equal(ret_link_packet_build(v_link_id, v_link_key, RET_CTX_REQUEST, plain,
					    RET_LINK_MDU + 1, out, sizeof(out)),
		      -EMSGSIZE);
}

ZTEST(link, test_keepalive_interval)
{
	zassert_equal(ret_link_keepalive_ms(0), 5000);
	zassert_equal(ret_link_keepalive_ms(10), 5000);
	zassert_equal(ret_link_keepalive_ms(175), 36000);
	zassert_equal(ret_link_keepalive_ms(2000), 360000);
}

ZTEST_SUITE(link, NULL, setup, before, NULL, NULL);
