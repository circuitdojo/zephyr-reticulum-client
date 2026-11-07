/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <mpack.h>
#include <zephyr/sys/util.h>

#include "ret_crypto.h"
#include "ret_link.h"
#include "ret_mp.h"

/* Signalling: MTU (21 bits) and mode (3 bits << 21), 3 bytes big-endian.
 * MODE_AES256_CBC = 1: (1 << 5) << 16 | 500 = 0x2001F4.
 */
static const uint8_t signalling_500[3] = { 0x20, 0x01, 0xF4 };
#define MODE_AES256_CBC 1

int ret_link_keys_generate(struct ret_link_keys *k)
{
	uint8_t seed[32];
	int err = ret_random(k->x25519_prv, sizeof(k->x25519_prv));

	if (!err) {
		err = ret_random(seed, sizeof(seed));
	}
	if (!err) {
		ret_link_keys_load(k, k->x25519_prv, seed);
	}
	ret_wipe(seed, sizeof(seed));
	return err;
}

void ret_link_keys_load(struct ret_link_keys *k, const uint8_t x25519_prv[RET_X25519_LEN],
			const uint8_t ed25519_seed[32])
{
	memmove(k->x25519_prv, x25519_prv, RET_X25519_LEN);
	ret_x25519_public_key(k->x25519_pub, k->x25519_prv);
	ret_ed25519_key_pair(k->ed25519_sk, k->ed25519_pub, ed25519_seed);
}

void ret_link_request_data(const struct ret_link_keys *k, uint8_t out[RET_LINK_REQUEST_LEN])
{
	memcpy(&out[0], k->x25519_pub, RET_X25519_LEN);
	memcpy(&out[RET_X25519_LEN], k->ed25519_pub, RET_ED25519_PUB_LEN);
	memcpy(&out[RET_X25519_LEN + RET_ED25519_PUB_LEN], signalling_500, 3);
}

int ret_link_id_from_request(const uint8_t *raw, size_t len, uint8_t link_id[RET_TRUNC_HASH_LEN])
{
	struct ret_packet pkt;
	uint8_t hash[RET_HASH_LEN];
	uint8_t nibble;
	size_t skip;
	int err = ret_packet_unpack(raw, len, &pkt);

	if (err) {
		return err;
	}
	if (pkt.packet_type != RET_PKT_LINKREQUEST || pkt.data_len < 64) {
		return -EINVAL;
	}

	/* Hashable part (as ret_packet_hash) minus everything past the keys. */
	nibble = raw[0] & 0x0F;
	skip = pkt.header_type == RET_HEADER_2 ? 2 + RET_TRUNC_HASH_LEN : 2;
	size_t keep = len - skip - (pkt.data_len - 64);

	const struct ret_iov iov[] = {
		{ &nibble, 1 },
		{ &raw[skip], keep },
	};

	err = ret_sha256(iov, 2, hash);
	if (!err) {
		memcpy(link_id, hash, RET_TRUNC_HASH_LEN);
	}
	return err;
}

int ret_link_proof_validate(const uint8_t link_id[RET_TRUNC_HASH_LEN],
			    const uint8_t dest_ed25519_pub[RET_ED25519_PUB_LEN],
			    const struct ret_link_keys *k, const struct ret_packet *proof,
			    uint8_t key[RET_TOKEN_KEY_LEN], uint16_t *mtu)
{
	const uint8_t *d = proof->data;
	uint8_t signed_data[RET_TRUNC_HASH_LEN + RET_X25519_LEN + RET_ED25519_PUB_LEN + 3];
	uint8_t shared[RET_X25519_LEN];
	size_t n = 0;
	bool has_signalling;
	int err;

	if (proof->packet_type != RET_PKT_PROOF || proof->context != RET_CTX_LRPROOF ||
	    memcmp(proof->dest_hash, link_id, RET_TRUNC_HASH_LEN) != 0) {
		return -EBADMSG;
	}
	if (proof->data_len == RET_SIG_LEN + RET_X25519_LEN + 3) {
		has_signalling = true;
	} else if (proof->data_len == RET_SIG_LEN + RET_X25519_LEN) {
		has_signalling = false;
	} else {
		return -EBADMSG;
	}

	const uint8_t *sig = &d[0];
	const uint8_t *peer_pub = &d[RET_SIG_LEN];
	const uint8_t *sigbytes = &d[RET_SIG_LEN + RET_X25519_LEN];

	if (has_signalling && (sigbytes[0] >> 5) != MODE_AES256_CBC) {
		return -EPROTO;
	}

	memcpy(&signed_data[n], link_id, RET_TRUNC_HASH_LEN);
	n += RET_TRUNC_HASH_LEN;
	memcpy(&signed_data[n], peer_pub, RET_X25519_LEN);
	n += RET_X25519_LEN;
	memcpy(&signed_data[n], dest_ed25519_pub, RET_ED25519_PUB_LEN);
	n += RET_ED25519_PUB_LEN;
	if (has_signalling) {
		memcpy(&signed_data[n], sigbytes, 3);
		n += 3;
	}
	if (!ret_ed25519_verify(sig, dest_ed25519_pub, signed_data, n)) {
		return -EBADMSG;
	}

	err = ret_x25519(shared, k->x25519_prv, peer_pub);
	if (err) {
		return -EBADMSG;
	}
	err = ret_hkdf_sha256(shared, sizeof(shared), link_id, RET_TRUNC_HASH_LEN, NULL, 0, key,
			      RET_TOKEN_KEY_LEN);
	ret_wipe(shared, sizeof(shared));
	if (err) {
		ret_wipe(key, RET_TOKEN_KEY_LEN);
		return err;
	}

	*mtu = has_signalling
		       ? (uint16_t)((((uint32_t)sigbytes[0] << 16) | ((uint32_t)sigbytes[1] << 8) |
				     sigbytes[2]) &
				    0x1FFFFF)
		       : RET_MTU;
	return 0;
}

static int build(const uint8_t link_id[RET_TRUNC_HASH_LEN], uint8_t packet_type, const uint8_t *key,
		 uint8_t context, const uint8_t *pt, size_t len, const uint8_t *iv, uint8_t *out,
		 size_t cap)
{
	/* Header (H1, BROADCAST, LINK, type, hops 0, link_id, context), then
	 * the body written straight into @p out: no second MTU-sized buffer
	 * on the client thread's stack.
	 */
	const size_t hdr = RET_H1_HEADER_LEN;
	size_t room = MIN(cap, RET_MTU);
	int n;

	if (room < hdr) {
		return -EMSGSIZE;
	}
	out[0] = (uint8_t)((RET_HEADER_1 << 6) | (RET_TRANSPORT_BROADCAST << 4) |
			   (RET_DEST_LINK << 2) | packet_type);
	out[1] = 0;
	memcpy(&out[2], link_id, RET_TRUNC_HASH_LEN);
	out[2 + RET_TRUNC_HASH_LEN] = context;

	if (key != NULL) {
		n = iv != NULL ? ret_token_encrypt_det(key, iv, pt, len, &out[hdr], room - hdr)
			       : ret_token_encrypt(key, pt, len, &out[hdr], room - hdr);
		if (n < 0) {
			return n == -ENOBUFS ? -EMSGSIZE : n;
		}
	} else {
		if (len > room - hdr) {
			return -EMSGSIZE;
		}
		memmove(&out[hdr], pt, len);
		n = (int)len;
	}
	return (int)hdr + n;
}

int ret_link_packet_build(const uint8_t link_id[RET_TRUNC_HASH_LEN],
			  const uint8_t key[RET_TOKEN_KEY_LEN], uint8_t context, const uint8_t *pt,
			  size_t len, uint8_t *out, size_t cap)
{
	return build(link_id, RET_PKT_DATA, key, context, pt, len, NULL, out, cap);
}

int ret_link_packet_build_det(const uint8_t link_id[RET_TRUNC_HASH_LEN],
			      const uint8_t key[RET_TOKEN_KEY_LEN], uint8_t context,
			      const uint8_t *pt, size_t len, const uint8_t iv[RET_AES_BLOCK_LEN],
			      uint8_t *out, size_t cap)
{
	return build(link_id, RET_PKT_DATA, key, context, pt, len, iv, out, cap);
}

int ret_link_resource_proof_build(const uint8_t link_id[RET_TRUNC_HASH_LEN],
				  const uint8_t proof[RET_LINK_RESOURCE_PROOF_LEN], uint8_t *out,
				  size_t cap)
{
	/* Resource proofs travel unencrypted (Packet.pack, RESOURCE_PRF). */
	return build(link_id, RET_PKT_PROOF, NULL, RET_CTX_RESOURCE_PRF, proof,
		     RET_LINK_RESOURCE_PROOF_LEN, NULL, out, cap);
}

int ret_link_rtt_plain(double rtt_s, uint8_t *out, size_t cap)
{
	mpack_writer_t w;

	mpack_writer_init(&w, (char *)out, cap);
	mpack_write_double(&w, rtt_s);

	size_t used = mpack_writer_buffer_used(&w);

	return mpack_writer_destroy(&w) == mpack_ok ? (int)used : -ENOBUFS;
}

int ret_link_request_plain(double timestamp, const char *path, const uint8_t *data_mp,
			   size_t data_len, uint8_t *out, size_t cap)
{
	uint8_t path_hash[RET_SHA256_LEN];
	const struct ret_iov iov[] = { { path, strlen(path) } };
	mpack_writer_t w;
	int err = ret_sha256(iov, 1, path_hash);

	if (err) {
		return err;
	}

	mpack_writer_init(&w, (char *)out, cap);
	mpack_start_array(&w, 3);
	mpack_write_double(&w, timestamp);
	mpack_write_bin(&w, (const char *)path_hash, RET_TRUNC_HASH_LEN);
	if (data_mp != NULL) {
		mpack_write_object_bytes(&w, (const char *)data_mp, data_len);
	} else {
		mpack_write_nil(&w);
	}
	mpack_finish_array(&w);

	size_t used = mpack_writer_buffer_used(&w);

	return mpack_writer_destroy(&w) == mpack_ok ? (int)used : -ENOBUFS;
}

int ret_link_response_parse(const uint8_t *plain, size_t len,
			    uint8_t request_id[RET_TRUNC_HASH_LEN], const uint8_t **response,
			    size_t *response_len)
{
	mpack_reader_t r;
	const char *rest;
	size_t rest_len;
	uint32_t id_len;

	mpack_reader_init_data(&r, (const char *)plain, len);
	if (mpack_expect_array(&r) != 2) {
		return -EBADMSG;
	}
	id_len = mpack_expect_bin(&r);
	if (mpack_reader_error(&r) != mpack_ok || id_len != RET_TRUNC_HASH_LEN) {
		return -EBADMSG;
	}
	mpack_read_bytes(&r, (char *)request_id, RET_TRUNC_HASH_LEN);
	mpack_done_bin(&r);

	/* The response is the last value: exactly one complete value, with
	 * nothing after it. Skipped without recursion (it is peer data).
	 */
	rest_len = mpack_reader_remaining(&r, &rest);
	if (mpack_reader_error(&r) != mpack_ok || rest_len == 0 || ret_mp_skip(&r) != 0 ||
	    mpack_reader_remaining(&r, NULL) != 0) {
		mpack_reader_destroy(&r);
		return -EBADMSG;
	}
	if (mpack_reader_destroy(&r) != mpack_ok) {
		return -EBADMSG;
	}
	*response = (const uint8_t *)rest;
	*response_len = rest_len;
	return 0;
}

void ret_link_identify_plain(const struct ret_local_identity *id,
			     const uint8_t link_id[RET_TRUNC_HASH_LEN],
			     uint8_t out[RET_LINK_IDENTIFY_LEN])
{
	uint8_t signed_data[RET_TRUNC_HASH_LEN + RET_PUBKEY_LEN];

	memcpy(signed_data, link_id, RET_TRUNC_HASH_LEN);
	memcpy(&signed_data[RET_TRUNC_HASH_LEN], id->pub, RET_PUBKEY_LEN);
	memcpy(out, id->pub, RET_PUBKEY_LEN);
	ret_local_identity_sign(id, signed_data, sizeof(signed_data), &out[RET_PUBKEY_LEN]);
}

uint32_t ret_link_keepalive_ms(uint32_t rtt_ms)
{
	/* rtt * (360 / 1.75), clamped to [5, 360] s. */
	uint64_t ka = (uint64_t)rtt_ms * 360U * 4U / 7U;

	if (ka < 5000U) {
		return 5000U;
	}
	if (ka > 360000U) {
		return 360000U;
	}
	return (uint32_t)ka;
}
