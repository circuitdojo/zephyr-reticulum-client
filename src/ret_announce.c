/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "ret_announce.h"

#define ANNOUNCE_FIXED_LEN (RET_PUBKEY_LEN + RET_NAME_HASH_LEN + RET_RANDOM_HASH_LEN + RET_SIG_LEN)

uint64_t ret_announce_emitted(const uint8_t random_hash[RET_RANDOM_HASH_LEN])
{
	uint64_t t = 0;

	for (int i = 5; i < RET_RANDOM_HASH_LEN; i++) {
		t = (t << 8) | random_hash[i];
	}
	return t;
}

int ret_announce_validate(const struct ret_packet *pkt, struct ret_announce *a)
{
	/* dest_hash + everything in the announce except the signature. */
	uint8_t signed_data[RET_TRUNC_HASH_LEN + RET_MTU];
	size_t ratchet_len = pkt->context_flag ? RET_RATCHET_LEN : 0;
	const uint8_t *p = pkt->data;
	size_t off = 0;
	uint8_t expected[RET_TRUNC_HASH_LEN];
	int err;

	if (pkt->packet_type != RET_PKT_ANNOUNCE) {
		return -EINVAL;
	}
	if (pkt->data_len < ANNOUNCE_FIXED_LEN + ratchet_len) {
		return -EMSGSIZE;
	}

	memcpy(a->dest_hash, pkt->dest_hash, RET_TRUNC_HASH_LEN);
	a->pub = &p[off];
	off += RET_PUBKEY_LEN;
	a->name_hash = &p[off];
	off += RET_NAME_HASH_LEN;
	a->random_hash = &p[off];
	off += RET_RANDOM_HASH_LEN;
	a->ratchet = ratchet_len ? &p[off] : NULL;
	off += ratchet_len;
	a->signature = &p[off];
	off += RET_SIG_LEN;
	a->app_data = &p[off];
	a->app_data_len = pkt->data_len - off;

	/* The signed fields are contiguous except for the signature. */
	size_t head = RET_PUBKEY_LEN + RET_NAME_HASH_LEN + RET_RANDOM_HASH_LEN + ratchet_len;
	size_t n = 0;

	memcpy(&signed_data[n], pkt->dest_hash, RET_TRUNC_HASH_LEN);
	n += RET_TRUNC_HASH_LEN;
	memcpy(&signed_data[n], p, head);
	n += head;
	memcpy(&signed_data[n], a->app_data, a->app_data_len);
	n += a->app_data_len;

	/* Ed25519 key is the second half of the public key. */
	if (!ret_ed25519_verify(a->signature, &a->pub[RET_X25519_LEN], signed_data, n)) {
		return -EBADMSG;
	}

	err = ret_identity_hash(a->pub, a->identity_hash);
	if (!err) {
		err = ret_dest_hash(a->name_hash, a->identity_hash, expected);
	}
	if (err) {
		return err;
	}
	if (memcmp(expected, pkt->dest_hash, RET_TRUNC_HASH_LEN) != 0) {
		return -EACCES;
	}
	return 0;
}

int ret_announce_build(const struct ret_local_identity *id,
		       const uint8_t name_hash[RET_NAME_HASH_LEN],
		       const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
		       const uint8_t random_hash[RET_RANDOM_HASH_LEN],
		       const uint8_t ratchet[RET_RATCHET_LEN], const uint8_t *app_data,
		       size_t app_data_len, uint8_t context, uint8_t *out, size_t cap)
{
	uint8_t signed_data[RET_TRUNC_HASH_LEN + RET_MTU];
	size_t ratchet_len = ratchet != NULL ? RET_RATCHET_LEN : 0;
	size_t head = RET_PUBKEY_LEN + RET_NAME_HASH_LEN + RET_RANDOM_HASH_LEN + ratchet_len;
	size_t n = 0;
	struct ret_packet pkt = {
		.header_type = RET_HEADER_1,
		.transport_type = RET_TRANSPORT_BROADCAST,
		.dest_type = RET_DEST_SINGLE,
		.packet_type = RET_PKT_ANNOUNCE,
		.context = context,
		.context_flag = ratchet != NULL,
	};
	uint8_t *data;

	if (RET_H1_HEADER_LEN + ANNOUNCE_FIXED_LEN + ratchet_len + app_data_len >
	    MIN(cap, RET_MTU)) {
		return -EMSGSIZE;
	}
	/* Assemble the payload where it ends up in @p out (packing then
	 * moves it onto itself), saving a second MTU-sized stack buffer.
	 */
	data = &out[RET_H1_HEADER_LEN];
	pkt.data = data;

	memcpy(&data[0], id->pub, RET_PUBKEY_LEN);
	memcpy(&data[RET_PUBKEY_LEN], name_hash, RET_NAME_HASH_LEN);
	memcpy(&data[RET_PUBKEY_LEN + RET_NAME_HASH_LEN], random_hash, RET_RANDOM_HASH_LEN);
	if (ratchet != NULL) {
		memcpy(&data[RET_PUBKEY_LEN + RET_NAME_HASH_LEN + RET_RANDOM_HASH_LEN], ratchet,
		       RET_RATCHET_LEN);
	}

	memcpy(&signed_data[n], dest_hash, RET_TRUNC_HASH_LEN);
	n += RET_TRUNC_HASH_LEN;
	memcpy(&signed_data[n], data, head);
	n += head;
	if (app_data_len > 0) {
		memcpy(&signed_data[n], app_data, app_data_len);
		n += app_data_len;
	}

	ret_local_identity_sign(id, signed_data, n, &data[head]);
	if (app_data_len > 0) {
		memcpy(&data[head + RET_SIG_LEN], app_data, app_data_len);
	}

	memcpy(pkt.dest_hash, dest_hash, RET_TRUNC_HASH_LEN);
	pkt.data_len = head + RET_SIG_LEN + app_data_len;
	return ret_packet_pack(&pkt, out, cap);
}

int ret_proof_build(const struct ret_local_identity *id, const uint8_t packet_hash[RET_HASH_LEN],
		    uint8_t *out, size_t cap)
{
	uint8_t sig[RET_SIG_LEN];
	struct ret_packet pkt = {
		.header_type = RET_HEADER_1,
		.transport_type = RET_TRANSPORT_BROADCAST,
		.dest_type = RET_DEST_SINGLE,
		.packet_type = RET_PKT_PROOF,
		.context = RET_CONTEXT_NONE,
		.data = sig,
		.data_len = sizeof(sig),
	};

	ret_local_identity_sign(id, packet_hash, RET_HASH_LEN, sig);
	memcpy(pkt.dest_hash, packet_hash, RET_TRUNC_HASH_LEN);
	return ret_packet_pack(&pkt, out, cap);
}

