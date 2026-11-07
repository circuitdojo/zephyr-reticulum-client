/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include "ret_announce.h"

#define ANNOUNCE_FIXED_LEN (RET_PUBKEY_LEN + RET_NAME_HASH_LEN + RET_RANDOM_HASH_LEN + RET_SIG_LEN)

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
