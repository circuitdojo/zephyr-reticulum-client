/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * LXMF message format (LXMF/LXMessage.py, lxmf 1.2.1). Pure functions.
 *
 *   packed = dest (16) | src (16) | Ed25519 sig (64) |
 *            msgpack [timestamp, title, content, fields(, stamp)]
 *
 * message hash = SHA256(dest | src | payload without the stamp), and the
 * signature covers dest | src | that payload | message hash. Both
 * addresses are lxmf.delivery destinations.
 *
 * Opportunistic delivery sends packed[16:] in one SINGLE packet to the
 * destination; a propagation node stores dest | SINGLE-encrypted(packed[16:]).
 * Either way the receiver holds the destination hash plus the "body"
 * src | sig | payload, which is what ret_lxmf_unpack() takes.
 */

#ifndef RET_LXMF_H_
#define RET_LXMF_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ret_identity.h"

#define RET_LXMF_ADDR_LEN   RET_TRUNC_HASH_LEN
#define RET_LXMF_SIG_LEN    64
/* src | sig: the part of the body before the payload. */
#define RET_LXMF_BODY_HDR   (RET_LXMF_ADDR_LEN + RET_LXMF_SIG_LEN)
/* Largest title + content that fits one opportunistic packet
 * (LXMessage.ENCRYPTED_PACKET_MAX_CONTENT).
 */
#define RET_LXMF_OPPORTUNISTIC_MAX 287

#define RET_LXMF_APP_NAME "lxmf.delivery"

/** A parsed message; pointers reference the body passed to unpack. */
struct ret_lxmf_msg {
	const uint8_t *dest;
	const uint8_t *src;
	const uint8_t *sig;
	uint8_t hash[RET_SHA256_LEN];
	double timestamp;
	const uint8_t *title;
	size_t title_len;
	const uint8_t *content;
	size_t content_len;
	/** The fields map, as encoded msgpack. */
	const uint8_t *fields;
	size_t fields_len;
	/** A stamp was present (and is not covered by hash or signature). */
	bool stamped;
	/* The payload span the hash covers: the stamped form drops element 4
	 * and hashes 0x94 | elements 0-3, as unpack_from_bytes re-packs it.
	 */
	const uint8_t *hashed_elems;
	size_t hashed_elems_len;
};

/**
 * Parse the body (src | sig | payload) of a message for @p dest and compute
 * its hash. Title and content may be bin or str.
 *
 * @retval -EBADMSG malformed
 */
int ret_lxmf_unpack(const uint8_t dest[RET_LXMF_ADDR_LEN], const uint8_t *body, size_t len,
		    struct ret_lxmf_msg *m);

/** Check the signature against the source's Ed25519 public key. */
bool ret_lxmf_verify(const struct ret_lxmf_msg *m, const uint8_t src_sig_pub[RET_ED25519_PUB_LEN]);

/**
 * Pack and sign a message from @p id (whose lxmf.delivery address is
 * @p src) to @p dest, with empty fields, into @p out:
 * dest | src | sig | payload.
 *
 * @return packed length, or -ENOBUFS
 */
int ret_lxmf_pack(const struct ret_local_identity *id, const uint8_t src[RET_LXMF_ADDR_LEN],
		  const uint8_t dest[RET_LXMF_ADDR_LEN], double timestamp, const uint8_t *title,
		  size_t title_len, const uint8_t *content, size_t content_len, uint8_t *out,
		  size_t cap, uint8_t hash_out[RET_SHA256_LEN]);

/**
 * Announce app_data for an lxmf.delivery destination:
 * msgpack [display name (bin) or nil, stamp cost nil, []]. The empty
 * functionality list says "no compression support"; no stamp cost means
 * senders need no proof of work.
 *
 * @return length, or -ENOBUFS
 */
int ret_lxmf_app_data(const char *display_name, uint8_t *out, size_t cap);

#endif /* RET_LXMF_H_ */
