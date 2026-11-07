/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * RNS Resources, receiving side (RNS/Resource.py): multi-packet transfers
 * on a link, used for request responses larger than one packet. Pure
 * functions over caller-owned state; the link driver feeds them packets.
 *
 * Only single-segment, uncompressed, encrypted resources without metadata
 * are accepted, bounded by CONFIG_RET_RESOURCE_MAX_SIZE: bz2 needs megabytes
 * of RAM, and nothing ret-client requests should arrive compressed (see
 * docs/protocol.md). Anything else is refused explicitly.
 */

#ifndef RET_RESOURCE_H_
#define RET_RESOURCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/sys/util.h>

#include "ret_identity.h"

#define RET_RESOURCE_SDU          464 /* MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE */
#define RET_RESOURCE_MAPHASH_LEN  4
#define RET_RESOURCE_RANDOM_LEN   4
#define RET_RESOURCE_HASHMAP_SEG  74 /* map hashes per advertisement / update */
#define RET_RESOURCE_MAX_PARTS    DIV_ROUND_UP(CONFIG_RET_RESOURCE_MAX_SIZE, RET_RESOURCE_SDU)
#define RET_RESOURCE_PROOF_LEN    (2 * RET_SHA256_LEN)

/* Advertisement flags (f). */
#define RET_RESOURCE_F_ENCRYPTED  BIT(0)
#define RET_RESOURCE_F_COMPRESSED BIT(1)
#define RET_RESOURCE_F_SPLIT      BIT(2)
#define RET_RESOURCE_F_REQUEST    BIT(3)
#define RET_RESOURCE_F_RESPONSE   BIT(4)
#define RET_RESOURCE_F_METADATA   BIT(5)

#define RET_RESOURCE_WINDOW       4
#define RET_RESOURCE_WINDOW_MIN   2
#define RET_RESOURCE_WINDOW_MAX   10

/** A parsed advertisement; pointers reference the plaintext. */
struct ret_resource_adv {
	uint64_t t; /* transfer (encrypted stream) size */
	uint64_t d; /* data size */
	uint64_t n; /* parts */
	uint64_t i; /* segment index */
	uint64_t l; /* total segments */
	uint64_t f; /* flags */
	const uint8_t *h; /* resource hash, 32 */
	const uint8_t *r; /* random hash, 4 */
	const uint8_t *q; /* request id, 16, or NULL */
	const uint8_t *m; /* first hashmap segment */
	size_t m_len;
};

/** Receiver state for one resource. */
struct ret_resource_rx {
	uint8_t h[RET_SHA256_LEN];
	uint8_t r[RET_RESOURCE_RANDOM_LEN];
	uint32_t t;
	uint32_t n;
	uint8_t *stream;
	uint8_t hashmap[RET_RESOURCE_MAX_PARTS][RET_RESOURCE_MAPHASH_LEN];
	uint32_t hashmap_height;
	bool have[RET_RESOURCE_MAX_PARTS];
	uint32_t received;
	int32_t cch; /* highest index with every part up to it received */
	uint32_t window;
	uint32_t outstanding;
	bool waiting_hmu;
};

enum ret_resource_part {
	RET_RESOURCE_PART_IGNORED,  /* unknown or duplicate part */
	RET_RESOURCE_PART_ACCEPTED,
	RET_RESOURCE_PART_WINDOW,   /* window complete: request the next one */
	RET_RESOURCE_PART_COMPLETE, /* every part in: assemble */
};

/** @retval -EBADMSG not a well-formed advertisement */
int ret_resource_adv_parse(const uint8_t *plain, size_t len, struct ret_resource_adv *adv);

/**
 * Start receiving @p adv into @p stream (at least adv->t bytes).
 *
 * @retval -ENOTSUP compressed, split, metadata or unencrypted
 * @retval -EFBIG larger than @p cap or CONFIG_RET_RESOURCE_MAX_SIZE
 * @retval -EBADMSG inconsistent sizes or hashmap
 */
int ret_resource_rx_init(struct ret_resource_rx *rx, const struct ret_resource_adv *adv,
			 uint8_t *stream, size_t cap);

/**
 * Build the next RESOURCE_REQ plaintext: flag (0x00, or 0xFF with the last
 * known map hash when the hashmap ran out) | resource hash | wanted map
 * hashes, from the first incomplete part across the window
 * (Resource.request_next).
 *
 * @return length, or -ENOBUFS
 */
int ret_resource_rx_request(struct ret_resource_rx *rx, uint8_t *out, size_t cap);

/** A RESOURCE part (unencrypted slice of the stream). */
enum ret_resource_part ret_resource_rx_part(struct ret_resource_rx *rx, const uint8_t *data,
					    size_t len);

/**
 * The sender went quiet: shrink the window (not below
 * RET_RESOURCE_WINDOW_MIN) before the request is repeated, as Resource's
 * watchdog does.
 */
void ret_resource_rx_timeout(struct ret_resource_rx *rx);

/**
 * Apply a hashmap update plaintext: resource hash | msgpack [segment,
 * bin map hashes].
 *
 * @retval -EBADMSG malformed, wrong resource, or not waiting for one
 */
int ret_resource_rx_hmu(struct ret_resource_rx *rx, const uint8_t *plain, size_t len);

/**
 * Decrypt the complete stream with the link key into @p out, strip the
 * random prefix, and check the resource hash.
 *
 * @return data length (the data starts at @p out)
 * @retval -EBADMSG bad HMAC, padding or hash
 */
int ret_resource_rx_assemble(const struct ret_resource_rx *rx, const uint8_t key[RET_TOKEN_KEY_LEN],
			     uint8_t *out, size_t cap);

/** RESOURCE_PRF data for the assembled @p data: hash | SHA256(data | hash). */
int ret_resource_proof(const struct ret_resource_rx *rx, const uint8_t *data, size_t len,
		       uint8_t out[RET_RESOURCE_PROOF_LEN]);

#endif /* RET_RESOURCE_H_ */
