/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * RNS Resources (RNS/Resource.py): multi-packet transfers on a link. Pure
 * functions over caller-owned state; the link driver feeds them packets.
 *
 * Receiving: request responses and LXMF DIRECT deliveries larger than one
 * packet. Only single-segment, uncompressed, encrypted resources without
 * metadata are accepted, bounded by CONFIG_RET_RESOURCE_MAX_SIZE: bz2 needs
 * megabytes of RAM, and nothing ret-client requests should arrive
 * compressed (see docs/protocol.md). Anything else is refused explicitly.
 *
 * Sending: the same kind of resource (single segment, uncompressed,
 * encrypted, neither request nor response), as LXMF DIRECT sends a packed
 * message too large for one link packet.
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
/* Resource.WINDOW_MAX_FAST: what a receiver on a fast link may ask for. */
#define RET_RESOURCE_WINDOW_MAX_FAST 75
/* ResourceAdvertisement.COLLISION_GUARD_SIZE: map hashes must be unique
 * within this many parts, and requests are matched within it.
 */
#define RET_RESOURCE_COLLISION_GUARD (2 * RET_RESOURCE_WINDOW_MAX + RET_RESOURCE_HASHMAP_SEG)

/** Stream (encrypted) length of a resource carrying @p data_len bytes. */
#define RET_RESOURCE_STREAM_LEN(data_len) RET_TOKEN_BODY_LEN(RET_RESOURCE_RANDOM_LEN + (data_len))

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

/* --- Sending ---------------------------------------------------------- */

/** Sender state for one resource. */
struct ret_resource_tx {
	uint8_t h[RET_SHA256_LEN];
	uint8_t r[RET_RESOURCE_RANDOM_LEN];
	uint8_t expected_proof[RET_SHA256_LEN];
	uint32_t t; /* stream length */
	uint32_t d; /* data length */
	uint32_t n; /* parts */
	const uint8_t *stream;
	uint8_t hashmap[RET_RESOURCE_MAX_PARTS][RET_RESOURCE_MAPHASH_LEN];
	bool sent[RET_RESOURCE_MAX_PARTS];
	uint32_t sent_parts;
	/* Resource.receiver_min_consecutive_height: requests match from here. */
	uint32_t min_height;
};

/**
 * Encrypt the stream: token(@p prefix | @p data) under the link key with
 * @p iv, into @p stream (RET_RESOURCE_STREAM_LEN(len) bytes; @p data must
 * not overlap it). Then call ret_resource_tx_map().
 *
 * @retval -EFBIG more than RET_RESOURCE_MAX_PARTS parts, or @p cap too small
 */
int ret_resource_tx_init(struct ret_resource_tx *tx, const uint8_t key[RET_TOKEN_KEY_LEN],
			 const uint8_t iv[RET_AES_BLOCK_LEN],
			 const uint8_t prefix[RET_RESOURCE_RANDOM_LEN], const uint8_t *data,
			 size_t len, uint8_t *stream, size_t cap);

/**
 * With random hash @p r: the resource hash SHA256(data | r), the proof the
 * receiver must send, SHA256(data | hash), and the map hashes.
 *
 * @retval -EAGAIN two map hashes collide within the collision guard: call
 *         again with another @p r, as Resource does
 */
int ret_resource_tx_map(struct ret_resource_tx *tx, const uint8_t *data, size_t len,
			const uint8_t r[RET_RESOURCE_RANDOM_LEN]);

/**
 * The advertisement plaintext (ResourceAdvertisement.pack): sizes, hashes,
 * flags (encrypted only) and the first hashmap segment.
 *
 * @return length, or -ENOBUFS
 */
int ret_resource_tx_adv(const struct ret_resource_tx *tx, uint8_t *out, size_t cap);

/** What a RESOURCE_REQ asks for (Resource.request). */
struct ret_resource_tx_req {
	/* Parts to send, in order; already sent ones are resent. */
	uint16_t parts[RET_RESOURCE_COLLISION_GUARD];
	size_t n_parts;
	/* The receiver ran out of map hashes: send this segment (HMU). */
	bool hmu;
	uint32_t hmu_segment;
};

/**
 * Handle a RESOURCE_REQ plaintext: flag (0x00, or 0xFF | last map hash) |
 * resource hash | wanted map hashes. Parts it lists are marked sent.
 *
 * @retval -EBADMSG malformed, or for another resource
 * @retval -EPROTO a hashmap request not at a segment boundary (Resource
 *         cancels the transfer: "sequencing error")
 */
int ret_resource_tx_request(struct ret_resource_tx *tx, const uint8_t *plain, size_t len,
			    struct ret_resource_tx_req *req);

/** Part @p index of the stream (a RESOURCE packet's data, unencrypted). */
const uint8_t *ret_resource_tx_part(const struct ret_resource_tx *tx, uint32_t index, size_t *len);

/** The hashmap update plaintext for @p segment: hash | msgpack [segment, hashes]. */
int ret_resource_tx_hmu(const struct ret_resource_tx *tx, uint32_t segment, uint8_t *out,
			size_t cap);

/** Every part went out at least once: the receiver's proof is due. */
bool ret_resource_tx_all_sent(const struct ret_resource_tx *tx);

/** A RESOURCE_PRF's data proves this resource: hash | expected proof. */
bool ret_resource_tx_proof_valid(const struct ret_resource_tx *tx, const uint8_t *data,
				 size_t len);

#endif /* RET_RESOURCE_H_ */
