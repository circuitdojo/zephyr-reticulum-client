/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reticulum packet header codec (RNS/Packet.py).
 */

#ifndef RET_PACKET_H_
#define RET_PACKET_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RET_MTU             500
#define RET_HASH_LEN        32
#define RET_TRUNC_HASH_LEN  16
#define RET_H1_HEADER_LEN   (2 + RET_TRUNC_HASH_LEN + 1)
#define RET_H2_HEADER_LEN   (2 + 2 * RET_TRUNC_HASH_LEN + 1)

enum ret_header_type {
	RET_HEADER_1 = 0,
	RET_HEADER_2 = 1,
};

enum ret_transport_type {
	RET_TRANSPORT_BROADCAST = 0,
	RET_TRANSPORT_TRANSPORT = 1,
};

enum ret_dest_type {
	RET_DEST_SINGLE = 0,
	RET_DEST_GROUP = 1,
	RET_DEST_PLAIN = 2,
	RET_DEST_LINK = 3,
};

enum ret_packet_type {
	RET_PKT_DATA = 0,
	RET_PKT_ANNOUNCE = 1,
	RET_PKT_LINKREQUEST = 2,
	RET_PKT_PROOF = 3,
};

#define RET_CONTEXT_NONE 0x00

struct ret_packet {
	uint8_t header_type;
	uint8_t context_flag;
	uint8_t transport_type;
	uint8_t dest_type;
	uint8_t packet_type;
	uint8_t hops;
	/** Valid only for RET_HEADER_2. */
	uint8_t transport_id[RET_TRUNC_HASH_LEN];
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	uint8_t context;
	/** Points into the buffer passed to ret_packet_unpack(). */
	const uint8_t *data;
	size_t data_len;
};

/**
 * Parse a raw packet. @p pkt->data points into @p raw.
 *
 * @retval 0 on success
 * @retval -EMSGSIZE if @p len is shorter than the header or above the MTU
 * @retval -ENOTSUP if the IFAC flag is set (interface access codes are
 *         not supported)
 */
int ret_packet_unpack(const uint8_t *raw, size_t len, struct ret_packet *pkt);

/**
 * Serialise @p pkt into @p out.
 *
 * @return packed length, or -EMSGSIZE if it exceeds @p cap or the MTU.
 */
int ret_packet_pack(const struct ret_packet *pkt, uint8_t *out, size_t cap);

/**
 * Packet hash as RNS computes it: SHA-256 over the low nibble of the
 * flags byte followed by everything after the hops byte, skipping the
 * transport ID of a HEADER_2 packet. It is therefore unchanged when a
 * transport node rewrites the header.
 */
int ret_packet_hash(const uint8_t *raw, size_t len, uint8_t hash[RET_HASH_LEN]);

#define RET_PATH_REQUEST_TAG_LEN 16
#define RET_PATH_REQUEST_LEN     (RET_H1_HEADER_LEN + RET_TRUNC_HASH_LEN + RET_PATH_REQUEST_TAG_LEN)

/**
 * Build a path request for @p dest_hash as a non-transport node sends it
 * (Transport.request_path): HEADER_1 PLAIN DATA to
 * "rnstransport.path.request", data = dest_hash | tag. The data must be
 * exactly 32 bytes; anything longer is read as a transport ID.
 *
 * @return packet length, or a negative errno.
 */
int ret_path_request_build(const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
			   const uint8_t tag[RET_PATH_REQUEST_TAG_LEN], uint8_t *out, size_t cap);

#endif /* RET_PACKET_H_ */
