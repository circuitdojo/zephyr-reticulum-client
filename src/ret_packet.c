/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include "ret_crypto.h"
#include "ret_identity.h"
#include "ret_packet.h"

#define BIT_IFAC  0x80

/* The packet hop limit (Transport.PATHFINDER_M). */
#define MAX_HOPS 128

static int unpack(const uint8_t *raw, size_t len, size_t max_len, struct ret_packet *pkt);

int ret_packet_unpack(const uint8_t *raw, size_t len, struct ret_packet *pkt)
{
	return unpack(raw, len, RET_MTU, pkt);
}

int ret_packet_unpack_max(const uint8_t *raw, size_t len, size_t max_len, struct ret_packet *pkt)
{
	int err = unpack(raw, len, max_len, pkt);

	if (err) {
		return err;
	}
	if (pkt->hops >= MAX_HOPS || pkt->data_len == 0) {
		return -EBADMSG;
	}
	return 0;
}

static int unpack(const uint8_t *raw, size_t len, size_t max_len, struct ret_packet *pkt)
{
	size_t off;

	if (len < 2 || len > max_len) {
		return -EMSGSIZE;
	}
	if (raw[0] & BIT_IFAC) {
		return -ENOTSUP;
	}

	pkt->header_type = (raw[0] >> 6) & 0x01;
	pkt->context_flag = (raw[0] >> 5) & 0x01;
	pkt->transport_type = (raw[0] >> 4) & 0x01;
	pkt->dest_type = (raw[0] >> 2) & 0x03;
	pkt->packet_type = raw[0] & 0x03;
	pkt->hops = raw[1];

	if (pkt->header_type == RET_HEADER_2) {
		if (len < RET_H2_HEADER_LEN) {
			return -EMSGSIZE;
		}
		memcpy(pkt->transport_id, &raw[2], RET_TRUNC_HASH_LEN);
		off = 2 + RET_TRUNC_HASH_LEN;
	} else {
		if (len < RET_H1_HEADER_LEN) {
			return -EMSGSIZE;
		}
		memset(pkt->transport_id, 0, RET_TRUNC_HASH_LEN);
		off = 2;
	}

	memcpy(pkt->dest_hash, &raw[off], RET_TRUNC_HASH_LEN);
	off += RET_TRUNC_HASH_LEN;
	pkt->context = raw[off++];
	pkt->data = &raw[off];
	pkt->data_len = len - off;

	return 0;
}

int ret_packet_pack(const struct ret_packet *pkt, uint8_t *out, size_t cap)
{
	size_t hdr = pkt->header_type == RET_HEADER_2 ? RET_H2_HEADER_LEN : RET_H1_HEADER_LEN;
	size_t total = hdr + pkt->data_len;
	size_t off = 0;

	if (total > cap || total > RET_MTU) {
		return -EMSGSIZE;
	}

	out[off++] = (uint8_t)(((pkt->header_type & 0x01) << 6) |
			       ((pkt->context_flag & 0x01) << 5) |
			       ((pkt->transport_type & 0x01) << 4) |
			       ((pkt->dest_type & 0x03) << 2) | (pkt->packet_type & 0x03));
	out[off++] = pkt->hops;
	if (pkt->header_type == RET_HEADER_2) {
		memcpy(&out[off], pkt->transport_id, RET_TRUNC_HASH_LEN);
		off += RET_TRUNC_HASH_LEN;
	}
	memcpy(&out[off], pkt->dest_hash, RET_TRUNC_HASH_LEN);
	off += RET_TRUNC_HASH_LEN;
	out[off++] = pkt->context;
	if (pkt->data_len > 0) {
		memmove(&out[off], pkt->data, pkt->data_len);
	}

	return (int)total;
}

int ret_packet_hash(const uint8_t *raw, size_t len, uint8_t hash[RET_HASH_LEN])
{
	uint8_t nibble;
	size_t skip;

	if (len < RET_H1_HEADER_LEN) {
		return -EMSGSIZE;
	}

	nibble = raw[0] & 0x0F;
	skip = ((raw[0] >> 6) & 0x01) == RET_HEADER_2 ? 2 + RET_TRUNC_HASH_LEN : 2;
	if (len < skip + RET_TRUNC_HASH_LEN + 1) {
		return -EMSGSIZE;
	}

	const struct ret_iov iov[] = {
		{ &nibble, 1 },
		{ &raw[skip], len - skip },
	};

	return ret_sha256(iov, 2, hash);
}

static int path_request(const uint8_t *data, size_t len, uint8_t *out, size_t cap)
{
	struct ret_packet pkt = {
		.header_type = RET_HEADER_1,
		.transport_type = RET_TRANSPORT_BROADCAST,
		.dest_type = RET_DEST_PLAIN,
		.packet_type = RET_PKT_DATA,
		.context = RET_CONTEXT_NONE,
		.data = data,
		.data_len = len,
	};
	int err = ret_plain_dest_hash("rnstransport.path.request", pkt.dest_hash);

	return err ? err : ret_packet_pack(&pkt, out, cap);
}

int ret_path_request_build_transport(const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
				     const uint8_t transport_id[RET_TRUNC_HASH_LEN],
				     const uint8_t tag[RET_PATH_REQUEST_TAG_LEN], uint8_t *out,
				     size_t cap)
{
	uint8_t data[2 * RET_TRUNC_HASH_LEN + RET_PATH_REQUEST_TAG_LEN];

	memcpy(data, dest_hash, RET_TRUNC_HASH_LEN);
	memcpy(&data[RET_TRUNC_HASH_LEN], transport_id, RET_TRUNC_HASH_LEN);
	memcpy(&data[2 * RET_TRUNC_HASH_LEN], tag, RET_PATH_REQUEST_TAG_LEN);
	return path_request(data, sizeof(data), out, cap);
}

int ret_path_request_build(const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
			   const uint8_t tag[RET_PATH_REQUEST_TAG_LEN], uint8_t *out, size_t cap)
{
	uint8_t data[RET_TRUNC_HASH_LEN + RET_PATH_REQUEST_TAG_LEN];

	memcpy(data, dest_hash, RET_TRUNC_HASH_LEN);
	memcpy(&data[RET_TRUNC_HASH_LEN], tag, RET_PATH_REQUEST_TAG_LEN);
	return path_request(data, sizeof(data), out, cap);
}
