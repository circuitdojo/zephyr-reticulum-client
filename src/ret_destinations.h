/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Destinations learned from validated announces, with the path
 * information needed to address packets to them. Not thread-safe: owned
 * by the client thread.
 */

#ifndef RET_DESTINATIONS_H_
#define RET_DESTINATIONS_H_

#include <stdbool.h>
#include <stdint.h>

#include "ret_announce.h"

struct ret_destination {
	bool used;
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	uint8_t identity_hash[RET_TRUNC_HASH_LEN];
	uint8_t name_hash[RET_NAME_HASH_LEN];
	uint8_t pub[RET_PUBKEY_LEN];
	bool has_ratchet;
	uint8_t ratchet[RET_RATCHET_LEN];
	/** Path length: announce hops + 1, as Transport counts it. */
	uint8_t hops;
	bool has_transport_id;
	uint8_t transport_id[RET_TRUNC_HASH_LEN];
	int64_t last_seen_ms;
};

void ret_destinations_clear(void);

/**
 * Record a validated announce received in @p pkt.
 *
 * @retval -EPERM the destination is known with a different public key;
 *         the announce is rejected (Identity.validate_announce does the
 *         same).
 */
int ret_destinations_update(const struct ret_packet *pkt, const struct ret_announce *a,
			    int64_t now_ms, const struct ret_destination **out);

const struct ret_destination *ret_destinations_find(const uint8_t dest_hash[RET_TRUNC_HASH_LEN]);

/**
 * Address an outbound packet to @p d the way Transport.outbound does:
 * more than one hop away and reached through a transport node means
 * HEADER_2/TRANSPORT with that node's ID, otherwise HEADER_1/BROADCAST.
 */
void ret_destinations_address(const struct ret_destination *d, struct ret_packet *pkt);

#endif /* RET_DESTINATIONS_H_ */
