/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RET_ANNOUNCE_H_
#define RET_ANNOUNCE_H_

#include <stddef.h>
#include <stdint.h>

#include "ret_identity.h"
#include "ret_packet.h"

/** Fields of a validated announce; pointers reference the packet data. */
struct ret_announce {
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	uint8_t identity_hash[RET_TRUNC_HASH_LEN];
	const uint8_t *pub;
	const uint8_t *name_hash;
	const uint8_t *random_hash;
	/** NULL unless the announce carries a ratchet (context_flag set). */
	const uint8_t *ratchet;
	const uint8_t *signature;
	const uint8_t *app_data;
	size_t app_data_len;
};

/**
 * Parse and validate an ANNOUNCE packet as Identity.validate_announce()
 * does: Ed25519 signature over dest_hash | pub | name_hash | random_hash
 * | ratchet | app_data, then dest_hash == H(name_hash | H(pub)).
 *
 * @retval 0 valid
 * @retval -EINVAL not an announce
 * @retval -EMSGSIZE truncated
 * @retval -EBADMSG bad signature
 * @retval -EACCES destination hash does not match the announced identity
 */
int ret_announce_validate(const struct ret_packet *pkt, struct ret_announce *out);

#endif /* RET_ANNOUNCE_H_ */
