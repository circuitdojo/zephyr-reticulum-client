/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * Delivery receipts for sent packets (RNS PacketReceipt). Not
 * thread-safe: owned by the client thread.
 */

#ifndef RET_RECEIPT_H_
#define RET_RECEIPT_H_

#include <stdint.h>

#include <ret/ret_client.h>

#include "ret_crypto.h"
#include "ret_packet.h"

void ret_receipts_clear(void);

/**
 * Track a sent packet.
 *
 * @param dest_hash destination it was sent to, reported back with its proof
 * @param watched   count a timeout of this receipt for the watchdog (the
 *                  destination is known to prove)
 * @retval -ENOMEM table full
 */
int ret_receipts_add(const uint8_t packet_hash[RET_HASH_LEN],
		     const uint8_t sig_pub[RET_ED25519_PUB_LEN],
		     const uint8_t dest_hash[RET_TRUNC_HASH_LEN], bool watched, int64_t now_ms,
		     uint32_t timeout_ms, ret_receipt_cb_t cb, void *user);

/**
 * Handle a PROOF packet. Implicit proofs are sig[64]; explicit proofs are
 * packet_hash[32] | sig[64]. The signature covers the full packet hash
 * and must verify against the destination's Ed25519 key.
 *
 * @param dest_out if not NULL, receives the destination the proved packet
 *                 was sent to
 * @retval 0 matched a receipt and the proof is valid; callback fired
 * @retval -ENOENT no pending receipt for this proof
 * @retval -EBADMSG matched but invalid; the receipt stays pending
 */
int ret_receipts_handle_proof(const struct ret_packet *pkt, int64_t now_ms,
			      uint8_t dest_out[RET_TRUNC_HASH_LEN]);

bool ret_receipts_full(void);

/**
 * Fire RET_RECEIPT_TIMEOUT for every receipt whose deadline is at or
 * before @p now_ms.
 *
 * @return number of watched receipts that timed out
 */
int ret_receipts_expire(int64_t now_ms);

/** Fail every pending receipt with @p status (e.g. on disconnect). */
void ret_receipts_fail_all(enum ret_receipt_status status, int64_t now_ms);

/** Earliest deadline, or INT64_MAX when nothing is pending. */
int64_t ret_receipts_next_deadline(void);

#endif /* RET_RECEIPT_H_ */
