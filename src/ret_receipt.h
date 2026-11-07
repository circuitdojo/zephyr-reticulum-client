/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
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

/** @retval -ENOMEM table full */
int ret_receipts_add(const uint8_t packet_hash[RET_HASH_LEN],
		     const uint8_t sig_pub[RET_ED25519_PUB_LEN], int64_t now_ms,
		     uint32_t timeout_ms, ret_receipt_cb_t cb, void *user);

/**
 * Handle a PROOF packet. Implicit proofs are sig[64]; explicit proofs are
 * packet_hash[32] | sig[64]. The signature covers the full packet hash
 * and must verify against the destination's Ed25519 key.
 *
 * @retval 0 matched a receipt and the proof is valid; callback fired
 * @retval -ENOENT no pending receipt for this proof
 * @retval -EBADMSG matched but invalid; the receipt stays pending
 */
int ret_receipts_handle_proof(const struct ret_packet *pkt, int64_t now_ms);

/** Fire @p status for every receipt whose deadline is at or before @p now_ms. */
void ret_receipts_expire(int64_t now_ms);

/** Fail every pending receipt with @p status (e.g. on disconnect). */
void ret_receipts_fail_all(enum ret_receipt_status status, int64_t now_ms);

/** Earliest deadline, or INT64_MAX when nothing is pending. */
int64_t ret_receipts_next_deadline(void);

#endif /* RET_RECEIPT_H_ */
