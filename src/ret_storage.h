/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * Persistent client state in Zephyr settings, under "ret/":
 *   ret/id    the identity's 64-byte RNS private key
 *   ret/aclk  the announce clock's reservation: no emission time above
 *             this value has been used, every one at or below it may have
 *   ret/lx/s/<n>  remembered LXMF message n: hash (16) | timestamp (double)
 *   ret/lx/f      the LXMF floor timestamp (double)
 *   ret/lk/<n>    known LXMF sender n: address (16) | public key (64) |
 *                 store order (u32)
 *   ret/rt/<n>    ratchet n of the own destination: order (u32) | created
 *                 (u64 wall-clock seconds, 0 if the clock was not set) |
 *                 X25519 private key (32)
 */

#ifndef RET_STORAGE_H_
#define RET_STORAGE_H_

#include <stdbool.h>
#include <stdint.h>

#include "ret_identity.h"
#include "ret_lxmf_seen.h"

/**
 * Load stored state. @p have_id is false when no identity is stored yet;
 * @p aclk is 0 when no announce clock is stored.
 *
 * Fails if any "ret/" record could not be read: the caller must never
 * mistake an unreadable identity for a missing one and replace it.
 */
int ret_storage_load(uint8_t prv[RET_PRVKEY_LEN], bool *have_id, uint64_t *aclk);

int ret_storage_save_identity(const uint8_t prv[RET_PRVKEY_LEN]);

int ret_storage_save_aclk(uint64_t aclk);

/**
 * Load remembered LXMF messages into @p s (entries zeroed first). Records
 * for slots beyond s->count (the table was made smaller) raise the floor
 * to their timestamp instead, so nothing forgotten can come back. An
 * unreadable record resets the whole table (logged): it is expendable,
 * unlike the identity.
 */
int ret_storage_load_lxmf_seen(struct ret_lxmf_seen *s);

/** One stored sender key, as ret/lk/<n> holds it. */
struct ret_storage_known {
	uint8_t dest[RET_TRUNC_HASH_LEN];
	uint8_t pub[RET_PUBKEY_LEN];
	uint32_t seq;
};

/**
 * Load stored sender keys into @p out[0..count) (unused slots have seq 0
 * and an all-zero address). An unreadable record resets them all.
 */
int ret_storage_load_known(struct ret_storage_known *out, size_t count);

int ret_storage_save_known(size_t slot, const struct ret_storage_known *k);

/** One ratchet, as ret/rt/<n> holds it (@p key is the <n>). */
struct ret_storage_ratchet {
	uint8_t prv[RET_RATCHET_LEN];
	uint64_t created;
	uint32_t seq;
	uint16_t key;
};

/**
 * Load stored ratchets into @p out, newest (highest seq) first, at most
 * @p count; @p n receives how many. Older records beyond @p count (the
 * table was made smaller) are deleted.
 *
 * Fails if any record is unreadable: senders keep encrypting to the
 * ratchet they last heard, so the set must not be silently replaced.
 */
int ret_storage_load_ratchets(struct ret_storage_ratchet *out, size_t count, size_t *n);

int ret_storage_save_ratchet(const struct ret_storage_ratchet *r);

/** Delete every ratchet (they belong to an identity that is gone). */
int ret_storage_clear_ratchets(void);

/** Persist slot @p slot, and the floor when @p floor changed. */
int ret_storage_save_lxmf_seen(const struct ret_lxmf_seen *s, size_t slot, bool floor);

#endif /* RET_STORAGE_H_ */
