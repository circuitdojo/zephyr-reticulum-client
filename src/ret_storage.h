/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Persistent client state in Zephyr settings, under "ret/":
 *   ret/id    the identity's 64-byte RNS private key
 *   ret/aclk  the announce clock's reservation: no emission time above
 *             this value has been used, every one at or below it may have
 */

#ifndef RET_STORAGE_H_
#define RET_STORAGE_H_

#include <stdbool.h>
#include <stdint.h>

#include "ret_identity.h"

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

#endif /* RET_STORAGE_H_ */
