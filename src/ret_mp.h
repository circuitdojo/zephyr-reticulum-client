/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * msgpack helpers on top of mpack for untrusted input.
 */

#ifndef RET_MP_H_
#define RET_MP_H_

#include <mpack.h>

/** Deepest container nesting accepted in a value from the network. */
#define RET_MP_MAX_DEPTH 16

/**
 * Skip one complete value without recursion. mpack_discard() recurses once
 * per nesting level, so a peer could exhaust the stack with a few hundred
 * bytes of nested arrays; this walks the value with a bounded explicit
 * stack instead.
 *
 * @retval 0 skipped
 * @retval -EBADMSG malformed, truncated, or nested deeper than RET_MP_MAX_DEPTH
 */
int ret_mp_skip(mpack_reader_t *r);

#endif /* RET_MP_H_ */
