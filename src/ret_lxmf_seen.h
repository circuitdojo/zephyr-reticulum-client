/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Replay protection for received LXMF messages. Pure functions over a
 * caller-owned table; the client persists every change.
 *
 * - A message older than max_age (by its own, signed, timestamp) is
 *   refused: no propagation node keeps one longer (LXMRouter
 *   MESSAGE_EXPIRY is 30 days), so it can only be a replay.
 * - Newer ones are remembered by hash with their timestamp. When the
 *   table is full, an expired entry is reused; failing that the oldest
 *   is evicted and the floor rises to its timestamp. Anything at or below
 *   the floor is refused too, so an evicted message can never come back:
 *   the cost is that a genuinely late message older than the floor is
 *   refused, explicitly, instead of a replay window opening.
 * - Reusing an expired entry raises the floor to it as well, so the rule
 *   "everything forgotten is at or below the floor" holds even after a
 *   reboot without a wall clock.
 * - A timestamp more than max_future_s ahead of the clock (or, without a
 *   clock, past year 2100) is refused: it would otherwise raise the floor
 *   past every genuine message once evicted. With the clock set, a raised
 *   floor is capped at now + max_future_s, and a floor beyond that (raised
 *   before the clock was set) is ignored, as are such entries.
 * - Unverified messages are not remembered while the table is full of
 *   verified ones: such a message, replayed, is delivered again (still
 *   marked unverified). The price of not letting anyone flush the table.
 * - Only verified messages may evict. Anyone can send unverified ones, so
 *   they take a free or expired entry or are not remembered at all; they
 *   cannot flush genuine entries or raise the floor that way. A flood of
 *   verified messages (from a fresh identity) can still fill the table and
 *   raise the floor to about "now": later, older messages are refused.
 * - Without a wall clock (now == 0) only the floor and the table apply.
 */

#ifndef RET_LXMF_SEEN_H_
#define RET_LXMF_SEEN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A truncated message hash: collisions among a few hundred entries are
 * out of reach at 128 bits.
 */
#define RET_LXMF_SEEN_HASH_LEN 16

struct ret_lxmf_seen_entry {
	uint8_t hash[RET_LXMF_SEEN_HASH_LEN];
	double timestamp;
	bool used;
};

struct ret_lxmf_seen {
	struct ret_lxmf_seen_entry *entries;
	size_t count;
	/** Messages with a timestamp at or below this are refused. */
	double floor;
	/** Maximum message age in seconds. */
	uint32_t max_age_s;
	/** Maximum clock skew ahead of now, in seconds. */
	uint32_t max_future_s;
};

/* Remembered nowhere: an unverified message with no free entry. */
#define RET_LXMF_SEEN_NOT_STORED SIZE_MAX

enum ret_lxmf_seen_verdict {
	RET_LXMF_SEEN_NEW,
	RET_LXMF_SEEN_DUPLICATE,
	RET_LXMF_SEEN_TOO_OLD,
	/** Not finite, or too far in the future. */
	RET_LXMF_SEEN_BAD_TIME,
};

/** @p now_s: wall-clock seconds, or 0 when the clock is not set. */
enum ret_lxmf_seen_verdict ret_lxmf_seen_check(const struct ret_lxmf_seen *s,
					       const uint8_t *hash, double timestamp,
					       int64_t now_s);

/**
 * Remember a message (after ret_lxmf_seen_check() said NEW).
 *
 * @param may_evict the message is verified: it may replace a live entry
 * @param floor_raised set when the floor rose (persist it)
 * @return the slot written (persist it), or RET_LXMF_SEEN_NOT_STORED
 */
size_t ret_lxmf_seen_add(struct ret_lxmf_seen *s, const uint8_t *hash, double timestamp,
			 int64_t now_s, bool may_evict, bool *floor_raised);

#endif /* RET_LXMF_SEEN_H_ */
