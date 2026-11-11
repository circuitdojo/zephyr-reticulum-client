/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <math.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "ret_lxmf_seen.h"

/* 2100-01-01: the ceiling while there is no wall clock. */
#define NO_CLOCK_CEILING 4102444800.0

/* Expired, or (stored before the clock was set) impossibly far ahead. */
static bool expired(const struct ret_lxmf_seen *s, double timestamp, int64_t now_s)
{
	return now_s > 0 && (timestamp < (double)(now_s - (int64_t)s->max_age_s) ||
			     timestamp > (double)now_s + s->max_future_s);
}

/* The floor in force. With the clock set, a floor can only be raised up
 * to now + max_future_s; one beyond that was raised before the clock was
 * set, from timestamps nothing vouched for. It is ignored (the age limit
 * still applies) rather than refusing every message until 2100.
 */
static double floor_now(const struct ret_lxmf_seen *s, int64_t now_s)
{
	if (now_s > 0 && s->floor > (double)now_s + s->max_future_s) {
		return 0;
	}
	return s->floor;
}

static void raise_floor(struct ret_lxmf_seen *s, double timestamp, int64_t now_s, bool *raised)
{
	/* An entry stored before the clock was set may claim any time up to
	 * 2100; forgetting it must not lift the floor past "now".
	 */
	if (now_s > 0) {
		timestamp = MIN(timestamp, (double)now_s + s->max_future_s);
	}
	if (timestamp > s->floor) {
		s->floor = timestamp;
		*raised = true;
	}
}

enum ret_lxmf_seen_verdict ret_lxmf_seen_check(const struct ret_lxmf_seen *s,
					       const uint8_t *hash, double timestamp,
					       int64_t now_s)
{
	double ceiling = now_s > 0 ? (double)now_s + s->max_future_s : NO_CLOCK_CEILING;

	for (size_t i = 0; i < s->count; i++) {
		const struct ret_lxmf_seen_entry *e = &s->entries[i];

		if (e->used && memcmp(e->hash, hash, RET_LXMF_SEEN_HASH_LEN) == 0) {
			return RET_LXMF_SEEN_DUPLICATE;
		}
	}
	if (!isfinite(timestamp) || timestamp > ceiling) {
		return RET_LXMF_SEEN_BAD_TIME;
	}
	if (timestamp <= floor_now(s, now_s) || expired(s, timestamp, now_s)) {
		return RET_LXMF_SEEN_TOO_OLD;
	}
	return RET_LXMF_SEEN_NEW;
}

size_t ret_lxmf_seen_add(struct ret_lxmf_seen *s, const uint8_t *hash, double timestamp,
			 int64_t now_s, bool may_evict, bool *floor_raised)
{
	size_t slot = s->count;
	size_t oldest = 0;

	*floor_raised = false;
	for (size_t i = 0; i < s->count; i++) {
		const struct ret_lxmf_seen_entry *e = &s->entries[i];

		if (!e->used) {
			slot = i;
			break;
		}
		if (slot == s->count && expired(s, e->timestamp, now_s)) {
			slot = i; /* reusable, but keep looking for a free one */
		}
		if (e->timestamp < s->entries[oldest].timestamp) {
			oldest = i;
		}
	}
	if (slot == s->count) {
		if (!may_evict) {
			return RET_LXMF_SEEN_NOT_STORED;
		}
		slot = oldest; /* full of live entries: forget the oldest */
	}

	struct ret_lxmf_seen_entry *e = &s->entries[slot];

	/* Whatever is forgotten, nothing as old may come back. */
	if (e->used) {
		raise_floor(s, e->timestamp, now_s, floor_raised);
	}
	memcpy(e->hash, hash, RET_LXMF_SEEN_HASH_LEN);
	e->timestamp = timestamp;
	e->used = true;
	return slot;
}
