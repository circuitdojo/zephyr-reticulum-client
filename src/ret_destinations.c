/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>

#include "ret_destinations.h"

static struct ret_destination table[CONFIG_RET_MAX_KNOWN_DESTINATIONS];

void ret_destinations_clear(void)
{
	memset(table, 0, sizeof(table));
}

const struct ret_destination *ret_destinations_find(const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(table); i++) {
		if (table[i].used && memcmp(table[i].dest_hash, dest_hash, RET_TRUNC_HASH_LEN) == 0) {
			return &table[i];
		}
	}
	return NULL;
}

static struct ret_destination *slot_for(const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_destination *oldest = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(table); i++) {
		if (!table[i].used) {
			return &table[i];
		}
		if (oldest == NULL || table[i].last_seen_ms < oldest->last_seen_ms) {
			oldest = &table[i];
		}
	}
	return oldest;
}

int ret_destinations_update(const struct ret_packet *pkt, const struct ret_announce *a,
			    int64_t now_ms, const struct ret_destination **out, bool *fresh)
{
	struct ret_destination *d = (struct ret_destination *)ret_destinations_find(a->dest_hash);
	bool is_fresh = true;

	if (d != NULL) {
		if (memcmp(d->pub, a->pub, RET_PUBKEY_LEN) != 0) {
			return -EPERM;
		}
		if (ret_announce_emitted(a->random_hash) < ret_announce_emitted(d->random_hash)) {
			if (fresh != NULL) {
				*fresh = false;
			}
			if (out != NULL) {
				*out = d;
			}
			return 0;
		}
		is_fresh = memcmp(d->random_hash, a->random_hash, RET_RANDOM_HASH_LEN) != 0;
	} else {
		d = slot_for(a->dest_hash);
		memset(d, 0, sizeof(*d));
		d->used = true;
		memcpy(d->dest_hash, a->dest_hash, RET_TRUNC_HASH_LEN);
		memcpy(d->identity_hash, a->identity_hash, RET_TRUNC_HASH_LEN);
		memcpy(d->name_hash, a->name_hash, RET_NAME_HASH_LEN);
		memcpy(d->pub, a->pub, RET_PUBKEY_LEN);
	}

	memcpy(d->random_hash, a->random_hash, RET_RANDOM_HASH_LEN);

	if (a->ratchet != NULL) {
		d->has_ratchet = true;
		memcpy(d->ratchet, a->ratchet, RET_RATCHET_LEN);
	}

	d->path_valid = true;
	d->hops = pkt->hops < UINT8_MAX ? pkt->hops + 1 : UINT8_MAX;
	d->has_transport_id = pkt->header_type == RET_HEADER_2;
	if (d->has_transport_id) {
		memcpy(d->transport_id, pkt->transport_id, RET_TRUNC_HASH_LEN);
	}
	d->last_seen_ms = now_ms;

	if (out != NULL) {
		*out = d;
	}
	if (fresh != NULL) {
		*fresh = is_fresh;
	}
	return 0;
}

void ret_destinations_mark_proves(const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_destination *d = (struct ret_destination *)ret_destinations_find(dest_hash);

	if (d != NULL) {
		d->proves = true;
	}
}

void ret_destinations_invalidate_paths(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(table); i++) {
		table[i].path_valid = false;
		table[i].has_transport_id = false;
	}
}

void ret_destinations_address(const struct ret_destination *d, struct ret_packet *pkt)
{
	memcpy(pkt->dest_hash, d->dest_hash, RET_TRUNC_HASH_LEN);
	if (d->hops > 1 && d->has_transport_id) {
		pkt->header_type = RET_HEADER_2;
		pkt->transport_type = RET_TRANSPORT_TRANSPORT;
		memcpy(pkt->transport_id, d->transport_id, RET_TRUNC_HASH_LEN);
	} else {
		pkt->header_type = RET_HEADER_1;
		pkt->transport_type = RET_TRANSPORT_BROADCAST;
	}
}
