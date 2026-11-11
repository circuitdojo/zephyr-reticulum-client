/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include "ret_transport_store_ram.h"

static struct ret_transport_store_ram_entry *find(struct ret_transport_store_ram *s,
						  const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	for (size_t i = 0; i < s->n; i++) {
		if (s->entries[i].used &&
		    memcmp(s->entries[i].meta.dest_hash, dest_hash, RET_TRUNC_HASH_LEN) == 0) {
			return &s->entries[i];
		}
	}
	return NULL;
}

static int load(struct ret_transport_store *store, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
		struct ret_transport_path_meta *meta, uint8_t *announce, size_t cap, size_t *len)
{
	struct ret_transport_store_ram *s = CONTAINER_OF(store, struct ret_transport_store_ram, store);
	struct ret_transport_store_ram_entry *e = find(s, dest_hash);

	if (!e) {
		return -ENOENT;
	}
	*meta = e->meta;
	if (announce) {
		if (cap < e->len) {
			return -ENOBUFS;
		}
		memcpy(announce, e->announce, e->len);
		*len = e->len;
	}
	return 0;
}

static int save(struct ret_transport_store *store, const struct ret_transport_path_meta *meta,
		const uint8_t *announce, size_t len)
{
	struct ret_transport_store_ram *s = CONTAINER_OF(store, struct ret_transport_store_ram, store);
	struct ret_transport_store_ram_entry *e = find(s, meta->dest_hash);

	if (announce && len > sizeof(e->announce)) {
		return -EMSGSIZE;
	}
	if (!e) {
		if (!announce) {
			return -ENOENT;
		}
		for (size_t i = 0; i < s->n; i++) {
			struct ret_transport_store_ram_entry *c = &s->entries[i];

			if (!c->used) {
				e = c;
				break;
			}
			if (!e || c->seq < e->seq) {
				e = c;
			}
		}
		if (!e) {
			return -ENOMEM;
		}
	}
	e->used = true;
	e->seq = ++s->seq;
	e->meta = *meta;
	if (announce) {
		memcpy(e->announce, announce, len);
		e->len = (uint16_t)len;
	}
	return 0;
}

static int remove_path(struct ret_transport_store *store,
		       const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	struct ret_transport_store_ram *s = CONTAINER_OF(store, struct ret_transport_store_ram, store);
	struct ret_transport_store_ram_entry *e = find(s, dest_hash);

	if (!e) {
		return -ENOENT;
	}
	e->used = false;
	return 0;
}

static int foreach(struct ret_transport_store *store,
		   int (*cb)(const struct ret_transport_path_meta *meta, void *user), void *user)
{
	struct ret_transport_store_ram *s = CONTAINER_OF(store, struct ret_transport_store_ram, store);

	for (size_t i = 0; i < s->n; i++) {
		if (s->entries[i].used && cb(&s->entries[i].meta, user)) {
			break;
		}
	}
	return 0;
}

void ret_transport_store_ram_init(struct ret_transport_store_ram *s,
				  struct ret_transport_store_ram_entry *entries, size_t n)
{
	memset(entries, 0, n * sizeof(*entries));
	s->store.load = load;
	s->store.save = save;
	s->store.remove = remove_path;
	s->store.foreach = foreach;
	s->entries = entries;
	s->n = n;
	s->seq = 0;
}
