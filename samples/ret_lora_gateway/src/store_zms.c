/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * The transport's path store in ZMS: one record per destination, value a
 * header, the path's metadata and the announce as received. ZMS appends
 * every write and reclaims the oldest sector when full; its data CRC
 * covers each record.
 *
 * Record IDs are 32 bits of the destination hash: bytes 0..3, or bytes
 * 8..11 when another destination holds the first. RAM keeps a sorted index
 * of the stored IDs with a tag from bytes 4..7 naming the owner, so:
 * - a lookup for a destination we don't have never touches flash;
 * - a write needs no read first;
 * - a stored path is never replaced by another destination's. One made to
 *   share an ID (32 bits are cheap to grind) moves to its second ID, and
 *   one whose IDs are both taken isn't stored, so the gateway doesn't
 *   rebroadcast it or answer for it (about 46 bits of grinding, and only
 *   that destination loses). A flood of new destinations still evicts the
 *   oldest records, as any bounded table would.
 * Records still carry the whole hash, which every read checks.
 *
 * ZMS finds a record by walking its log back from the newest entry unless
 * its lookup cache answers: about 0.15 ms per entry walked on the NOR. The
 * index is built at boot in one pass over the log (zms_iter_next_all):
 * zms_iter_next() looks for a newer copy of every entry it yields, which
 * makes a full walk quadratic. While more deleted paths are still in the
 * log than MAX_DEAD, each further copy of those costs a lookup at boot.
 * A record that can't be read (malformed, or its data CRC fails twice) is
 * deleted, so one bad record can't stop a boot.
 *
 * Eviction takes the record ZMS wrote longest ago: GC rewrites survivors at
 * the head, so this is roughly first in, first out.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/drivers/flash.h>
#include <zephyr/kernel.h>
#include <zephyr/kvss/zms.h>
#include <zephyr/logging/log.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include "gateway.h"

LOG_MODULE_REGISTER(store_zms, LOG_LEVEL_INF);

#define PATHS_PART gw_paths_partition
#define MAGIC      0x31505452 /* "RTP1" */
#define MAX_PATHS  CONFIG_RET_GATEWAY_STORE_MAX_PATHS
/* ZMS's own entries (sector headers, GC markers) use this ID. */
#define RESERVED_ID 0xFFFFFFFFu
/* Not a real tag: the owner is not known yet (indexed at boot, unread). */
#define TAG_UNKNOWN 0u
/*
 * IDs seen deleted while building the index, so older copies stay hidden.
 * Past this many, candidates are checked with ZMS before being indexed.
 */
#define MAX_DEAD  MAX_PATHS
/* Records over the limit removed per boot (a build with a lower limit). */
#define MAX_EXTRA 32

struct header {
	uint32_t magic;
	uint16_t meta_size;
	uint16_t len;
};

#define RECORD_MAX (sizeof(struct header) + sizeof(struct ret_transport_path_meta) + RET_MTU)

BUILD_ASSERT(sizeof(zms_id_t) == sizeof(uint32_t), "the path store needs 32-bit ZMS IDs");

/*
 * Sectors MAX_PATHS records take (4 KB sectors, five ZMS entries per sector
 * for its own use): ZMS wants twice that, or a full store spends its time
 * in garbage collection. Checked again at mount with the real sector size.
 */
#define ATE_SIZE 16
#define SECTORS_FOR(sector)                                                                    \
	DIV_ROUND_UP(MAX_PATHS, ((sector) - 5 * ATE_SIZE) / (RECORD_MAX + ATE_SIZE))
BUILD_ASSERT(2 * SECTORS_FOR(4096) + 2 <= PARTITION_SIZE(PATHS_PART) / 4096,
	     "gw_paths_partition can't hold twice RET_GATEWAY_STORE_MAX_PATHS records");

struct entry {
	uint32_t id;
	uint32_t tag;
};

static struct ret_transport_store store;
static struct zms_fs fs;
static uint64_t lookup_cache[CONFIG_RET_GATEWAY_ZMS_CACHE];
/* One record at a time: the transport thread is the only caller. */
static uint8_t rec[RECORD_MAX];

/* The records stored, sorted by ID. */
static struct entry entries[MAX_PATHS];
static size_t count;
/* Scratch for building the index and choosing an eviction. */
static uint32_t dead_ids[MAX_DEAD];
static uint8_t visited[DIV_ROUND_UP(MAX_PATHS, 8)];

static uint32_t usable(uint32_t id)
{
	return id == RESERVED_ID ? RESERVED_ID - 1 : id;
}

/* The destination's two record IDs: different, and never ZMS's own. */
static void ids_of(const uint8_t dest_hash[RET_TRUNC_HASH_LEN], uint32_t ids[2])
{
	ids[0] = usable(sys_get_be32(&dest_hash[0]));
	ids[1] = usable(sys_get_be32(&dest_hash[8]));
	if (ids[1] == ids[0]) {
		ids[1] = usable(ids[0] ^ 1);
		if (ids[1] == ids[0]) {
			ids[1] = ids[0] - 1;
		}
	}
}

static uint32_t tag_of(const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	uint32_t t = sys_get_be32(&dest_hash[4]);

	return t == TAG_UNKNOWN ? 1 : t;
}

/* Binary search over entries: the position of @p id, or where it would go. */
static size_t position(uint32_t id, bool *found)
{
	size_t lo = 0;
	size_t hi = count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (entries[mid].id < id) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	*found = lo < count && entries[lo].id == id;
	return lo;
}

static struct entry *find(uint32_t id)
{
	bool found;
	size_t at = position(id, &found);

	return found ? &entries[at] : NULL;
}

static bool add(uint32_t id, uint32_t tag)
{
	bool found;
	size_t at = position(id, &found);

	if (found) {
		entries[at].tag = tag;
		return true;
	}
	if (count == MAX_PATHS) {
		return false;
	}
	memmove(&entries[at + 1], &entries[at], (count - at) * sizeof(entries[0]));
	entries[at] = (struct entry){ .id = id, .tag = tag };
	count++;
	return true;
}

static void drop(uint32_t id)
{
	bool found;
	size_t at = position(id, &found);

	if (found) {
		memmove(&entries[at], &entries[at + 1], (count - at - 1) * sizeof(entries[0]));
		count--;
	}
}

/* A sorted set of IDs (the dead set built at boot). */
static bool in_set(const uint32_t *ids, size_t n, uint32_t id, size_t *at)
{
	size_t lo = 0;
	size_t hi = n;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (ids[mid] < id) {
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}
	*at = lo;
	return lo < n && ids[lo] == id;
}

static bool set_add(uint32_t *ids, size_t *n, size_t cap, uint32_t id)
{
	size_t at;

	if (in_set(ids, *n, id, &at)) {
		return true;
	}
	if (*n == cap) {
		return false;
	}
	memmove(&ids[at + 1], &ids[at], (*n - at) * sizeof(ids[0]));
	ids[at] = id;
	(*n)++;
	return true;
}

/*
 * Read record @p id into rec and check it: -EBADMSG when it is malformed.
 * @p meta and @p announce (when not NULL) are pointed into rec.
 */
static int read_record(uint32_t id, const struct ret_transport_path_meta **meta,
		       const uint8_t **announce, size_t *len)
{
	const struct header *h = (const struct header *)rec;
	ssize_t n = zms_read(&fs, id, rec, sizeof(rec));

	if (n < 0) {
		return (int)n;
	}
	if ((size_t)n < sizeof(*h) || h->magic != MAGIC ||
	    h->meta_size != sizeof(struct ret_transport_path_meta) || h->len == 0 ||
	    h->len > RET_MTU || (size_t)n != sizeof(*h) + h->meta_size + h->len) {
		return -EBADMSG;
	}
	/* A value longer than rec reads partially, past ZMS's data CRC. */
	if ((size_t)n == sizeof(rec)) {
		ssize_t stored = zms_get_data_length(&fs, id);

		if (stored < 0) {
			/* -EIO is retried by read_indexed(). */
			return (int)stored;
		}
		if (stored != n) {
			return -EBADMSG;
		}
	}
	*meta = (const struct ret_transport_path_meta *)&rec[sizeof(*h)];
	if (announce) {
		*announce = &rec[sizeof(*h) + h->meta_size];
		*len = h->len;
	}
	return 0;
}

/*
 * Read an indexed record, and learn its owner. One that is gone, malformed
 * or fails its CRC (-EIO) leaves the index (and flash): -ENOENT.
 */
static int read_indexed(uint32_t id, const struct ret_transport_path_meta **meta,
			const uint8_t **announce, size_t *len)
{
	struct entry *e;
	int err = read_record(id, meta, announce, len);

	if (err == -EIO) {
		/* A CRC mismatch, or a flash read error: only the first lasts. */
		err = read_record(id, meta, announce, len);
	}
	if (err == -EBADMSG || err == -EIO) {
		LOG_WRN("unreadable path record %08x (%d), removed", (unsigned int)id, err);
		(void)zms_delete(&fs, id);
		err = -ENOENT;
	}
	if (err == -ENOENT) {
		drop(id);
		return err;
	}
	if (err) {
		return err;
	}
	e = find(id);
	if (e) {
		e->tag = tag_of((*meta)->dest_hash);
	}
	return 0;
}

/*
 * Which of @p dest_hash's IDs holds its record: 0 or 1, or -ENOENT. Reads
 * flash only for an entry whose owner isn't known yet (once per entry).
 */
static int locate(const uint8_t dest_hash[RET_TRUNC_HASH_LEN], const uint32_t ids[2])
{
	uint32_t tag = tag_of(dest_hash);

	for (int k = 0; k < 2; k++) {
		struct entry *e = find(ids[k]);

		if (e && e->tag == TAG_UNKNOWN) {
			const struct ret_transport_path_meta *m;
			int err = read_indexed(ids[k], &m, NULL, NULL);

			if (err == -ENOENT) {
				continue;
			}
			if (err) {
				return err;
			}
			e = find(ids[k]);
		}
		if (e && e->tag == tag) {
			return k;
		}
	}
	return -ENOENT;
}

/*
 * Read @p dest_hash's own record: of its IDs, one whose owner may be it and
 * whose stored hash is it. @p k receives which. -ENOENT if neither.
 */
static int read_mine(const uint8_t dest_hash[RET_TRUNC_HASH_LEN], const uint32_t ids[2],
		     int *k, const struct ret_transport_path_meta **meta, const uint8_t **announce,
		     size_t *len)
{
	uint32_t tag = tag_of(dest_hash);

	for (int i = 0; i < 2; i++) {
		struct entry *e = find(ids[i]);
		int err;

		if (!e || (e->tag != TAG_UNKNOWN && e->tag != tag)) {
			continue;
		}
		err = read_indexed(ids[i], meta, announce, len);
		if (err == -ENOENT) {
			continue;
		}
		if (err) {
			return err;
		}
		if (memcmp((*meta)->dest_hash, dest_hash, RET_TRUNC_HASH_LEN) == 0) {
			*k = i;
			return 0;
		}
		/* Same tag, another destination (32-bit tags): try the other ID. */
	}
	return -ENOENT;
}

static int load(struct ret_transport_store *s, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
		struct ret_transport_path_meta *meta, uint8_t *announce, size_t cap, size_t *len)
{
	const struct ret_transport_path_meta *m;
	const uint8_t *a;
	uint32_t ids[2];
	size_t n;
	int k;
	int err;

	ARG_UNUSED(s);
	ids_of(dest_hash, ids);
	err = read_mine(dest_hash, ids, &k, &m, &a, &n);
	if (err) {
		return err;
	}
	*meta = *m;
	if (announce) {
		if (cap < n) {
			return -ENOBUFS;
		}
		memcpy(announce, a, n);
		*len = n;
	}
	return 0;
}

/*
 * Remove the record written longest ago: of the indexed IDs, the one whose
 * newest entry the walk (newest to oldest) reaches last. One pass.
 */
static int evict_oldest(void)
{
	struct zms_iter it;
	zms_id_t id;
	size_t len;
	bool found = false;
	uint32_t oldest = 0;
	int rc;

	memset(visited, 0, sizeof(visited));
	rc = zms_iter_init(&fs, &it);
	while (rc == 0 && (rc = zms_iter_next_all(&fs, &it, &id, &len, NULL, 0)) == 1) {
		bool hit;
		size_t at = position(id, &hit);

		rc = 0;
		if (hit && !(visited[at / 8] & BIT(at % 8))) {
			visited[at / 8] |= BIT(at % 8);
			oldest = id;
			found = true;
		}
	}
	if (rc < 0) {
		return rc;
	}
	if (!found) {
		return -ENOENT;
	}
	rc = zms_delete(&fs, oldest);
	if (!rc) {
		drop(oldest);
	}
	return rc;
}

/*
 * Write rec as record @p id, owned by @p tag. A full store (by count, or
 * ZMS out of space) gives up its oldest records until it fits.
 */
static int write_record(uint32_t id, uint32_t tag, size_t size)
{
	ssize_t n;
	int err;

	while (!find(id) && count >= MAX_PATHS) {
		err = evict_oldest();
		if (err) {
			return err;
		}
	}
	for (;;) {
		n = zms_write(&fs, id, rec, size);
		if (n != -ENOSPC) {
			break;
		}
		/* Eviction doesn't touch rec. */
		err = evict_oldest();
		if (err) {
			return err == -ENOENT ? -ENOSPC : err;
		}
	}
	if (n < 0) {
		return (int)n;
	}
	(void)add(id, tag);
	return 0;
}

static int save(struct ret_transport_store *s, const struct ret_transport_path_meta *meta,
		const uint8_t *announce, size_t len)
{
	struct header *h = (struct header *)rec;
	uint32_t ids[2];
	uint32_t id;
	size_t size;
	int k;

	ARG_UNUSED(s);
	ids_of(meta->dest_hash, ids);
	if (!announce) {
		/* Metadata only: keep the stored announce (read into rec). */
		const struct ret_transport_path_meta *old;
		int err = read_mine(meta->dest_hash, ids, &k, &old, NULL, NULL);

		if (err) {
			return err;
		}
		id = ids[k];
		memcpy(&rec[sizeof(*h)], meta, sizeof(*meta));
		size = sizeof(*h) + sizeof(*meta) + h->len;
	} else {
		if (len == 0 || len > RET_MTU) {
			return -EMSGSIZE;
		}
		/* By owner tag, no read: matching a stored path's ID and tag
		 * both would take 64 bits.
		 */
		k = locate(meta->dest_hash, ids);
		if (k >= 0) {
			id = ids[k];
		} else if (k != -ENOENT) {
			return k;
		} else if (!find(ids[0])) {
			id = ids[0];
		} else if (!find(ids[1])) {
			id = ids[1];
		} else {
			/* Both IDs belong to others, who keep them. */
			LOG_DBG("both IDs of a new path are taken, not stored");
			return -EEXIST;
		}
		h->magic = MAGIC;
		h->meta_size = sizeof(*meta);
		h->len = (uint16_t)len;
		memcpy(&rec[sizeof(*h)], meta, sizeof(*meta));
		memcpy(&rec[sizeof(*h) + sizeof(*meta)], announce, len);
		size = sizeof(*h) + sizeof(*meta) + len;
	}
	return write_record(id, tag_of(meta->dest_hash), size);
}

static int remove_path(struct ret_transport_store *s, const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	const struct ret_transport_path_meta *m;
	uint32_t ids[2];
	int k;
	int err;

	ARG_UNUSED(s);
	ids_of(dest_hash, ids);
	err = read_mine(dest_hash, ids, &k, &m, NULL, NULL);
	if (err) {
		return err;
	}
	err = zms_delete(&fs, ids[k]);
	if (!err) {
		drop(ids[k]);
	}
	return err;
}

/* Whether @p id has live data: what the newest of its entries says. */
static int live(uint32_t id)
{
	ssize_t n = zms_get_data_length(&fs, id);

	if (n == -ENOENT || n == 0) {
		return 0;
	}
	return n < 0 ? (int)n : 1;
}

/*
 * Build the index in one pass, newest entry first: an ID's first entry
 * decides whether it is stored or deleted, and older ones are history.
 * Owners are learned when records are first read. Records past MAX_PATHS
 * (a build with a lower limit than the one that wrote them) are deleted,
 * up to MAX_EXTRA per boot.
 */
static int build_index(void)
{
	uint32_t extra[MAX_EXTRA];
	struct zms_iter it;
	size_t n_dead = 0;
	size_t n_extra = 0;
	bool dead_full = false;
	zms_id_t id;
	size_t len;
	int rc;

	count = 0;
	rc = zms_iter_init(&fs, &it);
	while (rc == 0 && (rc = zms_iter_next_all(&fs, &it, &id, &len, NULL, 0)) == 1) {
		size_t at;
		bool known = false;

		rc = 0;
		if (id == RESERVED_ID || find(id) || in_set(dead_ids, n_dead, id, &at)) {
			continue;
		}
		for (size_t i = 0; i < n_extra; i++) {
			known |= extra[i] == id;
		}
		if (known) {
			continue;
		}
		if (len == 0) {
			dead_full |= !set_add(dead_ids, &n_dead, MAX_DEAD, id);
			continue;
		}
		if (dead_full) {
			/* Its delete marker may have been one the set couldn't hold. */
			int l = live(id);

			if (l < 0) {
				return l;
			}
			if (!l) {
				continue;
			}
		}
		if (!add(id, TAG_UNKNOWN) && n_extra < ARRAY_SIZE(extra)) {
			extra[n_extra++] = id;
		}
	}
	if (rc < 0) {
		return rc;
	}
	if (n_extra) {
		LOG_WRN("%zu paths over the limit of %d, removed", n_extra, MAX_PATHS);
		for (size_t i = 0; i < n_extra; i++) {
			(void)zms_delete(&fs, extra[i]);
		}
	}
	return 0;
}

/* Visit the indexed records; @p cb may stop the walk. */
static int foreach(struct ret_transport_store *s,
		   int (*cb)(const struct ret_transport_path_meta *meta, void *user), void *user)
{
	static struct ret_transport_path_meta meta;

	ARG_UNUSED(s);
	for (size_t i = 0; i < count;) {
		const struct ret_transport_path_meta *m;
		uint32_t id = entries[i].id;
		uint32_t ids[2];
		int err = read_indexed(id, &m, NULL, NULL);

		if (err == -ENOENT) {
			/* Dropped from the index: entries[i] is the next one now. */
			continue;
		}
		if (err) {
			LOG_WRN("path record %08x: %d", (unsigned int)id, err);
			i++;
			continue;
		}
		ids_of(m->dest_hash, ids);
		if (ids[0] != id && ids[1] != id) {
			/* Stored under an ID its hash doesn't give: not ours to keep. */
			LOG_WRN("path record %08x under the wrong ID, removed", (unsigned int)id);
			(void)zms_delete(&fs, id);
			drop(id);
			continue;
		}
		i++;
		meta = *m;
		if (cb(&meta, user)) {
			break;
		}
	}
	return 0;
}

ssize_t store_used_bytes(void)
{
	ssize_t free_space = zms_calc_free_space(&fs);

	return free_space < 0 ? free_space
			      : (ssize_t)((size_t)fs.sector_size * fs.sector_count - free_space);
}

int store_init(struct ret_transport_store **out)
{
	struct flash_pages_info info;
	int err;

	fs.flash_device = PARTITION_DEVICE(PATHS_PART);
	if (!device_is_ready(fs.flash_device)) {
		LOG_ERR("path store flash not ready");
		return -ENODEV;
	}
	fs.offset = PARTITION_OFFSET(PATHS_PART);
	err = flash_get_page_info_by_offs(fs.flash_device, fs.offset, &info);
	if (err) {
		return err;
	}
	/* A sector must hold the largest record; erase pages may be smaller. */
	fs.sector_size = ROUND_UP(MAX(info.size, 2 * RECORD_MAX), info.size);
	fs.sector_count = PARTITION_SIZE(PATHS_PART) / fs.sector_size;
	if (2 * SECTORS_FOR(fs.sector_size) + 2 > fs.sector_count) {
		LOG_ERR("path store: %u sectors of %u bytes can't hold twice %d paths",
			fs.sector_count, fs.sector_size, MAX_PATHS);
		return -ENOSPC;
	}

	err = zms_set_lookup_cache(&fs, lookup_cache, ARRAY_SIZE(lookup_cache));
	if (!err) {
		err = zms_mount(&fs);
	}
	if (err) {
		LOG_ERR("path store mount: %d", err);
		return err;
	}
	err = build_index();
	if (err) {
		LOG_ERR("reading the path store: %d", err);
		return err;
	}
	store.load = load;
	store.save = save;
	store.remove = remove_path;
	store.foreach = foreach;
	*out = &store;
	LOG_INF("%zu paths in flash (%u sectors of %u bytes)", count, fs.sector_count,
		fs.sector_size);
	return 0;
}
