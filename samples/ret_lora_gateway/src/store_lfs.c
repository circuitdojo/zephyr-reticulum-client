/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The transport's path store on LittleFS: one file per destination,
 * /lfs/tp/<hex destination hash>, holding a header, the path's metadata
 * and the announce as received. LittleFS replaces a file's contents
 * atomically when it is closed, so a reset never leaves half a record.
 * When the store is full, or the filesystem's free blocks fall to the
 * reserve, files are removed in directory order (by name, so effectively
 * random) to make room. Each file takes a block: a record is larger than
 * LittleFS inlines.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/fs/fs.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>

#include "gateway.h"

LOG_MODULE_REGISTER(store_lfs, LOG_LEVEL_INF);

#define DIR       "/lfs/tp"
#define MAGIC     0x31505452 /* "RTP1" */
#define NAME_LEN  (2 * RET_TRUNC_HASH_LEN)
#define PATH_SIZE (sizeof(DIR) + 1 + NAME_LEN + 1)
/* Invalid records found while iterating, removed afterwards. */
#define MAX_INVALID 8

struct header {
	uint32_t magic;
	uint16_t meta_size;
	uint16_t len;
};

static struct ret_transport_store store;
static size_t count;
/*
 * Free blocks, as last measured and then tracked: each record file takes a
 * block. fs_statvfs() walks the whole filesystem, so it runs only at start
 * and near the reserve.
 */
static unsigned long free_est;

static void counted_removed(void)
{
	if (count > 0) {
		count--;
	}
	free_est++;
}

static void path_of(const uint8_t dest_hash[RET_TRUNC_HASH_LEN], char out[PATH_SIZE])
{
	char *p = out + snprintf(out, PATH_SIZE, "%s/", DIR);

	for (int i = 0; i < RET_TRUNC_HASH_LEN; i++) {
		p += snprintf(p, 3, "%02x", dest_hash[i]);
	}
}

/* The path of record file @p name, which must be NAME_LEN characters. */
static void path_of_name(const char *name, char out[PATH_SIZE])
{
	snprintf(out, PATH_SIZE, "%s/%.*s", DIR, NAME_LEN, name);
}

static int name_to_hash(const char *name, uint8_t out[RET_TRUNC_HASH_LEN])
{
	if (strlen(name) != NAME_LEN) {
		return -EINVAL;
	}
	return hex2bin(name, NAME_LEN, out, RET_TRUNC_HASH_LEN) == RET_TRUNC_HASH_LEN ? 0 : -EINVAL;
}

static int read_all(struct fs_file_t *f, void *buf, size_t len)
{
	ssize_t n = fs_read(f, buf, len);

	return n < 0 ? (int)n : (n == (ssize_t)len ? 0 : -EBADMSG);
}

/* Close @p f, reporting the first error: @p err, else the close's. */
static int close_with(struct fs_file_t *f, int err)
{
	int cerr = fs_close(f);

	return err ? err : cerr;
}

static int write_all(struct fs_file_t *f, const void *buf, size_t len)
{
	ssize_t n = fs_write(f, buf, len);

	return n < 0 ? (int)n : (n == (ssize_t)len ? 0 : -ENOSPC);
}

/* Read a record; a malformed one reads as -EBADMSG. */
static int read_record(const char *path, struct ret_transport_path_meta *meta, uint8_t *announce,
		       size_t cap, size_t *len)
{
	struct fs_dirent st;
	struct fs_file_t f;
	struct header h;
	int err;

	/* Most lookups are for paths we don't have: fs_open() would log each. */
	err = fs_stat(path, &st);
	if (err) {
		return err;
	}
	fs_file_t_init(&f);
	err = fs_open(&f, path, FS_O_READ);
	if (err) {
		return err;
	}
	err = read_all(&f, &h, sizeof(h));
	if (!err && (h.magic != MAGIC || h.meta_size != sizeof(*meta) || h.len == 0 ||
		     h.len > RET_MTU)) {
		err = -EBADMSG;
	}
	if (!err) {
		err = read_all(&f, meta, sizeof(*meta));
	}
	if (!err && announce) {
		err = cap < h.len ? -ENOBUFS : read_all(&f, announce, h.len);
		if (!err) {
			*len = h.len;
		}
	}
	(void)fs_close(&f);
	return err;
}

static int load(struct ret_transport_store *s, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
		struct ret_transport_path_meta *meta, uint8_t *announce, size_t cap, size_t *len)
{
	char path[PATH_SIZE];
	int err;

	ARG_UNUSED(s);
	path_of(dest_hash, path);
	err = read_record(path, meta, announce, cap, len);
	if (err == -EBADMSG) {
		LOG_WRN("unreadable path record, removed");
		if (fs_unlink(path) == 0) {
			counted_removed();
		}
		return -ENOENT;
	}
	return err;
}

/* Make room by removing the first record in directory order. */
static int evict_one(void)
{
	struct fs_dir_t dir;
	struct fs_dirent entry;
	char path[PATH_SIZE];
	int err;

	fs_dir_t_init(&dir);
	err = fs_opendir(&dir, DIR);
	if (err) {
		return err;
	}
	path[0] = '\0';
	while (fs_readdir(&dir, &entry) == 0 && entry.name[0] != '\0') {
		if (entry.type == FS_DIR_ENTRY_FILE && strlen(entry.name) == NAME_LEN) {
			path_of_name(entry.name, path);
			break;
		}
	}
	(void)fs_closedir(&dir);
	if (path[0] == '\0') {
		return -ENOENT;
	}
	err = fs_unlink(path);
	if (!err) {
		counted_removed();
	}
	return err;
}

static int free_blocks(unsigned long *out)
{
	struct fs_statvfs st;
	int err = fs_statvfs(DIR, &st);

	if (!err) {
		*out = st.f_bfree;
	}
	return err;
}

/* Room for one more record: under the count, and the reserve left free. */
static int make_room(void)
{
	unsigned long bfree;
	int err;

	while (count >= CONFIG_RET_GATEWAY_STORE_MAX_PATHS) {
		err = evict_one();
		if (err) {
			return err;
		}
	}
	for (;;) {
		if (free_est > CONFIG_RET_GATEWAY_STORE_RESERVE_BLOCKS + 1) {
			return 0;
		}
		/* Near the reserve: measure. */
		err = free_blocks(&bfree);
		if (err) {
			return err;
		}
		free_est = bfree;
		if (bfree > CONFIG_RET_GATEWAY_STORE_RESERVE_BLOCKS) {
			return 0;
		}
		err = evict_one();
		if (err) {
			/* Nothing left to remove: the filesystem is full of something else. */
			return err == -ENOENT ? -ENOSPC : err;
		}
	}
}

static int save(struct ret_transport_store *s, const struct ret_transport_path_meta *meta,
		const uint8_t *announce, size_t len)
{
	struct fs_dirent st;
	struct fs_file_t f;
	char path[PATH_SIZE];
	struct header h = { .magic = MAGIC, .meta_size = sizeof(*meta), .len = (uint16_t)len };
	bool exists;
	int err;

	ARG_UNUSED(s);
	path_of(meta->dest_hash, path);
	exists = fs_stat(path, &st) == 0;

	fs_file_t_init(&f);
	if (!announce) {
		/* Metadata only: rewrite it in place, keeping the announce. */
		if (!exists) {
			return -ENOENT;
		}
		err = fs_open(&f, path, FS_O_RDWR);
		if (err) {
			return err;
		}
		err = fs_seek(&f, sizeof(h), FS_SEEK_SET);
		if (!err) {
			err = write_all(&f, meta, sizeof(*meta));
		}
		return close_with(&f, err);
	}

	if (len == 0 || len > RET_MTU) {
		return -EMSGSIZE;
	}
	if (!exists) {
		err = make_room();
		if (err) {
			return err;
		}
	}
	err = fs_open(&f, path, FS_O_CREATE | FS_O_WRITE | FS_O_TRUNC);
	if (err) {
		return err;
	}
	err = write_all(&f, &h, sizeof(h));
	if (!err) {
		err = write_all(&f, meta, sizeof(*meta));
	}
	if (!err) {
		err = write_all(&f, announce, len);
	}
	err = close_with(&f, err);
	if (err == -ENOSPC) {
		/* The estimate was off (directory blocks, the settings file):
		 * measure on the next insert, and evict from there.
		 */
		free_est = 0;
	}
	if (!exists) {
		if (!err) {
			count++;
			if (free_est > 0) {
				free_est--;
			}
		} else {
			/* Not half a record: it would read as invalid anyway. */
			(void)fs_unlink(path);
		}
	}
	return err;
}

static int remove_path(struct ret_transport_store *s, const uint8_t dest_hash[RET_TRUNC_HASH_LEN])
{
	char path[PATH_SIZE];
	int err;

	ARG_UNUSED(s);
	path_of(dest_hash, path);
	err = fs_unlink(path);
	if (!err) {
		counted_removed();
	}
	return err;
}

/*
 * Visit every record: @p cb gets each valid one (and may stop the walk);
 * unreadable ones are removed once the directory is closed.
 */
static int walk(int (*cb)(const struct ret_transport_path_meta *meta, void *user), void *user,
		size_t *n_files)
{
	static struct ret_transport_path_meta meta;
	static char invalid[MAX_INVALID][PATH_SIZE];
	struct fs_dir_t dir;
	struct fs_dirent entry;
	char path[PATH_SIZE];
	size_t n_invalid = 0;
	size_t n = 0;
	int err;

	fs_dir_t_init(&dir);
	err = fs_opendir(&dir, DIR);
	if (err) {
		return err;
	}
	while ((err = fs_readdir(&dir, &entry)) == 0 && entry.name[0] != '\0') {
		uint8_t hash[RET_TRUNC_HASH_LEN];
		bool ok;

		if (entry.type != FS_DIR_ENTRY_FILE) {
			continue;
		}
		if (strlen(entry.name) != NAME_LEN) {
			/* Not ours: its path may not even fit, so leave it alone. */
			LOG_WRN("unexpected file %s in %s", entry.name, DIR);
			continue;
		}
		path_of_name(entry.name, path);
		ok = name_to_hash(entry.name, hash) == 0 &&
		     read_record(path, &meta, NULL, 0, NULL) == 0 &&
		     memcmp(meta.dest_hash, hash, sizeof(hash)) == 0;
		if (!ok) {
			if (n_invalid < MAX_INVALID) {
				memcpy(invalid[n_invalid++], path, sizeof(path));
			}
			continue;
		}
		n++;
		if (cb && cb(&meta, user)) {
			cb = NULL;
		}
	}
	(void)fs_closedir(&dir);
	for (size_t i = 0; i < n_invalid; i++) {
		LOG_WRN("unreadable path record %s, removed", invalid[i]);
		(void)fs_unlink(invalid[i]);
	}
	if (n_files) {
		*n_files = n;
	}
	return err;
}

static int foreach(struct ret_transport_store *s,
		   int (*cb)(const struct ret_transport_path_meta *meta, void *user), void *user)
{
	ARG_UNUSED(s);
	return walk(cb, user, NULL);
}

ssize_t store_used_bytes(void)
{
	struct fs_statvfs st;
	int err = fs_statvfs(DIR, &st);

	return err ? err : (ssize_t)((st.f_blocks - st.f_bfree) * st.f_frsize);
}

int store_init(struct ret_transport_store **out)
{
	struct fs_dirent st;
	int err = fs_stat(DIR, &st) == 0 ? 0 : fs_mkdir(DIR);

	if (err) {
		LOG_ERR("mkdir %s: %d", DIR, err);
		return err;
	}
	err = walk(NULL, NULL, &count);
	if (!err) {
		err = free_blocks(&free_est);
	}
	if (err) {
		LOG_ERR("reading %s: %d", DIR, err);
		return err;
	}
	store.load = load;
	store.save = save;
	store.remove = remove_path;
	store.foreach = foreach;
	*out = &store;
	LOG_INF("%zu paths in flash", count);
	return 0;
}
