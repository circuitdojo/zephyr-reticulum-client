/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/settings/settings.h>

#include "ret_crypto.h"
#include "ret_storage.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

struct load_ctx {
	uint8_t *prv;
	bool have_id;
	uint64_t aclk;
	/* settings_load_subtree_direct() discards callback errors. */
	int err;
};

static int load_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		   void *param)
{
	struct load_ctx *ctx = param;
	ssize_t n;
	int err = 0;

	if (strcmp(key, "id") == 0) {
		if (len != RET_PRVKEY_LEN) {
			LOG_ERR("stored identity has length %zu, want %d", len, RET_PRVKEY_LEN);
			err = -EINVAL;
		} else {
			n = read_cb(cb_arg, ctx->prv, RET_PRVKEY_LEN);
			if (n == RET_PRVKEY_LEN) {
				ctx->have_id = true;
			} else {
				err = n < 0 ? (int)n : -EIO;
			}
		}
	} else if (strcmp(key, "aclk") == 0) {
		if (len != sizeof(ctx->aclk)) {
			LOG_ERR("stored announce clock has length %zu", len);
			err = -EINVAL;
		} else {
			n = read_cb(cb_arg, &ctx->aclk, sizeof(ctx->aclk));
			if (n != sizeof(ctx->aclk)) {
				err = n < 0 ? (int)n : -EIO;
			}
		}
	}
	if (err && !ctx->err) {
		ctx->err = err;
	}
	return err;
}

int ret_storage_load(uint8_t prv[RET_PRVKEY_LEN], bool *have_id, uint64_t *aclk)
{
	struct load_ctx ctx = { .prv = prv };
	int err = settings_subsys_init();

	if (err) {
		LOG_ERR("settings init failed: %d", err);
		return err;
	}
	err = settings_load_subtree_direct("ret", load_cb, &ctx);
	if (!err) {
		err = ctx.err;
	}
	if (err) {
		LOG_ERR("loading stored state failed: %d", err);
		ret_wipe(prv, RET_PRVKEY_LEN);
		return err;
	}
	*have_id = ctx.have_id;
	*aclk = ctx.aclk;
	return 0;
}

int ret_storage_save_identity(const uint8_t prv[RET_PRVKEY_LEN])
{
	int err = settings_save_one("ret/id", prv, RET_PRVKEY_LEN);

	if (err) {
		LOG_ERR("saving identity failed: %d", err);
	}
	return err;
}

int ret_storage_save_aclk(uint64_t aclk)
{
	int err = settings_save_one("ret/aclk", &aclk, sizeof(aclk));

	if (err) {
		LOG_ERR("saving announce clock failed: %d", err);
	}
	return err;
}

#define SEEN_RECORD_LEN (RET_LXMF_SEEN_HASH_LEN + sizeof(double))

/* Keys seen under ret/lx/, to delete them all on a reset. */
#define SEEN_KEYS_MAX (CONFIG_RET_LXMF_SEEN_ENTRIES + 8)

struct seen_ctx {
	struct ret_lxmf_seen *s;
	int err;
	char keys[SEEN_KEYS_MAX][16];
	size_t n_keys;
	bool keys_overflow;
};

static int seen_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		   void *param)
{
	struct seen_ctx *ctx = param;
	uint8_t rec[SEEN_RECORD_LEN];
	double ts;
	ssize_t n;
	int err = 0;

	if (ctx->n_keys < SEEN_KEYS_MAX && strlen(key) < sizeof(ctx->keys[0])) {
		strcpy(ctx->keys[ctx->n_keys++], key);
	} else {
		ctx->keys_overflow = true;
	}

	if (strcmp(key, "f") == 0) {
		n = len == sizeof(ts) ? read_cb(cb_arg, &ts, sizeof(ts)) : -EINVAL;
		if (n != sizeof(ts)) {
			err = n < 0 ? (int)n : -EIO;
		} else if (!isfinite(ts)) {
			err = -EINVAL;
		} else {
			ctx->s->floor = MAX(ctx->s->floor, ts);
		}
	} else if (strncmp(key, "s/", 2) == 0) {
		char *end;
		unsigned long slot = strtoul(&key[2], &end, 10);
		bool digits = key[2] >= '0' && key[2] <= '9' && strlen(&key[2]) <= 5;

		n = (digits && *end == '\0' && len == sizeof(rec))
			    ? read_cb(cb_arg, rec, sizeof(rec))
			    : -EINVAL;
		if (n != sizeof(rec)) {
			err = n < 0 ? (int)n : -EIO;
		} else if (memcpy(&ts, &rec[RET_LXMF_SEEN_HASH_LEN], sizeof(ts)), !isfinite(ts)) {
			err = -EINVAL;
		} else {
			if (slot < ctx->s->count) {
				struct ret_lxmf_seen_entry *e = &ctx->s->entries[slot];

				memcpy(e->hash, rec, RET_LXMF_SEEN_HASH_LEN);
				e->timestamp = ts;
				e->used = true;
			} else {
				ctx->s->floor = MAX(ctx->s->floor, ts);
			}
		}
	}
	if (err) {
		LOG_ERR("stored LXMF record %s unreadable: %d", key, err);
		if (!ctx->err) {
			ctx->err = err;
		}
	}
	return err;
}

int ret_storage_load_lxmf_seen(struct ret_lxmf_seen *s)
{
	/* static: the key list is too big for the caller's stack. */
	static struct seen_ctx ctx;
	char name[32];
	int err;

	memset(&ctx, 0, sizeof(ctx));
	ctx.s = s;

	memset(s->entries, 0, s->count * sizeof(s->entries[0]));
	s->floor = 0;
	err = settings_load_subtree_direct("ret/lx", seen_cb, &ctx);
	if (!err) {
		err = ctx.err;
	}
	if (err) {
		/* Unlike the identity, this table is expendable: start it over.
		 * Until it fills again, a replay of an earlier message is not
		 * recognised.
		 */
		LOG_ERR("LXMF replay table unreadable (%d): resetting it", err);
		memset(s->entries, 0, s->count * sizeof(s->entries[0]));
		s->floor = 0;
		err = 0;
		/* Deleted after the load, not while the backend iterates. */
		for (size_t i = 0; i < ctx.n_keys && !err; i++) {
			snprintf(name, sizeof(name), "ret/lx/%s", ctx.keys[i]);
			err = settings_delete(name);
		}
		if (!err && ctx.keys_overflow) {
			LOG_WRN("more ret/lx records than expected; some remain");
		}
		if (err) {
			/* Starts empty in RAM regardless; the reset is tried
			 * again next boot.
			 */
			LOG_ERR("resetting the LXMF replay table failed: %d", err);
			err = 0;
		}
	}
	return err;
}

int ret_storage_save_lxmf_seen(const struct ret_lxmf_seen *s, size_t slot, bool floor)
{
	uint8_t rec[SEEN_RECORD_LEN];
	char key[24];
	int err;

	memcpy(rec, s->entries[slot].hash, RET_LXMF_SEEN_HASH_LEN);
	memcpy(&rec[RET_LXMF_SEEN_HASH_LEN], &s->entries[slot].timestamp, sizeof(double));
	/* The floor first: the slot overwrites the entry it replaces, which
	 * must stay refused if we stop in between.
	 */
	err = floor ? settings_save_one("ret/lx/f", &s->floor, sizeof(s->floor)) : 0;
	if (!err) {
		snprintf(key, sizeof(key), "ret/lx/s/%u", (unsigned int)slot);
		err = settings_save_one(key, rec, sizeof(rec));
	}
	if (err) {
		/* Still remembered in RAM until the next boot. */
		LOG_ERR("saving LXMF replay state failed: %d", err);
	}
	return err;
}

/* --- Known LXMF senders ------------------------------------------------ */

#define KNOWN_RECORD_LEN (RET_TRUNC_HASH_LEN + RET_PUBKEY_LEN + sizeof(uint32_t))

struct known_ctx {
	struct ret_storage_known *out;
	size_t count;
	int err;
	char keys[CONFIG_RET_LXMF_KNOWN_SENDERS + 8][8];
	size_t n_keys;
};

static int known_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		    void *param)
{
	struct known_ctx *ctx = param;
	uint8_t rec[KNOWN_RECORD_LEN];
	char *end;
	unsigned long slot = strtoul(key, &end, 10);
	bool digits = key[0] >= '0' && key[0] <= '9' && strlen(key) <= 5 && *end == '\0';
	ssize_t n;
	int err = 0;

	if (ctx->n_keys < ARRAY_SIZE(ctx->keys) && strlen(key) < sizeof(ctx->keys[0])) {
		strcpy(ctx->keys[ctx->n_keys++], key);
	}
	n = (digits && len == sizeof(rec)) ? read_cb(cb_arg, rec, sizeof(rec)) : -EINVAL;
	if (n != sizeof(rec)) {
		err = n < 0 ? (int)n : -EIO;
	} else if (slot < ctx->count) {
		struct ret_storage_known *k = &ctx->out[slot];

		memcpy(k->dest, rec, RET_TRUNC_HASH_LEN);
		memcpy(k->pub, &rec[RET_TRUNC_HASH_LEN], RET_PUBKEY_LEN);
		memcpy(&k->seq, &rec[RET_TRUNC_HASH_LEN + RET_PUBKEY_LEN], sizeof(k->seq));
	} /* beyond a shrunken table: dropped */
	if (err && !ctx->err) {
		LOG_ERR("stored LXMF sender %s unreadable: %d", key, err);
		ctx->err = err;
	}
	return err;
}

int ret_storage_load_known(struct ret_storage_known *out, size_t count)
{
	static struct known_ctx ctx;
	char name[24];
	int err;

	memset(out, 0, count * sizeof(out[0]));
	memset(&ctx, 0, sizeof(ctx));
	ctx.out = out;
	ctx.count = count;
	err = settings_load_subtree_direct("ret/lk", known_cb, &ctx);
	if (!err) {
		err = ctx.err;
	}
	if (err) {
		/* Expendable: those senders verify again once they announce. */
		LOG_ERR("LXMF sender keys unreadable (%d): resetting them", err);
		memset(out, 0, count * sizeof(out[0]));
		err = 0;
		for (size_t i = 0; i < ctx.n_keys && !err; i++) {
			snprintf(name, sizeof(name), "ret/lk/%s", ctx.keys[i]);
			err = settings_delete(name);
		}
		if (err) {
			LOG_ERR("resetting the LXMF sender keys failed: %d", err);
			err = 0;
		}
	}
	return err;
}

int ret_storage_save_known(size_t slot, const struct ret_storage_known *k)
{
	uint8_t rec[KNOWN_RECORD_LEN];
	char key[24];
	int err;

	memcpy(rec, k->dest, RET_TRUNC_HASH_LEN);
	memcpy(&rec[RET_TRUNC_HASH_LEN], k->pub, RET_PUBKEY_LEN);
	memcpy(&rec[RET_TRUNC_HASH_LEN + RET_PUBKEY_LEN], &k->seq, sizeof(k->seq));
	snprintf(key, sizeof(key), "ret/lk/%u", (unsigned int)slot);
	err = settings_save_one(key, rec, sizeof(rec));
	if (err) {
		LOG_ERR("saving an LXMF sender key failed: %d", err);
	}
	return err;
}
