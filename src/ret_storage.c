/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>
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
