/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include "ret_crypto.h"
#include "ret_ifac.h"

/* Reticulum.IFAC_SALT */
static const uint8_t ifac_salt[RET_SHA256_LEN] = {
	0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80, 0x77, 0x1e, 0xb4,
	0x99, 0x5d, 0x70, 0x2d, 0x4a, 0x3e, 0x73, 0x33, 0x91, 0xb2, 0xa0,
	0xf5, 0x3f, 0x41, 0x6d, 0x9f, 0x90, 0x7e, 0x55, 0xcf, 0xf8,
};

int ret_ifac_init(struct ret_ifac *f, const char *netname, const char *passphrase,
		  uint8_t size)
{
	uint8_t origin[2 * RET_SHA256_LEN];
	uint8_t origin_hash[RET_SHA256_LEN];
	size_t n = 0;
	int err = 0;

	if (size < 1 || size > RET_IFAC_MAX_SIZE) {
		return -EINVAL;
	}
	if (netname != NULL && netname[0] != '\0') {
		const struct ret_iov iov = { netname, strlen(netname) };

		err = ret_sha256(&iov, 1, &origin[n]);
		n += RET_SHA256_LEN;
	}
	if (!err && passphrase != NULL && passphrase[0] != '\0') {
		const struct ret_iov iov = { passphrase, strlen(passphrase) };

		err = ret_sha256(&iov, 1, &origin[n]);
		n += RET_SHA256_LEN;
	}
	if (!err && n == 0) {
		err = -EINVAL;
	}
	if (!err) {
		const struct ret_iov iov = { origin, n };

		err = ret_sha256(&iov, 1, origin_hash);
	}
	if (!err) {
		err = ret_hkdf_sha256(origin_hash, sizeof(origin_hash), ifac_salt, sizeof(ifac_salt),
				      NULL, 0, f->key, sizeof(f->key));
	}
	if (!err) {
		err = ret_local_identity_load(&f->id, f->key);
	}
	ret_wipe(origin, sizeof(origin));
	ret_wipe(origin_hash, sizeof(origin_hash));
	if (err) {
		ret_wipe(f, sizeof(*f));
		return err;
	}
	f->size = size;
	return 0;
}

/*
 * The mask: HKDF-SHA256 (ikm = @p code, salt = the interface key, info
 * empty) over @p len bytes, streamed a block at a time to @p fn, so no
 * mask buffer is needed. Callers skip positions [2, 2 + size), the code.
 */
typedef void (*mask_fn)(size_t pos, uint8_t k, void *ctx);

static int mask(const struct ret_ifac *f, const uint8_t *code, size_t len, mask_fn fn, void *ctx)
{
	uint8_t prk[RET_SHA256_LEN];
	uint8_t block[RET_SHA256_LEN];
	size_t block_len = 0;
	size_t pos = 0;
	const struct ret_iov extract = { code, f->size };
	int err = ret_hmac_sha256(f->key, sizeof(f->key), &extract, 1, prk);

	for (uint8_t counter = 1; !err && pos < len; counter++) {
		const struct ret_iov expand[] = {
			{ block, block_len },
			{ &counter, 1 },
		};

		err = ret_hmac_sha256(prk, sizeof(prk), expand, 2, block);
		block_len = sizeof(block);
		for (size_t i = 0; !err && i < sizeof(block) && pos < len; i++, pos++) {
			fn(pos, block[i], ctx);
		}
	}
	ret_wipe(prk, sizeof(prk));
	ret_wipe(block, sizeof(block));
	return err;
}

struct mask_ctx {
	uint8_t *buf; /* the packet as it is laid out without the code */
	size_t size;
};

/* Frame position @p pos maps to packet byte pos (header) or pos - size. */
static void mask_xor(size_t pos, uint8_t k, void *ctx)
{
	struct mask_ctx *m = ctx;

	if (pos < 2) {
		m->buf[pos] ^= k;
	} else if (pos >= 2 + m->size) {
		m->buf[pos - m->size] ^= k;
	}
}

/* As mask_xor(), for the frame itself (code in place). */
static void mask_xor_frame(size_t pos, uint8_t k, void *ctx)
{
	struct mask_ctx *m = ctx;

	if (pos < 2 || pos >= 2 + m->size) {
		m->buf[pos] ^= k;
	}
}

int ret_ifac_apply(const struct ret_ifac *f, const uint8_t *raw, size_t len, uint8_t *out,
		   size_t cap)
{
	uint8_t sig[RET_SIG_LEN];
	size_t n = len + f->size;
	struct mask_ctx m = { .buf = out, .size = f->size };
	int err;

	if (len < 2 || (raw[0] & RET_IFAC_FLAG)) {
		return -EINVAL;
	}
	if (cap < n) {
		return -ENOBUFS;
	}
	ret_local_identity_sign(&f->id, raw, len, sig);

	out[0] = raw[0] | RET_IFAC_FLAG;
	out[1] = raw[1];
	memcpy(&out[2], &sig[RET_SIG_LEN - f->size], f->size);
	memcpy(&out[2 + f->size], &raw[2], len - 2);
	err = mask(f, &out[2], n, mask_xor_frame, &m);
	out[0] |= RET_IFAC_FLAG; /* the flag stays set whatever the mask */
	return err ? err : (int)n;
}

int ret_ifac_strip(const struct ret_ifac *f, const uint8_t *in, size_t len, uint8_t *raw,
		   size_t cap)
{
	uint8_t sig[RET_SIG_LEN];
	uint8_t code[RET_IFAC_MAX_SIZE];
	struct mask_ctx m = { .buf = raw, .size = f->size };
	size_t n;
	int err;

	if (len < 2 + (size_t)f->size + 1 || !(in[0] & RET_IFAC_FLAG)) {
		return -EBADMSG;
	}
	n = len - f->size;
	if (cap < n) {
		return -ENOBUFS;
	}

	/* The packet without the code, then unmasked in place. The code is
	 * copied out first, so @p raw may be @p in.
	 */
	memcpy(code, &in[2], f->size);
	raw[0] = in[0];
	raw[1] = in[1];
	memmove(&raw[2], &in[2 + f->size], n - 2);
	err = mask(f, code, len, mask_xor, &m);
	if (err) {
		return err;
	}
	raw[0] &= (uint8_t)~RET_IFAC_FLAG;

	/* Only the signature's tail travels: check it by signing again. */
	ret_local_identity_sign(&f->id, raw, n, sig);
	if (!ret_ct_equal(&sig[RET_SIG_LEN - f->size], code, f->size)) {
		ret_wipe(raw, n);
		return -EACCES;
	}
	return (int)n;
}
