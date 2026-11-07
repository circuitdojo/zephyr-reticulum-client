/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include "ret_crypto.h"

int ret_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
		    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len)
{
	static const uint8_t zero_salt[RET_SHA256_LEN];
	uint8_t prk[RET_SHA256_LEN];
	uint8_t block[RET_SHA256_LEN];
	size_t block_len = 0;
	size_t produced = 0;
	int err;

	if (out_len == 0 || out_len > 255 * RET_SHA256_LEN || ikm_len == 0) {
		return -EINVAL;
	}
	if (salt == NULL || salt_len == 0) {
		salt = zero_salt;
		salt_len = sizeof(zero_salt);
	}

	const struct ret_iov extract[] = { { ikm, ikm_len } };

	err = ret_hmac_sha256(salt, salt_len, extract, 1, prk);
	if (err) {
		return err;
	}

	for (uint8_t counter = 1; produced < out_len; counter++) {
		const struct ret_iov expand[] = {
			{ block, block_len },
			{ info, info != NULL ? info_len : 0 },
			{ &counter, 1 },
		};
		size_t n;

		err = ret_hmac_sha256(prk, sizeof(prk), expand, 3, block);
		if (err) {
			break;
		}
		block_len = sizeof(block);
		n = (out_len - produced < sizeof(block) ? out_len - produced : sizeof(block));
		memcpy(&out[produced], block, n);
		produced += n;
	}

	ret_wipe(prk, sizeof(prk));
	ret_wipe(block, sizeof(block));
	return err;
}

size_t ret_pkcs7_pad(uint8_t *buf, size_t len)
{
	size_t padded = ret_pkcs7_padded_len(len);
	uint8_t pad = (uint8_t)(padded - len);

	memset(&buf[len], pad, pad);
	return padded;
}

int ret_pkcs7_unpad(const uint8_t *buf, size_t len)
{
	uint8_t pad;

	if (len == 0 || len % RET_AES_BLOCK_LEN != 0) {
		return -EBADMSG;
	}
	pad = buf[len - 1];
	if (pad == 0 || pad > RET_AES_BLOCK_LEN) {
		return -EBADMSG;
	}
	for (size_t i = len - pad; i < len; i++) {
		if (buf[i] != pad) {
			return -EBADMSG;
		}
	}
	return (int)(len - pad);
}

bool ret_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
	uint8_t diff = 0;

	for (size_t i = 0; i < len; i++) {
		diff |= a[i] ^ b[i];
	}
	return diff == 0;
}
