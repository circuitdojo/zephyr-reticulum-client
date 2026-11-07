/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/logging/log.h>

#include "ret_identity.h"

LOG_MODULE_REGISTER(ret, CONFIG_RET_LOG_LEVEL);

int ret_name_hash(const char *full_name, uint8_t out[RET_NAME_HASH_LEN])
{
	uint8_t h[RET_SHA256_LEN];
	const struct ret_iov iov[] = { { full_name, strlen(full_name) } };
	int err = ret_sha256(iov, 1, h);

	if (!err) {
		memcpy(out, h, RET_NAME_HASH_LEN);
	}
	return err;
}

int ret_identity_hash(const uint8_t pub[RET_PUBKEY_LEN], uint8_t out[RET_TRUNC_HASH_LEN])
{
	uint8_t h[RET_SHA256_LEN];
	const struct ret_iov iov[] = { { pub, RET_PUBKEY_LEN } };
	int err = ret_sha256(iov, 1, h);

	if (!err) {
		memcpy(out, h, RET_TRUNC_HASH_LEN);
	}
	return err;
}

int ret_dest_hash(const uint8_t name_hash[RET_NAME_HASH_LEN],
		  const uint8_t identity_hash[RET_TRUNC_HASH_LEN],
		  uint8_t out[RET_TRUNC_HASH_LEN])
{
	uint8_t h[RET_SHA256_LEN];
	const struct ret_iov iov[] = {
		{ name_hash, RET_NAME_HASH_LEN },
		{ identity_hash, RET_TRUNC_HASH_LEN },
	};
	int err = ret_sha256(iov, 2, h);

	if (!err) {
		memcpy(out, h, RET_TRUNC_HASH_LEN);
	}
	return err;
}

int ret_plain_dest_hash(const char *full_name, uint8_t out[RET_TRUNC_HASH_LEN])
{
	uint8_t nh[RET_NAME_HASH_LEN];
	uint8_t h[RET_SHA256_LEN];
	int err = ret_name_hash(full_name, nh);

	if (!err) {
		const struct ret_iov iov[] = { { nh, sizeof(nh) } };

		err = ret_sha256(iov, 1, h);
	}
	if (!err) {
		memcpy(out, h, RET_TRUNC_HASH_LEN);
	}
	return err;
}

int ret_identity_encrypt_det(const uint8_t target_pub[RET_X25519_LEN],
			     const uint8_t identity_hash[RET_TRUNC_HASH_LEN], const uint8_t *pt,
			     size_t pt_len, const uint8_t eph_prv[RET_X25519_LEN],
			     const uint8_t iv[RET_AES_BLOCK_LEN], uint8_t *out, size_t out_cap)
{
	uint8_t shared[RET_X25519_LEN];
	uint8_t derived[64];
	const uint8_t *signing_key = &derived[0];
	const uint8_t *enc_key = &derived[32];
	size_t padded = ret_pkcs7_padded_len(pt_len);
	size_t total = RET_TOKEN_OVERHEAD + padded;
	uint8_t *eph_pub = out;
	uint8_t *iv_out = out + RET_X25519_LEN;
	uint8_t *ct = iv_out + RET_AES_BLOCK_LEN;
	uint8_t *mac = ct + padded;
	int err;

	if (out_cap < total) {
		return -ENOBUFS;
	}

	ret_x25519_public_key(eph_pub, eph_prv);
	err = ret_x25519(shared, eph_prv, target_pub);
	if (err) {
		return err;
	}

	err = ret_hkdf_sha256(shared, sizeof(shared), identity_hash, RET_TRUNC_HASH_LEN, NULL, 0,
			      derived, sizeof(derived));
	ret_wipe(shared, sizeof(shared));
	if (err) {
		goto out;
	}

	memcpy(iv_out, iv, RET_AES_BLOCK_LEN);
	memmove(ct, pt, pt_len);
	ret_pkcs7_pad(ct, pt_len);
	err = ret_aes256_cbc_encrypt(enc_key, iv_out, ct, padded, ct);
	if (err) {
		goto out;
	}

	const struct ret_iov signed_parts[] = { { iv_out, RET_AES_BLOCK_LEN + padded } };

	err = ret_hmac_sha256(signing_key, 32, signed_parts, 1, mac);

out:
	ret_wipe(derived, sizeof(derived));
	return err ? err : (int)total;
}

int ret_identity_encrypt(const uint8_t target_pub[RET_X25519_LEN],
			 const uint8_t identity_hash[RET_TRUNC_HASH_LEN], const uint8_t *pt,
			 size_t pt_len, uint8_t *out, size_t out_cap)
{
	uint8_t eph_prv[RET_X25519_LEN];
	uint8_t iv[RET_AES_BLOCK_LEN];
	int err;

	err = ret_random(eph_prv, sizeof(eph_prv));
	if (!err) {
		err = ret_random(iv, sizeof(iv));
	}
	if (!err) {
		err = ret_identity_encrypt_det(target_pub, identity_hash, pt, pt_len, eph_prv, iv,
					       out, out_cap);
	}
	ret_wipe(eph_prv, sizeof(eph_prv));
	return err;
}
