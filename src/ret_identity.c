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

int ret_token_encrypt_det(const uint8_t key[RET_TOKEN_KEY_LEN],
			  const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *pt, size_t pt_len,
			  uint8_t *out, size_t out_cap)
{
	const uint8_t *signing_key = &key[0];
	const uint8_t *enc_key = &key[32];
	size_t padded = ret_pkcs7_padded_len(pt_len);
	size_t total = RET_TOKEN_BODY_LEN(pt_len);
	uint8_t *iv_out = out;
	uint8_t *ct = iv_out + RET_AES_BLOCK_LEN;
	uint8_t *mac = ct + padded;
	int err;

	if (out_cap < total) {
		return -ENOBUFS;
	}

	memcpy(iv_out, iv, RET_AES_BLOCK_LEN);
	memmove(ct, pt, pt_len);
	ret_pkcs7_pad(ct, pt_len);
	err = ret_aes256_cbc_encrypt(enc_key, iv_out, ct, padded, ct);
	if (err) {
		return err;
	}

	const struct ret_iov signed_parts[] = { { iv_out, RET_AES_BLOCK_LEN + padded } };

	err = ret_hmac_sha256(signing_key, 32, signed_parts, 1, mac);
	return err ? err : (int)total;
}

int ret_token_encrypt(const uint8_t key[RET_TOKEN_KEY_LEN], const uint8_t *pt, size_t pt_len,
		      uint8_t *out, size_t out_cap)
{
	uint8_t iv[RET_AES_BLOCK_LEN];
	int err = ret_random(iv, sizeof(iv));

	return err ? err : ret_token_encrypt_det(key, iv, pt, pt_len, out, out_cap);
}

int ret_token_decrypt(const uint8_t key[RET_TOKEN_KEY_LEN], const uint8_t *token, size_t len,
		      uint8_t *out, size_t out_cap)
{
	const uint8_t *iv = token;
	const uint8_t *ct = iv + RET_AES_BLOCK_LEN;
	uint8_t mac[RET_SHA256_LEN];
	size_t ct_len;
	int err;

	if (len < RET_AES_BLOCK_LEN + RET_AES_BLOCK_LEN + RET_SHA256_LEN) {
		return -EBADMSG;
	}
	ct_len = len - RET_AES_BLOCK_LEN - RET_SHA256_LEN;
	if (ct_len % RET_AES_BLOCK_LEN != 0) {
		return -EBADMSG;
	}
	if (out_cap < ct_len) {
		return -ENOBUFS;
	}

	/* Authenticate before decrypting (Token.decrypt verifies first). */
	const struct ret_iov signed_parts[] = { { iv, RET_AES_BLOCK_LEN + ct_len } };

	err = ret_hmac_sha256(&key[0], 32, signed_parts, 1, mac);
	if (err) {
		return err;
	}
	if (!ret_ct_equal(mac, &token[len - RET_SHA256_LEN], RET_SHA256_LEN)) {
		return -EBADMSG;
	}

	err = ret_aes256_cbc_decrypt(&key[32], iv, ct, ct_len, out);
	if (err) {
		return err;
	}
	err = ret_pkcs7_unpad(out, ct_len);
	if (err < 0) {
		ret_wipe(out, ct_len);
	}
	return err;
}

int ret_identity_encrypt_det(const uint8_t target_pub[RET_X25519_LEN],
			     const uint8_t identity_hash[RET_TRUNC_HASH_LEN], const uint8_t *pt,
			     size_t pt_len, const uint8_t eph_prv[RET_X25519_LEN],
			     const uint8_t iv[RET_AES_BLOCK_LEN], uint8_t *out, size_t out_cap)
{
	uint8_t shared[RET_X25519_LEN];
	uint8_t derived[RET_TOKEN_KEY_LEN];
	int err;
	int n;

	if (out_cap < RET_X25519_LEN + RET_TOKEN_BODY_LEN(pt_len)) {
		return -ENOBUFS;
	}

	ret_x25519_public_key(out, eph_prv);
	err = ret_x25519(shared, eph_prv, target_pub);
	if (err) {
		return err;
	}
	err = ret_hkdf_sha256(shared, sizeof(shared), identity_hash, RET_TRUNC_HASH_LEN, NULL, 0,
			      derived, sizeof(derived));
	ret_wipe(shared, sizeof(shared));
	if (err) {
		ret_wipe(derived, sizeof(derived));
		return err;
	}

	n = ret_token_encrypt_det(derived, iv, pt, pt_len, out + RET_X25519_LEN,
				  out_cap - RET_X25519_LEN);
	ret_wipe(derived, sizeof(derived));
	return n < 0 ? n : RET_X25519_LEN + n;
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

int ret_local_identity_load(struct ret_local_identity *id, const uint8_t prv[RET_PRVKEY_LEN])
{
	memcpy(id->x25519_prv, prv, RET_X25519_LEN);
	ret_x25519_public_key(id->pub, id->x25519_prv);
	ret_ed25519_key_pair(id->ed25519_sk, &id->pub[RET_X25519_LEN], &prv[RET_X25519_LEN]);
	return ret_identity_hash(id->pub, id->hash);
}

int ret_local_identity_generate(struct ret_local_identity *id, uint8_t prv_out[RET_PRVKEY_LEN])
{
	int err = ret_random(prv_out, RET_PRVKEY_LEN);

	return err ? err : ret_local_identity_load(id, prv_out);
}

void ret_local_identity_sign(const struct ret_local_identity *id, const uint8_t *msg,
			     size_t len, uint8_t sig[RET_SIG_LEN])
{
	ret_ed25519_sign(sig, id->ed25519_sk, msg, len);
}

/* SINGLE decryption with one X25519 private key; the salt is always the
 * identity hash, ratchet or not.
 */
static int decrypt_with(const uint8_t prv[RET_X25519_LEN], const uint8_t salt[RET_TRUNC_HASH_LEN],
			const uint8_t *token, size_t len, uint8_t *out, size_t out_cap)
{
	uint8_t shared[RET_X25519_LEN];
	uint8_t derived[RET_TOKEN_KEY_LEN];
	int err;

	err = ret_x25519(shared, prv, token);
	if (err) {
		return -EBADMSG;
	}
	err = ret_hkdf_sha256(shared, sizeof(shared), salt, RET_TRUNC_HASH_LEN, NULL, 0, derived,
			      sizeof(derived));
	ret_wipe(shared, sizeof(shared));
	if (!err) {
		err = ret_token_decrypt(derived, token + RET_X25519_LEN, len - RET_X25519_LEN, out,
					out_cap);
	}
	ret_wipe(derived, sizeof(derived));
	return err;
}

static int check_token(size_t len, size_t out_cap)
{
	if (len < RET_TOKEN_OVERHEAD + RET_AES_BLOCK_LEN) {
		return -EBADMSG;
	}
	if ((len - RET_TOKEN_OVERHEAD) % RET_AES_BLOCK_LEN != 0) {
		return -EBADMSG;
	}
	if (out_cap < len - RET_TOKEN_OVERHEAD) {
		return -ENOBUFS;
	}
	return 0;
}

int ret_local_identity_decrypt(const struct ret_local_identity *id, const uint8_t *token,
			       size_t len, uint8_t *out, size_t out_cap)
{
	int err = check_token(len, out_cap);

	return err ? err : decrypt_with(id->x25519_prv, id->hash, token, len, out, out_cap);
}

int ret_local_identity_decrypt_ratchets(const struct ret_local_identity *id,
					const uint8_t *const *ratchets,
					size_t n_ratchets, const uint8_t *token, size_t len,
					uint8_t *out, size_t out_cap, int *used)
{
	int err = check_token(len, out_cap);

	if (err) {
		return err;
	}
	/* The HMAC is checked before anything is decrypted, so a wrong key
	 * leaves @p out untouched.
	 */
	for (size_t i = 0; i < n_ratchets; i++) {
		err = decrypt_with(ratchets[i], id->hash, token, len, out, out_cap);
		if (err >= 0) {
			*used = (int)i;
		}
		if (err != -EBADMSG) {
			return err;
		}
	}
	err = decrypt_with(id->x25519_prv, id->hash, token, len, out, out_cap);
	if (err >= 0) {
		*used = -1;
	}
	return err;
}

int ret_ratchet_id(const uint8_t pub[RET_RATCHET_LEN], uint8_t out[RET_RATCHET_ID_LEN])
{
	uint8_t full[RET_SHA256_LEN];
	struct ret_iov iov = { pub, RET_RATCHET_LEN };
	int err = ret_sha256(&iov, 1, full);

	if (!err) {
		memcpy(out, full, RET_RATCHET_ID_LEN);
	}
	return err;
}
