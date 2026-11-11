/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * Crypto backend: PSA Crypto API for SHA-256, HMAC and AES (mbedTLS on
 * vanilla Zephyr, nrf_security on NCS), Monocypher for X25519 and
 * Ed25519, Zephyr's CSPRNG for randomness.
 */

#include <errno.h>
#include <string.h>

#include <psa/crypto.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/random.h>

#include <monocypher.h>
#include <monocypher-ed25519.h>

#include "ret_crypto.h"

LOG_MODULE_DECLARE(ret, CONFIG_RET_LOG_LEVEL);

static int psa_to_errno(psa_status_t st)
{
	switch (st) {
	case PSA_SUCCESS:
		return 0;
	case PSA_ERROR_INSUFFICIENT_MEMORY:
		return -ENOMEM;
	case PSA_ERROR_INVALID_ARGUMENT:
		return -EINVAL;
	case PSA_ERROR_NOT_SUPPORTED:
		return -ENOTSUP;
	case PSA_ERROR_BUFFER_TOO_SMALL:
		return -ENOBUFS;
	default:
		return -EIO;
	}
}

int ret_crypto_init(void)
{
	psa_status_t st = psa_crypto_init();

	if (st != PSA_SUCCESS) {
		LOG_ERR("psa_crypto_init failed: %d", (int)st);
	}
	return psa_to_errno(st);
}

int ret_sha256(const struct ret_iov *iov, size_t iov_cnt, uint8_t out[RET_SHA256_LEN])
{
	psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
	psa_status_t st;
	size_t out_len;

	st = psa_hash_setup(&op, PSA_ALG_SHA_256);
	for (size_t i = 0; st == PSA_SUCCESS && i < iov_cnt; i++) {
		if (iov[i].len > 0) {
			st = psa_hash_update(&op, iov[i].base, iov[i].len);
		}
	}
	if (st == PSA_SUCCESS) {
		st = psa_hash_finish(&op, out, RET_SHA256_LEN, &out_len);
	}
	if (st != PSA_SUCCESS) {
		psa_hash_abort(&op);
	}
	return psa_to_errno(st);
}

static psa_status_t import_key(psa_key_type_t type, psa_algorithm_t alg, psa_key_usage_t usage,
			       const uint8_t *key, size_t key_len, psa_key_id_t *id)
{
	psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

	psa_set_key_type(&attr, type);
	psa_set_key_algorithm(&attr, alg);
	psa_set_key_usage_flags(&attr, usage);
	psa_set_key_lifetime(&attr, PSA_KEY_LIFETIME_VOLATILE);
	return psa_import_key(&attr, key, key_len, id);
}

int ret_hmac_sha256(const uint8_t *key, size_t key_len, const struct ret_iov *iov,
		    size_t iov_cnt, uint8_t out[RET_SHA256_LEN])
{
	psa_mac_operation_t op = PSA_MAC_OPERATION_INIT;
	psa_key_id_t id = PSA_KEY_ID_NULL;
	psa_status_t st;
	size_t out_len;

	st = import_key(PSA_KEY_TYPE_HMAC, PSA_ALG_HMAC(PSA_ALG_SHA_256),
			PSA_KEY_USAGE_SIGN_MESSAGE, key, key_len, &id);
	if (st == PSA_SUCCESS) {
		st = psa_mac_sign_setup(&op, id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
	}
	for (size_t i = 0; st == PSA_SUCCESS && i < iov_cnt; i++) {
		if (iov[i].len > 0) {
			st = psa_mac_update(&op, iov[i].base, iov[i].len);
		}
	}
	if (st == PSA_SUCCESS) {
		st = psa_mac_sign_finish(&op, out, RET_SHA256_LEN, &out_len);
	}
	if (st != PSA_SUCCESS) {
		psa_mac_abort(&op);
	}
	if (id != PSA_KEY_ID_NULL) {
		psa_destroy_key(id);
	}
	return psa_to_errno(st);
}

static int aes_cbc(bool encrypt, const uint8_t key[RET_AES256_KEY_LEN],
		   const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *in, size_t len,
		   uint8_t *out)
{
	psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
	psa_key_id_t id = PSA_KEY_ID_NULL;
	psa_status_t st;
	size_t n = 0;
	size_t fin = 0;

	if (len % RET_AES_BLOCK_LEN != 0) {
		return -EINVAL;
	}

	st = import_key(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING,
			encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT, key,
			RET_AES256_KEY_LEN, &id);
	if (st == PSA_SUCCESS) {
		st = encrypt ? psa_cipher_encrypt_setup(&op, id, PSA_ALG_CBC_NO_PADDING)
			     : psa_cipher_decrypt_setup(&op, id, PSA_ALG_CBC_NO_PADDING);
	}
	if (st == PSA_SUCCESS) {
		st = psa_cipher_set_iv(&op, iv, RET_AES_BLOCK_LEN);
	}
	if (st == PSA_SUCCESS) {
		st = psa_cipher_update(&op, in, len, out, len, &n);
	}
	if (st == PSA_SUCCESS) {
		st = psa_cipher_finish(&op, out + n, len - n, &fin);
	}
	if (st == PSA_SUCCESS && n + fin != len) {
		st = PSA_ERROR_GENERIC_ERROR;
	}
	if (st != PSA_SUCCESS) {
		psa_cipher_abort(&op);
	}
	if (id != PSA_KEY_ID_NULL) {
		psa_destroy_key(id);
	}
	return psa_to_errno(st);
}

int ret_aes256_cbc_encrypt(const uint8_t key[RET_AES256_KEY_LEN],
			   const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *in, size_t len,
			   uint8_t *out)
{
	return aes_cbc(true, key, iv, in, len, out);
}

int ret_aes256_cbc_decrypt(const uint8_t key[RET_AES256_KEY_LEN],
			   const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *in, size_t len,
			   uint8_t *out)
{
	return aes_cbc(false, key, iv, in, len, out);
}

void ret_x25519_public_key(uint8_t pub[RET_X25519_LEN], const uint8_t prv[RET_X25519_LEN])
{
	crypto_x25519_public_key(pub, prv);
}

int ret_x25519(uint8_t shared[RET_X25519_LEN], const uint8_t prv[RET_X25519_LEN],
	       const uint8_t pub[RET_X25519_LEN])
{
	static const uint8_t zero[RET_X25519_LEN];

	crypto_x25519(shared, prv, pub);
	if (ret_ct_equal(shared, zero, RET_X25519_LEN)) {
		ret_wipe(shared, RET_X25519_LEN);
		return -EINVAL;
	}
	return 0;
}

void ret_ed25519_key_pair(uint8_t secret_key[64], uint8_t pub[RET_ED25519_PUB_LEN],
			  const uint8_t seed[32])
{
	uint8_t seed_copy[32];

	/* Monocypher wipes the seed it is given. */
	memcpy(seed_copy, seed, sizeof(seed_copy));
	crypto_ed25519_key_pair(secret_key, pub, seed_copy);
}

/* SHA-512 over a prefix and @p iov, reduced mod L (Monocypher's hash_reduce). */
static void hash_reduce_iov(uint8_t out[32], const uint8_t *a, size_t a_len, const uint8_t *b,
			    size_t b_len, const struct ret_iov *iov, size_t iov_cnt)
{
	uint8_t hash[64];
	crypto_sha512_ctx ctx;

	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, a, a_len);
	crypto_sha512_update(&ctx, b, b_len);
	for (size_t i = 0; i < iov_cnt; i++) {
		crypto_sha512_update(&ctx, iov[i].base, iov[i].len);
	}
	crypto_sha512_final(&ctx, hash);
	crypto_eddsa_reduce(out, hash);
	crypto_wipe(hash, sizeof(hash));
	crypto_wipe(&ctx, sizeof(ctx));
}

void ret_ed25519_sign_iov(uint8_t sig[RET_ED25519_SIG_LEN], const uint8_t secret_key[64],
			  const struct ret_iov *iov, size_t iov_cnt)
{
	/* RFC 8032, as crypto_ed25519_sign (ed25519_dom_sign without a
	 * domain), over a message in pieces.
	 */
	uint8_t a[64]; /* secret scalar | prefix */
	uint8_t r[32]; /* deterministic nonce */
	uint8_t h[32];
	uint8_t big_r[32];
	const uint8_t *pk = secret_key + 32;

	crypto_sha512(a, secret_key, 32);
	crypto_eddsa_trim_scalar(a, a);
	hash_reduce_iov(r, a + 32, 32, NULL, 0, iov, iov_cnt);
	crypto_eddsa_scalarbase(big_r, r);
	hash_reduce_iov(h, big_r, 32, pk, 32, iov, iov_cnt);
	memcpy(sig, big_r, 32);
	crypto_eddsa_mul_add(sig + 32, h, a, r);
	crypto_wipe(a, sizeof(a));
	crypto_wipe(r, sizeof(r));
}

void ret_ed25519_sign(uint8_t sig[RET_ED25519_SIG_LEN], const uint8_t secret_key[64],
		      const uint8_t *msg, size_t len)
{
	const struct ret_iov iov = { msg, len };

	ret_ed25519_sign_iov(sig, secret_key, &iov, 1);
}

bool ret_ed25519_verify_iov(const uint8_t sig[RET_ED25519_SIG_LEN],
			    const uint8_t pub[RET_ED25519_PUB_LEN], const struct ret_iov *iov,
			    size_t iov_cnt)
{
	uint8_t h_ram[32];

	hash_reduce_iov(h_ram, sig, 32, pub, 32, iov, iov_cnt);
	return crypto_eddsa_check_equation(sig, pub, h_ram) == 0;
}

bool ret_ed25519_verify(const uint8_t sig[RET_ED25519_SIG_LEN],
			const uint8_t pub[RET_ED25519_PUB_LEN], const uint8_t *msg, size_t len)
{
	const struct ret_iov iov = { msg, len };

	return ret_ed25519_verify_iov(sig, pub, &iov, 1);
}

int ret_random(uint8_t *buf, size_t len)
{
	return sys_csrand_get(buf, len);
}

void ret_wipe(void *buf, size_t len)
{
	crypto_wipe(buf, len);
}
