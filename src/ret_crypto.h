/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Crypto primitives used by the Reticulum protocol. Backends implement
 * the hash/MAC/cipher/curve/RNG functions; HKDF and PKCS7 are built on
 * top of them once in ret_crypto_common.c.
 */

#ifndef RET_CRYPTO_H_
#define RET_CRYPTO_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RET_SHA256_LEN     32
#define RET_AES_BLOCK_LEN  16
#define RET_AES256_KEY_LEN 32
#define RET_X25519_LEN     32
#define RET_ED25519_PUB_LEN 32
#define RET_ED25519_SIG_LEN 64

struct ret_iov {
	const void *base;
	size_t len;
};

/** Initialise the backend. Idempotent. */
int ret_crypto_init(void);

int ret_sha256(const struct ret_iov *iov, size_t iov_cnt, uint8_t out[RET_SHA256_LEN]);

int ret_hmac_sha256(const uint8_t *key, size_t key_len, const struct ret_iov *iov,
		    size_t iov_cnt, uint8_t out[RET_SHA256_LEN]);

/** RFC 5869 HKDF-SHA256. An empty salt means HashLen zero bytes. */
int ret_hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *salt, size_t salt_len,
		    const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/** AES-256-CBC without padding. @p len must be a multiple of 16. */
int ret_aes256_cbc_encrypt(const uint8_t key[RET_AES256_KEY_LEN],
			   const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *in, size_t len,
			   uint8_t *out);
int ret_aes256_cbc_decrypt(const uint8_t key[RET_AES256_KEY_LEN],
			   const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *in, size_t len,
			   uint8_t *out);

/**
 * Apply PKCS7 padding in place. @p buf must have room for
 * ret_pkcs7_padded_len(@p len) bytes.
 *
 * @return padded length
 */
size_t ret_pkcs7_pad(uint8_t *buf, size_t len);

static inline size_t ret_pkcs7_padded_len(size_t len)
{
	return (len / RET_AES_BLOCK_LEN + 1) * RET_AES_BLOCK_LEN;
}

/** @return unpadded length, or -EBADMSG if the padding is malformed. */
int ret_pkcs7_unpad(const uint8_t *buf, size_t len);

void ret_x25519_public_key(uint8_t pub[RET_X25519_LEN], const uint8_t prv[RET_X25519_LEN]);

/**
 * X25519 key agreement.
 *
 * @retval -EINVAL if the shared secret is all zero (low-order peer key),
 *         which the Python cryptography backend also rejects.
 */
int ret_x25519(uint8_t shared[RET_X25519_LEN], const uint8_t prv[RET_X25519_LEN],
	       const uint8_t pub[RET_X25519_LEN]);

/** Derive the 64-byte signing key and public key from a 32-byte seed. */
void ret_ed25519_key_pair(uint8_t secret_key[64], uint8_t pub[RET_ED25519_PUB_LEN],
			  const uint8_t seed[32]);

/** RFC 8032 Ed25519 signature (deterministic). */
void ret_ed25519_sign(uint8_t sig[RET_ED25519_SIG_LEN], const uint8_t secret_key[64],
		      const uint8_t *msg, size_t len);

/** RFC 8032 Ed25519 (SHA-512) signature check. */
bool ret_ed25519_verify(const uint8_t sig[RET_ED25519_SIG_LEN],
			const uint8_t pub[RET_ED25519_PUB_LEN], const uint8_t *msg, size_t len);

int ret_random(uint8_t *buf, size_t len);

/** Zero a secret in a way the compiler will not elide. */
void ret_wipe(void *buf, size_t len);

/** Constant-time comparison. */
bool ret_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* RET_CRYPTO_H_ */
