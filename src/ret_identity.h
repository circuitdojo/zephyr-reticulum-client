/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Identity and destination hashing, and encryption to a SINGLE
 * destination (RNS/Identity.py, RNS/Cryptography/Token.py).
 */

#ifndef RET_IDENTITY_H_
#define RET_IDENTITY_H_

#include <stddef.h>
#include <stdint.h>

#include "ret_crypto.h"
#include "ret_packet.h"

#define RET_NAME_HASH_LEN   10
#define RET_RANDOM_HASH_LEN 10
#define RET_PUBKEY_LEN      64 /* X25519 pub[32] || Ed25519 pub[32] */
#define RET_RATCHET_LEN     32
#define RET_SIG_LEN         64

/** Ephemeral pub + IV + HMAC around the padded ciphertext. */
#define RET_TOKEN_OVERHEAD (RET_X25519_LEN + RET_AES_BLOCK_LEN + RET_SHA256_LEN)
#define RET_TOKEN_LEN(pt_len) (RET_TOKEN_OVERHEAD + ret_pkcs7_padded_len(pt_len))

/** Largest plaintext for one encrypted packet (RNS Packet.ENCRYPTED_MDU). */
#define RET_ENCRYPTED_MDU 383

int ret_name_hash(const char *full_name, uint8_t out[RET_NAME_HASH_LEN]);
int ret_identity_hash(const uint8_t pub[RET_PUBKEY_LEN], uint8_t out[RET_TRUNC_HASH_LEN]);
int ret_dest_hash(const uint8_t name_hash[RET_NAME_HASH_LEN],
		  const uint8_t identity_hash[RET_TRUNC_HASH_LEN],
		  uint8_t out[RET_TRUNC_HASH_LEN]);

/**
 * Encrypt @p pt for a destination: ephemeral X25519 against
 * @p target_pub (the announced ratchet if any, otherwise the identity's
 * X25519 key), HKDF-SHA256 salted with @p identity_hash to 64 bytes,
 * then AES-256-CBC + HMAC-SHA256.
 *
 * @return token length, or a negative errno.
 */
int ret_identity_encrypt(const uint8_t target_pub[RET_X25519_LEN],
			 const uint8_t identity_hash[RET_TRUNC_HASH_LEN], const uint8_t *pt,
			 size_t pt_len, uint8_t *out, size_t out_cap);

/** As ret_identity_encrypt() with caller-supplied randomness (tests). */
int ret_identity_encrypt_det(const uint8_t target_pub[RET_X25519_LEN],
			     const uint8_t identity_hash[RET_TRUNC_HASH_LEN], const uint8_t *pt,
			     size_t pt_len, const uint8_t eph_prv[RET_X25519_LEN],
			     const uint8_t iv[RET_AES_BLOCK_LEN], uint8_t *out, size_t out_cap);

#endif /* RET_IDENTITY_H_ */
