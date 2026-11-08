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
#define RET_RATCHET_LEN     32 /* X25519 key */
#define RET_RATCHET_ID_LEN  10
#define RET_SIG_LEN         64

/** Token key: HMAC signing key (32) || AES-256 key (32). */
#define RET_TOKEN_KEY_LEN 64

/** A token on its own (link encryption): IV | CBC ciphertext | HMAC. */
#define RET_TOKEN_BODY_LEN(pt_len) \
	(RET_AES_BLOCK_LEN + ((pt_len) / RET_AES_BLOCK_LEN + 1) * RET_AES_BLOCK_LEN + RET_SHA256_LEN)

/** Ephemeral pub + IV + HMAC around the padded ciphertext. */
#define RET_TOKEN_OVERHEAD (RET_X25519_LEN + RET_AES_BLOCK_LEN + RET_SHA256_LEN)
/* Constant expression (usable for static buffers); same as ret_pkcs7_padded_len(). */
#define RET_TOKEN_LEN(pt_len) \
	(RET_TOKEN_OVERHEAD + ((pt_len) / RET_AES_BLOCK_LEN + 1) * RET_AES_BLOCK_LEN)

/** Largest plaintext for one encrypted packet (RNS Packet.ENCRYPTED_MDU). */
#define RET_ENCRYPTED_MDU 383

/** RNS private key layout: X25519 private key || Ed25519 seed. */
#define RET_PRVKEY_LEN 64

/** An identity we hold the private keys for. */
struct ret_local_identity {
	uint8_t x25519_prv[RET_X25519_LEN];
	uint8_t ed25519_sk[64];
	/** X25519 pub || Ed25519 pub, as announced. */
	uint8_t pub[RET_PUBKEY_LEN];
	uint8_t hash[RET_TRUNC_HASH_LEN];
};

/** Load from the 64-byte RNS private key (Identity.get_private_key()). */
int ret_local_identity_load(struct ret_local_identity *id, const uint8_t prv[RET_PRVKEY_LEN]);

/** Generate a new identity; @p prv_out receives its private key to store. */
int ret_local_identity_generate(struct ret_local_identity *id, uint8_t prv_out[RET_PRVKEY_LEN]);

void ret_local_identity_sign(const struct ret_local_identity *id, const uint8_t *msg,
			     size_t len, uint8_t sig[RET_SIG_LEN]);

/**
 * Decrypt a token encrypted to @p id (the inverse of
 * ret_identity_encrypt): ephemeral pub | IV | ciphertext | HMAC.
 *
 * @return plaintext length
 * @retval -EBADMSG malformed token, bad HMAC or bad padding
 */
int ret_local_identity_decrypt(const struct ret_local_identity *id, const uint8_t *token,
			       size_t len, uint8_t *out, size_t out_cap);

/**
 * As ret_local_identity_decrypt(), trying each of @p ratchets (X25519
 * private keys, newest first) before the identity key, as
 * Identity.decrypt() does. A sender that has our announced ratchet
 * encrypts to it; one that has not, to the identity key.
 *
 * @param used set to the index of the ratchet that decrypted the token,
 *             or -1 for the identity key; unchanged on failure
 * @return plaintext length
 * @retval -EBADMSG no key decrypts it
 */
int ret_local_identity_decrypt_ratchets(const struct ret_local_identity *id,
					const uint8_t *const *ratchets,
					size_t n_ratchets, const uint8_t *token, size_t len,
					uint8_t *out, size_t out_cap, int *used);

/** Ratchet id, as RNS logs it: SHA256(ratchet public key)[:10]. */
int ret_ratchet_id(const uint8_t pub[RET_RATCHET_LEN], uint8_t out[RET_RATCHET_ID_LEN]);

int ret_name_hash(const char *full_name, uint8_t out[RET_NAME_HASH_LEN]);
int ret_identity_hash(const uint8_t pub[RET_PUBKEY_LEN], uint8_t out[RET_TRUNC_HASH_LEN]);
int ret_dest_hash(const uint8_t name_hash[RET_NAME_HASH_LEN],
		  const uint8_t identity_hash[RET_TRUNC_HASH_LEN],
		  uint8_t out[RET_TRUNC_HASH_LEN]);

/** Hash of a PLAIN destination (no identity): H(name_hash)[:16]. */
int ret_plain_dest_hash(const char *full_name, uint8_t out[RET_TRUNC_HASH_LEN]);

/**
 * RNS Token (RNS/Cryptography/Token.py) with a 64-byte key: AES-256-CBC
 * with PKCS7, then HMAC-SHA256 over IV | ciphertext. SINGLE encryption is
 * an ephemeral X25519 pub followed by a token; link packets are a token
 * under the link's derived key.
 *
 * @return token length, or a negative errno
 */
int ret_token_encrypt(const uint8_t key[RET_TOKEN_KEY_LEN], const uint8_t *pt, size_t pt_len,
		      uint8_t *out, size_t out_cap);

/** As ret_token_encrypt() with a caller-supplied IV (tests). */
int ret_token_encrypt_det(const uint8_t key[RET_TOKEN_KEY_LEN],
			  const uint8_t iv[RET_AES_BLOCK_LEN], const uint8_t *pt, size_t pt_len,
			  uint8_t *out, size_t out_cap);

/**
 * Verify the HMAC, then decrypt.
 *
 * @return plaintext length
 * @retval -EBADMSG malformed, bad HMAC or bad padding
 */
int ret_token_decrypt(const uint8_t key[RET_TOKEN_KEY_LEN], const uint8_t *token, size_t len,
		      uint8_t *out, size_t out_cap);

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
