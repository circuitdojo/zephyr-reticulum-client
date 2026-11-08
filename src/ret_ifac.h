/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Interface Access Codes (RNS/Reticulum.py interface setup,
 * Transport.handle_outgoing_ifac / handle_ifac): an interface configured
 * with a network name and/or passphrase signs every packet with a key
 * derived from them and drops packets without a valid code. See
 * docs/protocol.md.
 */

#ifndef RET_IFAC_H_
#define RET_IFAC_H_

#include <stddef.h>
#include <stdint.h>

#include "ret_identity.h"

#define RET_IFAC_KEY_LEN  64
#define RET_IFAC_MAX_SIZE 64 /* an Ed25519 signature */
#define RET_IFAC_FLAG     0x80

struct ret_ifac {
	uint8_t key[RET_IFAC_KEY_LEN];
	/** Identity.from_bytes(key): signs the codes. */
	struct ret_local_identity id;
	/** Code length in bytes (RNS ifac_size / 8; 16 for TCP interfaces). */
	uint8_t size;
};

/**
 * Derive the interface key: HKDF-SHA256 (64 bytes) of
 * SHA256(SHA256(name) | SHA256(passphrase)), either part left out when
 * NULL or empty, salted with RNS's IFAC_SALT.
 *
 * @retval -EINVAL neither name nor passphrase, or @p size not in 1..64
 */
int ret_ifac_init(struct ret_ifac *f, const char *netname, const char *passphrase,
		  uint8_t size);

/**
 * Add the access code to packet @p raw: the last f->size bytes of its
 * signature go after the two header bytes, everything else is masked, and
 * the IFAC flag is set.
 *
 * @return @p len + f->size
 * @retval -ENOBUFS @p cap too small
 * @retval -EINVAL @p len under 2, or @p raw already carries the flag
 */
int ret_ifac_apply(const struct ret_ifac *f, const uint8_t *raw, size_t len, uint8_t *out,
		   size_t cap);

/**
 * Check and remove the access code from frame @p in, recovering the packet
 * into @p raw, which may be @p in itself (in place) but must not otherwise
 * overlap it.
 *
 * @return the packet's length (@p len - f->size)
 * @retval -EBADMSG no IFAC flag, or shorter than a code plus header
 * @retval -EACCES the code does not match (wrong network or passphrase,
 *         or tampered)
 * @retval -ENOBUFS @p cap too small
 */
int ret_ifac_strip(const struct ret_ifac *f, const uint8_t *in, size_t len, uint8_t *raw,
		   size_t cap);

#endif /* RET_IFAC_H_ */
