/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Known-answer tests for the crypto backend (RFC / NIST vectors), and
 * byte-exact interop with RNS for identity hashing and encryption.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/sys/util.h>
#include <zephyr/ztest.h>

#include "ret_crypto.h"
#include "ret_identity.h"
#include "vectors_rns.h"

static size_t hex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = hex2bin(s, strlen(s), out, cap);

	zassert_equal(n, strlen(s) / 2, "bad hex literal");
	return n;
}

static void *setup(void)
{
	zassert_ok(ret_crypto_init());
	return NULL;
}

/* --- Primitives ---------------------------------------------------- */

ZTEST(crypto_kat, test_sha256_abc)
{
	uint8_t want[32], got[32];
	const struct ret_iov iov[] = { { "a", 1 }, { "", 0 }, { "bc", 2 } };

	hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", want, 32);
	zassert_ok(ret_sha256(iov, ARRAY_SIZE(iov), got));
	zassert_mem_equal(got, want, 32);
}

ZTEST(crypto_kat, test_hmac_rfc4231_case1)
{
	uint8_t key[20], want[32], got[32];
	const struct ret_iov iov[] = { { "Hi ", 3 }, { "There", 5 } };

	memset(key, 0x0b, sizeof(key));
	hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", want, 32);
	zassert_ok(ret_hmac_sha256(key, sizeof(key), iov, ARRAY_SIZE(iov), got));
	zassert_mem_equal(got, want, 32);
}

ZTEST(crypto_kat, test_hkdf_rfc5869_case1)
{
	uint8_t ikm[22], salt[13], info[10], want[42], got[42];

	memset(ikm, 0x0b, sizeof(ikm));
	hex("000102030405060708090a0b0c", salt, sizeof(salt));
	hex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
	hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
	    "34007208d5b887185865",
	    want, sizeof(want));
	zassert_ok(ret_hkdf_sha256(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), got,
				   sizeof(got)));
	zassert_mem_equal(got, want, sizeof(want));
}

ZTEST(crypto_kat, test_hkdf_rfc5869_case3_empty_salt)
{
	uint8_t ikm[22], want[42], got[42];

	memset(ikm, 0x0b, sizeof(ikm));
	hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
	    "9d201395faa4b61a96c8",
	    want, sizeof(want));
	zassert_ok(ret_hkdf_sha256(ikm, sizeof(ikm), NULL, 0, NULL, 0, got, sizeof(got)));
	zassert_mem_equal(got, want, sizeof(want));
}

ZTEST(crypto_kat, test_hkdf_rejects)
{
	uint8_t ikm[4] = { 1 }, out[8];

	zassert_equal(ret_hkdf_sha256(ikm, 0, NULL, 0, NULL, 0, out, sizeof(out)), -EINVAL);
	zassert_equal(ret_hkdf_sha256(ikm, sizeof(ikm), NULL, 0, NULL, 0, out, 0), -EINVAL);
}

ZTEST(crypto_kat, test_aes256_cbc_sp800_38a)
{
	uint8_t key[32], iv[16], pt[32], ct[32], got[32];

	hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
	hex("000102030405060708090a0b0c0d0e0f", iv, 16);
	hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", pt, 32);
	hex("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d", ct, 32);

	zassert_ok(ret_aes256_cbc_encrypt(key, iv, pt, 32, got));
	zassert_mem_equal(got, ct, 32);
	zassert_ok(ret_aes256_cbc_decrypt(key, iv, ct, 32, got));
	zassert_mem_equal(got, pt, 32);
	zassert_equal(ret_aes256_cbc_encrypt(key, iv, pt, 15, got), -EINVAL);
}

ZTEST(crypto_kat, test_x25519_rfc7748)
{
	uint8_t a_prv[32], a_pub[32], b_prv[32], b_pub[32], want[32], got[32];

	hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", a_prv, 32);
	hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", a_pub, 32);
	hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", b_prv, 32);
	hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", b_pub, 32);
	hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", want, 32);

	ret_x25519_public_key(got, a_prv);
	zassert_mem_equal(got, a_pub, 32);
	zassert_ok(ret_x25519(got, a_prv, b_pub));
	zassert_mem_equal(got, want, 32);
	zassert_ok(ret_x25519(got, b_prv, a_pub));
	zassert_mem_equal(got, want, 32);
}

ZTEST(crypto_kat, test_x25519_rejects_low_order)
{
	uint8_t prv[32] = { 1 }, zero_pub[32] = { 0 }, out[32];

	zassert_equal(ret_x25519(out, prv, zero_pub), -EINVAL);
}

ZTEST(crypto_kat, test_ed25519_rfc8032_test1)
{
	uint8_t pub[32], sig[64];

	hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", pub, 32);
	hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
	    "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	    sig, 64);

	zassert_true(ret_ed25519_verify(sig, pub, NULL, 0));
	sig[10] ^= 0x01;
	zassert_false(ret_ed25519_verify(sig, pub, NULL, 0));
}

ZTEST(crypto_kat, test_pkcs7)
{
	uint8_t buf[48] = "0123456789abcdef";
	uint8_t bad[16];

	zassert_equal(ret_pkcs7_padded_len(0), 16);
	zassert_equal(ret_pkcs7_padded_len(15), 16);
	zassert_equal(ret_pkcs7_padded_len(16), 32);

	zassert_equal(ret_pkcs7_pad(buf, 16), 32);
	for (int i = 16; i < 32; i++) {
		zassert_equal(buf[i], 16);
	}
	zassert_equal(ret_pkcs7_unpad(buf, 32), 16);

	zassert_equal(ret_pkcs7_pad(buf, 13), 16);
	zassert_equal(ret_pkcs7_unpad(buf, 16), 13);

	memset(bad, 0, sizeof(bad));
	zassert_equal(ret_pkcs7_unpad(bad, 16), -EBADMSG);
	bad[15] = 17;
	zassert_equal(ret_pkcs7_unpad(bad, 16), -EBADMSG);
	bad[15] = 2;
	bad[14] = 3;
	zassert_equal(ret_pkcs7_unpad(bad, 16), -EBADMSG);
	zassert_equal(ret_pkcs7_unpad(bad, 15), -EBADMSG);
}

ZTEST(crypto_kat, test_random)
{
	uint8_t a[32] = { 0 }, b[32] = { 0 };

	zassert_ok(ret_random(a, sizeof(a)));
	zassert_ok(ret_random(b, sizeof(b)));
	zassert_false(memcmp(a, b, sizeof(a)) == 0);
}

ZTEST_SUITE(crypto_kat, NULL, setup, NULL, NULL, NULL);

/* --- RNS interop --------------------------------------------------- */

ZTEST(identity, test_hashes_match_rns)
{
	uint8_t nh[RET_NAME_HASH_LEN], ih[RET_TRUNC_HASH_LEN], dh[RET_TRUNC_HASH_LEN];

	zassert_ok(ret_name_hash(V_NAME, nh));
	zassert_mem_equal(nh, v_name_hash, sizeof(nh));
	zassert_ok(ret_identity_hash(v_identity_pub, ih));
	zassert_mem_equal(ih, v_identity_hash, sizeof(ih));
	zassert_ok(ret_dest_hash(nh, ih, dh));
	zassert_mem_equal(dh, v_dest_hash, sizeof(dh));
}

ZTEST(identity, test_plain_dest_hash_matches_rns)
{
	uint8_t h[RET_TRUNC_HASH_LEN];

	zassert_ok(ret_plain_dest_hash("rnstransport.path.request", h));
	zassert_mem_equal(h, v_path_request_dest, sizeof(h));
}

ZTEST(identity, test_hkdf_matches_rns)
{
	uint8_t out[64];

	zassert_ok(ret_hkdf_sha256(v_hkdf_ikm, sizeof(v_hkdf_ikm), v_identity_hash,
				   sizeof(v_identity_hash), NULL, 0, out, sizeof(out)));
	zassert_mem_equal(out, v_hkdf_out, sizeof(out));
}

ZTEST(identity, test_token_matches_rns)
{
	uint8_t out[RET_TOKEN_LEN(sizeof(V_PLAINTEXT) - 1)];
	int n;

	zassert_equal(sizeof(out), sizeof(v_token));
	n = ret_identity_encrypt_det(v_identity_pub, v_identity_hash,
				     (const uint8_t *)V_PLAINTEXT, sizeof(V_PLAINTEXT) - 1,
				     v_eph_prv, v_iv, out, sizeof(out));
	zassert_equal(n, sizeof(v_token));
	zassert_mem_equal(out, v_token, sizeof(v_token));
}

ZTEST(identity, test_ratchet_token_matches_rns)
{
	uint8_t out[sizeof(v_token_ratchet)];
	int n;

	/* Encrypted to the ratchet key, still salted with the identity hash. */
	n = ret_identity_encrypt_det(v_ratchet_pub, v_identity_hash,
				     (const uint8_t *)V_PLAINTEXT, sizeof(V_PLAINTEXT) - 1,
				     v_eph_prv, v_iv, out, sizeof(out));
	zassert_equal(n, sizeof(v_token_ratchet));
	zassert_mem_equal(out, v_token_ratchet, sizeof(v_token_ratchet));
}

ZTEST(identity, test_encrypt_random_and_bounds)
{
	uint8_t a[RET_TOKEN_LEN(RET_ENCRYPTED_MDU)], b[sizeof(a)];
	static uint8_t pt[RET_ENCRYPTED_MDU];

	zassert_equal(ret_identity_encrypt(v_identity_pub, v_identity_hash, pt, sizeof(pt), a,
					   sizeof(a)),
		      sizeof(a));
	zassert_equal(ret_identity_encrypt(v_identity_pub, v_identity_hash, pt, sizeof(pt), b,
					   sizeof(b)),
		      sizeof(b));
	/* Fresh ephemeral key and IV each time. */
	zassert_false(memcmp(a, b, 48) == 0);
	zassert_equal(ret_identity_encrypt(v_identity_pub, v_identity_hash, pt, sizeof(pt), a,
					   sizeof(a) - 1),
		      -ENOBUFS);
	/* The largest token still fits an H2 packet within the MTU. */
	zassert_true(RET_H2_HEADER_LEN + sizeof(a) <= RET_MTU);
}

ZTEST_SUITE(identity, NULL, setup, NULL, NULL, NULL);
