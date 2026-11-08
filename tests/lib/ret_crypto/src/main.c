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

ZTEST(identity, test_local_identity_matches_rns)
{
	struct ret_local_identity id;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	zassert_mem_equal(id.pub, v_identity_pub, RET_PUBKEY_LEN);
	zassert_mem_equal(id.hash, v_identity_hash, RET_TRUNC_HASH_LEN);
}

ZTEST(identity, test_decrypt_rns_token)
{
	struct ret_local_identity id;
	uint8_t out[64];
	int n;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	n = ret_local_identity_decrypt(&id, v_token, sizeof(v_token), out, sizeof(out));
	zassert_equal(n, strlen(V_PLAINTEXT));
	zassert_mem_equal(out, V_PLAINTEXT, n);
}

ZTEST(identity, test_decrypt_ratchets)
{
	struct ret_local_identity id;
	uint8_t keys[3][RET_RATCHET_LEN];
	const uint8_t *ratchets[] = { keys[0], keys[1], keys[2] };
	uint8_t pub[RET_RATCHET_LEN];
	uint8_t rid[RET_RATCHET_ID_LEN];
	uint8_t out[64];
	int used = 99;
	int n;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));

	/* RNS's Destination.encrypt() to our announced ratchet: found
	 * after a ratchet that does not open it.
	 */
	memset(keys[0], 0x11, RET_RATCHET_LEN);
	memcpy(keys[1], v_ratchet_prv, RET_RATCHET_LEN);
	memset(keys[2], 0x22, RET_RATCHET_LEN);
	n = ret_local_identity_decrypt_ratchets(&id, ratchets, 3, v_token_ratchet,
						sizeof(v_token_ratchet), out, sizeof(out), &used);
	zassert_equal(n, strlen(V_PLAINTEXT));
	zassert_mem_equal(out, V_PLAINTEXT, n);
	zassert_equal(used, 1);

	/* To the identity key: every ratchet fails, then the identity. */
	n = ret_local_identity_decrypt_ratchets(&id, ratchets, 3, v_token, sizeof(v_token), out,
						sizeof(out), &used);
	zassert_equal(n, strlen(V_PLAINTEXT));
	zassert_equal(used, -1);

	/* No ratchet held that opens it. */
	used = 99;
	zassert_equal(ret_local_identity_decrypt_ratchets(&id, &ratchets[2], 1, v_token_ratchet,
							  sizeof(v_token_ratchet), out,
							  sizeof(out), &used),
		      -EBADMSG);
	zassert_equal(used, 99);

	/* The ratchet id RNS logs. */
	ret_x25519_public_key(pub, v_ratchet_prv);
	zassert_mem_equal(pub, v_ratchet_pub, RET_RATCHET_LEN);
	zassert_ok(ret_ratchet_id(pub, rid));
	zassert_mem_equal(rid, v_ratchet_id, RET_RATCHET_ID_LEN);
}

ZTEST(identity, test_decrypt_rejects)
{
	struct ret_local_identity id;
	uint8_t tok[sizeof(v_token)];
	uint8_t out[64];

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));

	/* Encrypted to a ratchet, which the identity key alone cannot open. */
	zassert_equal(ret_local_identity_decrypt(&id, v_token_ratchet, sizeof(v_token_ratchet),
						 out, sizeof(out)),
		      -EBADMSG);

	/* Any flipped bit fails the HMAC: ephemeral key, IV, ciphertext, MAC. */
	const size_t offsets[] = { 0, 40, 50, sizeof(tok) - 1 };

	for (size_t i = 0; i < ARRAY_SIZE(offsets); i++) {
		memcpy(tok, v_token, sizeof(tok));
		tok[offsets[i]] ^= 0x01;
		zassert_equal(ret_local_identity_decrypt(&id, tok, sizeof(tok), out, sizeof(out)),
			      -EBADMSG, "offset %zu", offsets[i]);
	}

	/* Truncated or misaligned. */
	zassert_equal(ret_local_identity_decrypt(&id, v_token, RET_TOKEN_OVERHEAD, out,
						 sizeof(out)),
		      -EBADMSG);
	zassert_equal(ret_local_identity_decrypt(&id, v_token, sizeof(v_token) - 1, out,
						 sizeof(out)),
		      -EBADMSG);
	zassert_equal(ret_local_identity_decrypt(&id, v_token, sizeof(v_token), out, 15),
		      -ENOBUFS);
}

ZTEST(identity, test_encrypt_decrypt_roundtrip)
{
	struct ret_local_identity id;
	uint8_t prv[RET_PRVKEY_LEN];
	static uint8_t pt[RET_ENCRYPTED_MDU];
	static uint8_t tok[RET_TOKEN_LEN(RET_ENCRYPTED_MDU)];
	static uint8_t out[sizeof(tok)];
	int n;

	zassert_ok(ret_local_identity_generate(&id, prv));
	for (size_t i = 0; i < sizeof(pt); i++) {
		pt[i] = (uint8_t)i;
	}
	n = ret_identity_encrypt(id.pub, id.hash, pt, sizeof(pt), tok, sizeof(tok));
	zassert_equal(n, sizeof(tok));
	zassert_equal(ret_local_identity_decrypt(&id, tok, n, out, sizeof(out)), sizeof(pt));
	zassert_mem_equal(out, pt, sizeof(pt));
}

ZTEST(identity, test_sign_verifies)
{
	struct ret_local_identity id;
	uint8_t sig[RET_SIG_LEN];

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	ret_local_identity_sign(&id, v_packet_hash, RET_HASH_LEN, sig);
	zassert_true(ret_ed25519_verify(sig, &v_identity_pub[RET_X25519_LEN], v_packet_hash,
					RET_HASH_LEN));
}

/* RFC 8032 section 7.1, TEST 3 (a 2-byte message), signed in pieces:
 * independent of ret_ed25519_sign, which wraps the iov version.
 */
ZTEST(identity, test_ed25519_iov_rfc8032_test3)
{
	static const uint8_t seed[32] = {
		0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44,
		0x2f, 0x31, 0xdc, 0xb7, 0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f,
		0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44, 0x58, 0xf7,
	};
	static const uint8_t want_pub[32] = {
		0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e,
		0xd0, 0x02, 0x30, 0xf0, 0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33,
		0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90, 0x80, 0x25,
	};
	static const uint8_t want_sig[64] = {
		0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6,
		0x9c, 0x3a, 0xbe, 0x01, 0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74,
		0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a, 0xc3, 0xac, 0x18,
		0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60,
		0x98, 0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2,
		0x8d, 0xc0, 0x27, 0xbe, 0xce, 0xea, 0x1e, 0xc4, 0x0a,
	};
	static const uint8_t m0 = 0xaf;
	static const uint8_t m1 = 0x82;
	const struct ret_iov iov[] = { { &m0, 1 }, { &m1, 1 } };
	uint8_t sk[64];
	uint8_t pub[32];
	uint8_t sig[64];

	ret_ed25519_key_pair(sk, pub, seed);
	zassert_mem_equal(pub, want_pub, sizeof(pub));
	ret_ed25519_sign_iov(sig, sk, iov, ARRAY_SIZE(iov));
	zassert_mem_equal(sig, want_sig, sizeof(sig));
	zassert_true(ret_ed25519_verify_iov(sig, pub, iov, ARRAY_SIZE(iov)));
	ret_wipe(sk, sizeof(sk));
}

ZTEST(identity, test_sign_verify_iov)
{
	struct ret_local_identity id;
	uint8_t whole[RET_SIG_LEN];
	uint8_t pieces[RET_SIG_LEN];
	uint8_t tampered[RET_HASH_LEN];
	const uint8_t *pub = &v_identity_pub[RET_X25519_LEN];
	const struct ret_iov iov[] = {
		{ v_packet_hash, 5 }, { NULL, 0 }, { &v_packet_hash[5], 20 },
		{ &v_packet_hash[25], RET_HASH_LEN - 25 },
	};

	/* A message in pieces signs and verifies as the whole message. */
	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	ret_ed25519_sign(whole, id.ed25519_sk, v_packet_hash, RET_HASH_LEN);
	ret_ed25519_sign_iov(pieces, id.ed25519_sk, iov, ARRAY_SIZE(iov));
	zassert_mem_equal(whole, pieces, RET_SIG_LEN);
	zassert_true(ret_ed25519_verify_iov(whole, pub, iov, ARRAY_SIZE(iov)));

	memcpy(tampered, v_packet_hash, sizeof(tampered));
	tampered[31] ^= 1;
	const struct ret_iov bad[] = { { tampered, 16 }, { &tampered[16], 16 } };

	zassert_false(ret_ed25519_verify_iov(whole, pub, bad, ARRAY_SIZE(bad)));
}

ZTEST_SUITE(identity, NULL, setup, NULL, NULL, NULL);
