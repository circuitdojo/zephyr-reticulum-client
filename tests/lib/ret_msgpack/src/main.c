/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * mpack (the msgpack library ret-client uses) against RNS's umsgpack:
 * LXMF hashes and signs re-serialized payloads, so mpack must write the
 * exact bytes umsgpack writes. Vectors come from umsgpack itself
 * (tools/rns_peer/gen_vectors.py).
 */

#include <errno.h>
#include <string.h>

#include <mpack.h>
#include <zephyr/ztest.h>

#include "ret_mp.h"
#include "vectors_rns.h"

static uint8_t buf[1024];
static char text[300];
static uint8_t blob[300];

/* Writers are initialised in place, never copied: mpack_writer_t can hold
 * pointers into itself in other configurations.
 */
static void writer(mpack_writer_t *w)
{
	mpack_writer_init(w, (char *)buf, sizeof(buf));
}

static void expect_bytes(mpack_writer_t *w, const uint8_t *want, size_t want_len)
{
	size_t used = mpack_writer_buffer_used(w);

	zassert_equal(mpack_writer_destroy(w), mpack_ok);
	zassert_equal(used, want_len, "encoded %zu bytes, umsgpack %zu", used, want_len);
	zassert_mem_equal(buf, want, want_len);
}

static const uint64_t uints[] = {
	0, 127, 128, 255, 256, 65535, 65536, 4294967295ULL, 4294967296ULL, INT64_MAX, UINT64_MAX,
};
static const int64_t negs[] = {
	-1, -32, -33, -128, -129, -32768, -32769, -2147483648LL, -2147483649LL, INT64_MIN,
};

ZTEST(msgpack_encode, test_int_boundaries)
{
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, ARRAY_SIZE(uints) + ARRAY_SIZE(negs));
	for (size_t i = 0; i < ARRAY_SIZE(uints); i++) {
		mpack_write_u64(&w, uints[i]);
	}
	for (size_t i = 0; i < ARRAY_SIZE(negs); i++) {
		mpack_write_i64(&w, negs[i]);
	}
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_ints, sizeof(v_mp_ints));
}

ZTEST(msgpack_encode, test_signed_writer_uses_uint_forms)
{
	/* RNS code mostly holds ints as signed: non-negative values must still
	 * go out in umsgpack's unsigned forms. Written in the same array
	 * (array16 header 0xdc 00 15) so the bytes compare directly.
	 */
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, ARRAY_SIZE(uints) + ARRAY_SIZE(negs));
	for (size_t i = 0; i < ARRAY_SIZE(uints); i++) {
		if (uints[i] <= INT64_MAX) {
			mpack_write_i64(&w, (int64_t)uints[i]);
		} else {
			mpack_write_u64(&w, uints[i]); /* no signed equivalent */
		}
	}
	for (size_t i = 0; i < ARRAY_SIZE(negs); i++) {
		mpack_write_i64(&w, negs[i]);
	}
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_ints, sizeof(v_mp_ints));
}

ZTEST(msgpack_encode, test_str_lengths)
{
	static const size_t lens[] = { 0, 31, 32, 255, 256 };
	mpack_writer_t w;

	writer(&w);
	memset(text, 'a', sizeof(text));
	mpack_start_array(&w, ARRAY_SIZE(lens));
	for (size_t i = 0; i < ARRAY_SIZE(lens); i++) {
		mpack_write_str(&w, text, lens[i]);
	}
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_str_lengths, sizeof(v_mp_str_lengths));
}

ZTEST(msgpack_encode, test_bin_lengths)
{
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, 3);
	mpack_write_bin(&w, (const char *)blob, 0);
	memset(blob, 0x01, sizeof(blob));
	mpack_write_bin(&w, (const char *)blob, 255);
	memset(blob, 0x02, sizeof(blob));
	mpack_write_bin(&w, (const char *)blob, 256);
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_bin_lengths, sizeof(v_mp_bin_lengths));
}

ZTEST(msgpack_encode, test_bin32_header)
{
	/* Resource-sized payloads: 65536 bytes needs the bin32 form. */
	static uint8_t big[65536 + 16];
	mpack_writer_t w;

	mpack_writer_init(&w, (char *)big, sizeof(big));
	memset(blob, 0, sizeof(blob));
	mpack_start_bin(&w, 65536);
	for (int i = 0; i < 65536 / 256; i++) {
		mpack_write_bytes(&w, (const char *)blob, 256);
	}
	mpack_finish_bin(&w);
	zassert_equal(mpack_writer_destroy(&w), mpack_ok);
	zassert_mem_equal(big, v_mp_bin32_header, sizeof(v_mp_bin32_header));
}

ZTEST(msgpack_encode, test_scalars)
{
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, 4);
	mpack_write_double(&w, 1800000000.25);
	mpack_write_nil(&w);
	mpack_write_bool(&w, true);
	mpack_write_bool(&w, false);
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_scalars, sizeof(v_mp_scalars));
}

ZTEST(msgpack_encode, test_16_element_containers)
{
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, 16);
	for (int i = 0; i < 16; i++) {
		mpack_write_i64(&w, i);
	}
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_array16, sizeof(v_mp_array16));

	writer(&w);
	mpack_start_map(&w, 16);
	for (int i = 0; i < 16; i++) {
		mpack_write_i64(&w, i);
		mpack_write_i64(&w, i * 2);
	}
	mpack_finish_map(&w);
	expect_bytes(&w, v_mp_map16, sizeof(v_mp_map16));
}

ZTEST(msgpack_encode, test_rns_link_request)
{
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, 3);
	mpack_write_double(&w, 1800000000.5);
	/* 93, cb + 8 bytes, c4 10, then the 16-byte path hash at offset 12 */
	mpack_write_bin(&w, (const char *)&v_mp_link_request[12], 16);
	mpack_start_array(&w, 2);
	mpack_write_nil(&w);
	mpack_write_nil(&w);
	mpack_finish_array(&w);
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_link_request, sizeof(v_mp_link_request));
}

ZTEST(msgpack_encode, test_resource_advertisement)
{
	/* The 11 keys in RNS ResourceAdvertisement.pack order. */
	mpack_writer_t w;

	writer(&w);
	mpack_start_map(&w, 11);
	mpack_write_str(&w, "t", 1);
	mpack_write_u64(&w, 1300);
	mpack_write_str(&w, "d", 1);
	mpack_write_u64(&w, 1200);
	mpack_write_str(&w, "n", 1);
	mpack_write_u64(&w, 3);
	mpack_write_str(&w, "h", 1);
	mpack_write_bin(&w, (const char *)v_mp_adv_h, sizeof(v_mp_adv_h));
	mpack_write_str(&w, "r", 1);
	mpack_write_bin(&w, (const char *)v_mp_adv_r, sizeof(v_mp_adv_r));
	mpack_write_str(&w, "o", 1);
	mpack_write_bin(&w, (const char *)v_mp_adv_h, sizeof(v_mp_adv_h));
	mpack_write_str(&w, "i", 1);
	mpack_write_u64(&w, 1);
	mpack_write_str(&w, "l", 1);
	mpack_write_u64(&w, 1);
	mpack_write_str(&w, "q", 1);
	mpack_write_bin(&w, (const char *)v_mp_adv_q, sizeof(v_mp_adv_q));
	mpack_write_str(&w, "f", 1);
	mpack_write_u64(&w, 0x11);
	mpack_write_str(&w, "m", 1);
	mpack_write_bin(&w, (const char *)v_mp_adv_m, sizeof(v_mp_adv_m));
	mpack_finish_map(&w);
	expect_bytes(&w, v_mp_resource_adv, sizeof(v_mp_resource_adv));
}

ZTEST(msgpack_encode, test_lxmf_shaped_payload_and_app_data)
{
	mpack_writer_t w;

	writer(&w);
	mpack_start_array(&w, 4);
	mpack_write_double(&w, 1800000000.125);
	mpack_write_bin(&w, "title", 5);
	mpack_write_bin(&w, "hello", 5);
	mpack_start_map(&w, 0);
	mpack_finish_map(&w);
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_lxmf_payload, sizeof(v_mp_lxmf_payload));

	writer(&w);
	mpack_start_array(&w, 3);
	mpack_write_bin(&w, "ret-node", 8);
	mpack_write_nil(&w);
	mpack_start_array(&w, 0);
	mpack_finish_array(&w);
	mpack_finish_array(&w);
	expect_bytes(&w, v_mp_lxmf_app_data, sizeof(v_mp_lxmf_app_data));
}

ZTEST(msgpack_encode, test_overflow_is_reported)
{
	mpack_writer_t w;
	char small[4];

	mpack_writer_init(&w, small, sizeof(small));
	mpack_write_bin(&w, "hello", 5);
	zassert_not_equal(mpack_writer_destroy(&w), mpack_ok);
}

ZTEST_SUITE(msgpack_encode, NULL, NULL, NULL, NULL, NULL);

/* --- Decoding what umsgpack wrote ---------------------------------- */

ZTEST(msgpack_decode, test_resource_adv_map)
{
	mpack_reader_t r;
	uint32_t n;
	uint64_t t = 0, d = 0, parts = 0, f = 0;
	bool have_h = false, have_q = false;

	mpack_reader_init_data(&r, (const char *)v_mp_resource_adv, sizeof(v_mp_resource_adv));
	n = mpack_expect_map(&r);
	zassert_equal(n, 11);
	for (uint32_t i = 0; i < n; i++) {
		char key[2];

		mpack_expect_cstr(&r, key, sizeof(key));
		switch (key[0]) {
		case 't':
			t = mpack_expect_u64(&r);
			break;
		case 'd':
			d = mpack_expect_u64(&r);
			break;
		case 'n':
			parts = mpack_expect_u64(&r);
			break;
		case 'f':
			f = mpack_expect_u64(&r);
			break;
		case 'h':
		case 'q': {
			uint32_t len = mpack_expect_bin(&r);
			const char *p = mpack_read_bytes_inplace(&r, len);

			zassert_not_null(p);
			if (key[0] == 'h') {
				zassert_equal(len, sizeof(v_mp_adv_h));
				zassert_mem_equal(p, v_mp_adv_h, len);
				have_h = true;
			} else {
				zassert_equal(len, sizeof(v_mp_adv_q));
				zassert_mem_equal(p, v_mp_adv_q, len);
				have_q = true;
			}
			mpack_done_bin(&r);
			break;
		}
		default:
			mpack_discard(&r);
		}
	}
	zassert_equal(mpack_reader_destroy(&r), mpack_ok);
	zassert_equal(t, 1300);
	zassert_equal(d, 1200);
	zassert_equal(parts, 3);
	zassert_equal(f, 0x11);
	zassert_true(have_h);
	zassert_true(have_q);
}

ZTEST(msgpack_decode, test_ints_and_type_errors)
{
	mpack_reader_t r;

	mpack_reader_init_data(&r, (const char *)v_mp_ints, sizeof(v_mp_ints));
	zassert_equal(mpack_expect_array(&r), ARRAY_SIZE(uints) + ARRAY_SIZE(negs));
	for (size_t i = 0; i < ARRAY_SIZE(uints); i++) {
		zassert_equal(mpack_expect_u64(&r), uints[i], "uint %zu", i);
	}
	zassert_equal(mpack_expect_i64(&r), -1);
	zassert_equal(mpack_reader_error(&r), mpack_ok);
	/* -32 is not a valid u64: the reader goes into an error state. */
	(void)mpack_expect_u64(&r);
	zassert_not_equal(mpack_reader_error(&r), mpack_ok);
}

ZTEST(msgpack_decode, test_int64_edges)
{
	mpack_reader_t r;

	mpack_reader_init_data(&r, (const char *)v_mp_ints, sizeof(v_mp_ints));
	(void)mpack_expect_array(&r);
	for (size_t i = 0; i < ARRAY_SIZE(uints); i++) {
		(void)mpack_expect_u64(&r);
	}
	for (size_t i = 0; i < ARRAY_SIZE(negs); i++) {
		zassert_equal(mpack_expect_i64(&r), negs[i], "neg %zu", i);
	}
	zassert_equal(mpack_reader_destroy(&r), mpack_ok);
}

ZTEST(msgpack_decode, test_truncated_input)
{
	mpack_reader_t r;

	mpack_reader_init_data(&r, (const char *)v_mp_lxmf_payload,
			       sizeof(v_mp_lxmf_payload) - 3);
	mpack_expect_array(&r);
	mpack_expect_double(&r);
	mpack_discard(&r);
	mpack_discard(&r);
	mpack_discard(&r);
	zassert_not_equal(mpack_reader_destroy(&r), mpack_ok);
}

ZTEST_SUITE(msgpack_decode, NULL, NULL, NULL, NULL, NULL);

/* --- ret_mp_skip: bounded, non-recursive ---------------------------- */

static int skip_nested(int levels)
{
	static uint8_t data[64];
	mpack_reader_t r;
	int err;

	memset(data, 0x91, levels); /* fixarray of one element, repeated */
	data[levels] = 0xc0;        /* innermost: nil */
	mpack_reader_init_data(&r, (const char *)data, levels + 1);
	err = ret_mp_skip(&r);
	if (!err && mpack_reader_remaining(&r, NULL) != 0) {
		err = -1;
	}
	mpack_reader_destroy(&r);
	return err;
}

ZTEST(msgpack_skip, test_depth_limit)
{
	zassert_ok(skip_nested(RET_MP_MAX_DEPTH));
	zassert_equal(skip_nested(RET_MP_MAX_DEPTH + 1), -EBADMSG);
}

ZTEST(msgpack_skip, test_skips_real_values)
{
	mpack_reader_t r;

	mpack_reader_init_data(&r, (const char *)v_mp_resource_adv, sizeof(v_mp_resource_adv));
	zassert_ok(ret_mp_skip(&r));
	zassert_equal(mpack_reader_remaining(&r, NULL), 0);
	mpack_reader_destroy(&r);

	mpack_reader_init_data(&r, (const char *)v_mp_lxmf_payload, sizeof(v_mp_lxmf_payload) - 1);
	zassert_equal(ret_mp_skip(&r), -EBADMSG); /* truncated */
	mpack_reader_destroy(&r);
}

ZTEST_SUITE(msgpack_skip, NULL, NULL, NULL, NULL, NULL);

