/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * LXMF messages against vectors from the real LXMF (LXMessage.pack and
 * unpack_from_bytes, lxmf 1.2.1).
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ret_crypto.h"
#include "ret_lxmf.h"
#include "ret_lxmf_seen.h"
#include "vectors_rns.h"

/* RET_MAX_PAYLOAD (ret_client.h): the SINGLE packet plaintext limit. */
#define SINGLE_MAX_PAYLOAD 383

static const uint8_t *snd_sig_pub = &v_lxmf_snd_pub[RET_X25519_LEN];

static void *setup(void)
{
	zassert_ok(ret_crypto_init());
	return NULL;
}

/* A packed message is dest | body. */
static int unpack_packed(const uint8_t *packed, size_t len, struct ret_lxmf_msg *m)
{
	return ret_lxmf_unpack(packed, &packed[RET_LXMF_ADDR_LEN], len - RET_LXMF_ADDR_LEN, m);
}

ZTEST(lxmf, test_unpack_and_verify)
{
	struct ret_lxmf_msg m;

	zassert_ok(unpack_packed(v_lxmf_in_packed, sizeof(v_lxmf_in_packed), &m));
	zassert_mem_equal(m.hash, v_lxmf_in_hash, sizeof(m.hash));
	zassert_mem_equal(m.dest, v_lxmf_dev_dest, RET_LXMF_ADDR_LEN);
	zassert_mem_equal(m.src, v_lxmf_snd_dest, RET_LXMF_ADDR_LEN);
	zassert_equal(m.timestamp, 1800000000.25);
	zassert_equal(m.title_len, 2);
	zassert_mem_equal(m.title, "hi", 2);
	zassert_equal(m.content_len, strlen("hello device"));
	zassert_mem_equal(m.content, "hello device", m.content_len);
	zassert_equal(m.fields_len, 1);
	zassert_equal(m.fields[0], 0x80);
	zassert_false(m.stamped);
	zassert_true(ret_lxmf_verify(&m, snd_sig_pub));

	/* Not the sender's key. */
	zassert_false(ret_lxmf_verify(&m, &v_lxmf_dev_prv[0]));
}

ZTEST(lxmf, test_stamp_is_not_hashed)
{
	struct ret_lxmf_msg m;

	zassert_ok(unpack_packed(v_lxmf_in_stamped, sizeof(v_lxmf_in_stamped), &m));
	zassert_true(m.stamped);
	zassert_mem_equal(m.hash, v_lxmf_in_hash, sizeof(m.hash));
	zassert_true(ret_lxmf_verify(&m, snd_sig_pub));
	zassert_mem_equal(m.content, "hello device", m.content_len);
}

ZTEST(lxmf, test_fields_passed_through)
{
	struct ret_lxmf_msg m;

	zassert_ok(unpack_packed(v_lxmf_fields_packed, sizeof(v_lxmf_fields_packed), &m));
	zassert_mem_equal(m.hash, v_lxmf_fields_hash, sizeof(m.hash));
	zassert_true(ret_lxmf_verify(&m, snd_sig_pub));
	zassert_equal(m.title_len, 0);
	zassert_equal(m.fields[0], 0x82, "a 2-entry fixmap");
	zassert_true(m.fields_len > 1);
}

ZTEST(lxmf, test_str_title_content_stamp_and_fields)
{
	struct ret_lxmf_msg m;
	static const char title[] = "T\xc3\xaftle";

	zassert_ok(unpack_packed(v_lxmf_str_packed, sizeof(v_lxmf_str_packed), &m));
	zassert_true(m.stamped);
	zassert_mem_equal(m.hash, v_lxmf_str_hash, sizeof(m.hash));
	zassert_true(ret_lxmf_verify(&m, snd_sig_pub));
	zassert_equal(m.title_len, strlen(title));
	zassert_mem_equal(m.title, title, m.title_len);
	zassert_mem_equal(m.content, "content as str", m.content_len);
	zassert_equal(m.fields[0], 0x81);
}

ZTEST(lxmf, test_fields_must_be_a_map)
{
	uint8_t buf[sizeof(v_lxmf_in_packed)];
	struct ret_lxmf_msg m;

	/* The empty fields map is the last byte: make it an empty array. */
	memcpy(buf, v_lxmf_in_packed, sizeof(buf));
	zassert_equal(buf[sizeof(buf) - 1], 0x80);
	buf[sizeof(buf) - 1] = 0x90;
	zassert_equal(unpack_packed(buf, sizeof(buf), &m), -EBADMSG);
}

ZTEST(lxmf, test_tampered_fails)
{
	uint8_t buf[sizeof(v_lxmf_in_packed)];
	struct ret_lxmf_msg m;

	memcpy(buf, v_lxmf_in_packed, sizeof(buf));
	buf[sizeof(buf) - 2] ^= 0x01; /* inside the content */
	zassert_ok(unpack_packed(buf, sizeof(buf), &m));
	zassert_false(ret_lxmf_verify(&m, snd_sig_pub));
}

ZTEST(lxmf, test_unpack_rejects)
{
	uint8_t buf[sizeof(v_lxmf_in_packed) + 1];
	struct ret_lxmf_msg m;

	/* Truncated, trailing bytes, too short for the header. */
	zassert_equal(unpack_packed(v_lxmf_in_packed, sizeof(v_lxmf_in_packed) - 1, &m),
		      -EBADMSG);
	memcpy(buf, v_lxmf_in_packed, sizeof(v_lxmf_in_packed));
	buf[sizeof(buf) - 1] = 0xc0;
	zassert_equal(unpack_packed(buf, sizeof(buf), &m), -EBADMSG);
	zassert_equal(unpack_packed(v_lxmf_in_packed, RET_LXMF_ADDR_LEN + RET_LXMF_BODY_HDR, &m),
		      -EBADMSG);

	/* A 3-element payload. */
	memcpy(buf, v_lxmf_in_packed, sizeof(v_lxmf_in_packed));
	zassert_equal(buf[RET_LXMF_ADDR_LEN + RET_LXMF_BODY_HDR], 0x94);
	buf[RET_LXMF_ADDR_LEN + RET_LXMF_BODY_HDR] = 0x93;
	zassert_equal(unpack_packed(buf, sizeof(v_lxmf_in_packed), &m), -EBADMSG);
}

ZTEST(lxmf, test_pack_matches_lxmf)
{
	struct ret_local_identity id;
	uint8_t out[512];
	uint8_t hash[RET_SHA256_LEN];
	static const char content[] = "reply from device";
	int n;

	zassert_ok(ret_local_identity_load(&id, v_lxmf_dev_prv));
	n = ret_lxmf_pack(&id, v_lxmf_dev_dest, v_lxmf_snd_dest, 1800000001.5, NULL, 0,
			  (const uint8_t *)content, strlen(content), out, sizeof(out), hash);
	zassert_equal(n, sizeof(v_lxmf_out_packed));
	zassert_mem_equal(out, v_lxmf_out_packed, n);

	/* And it reads back. */
	struct ret_lxmf_msg m;

	zassert_ok(unpack_packed(out, n, &m));
	zassert_mem_equal(m.hash, hash, sizeof(hash));
	zassert_true(ret_lxmf_verify(&m, &id.pub[RET_X25519_LEN]));
	ret_wipe(&id, sizeof(id));
}

ZTEST(lxmf, test_opportunistic_limit)
{
	struct ret_local_identity id;
	static uint8_t content[RET_LXMF_OPPORTUNISTIC_MAX];
	uint8_t out[512];
	uint8_t hash[RET_SHA256_LEN];
	int n;

	/* The largest content exactly fills one SINGLE packet's plaintext. */
	zassert_ok(ret_local_identity_load(&id, v_lxmf_dev_prv));
	n = ret_lxmf_pack(&id, v_lxmf_dev_dest, v_lxmf_snd_dest, 1800000001.5, NULL, 0, content,
			  sizeof(content), out, sizeof(out), hash);
	zassert_equal(n - RET_LXMF_ADDR_LEN, SINGLE_MAX_PAYLOAD);
	zassert_equal(ret_lxmf_pack(&id, v_lxmf_dev_dest, v_lxmf_snd_dest, 0, NULL, 0, content,
				    sizeof(content), out, 200, hash),
		      -ENOBUFS);
	ret_wipe(&id, sizeof(id));
}

ZTEST(lxmf, test_app_data)
{
	uint8_t out[32];
	int n = ret_lxmf_app_data("ret-node", out, sizeof(out));

	zassert_equal(n, sizeof(v_lxmf_app_data));
	zassert_mem_equal(out, v_lxmf_app_data, n);
	zassert_equal(ret_lxmf_app_data("ret-node", out, 4), -ENOBUFS);
	zassert_equal(ret_lxmf_app_data(NULL, out, sizeof(out)), 4); /* 93 c0 c0 90 */
}

ZTEST_SUITE(lxmf, NULL, setup, NULL, NULL, NULL);

/* --- Replay protection ----------------------------------------------- */

#define DAY   86400
#define NOW   1800000000LL
#define SEEN_N 4

static struct ret_lxmf_seen_entry seen_entries[SEEN_N];
static struct ret_lxmf_seen seen;

static void seen_reset(void *f)
{
	ARG_UNUSED(f);
	memset(seen_entries, 0, sizeof(seen_entries));
	seen = (struct ret_lxmf_seen){
		.entries = seen_entries, .count = SEEN_N, .max_age_s = 30 * DAY,
		.max_future_s = 3600,
	};
}

static const uint8_t *h(uint8_t n)
{
	static uint8_t buf[8][RET_LXMF_SEEN_HASH_LEN];

	memset(buf[n % 8], n, RET_LXMF_SEEN_HASH_LEN);
	return buf[n % 8];
}

static size_t add_as(uint8_t n, double ts, int64_t now, bool verified, bool *raised)
{
	zassert_equal(ret_lxmf_seen_check(&seen, h(n), ts, now), RET_LXMF_SEEN_NEW);
	return ret_lxmf_seen_add(&seen, h(n), ts, now, verified, raised);
}

static size_t add(uint8_t n, double ts, int64_t now, bool *raised)
{
	return add_as(n, ts, now, true, raised);
}

ZTEST(lxmf_seen, test_duplicates_and_age)
{
	bool raised;

	add(1, NOW - DAY, NOW, &raised);
	zassert_false(raised);
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), NOW - DAY, NOW), RET_LXMF_SEEN_DUPLICATE);
	/* Older than 30 days: refused whatever it is. */
	zassert_equal(ret_lxmf_seen_check(&seen, h(2), NOW - 31 * DAY, NOW), RET_LXMF_SEEN_TOO_OLD);
	zassert_equal(ret_lxmf_seen_check(&seen, h(2), NOW - 29 * DAY, NOW), RET_LXMF_SEEN_NEW);
	/* No wall clock: the age check waits for it. */
	zassert_equal(ret_lxmf_seen_check(&seen, h(2), NOW - 31 * DAY, 0), RET_LXMF_SEEN_NEW);
	zassert_equal(ret_lxmf_seen_check(&seen, h(2), __builtin_nan(""), 0), RET_LXMF_SEEN_BAD_TIME);
}

ZTEST(lxmf_seen, test_future_and_infinite_timestamps_refused)
{
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), NOW + 3600, NOW), RET_LXMF_SEEN_NEW);
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), NOW + 3601, NOW), RET_LXMF_SEEN_BAD_TIME);
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), __builtin_inf(), NOW),
		      RET_LXMF_SEEN_BAD_TIME);
	/* Without a clock: nothing past 2100. */
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), 1e18, 0), RET_LXMF_SEEN_BAD_TIME);
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), NOW + 3601, 0), RET_LXMF_SEEN_NEW);
}

ZTEST(lxmf_seen, test_pre_clock_flood_cannot_block_messages_later)
{
	bool raised;

	/* No clock yet: a flood stamped 2099 fills the table and, evicting,
	 * lifts the floor there.
	 */
	for (uint8_t n = 1; n <= SEEN_N + 2; n++) {
		add(n, 4070908800.0 + n, 0, &raised);
	}
	zassert_true(seen.floor > 4070908800.0);
	zassert_equal(ret_lxmf_seen_check(&seen, h(9), NOW, 0), RET_LXMF_SEEN_TOO_OLD);

	/* Once the clock is set, neither the floor nor those entries block
	 * genuine messages: the floor counts up to now + max_future_s, and
	 * the 2099 entries are reusable.
	 */
	size_t slot = add(9, NOW, NOW, &raised);

	zassert_true(slot < SEEN_N);
	zassert_equal(ret_lxmf_seen_check(&seen, h(9), NOW, NOW), RET_LXMF_SEEN_DUPLICATE);
	zassert_equal(ret_lxmf_seen_check(&seen, h(10), NOW - DAY, NOW), RET_LXMF_SEEN_NEW);
}

ZTEST(lxmf_seen, test_unverified_never_evicts)
{
	bool raised;

	for (uint8_t n = 1; n <= SEEN_N; n++) {
		add(n, NOW - 10 * DAY + n, NOW, &raised);
	}
	/* Full of live entries: an unverified message is delivered but not
	 * remembered, and neither flushes an entry nor raises the floor.
	 */
	zassert_equal(add_as(5, NOW, NOW, false, &raised), RET_LXMF_SEEN_NOT_STORED);
	zassert_false(raised);
	zassert_equal(seen.floor, 0);
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), NOW - 10 * DAY + 1, NOW),
		      RET_LXMF_SEEN_DUPLICATE);

	/* With a free entry it is remembered like any other. */
	seen_entries[2].used = false;
	zassert_equal(add_as(5, NOW, NOW, false, &raised), 2);
}

ZTEST(lxmf_seen, test_full_table_raises_the_floor)
{
	bool raised;

	for (uint8_t n = 1; n <= SEEN_N; n++) {
		add(n, NOW - 10 * DAY + n, NOW, &raised);
		zassert_false(raised);
	}
	/* Full of live entries: the oldest (1) goes, and the floor rises to
	 * its timestamp, so neither it nor anything older can come back.
	 */
	size_t slot = add(5, NOW, NOW, &raised);

	zassert_true(raised);
	zassert_equal(slot, 0);
	zassert_equal(seen.floor, NOW - 10 * DAY + 1);
	zassert_equal(ret_lxmf_seen_check(&seen, h(1), NOW - 10 * DAY + 1, NOW),
		      RET_LXMF_SEEN_TOO_OLD);
	zassert_equal(ret_lxmf_seen_check(&seen, h(6), NOW - 10 * DAY, NOW), RET_LXMF_SEEN_TOO_OLD);
	zassert_equal(ret_lxmf_seen_check(&seen, h(6), NOW - 10 * DAY + 2, NOW), RET_LXMF_SEEN_NEW);
	zassert_equal(ret_lxmf_seen_check(&seen, h(2), NOW - 10 * DAY + 2, NOW),
		      RET_LXMF_SEEN_DUPLICATE);
}

ZTEST(lxmf_seen, test_expired_entries_are_reused_first)
{
	bool raised;

	for (uint8_t n = 1; n <= SEEN_N; n++) {
		add(n, NOW - 10 * DAY + n, NOW, &raised);
	}
	/* 25 days on, entries 1..4 are 35 days old: one is reused, and the
	 * floor rises to it, so after a reboot without a clock its message
	 * still cannot come back.
	 */
	size_t slot = add(5, NOW + 25 * DAY, NOW + 25 * DAY, &raised);

	zassert_true(slot < SEEN_N);
	zassert_true(raised);
	zassert_true(seen.floor >= NOW - 10 * DAY + 1);
	zassert_equal(ret_lxmf_seen_check(&seen, h(9), seen.floor, 0), RET_LXMF_SEEN_TOO_OLD);
	zassert_equal(ret_lxmf_seen_check(&seen, h(5), NOW + 25 * DAY, NOW + 25 * DAY),
		      RET_LXMF_SEEN_DUPLICATE);
}

ZTEST_SUITE(lxmf_seen, NULL, NULL, seen_reset, NULL, NULL);
