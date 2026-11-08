/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * ret_storage against real Zephyr settings (NVS on native_sim's simulated
 * flash), as the client uses it.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/settings/settings.h>
#include <zephyr/ztest.h>

#include "ret_storage.h"

#define COUNT CONFIG_RET_RATCHET_COUNT

/* --- Helpers ------------------------------------------------------------ */

static struct {
	char keys[64][24];
	size_t n;
} found;

static int collect_cb(const char *key, size_t len, settings_read_cb read_cb, void *cb_arg,
		      void *param)
{
	ARG_UNUSED(len);
	ARG_UNUSED(read_cb);
	ARG_UNUSED(cb_arg);
	ARG_UNUSED(param);
	if (found.n < ARRAY_SIZE(found.keys)) {
		snprintf(found.keys[found.n++], sizeof(found.keys[0]), "ret/%s", key);
	}
	return 0;
}

/* Every "ret/" record, deleted after the load (not while iterating). */
static void wipe(void *fixture)
{
	ARG_UNUSED(fixture);
	do {
		found.n = 0;
		zassert_ok(settings_load_subtree_direct("ret", collect_cb, NULL));
		for (size_t i = 0; i < found.n; i++) {
			zassert_ok(settings_delete(found.keys[i]));
		}
	} while (found.n == ARRAY_SIZE(found.keys));
}

static size_t count_records(const char *subtree)
{
	found.n = 0;
	zassert_ok(settings_load_subtree_direct(subtree, collect_cb, NULL));
	return found.n;
}

static struct ret_storage_ratchet ratchet(uint32_t seq, uint16_t key)
{
	struct ret_storage_ratchet r = {
		.created = 1700000000ULL + seq,
		.seq = seq,
		.key = key,
	};

	memset(r.prv, (int)seq, sizeof(r.prv));
	return r;
}

static void save_ratchet(uint32_t seq, uint16_t key)
{
	struct ret_storage_ratchet r = ratchet(seq, key);

	zassert_ok(ret_storage_save_ratchet(&r));
}

static void *setup(void)
{
	zassert_ok(settings_subsys_init());
	return NULL;
}

/* --- Identity and announce clock ---------------------------------------- */

ZTEST(storage, test_identity_round_trip)
{
	uint8_t prv[RET_PRVKEY_LEN];
	uint8_t got[RET_PRVKEY_LEN];
	bool have_id = true;
	uint64_t aclk = 1;

	zassert_ok(ret_storage_load(got, &have_id, &aclk));
	zassert_false(have_id);
	zassert_equal(aclk, 0);

	memset(prv, 0xA5, sizeof(prv));
	zassert_ok(ret_storage_save_identity(prv));
	zassert_ok(ret_storage_save_aclk(4096));
	zassert_ok(ret_storage_load(got, &have_id, &aclk));
	zassert_true(have_id);
	zassert_mem_equal(got, prv, sizeof(prv));
	zassert_equal(aclk, 4096);
}

ZTEST(storage, test_identity_unreadable_fails)
{
	uint8_t got[RET_PRVKEY_LEN];
	uint8_t bad[RET_PRVKEY_LEN - 1] = { 0 };
	bool have_id;
	uint64_t aclk;

	/* Never mistaken for "no identity", which would replace it. */
	zassert_ok(settings_save_one("ret/id", bad, sizeof(bad)));
	zassert_equal(ret_storage_load(got, &have_id, &aclk), -EINVAL);
}

/* --- Ratchets ------------------------------------------------------------ */

ZTEST(storage, test_ratchets_empty)
{
	struct ret_storage_ratchet out[COUNT];
	size_t n = 99;

	zassert_ok(ret_storage_load_ratchets(out, COUNT, &n));
	zassert_equal(n, 0);
}

ZTEST(storage, test_ratchets_newest_first)
{
	struct ret_storage_ratchet out[COUNT];
	size_t n;

	/* Record numbers say nothing about age: order is by seq. */
	save_ratchet(2, 0);
	save_ratchet(3, 5);
	save_ratchet(1, 2);
	zassert_ok(ret_storage_load_ratchets(out, COUNT, &n));
	zassert_equal(n, 3);
	for (size_t i = 0; i < n; i++) {
		struct ret_storage_ratchet want = ratchet(3 - i, (uint16_t[]){ 5, 0, 2 }[i]);

		zassert_equal(out[i].seq, want.seq);
		zassert_equal(out[i].key, want.key);
		zassert_equal(out[i].created, want.created);
		zassert_mem_equal(out[i].prv, want.prv, RET_RATCHET_LEN);
	}
}

ZTEST(storage, test_ratchets_replaced_in_place)
{
	struct ret_storage_ratchet out[COUNT];
	size_t n;

	/* The client replaces the oldest by reusing its record number. */
	save_ratchet(1, 0);
	save_ratchet(2, 1);
	save_ratchet(3, 0);
	zassert_ok(ret_storage_load_ratchets(out, COUNT, &n));
	zassert_equal(n, 2);
	zassert_equal(out[0].seq, 3);
	zassert_equal(out[0].key, 0);
	zassert_equal(out[1].seq, 2);
	zassert_equal(count_records("ret/rt"), 2);
}

ZTEST(storage, test_ratchets_shrunk_keeps_newest)
{
	struct ret_storage_ratchet out[COUNT];
	size_t n;

	/* Five stored, the table now holds three: the newest three stay and
	 * the two oldest are deleted, whatever their record numbers.
	 */
	save_ratchet(4, 0);
	save_ratchet(1, 1);
	save_ratchet(5, 2);
	save_ratchet(2, 3);
	save_ratchet(3, 4);
	zassert_ok(ret_storage_load_ratchets(out, 3, &n));
	zassert_equal(n, 3);
	zassert_equal(out[0].seq, 5);
	zassert_equal(out[1].seq, 4);
	zassert_equal(out[2].seq, 3);
	zassert_equal(count_records("ret/rt"), 3);

	zassert_ok(ret_storage_load_ratchets(out, COUNT, &n));
	zassert_equal(n, 3);
	zassert_equal(out[2].seq, 3);
	zassert_equal(out[2].key, 4);
}

ZTEST(storage, test_ratchets_unreadable_fail)
{
	struct ret_storage_ratchet out[COUNT];
	uint8_t bad[3] = { 0 };
	size_t n = 99;

	/* Senders encrypt to the last ratchet they heard: an unreadable set
	 * must stop the client, not be replaced.
	 */
	save_ratchet(1, 0);
	zassert_ok(settings_save_one("ret/rt/1", bad, sizeof(bad)));
	zassert_not_equal(ret_storage_load_ratchets(out, COUNT, &n), 0);
	zassert_equal(n, 99);
	zassert_equal(count_records("ret/rt"), 2, "nothing deleted on failure");

	/* So does a key that is not a record number. */
	zassert_ok(settings_delete("ret/rt/1"));
	zassert_ok(ret_storage_load_ratchets(out, COUNT, &n));
	zassert_ok(settings_save_one("ret/rt/x", bad, sizeof(bad)));
	zassert_not_equal(ret_storage_load_ratchets(out, COUNT, &n), 0);
}

ZTEST(storage, test_ratchets_clear)
{
	struct ret_storage_ratchet out[COUNT];
	uint8_t bad[3] = { 0 };
	size_t n;

	/* More than one deletion pass, and a malformed record among them. */
	for (uint32_t i = 0; i < 20; i++) {
		save_ratchet(i + 1, (uint16_t)i);
	}
	zassert_ok(settings_save_one("ret/rt/40", bad, sizeof(bad)));
	zassert_ok(ret_storage_clear_ratchets());
	zassert_equal(count_records("ret/rt"), 0);
	zassert_ok(ret_storage_load_ratchets(out, COUNT, &n));
	zassert_equal(n, 0);
}

ZTEST(storage, test_ratchets_beside_identity)
{
	uint8_t prv[RET_PRVKEY_LEN] = { 1 };
	uint8_t got[RET_PRVKEY_LEN];
	bool have_id;
	uint64_t aclk;

	/* The identity loader ignores ret/rt records, and clearing ratchets
	 * leaves the identity alone.
	 */
	zassert_ok(ret_storage_save_identity(prv));
	save_ratchet(1, 0);
	zassert_ok(ret_storage_load(got, &have_id, &aclk));
	zassert_true(have_id);
	zassert_ok(ret_storage_clear_ratchets());
	zassert_ok(ret_storage_load(got, &have_id, &aclk));
	zassert_true(have_id);
	zassert_mem_equal(got, prv, sizeof(prv));
}

/* --- Known LXMF senders --------------------------------------------------- */

ZTEST(storage, test_known_round_trip)
{
	struct ret_storage_known k = { .seq = 7 };
	struct ret_storage_known out[4];

	memset(k.dest, 0x11, sizeof(k.dest));
	memset(k.pub, 0x22, sizeof(k.pub));
	zassert_ok(ret_storage_save_known(2, &k));
	zassert_ok(ret_storage_load_known(out, ARRAY_SIZE(out)));
	zassert_equal(out[0].seq, 0);
	zassert_equal(out[2].seq, 7);
	zassert_mem_equal(out[2].dest, k.dest, sizeof(k.dest));
	zassert_mem_equal(out[2].pub, k.pub, sizeof(k.pub));
}

ZTEST(storage, test_known_unreadable_resets)
{
	struct ret_storage_known k = { .seq = 7 };
	struct ret_storage_known out[4];
	uint8_t bad[3] = { 0 };

	/* Expendable: reset (all of them), not a failure. */
	zassert_ok(ret_storage_save_known(0, &k));
	zassert_ok(settings_save_one("ret/lk/1", bad, sizeof(bad)));
	zassert_ok(ret_storage_load_known(out, ARRAY_SIZE(out)));
	zassert_equal(out[0].seq, 0);
	zassert_equal(count_records("ret/lk"), 0);
}

/* --- Remembered LXMF messages ---------------------------------------------- */

ZTEST(storage, test_seen_round_trip_and_shrink)
{
	struct ret_lxmf_seen_entry e[4] = { 0 };
	struct ret_lxmf_seen s = { .entries = e, .count = 4 };
	struct ret_lxmf_seen_entry e2[2];
	struct ret_lxmf_seen s2 = { .entries = e2, .count = 2 };

	memset(e[1].hash, 0x33, RET_LXMF_SEEN_HASH_LEN);
	e[1].timestamp = 1700000001.5;
	e[1].used = true;
	memset(e[3].hash, 0x44, RET_LXMF_SEEN_HASH_LEN);
	e[3].timestamp = 1700000009.0;
	e[3].used = true;
	s.floor = 1600000000.0;
	zassert_ok(ret_storage_save_lxmf_seen(&s, 1, true));
	zassert_ok(ret_storage_save_lxmf_seen(&s, 3, false));

	memset(e, 0xFF, sizeof(e));
	zassert_ok(ret_storage_load_lxmf_seen(&s));
	zassert_true(s.entries[1].used);
	zassert_equal(s.entries[1].timestamp, 1700000001.5);
	zassert_false(s.entries[0].used);
	zassert_true(s.entries[3].used);
	zassert_equal(s.floor, 1600000000.0);

	/* A smaller table: slot 3 is beyond it, so its timestamp becomes
	 * the floor and nothing forgotten can come back.
	 */
	zassert_ok(ret_storage_load_lxmf_seen(&s2));
	zassert_true(s2.entries[1].used);
	zassert_equal(s2.floor, 1700000009.0);
}

ZTEST(storage, test_seen_unreadable_resets)
{
	struct ret_lxmf_seen_entry e[4] = { 0 };
	struct ret_lxmf_seen s = { .entries = e, .count = 4 };
	uint8_t bad[3] = { 0 };

	e[0].used = true;
	e[0].timestamp = 1700000000.0;
	zassert_ok(ret_storage_save_lxmf_seen(&s, 0, false));
	zassert_ok(settings_save_one("ret/lx/s/2", bad, sizeof(bad)));
	zassert_ok(ret_storage_load_lxmf_seen(&s));
	zassert_false(s.entries[0].used);
	zassert_equal(count_records("ret/lx"), 0);
}

ZTEST_SUITE(storage, NULL, setup, wipe, NULL, NULL);
