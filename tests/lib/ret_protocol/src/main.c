/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Announce validation, destination table / outbound addressing, and
 * delivery proofs, against packets produced by RNS.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ret_announce.h"
#include "ret_crypto.h"
#include "ret_destinations.h"
#include "ret_receipt.h"
#include "vectors_rns.h"

static void *setup(void)
{
	zassert_ok(ret_crypto_init());
	return NULL;
}

static int validate_raw(const uint8_t *raw, size_t len, struct ret_packet *p,
			struct ret_announce *a)
{
	zassert_ok(ret_packet_unpack(raw, len, p));
	return ret_announce_validate(p, a);
}

/* --- Announce ------------------------------------------------------ */

ZTEST(announce, test_valid_h1)
{
	struct ret_packet p;
	struct ret_announce a;

	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	zassert_mem_equal(a.dest_hash, v_dest_hash, RET_TRUNC_HASH_LEN);
	zassert_mem_equal(a.identity_hash, v_identity_hash, RET_TRUNC_HASH_LEN);
	zassert_mem_equal(a.pub, v_identity_pub, RET_PUBKEY_LEN);
	zassert_mem_equal(a.name_hash, v_name_hash, RET_NAME_HASH_LEN);
	zassert_is_null(a.ratchet);
	zassert_equal(a.app_data_len, strlen(V_APP_DATA));
	zassert_mem_equal(a.app_data, V_APP_DATA, a.app_data_len);
}

ZTEST(announce, test_valid_h2_with_ratchet)
{
	struct ret_packet p;
	struct ret_announce a;

	zassert_ok(validate_raw(v_announce_ratchet_h2, sizeof(v_announce_ratchet_h2), &p, &a));
	zassert_not_null(a.ratchet);
	zassert_mem_equal(a.ratchet, v_ratchet_pub, RET_RATCHET_LEN);
	zassert_mem_equal(a.app_data, V_APP_DATA, strlen(V_APP_DATA));
}

ZTEST(announce, test_real_destination_announce)
{
	/* Built by RNS Destination.announce() with ratchets enabled. */
	struct ret_packet p;
	struct ret_announce a;

	zassert_ok(validate_raw(v_announce_real, sizeof(v_announce_real), &p, &a));
	zassert_equal(p.context_flag, 1);
	zassert_mem_equal(a.dest_hash, v_dest_hash, RET_TRUNC_HASH_LEN);
	zassert_mem_equal(a.ratchet, v_ratchet_pub, RET_RATCHET_LEN);
	zassert_mem_equal(a.app_data, V_APP_DATA, strlen(V_APP_DATA));
}

ZTEST(announce, test_path_response_announce)
{
	struct ret_packet p;
	struct ret_announce a;

	zassert_ok(validate_raw(v_announce_path_response, sizeof(v_announce_path_response), &p,
				&a));
	zassert_equal(p.context, 0x0B); /* PATH_RESPONSE */
	zassert_mem_equal(a.dest_hash, v_dest_hash, RET_TRUNC_HASH_LEN);
}

ZTEST(announce, test_max_size_announce)
{
	struct ret_packet p;
	struct ret_announce a;

	zassert_equal(sizeof(v_announce_max), RET_MTU);
	zassert_ok(validate_raw(v_announce_max, sizeof(v_announce_max), &p, &a));
	zassert_equal(a.app_data_len, RET_MTU - RET_H1_HEADER_LEN - 148);
}

ZTEST(announce, test_tampered_rejected)
{
	static const size_t offsets[] = {
		RET_H1_HEADER_LEN + 0,                 /* X25519 key */
		RET_H1_HEADER_LEN + 40,                /* Ed25519 key */
		RET_H1_HEADER_LEN + 64,                /* name hash */
		RET_H1_HEADER_LEN + 74,                /* random hash */
		RET_H1_HEADER_LEN + 84 + 5,            /* signature */
		sizeof(v_announce) - 1,                /* app data */
		2,                                     /* destination hash */
	};
	uint8_t raw[sizeof(v_announce)];
	struct ret_packet p;
	struct ret_announce a;

	for (size_t i = 0; i < ARRAY_SIZE(offsets); i++) {
		memcpy(raw, v_announce, sizeof(raw));
		raw[offsets[i]] ^= 0x01;
		zassert_equal(validate_raw(raw, sizeof(raw), &p, &a), -EBADMSG, "offset %zu",
			      offsets[i]);
	}
}

ZTEST(announce, test_hops_not_signed)
{
	/* Transport nodes rewrite hops; the signature must not cover it. */
	uint8_t raw[sizeof(v_announce)];
	struct ret_packet p;
	struct ret_announce a;

	memcpy(raw, v_announce, sizeof(raw));
	raw[1] = 7;
	zassert_ok(validate_raw(raw, sizeof(raw), &p, &a));
}

ZTEST(announce, test_ratchet_flag_mismatch_rejected)
{
	/* Clearing context_flag shifts the parse: signature check fails. */
	uint8_t raw[sizeof(v_announce_ratchet_h2)];
	struct ret_packet p;
	struct ret_announce a;

	memcpy(raw, v_announce_ratchet_h2, sizeof(raw));
	raw[0] &= ~0x20;
	zassert_equal(validate_raw(raw, sizeof(raw), &p, &a), -EBADMSG);
}

ZTEST(announce, test_wrong_dest_rejected)
{
	struct ret_packet p;
	struct ret_announce a;

	zassert_equal(validate_raw(v_announce_wrong_dest, sizeof(v_announce_wrong_dest), &p, &a),
		      -EACCES);
}

ZTEST(announce, test_truncated_and_wrong_type)
{
	struct ret_packet p;
	struct ret_announce a;

	/* Fixed part is 148 bytes; one short of that. */
	zassert_equal(validate_raw(v_announce, RET_H1_HEADER_LEN + 147, &p, &a), -EMSGSIZE);
	zassert_ok(ret_packet_unpack(v_data_h1, sizeof(v_data_h1), &p));
	zassert_equal(ret_announce_validate(&p, &a), -EINVAL);
}

ZTEST(announce, test_build_matches_rns)
{
	/* Ed25519 is deterministic: same key, same fields, same bytes. */
	struct ret_local_identity id;
	struct ret_packet p;
	struct ret_announce a;
	uint8_t out[RET_MTU];
	int n;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	n = ret_announce_build(&id, v_name_hash, v_dest_hash, a.random_hash, NULL,
			       (const uint8_t *)V_APP_DATA, strlen(V_APP_DATA), RET_CONTEXT_NONE,
			       out, sizeof(out));
	zassert_equal(n, sizeof(v_announce));
	zassert_mem_equal(out, v_announce, sizeof(v_announce));
}

ZTEST(announce, test_build_path_response_validates)
{
	struct ret_local_identity id;
	struct ret_packet p;
	struct ret_announce a;
	uint8_t rh[RET_RANDOM_HASH_LEN] = { 1, 2, 3, 4, 5, 0, 0, 0, 0, 9 };
	uint8_t out[RET_MTU];
	int n;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	n = ret_announce_build(&id, v_name_hash, v_dest_hash, rh, NULL, NULL, 0,
			       RET_CONTEXT_PATH_RESPONSE, out, sizeof(out));
	zassert_equal(n, RET_H1_HEADER_LEN + 148);
	zassert_ok(validate_raw(out, n, &p, &a));
	zassert_equal(p.context, RET_CONTEXT_PATH_RESPONSE);
	zassert_equal(a.app_data_len, 0);

	zassert_equal(ret_announce_build(&id, v_name_hash, v_dest_hash, rh, NULL, out,
					 RET_MTU - RET_H1_HEADER_LEN - 148 + 1, RET_CONTEXT_NONE,
					 out, sizeof(out)),
		      -EMSGSIZE);
	/* A ratchet takes 32 bytes of that room. */
	zassert_equal(ret_announce_build(&id, v_name_hash, v_dest_hash, rh, v_ratchet_pub, out,
					 RET_MTU - RET_H1_HEADER_LEN - 148 - 32 + 1,
					 RET_CONTEXT_NONE, out, sizeof(out)),
		      -EMSGSIZE);
}

ZTEST(announce, test_build_ratchet_matches_rns)
{
	/* Destination.announce() with ratchets enabled, its inputs pinned. */
	struct ret_local_identity id;
	struct ret_packet p;
	struct ret_announce a;
	uint8_t out[RET_MTU];
	int n;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	zassert_ok(validate_raw(v_announce_real, sizeof(v_announce_real), &p, &a));
	zassert_not_null(a.ratchet);
	zassert_mem_equal(a.ratchet, v_ratchet_pub, RET_RATCHET_LEN);
	n = ret_announce_build(&id, v_name_hash, v_dest_hash, a.random_hash, v_ratchet_pub,
			       (const uint8_t *)V_APP_DATA, strlen(V_APP_DATA), RET_CONTEXT_NONE,
			       out, sizeof(out));
	zassert_equal(n, sizeof(v_announce_real));
	zassert_mem_equal(out, v_announce_real, sizeof(v_announce_real));
}

ZTEST(announce, test_proof_build_matches_rns)
{
	struct ret_local_identity id;
	uint8_t out[RET_MTU];
	int n;

	zassert_ok(ret_local_identity_load(&id, v_identity_prv));
	n = ret_proof_build(&id, v_packet_hash, out, sizeof(out));
	zassert_equal(n, sizeof(v_proof_implicit));
	zassert_mem_equal(out, v_proof_implicit, sizeof(v_proof_implicit));
}

ZTEST_SUITE(announce, NULL, setup, NULL, NULL, NULL);

/* --- Destinations -------------------------------------------------- */

static void dest_before(void *f)
{
	ARG_UNUSED(f);
	ret_destinations_clear();
}

ZTEST(destinations, test_direct_path_uses_h1)
{
	struct ret_packet p, out = { 0 };
	struct ret_announce a;
	const struct ret_destination *d;

	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, &d, NULL));
	zassert_equal_ptr(ret_destinations_find(v_dest_hash), d);
	zassert_equal(d->hops, 1);
	zassert_false(d->has_transport_id);
	zassert_false(d->has_ratchet);

	ret_destinations_address(d, &out);
	zassert_equal(out.header_type, RET_HEADER_1);
	zassert_equal(out.transport_type, RET_TRANSPORT_BROADCAST);
	zassert_mem_equal(out.dest_hash, v_dest_hash, RET_TRUNC_HASH_LEN);
}

ZTEST(destinations, test_transported_path_uses_h2)
{
	struct ret_packet p, out = { 0 };
	struct ret_announce a;
	const struct ret_destination *d;

	zassert_ok(validate_raw(v_announce_ratchet_h2, sizeof(v_announce_ratchet_h2), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, &d, NULL));
	zassert_equal(d->hops, 2);
	zassert_true(d->has_transport_id);
	zassert_true(d->has_ratchet);
	zassert_mem_equal(d->ratchet, v_ratchet_pub, RET_RATCHET_LEN);

	ret_destinations_address(d, &out);
	zassert_equal(out.header_type, RET_HEADER_2);
	zassert_equal(out.transport_type, RET_TRANSPORT_TRANSPORT);
	zassert_mem_equal(out.transport_id, v_transport_id, RET_TRUNC_HASH_LEN);
}

ZTEST(destinations, test_ratchet_kept_and_path_updated)
{
	struct ret_packet p;
	struct ret_announce a;
	const struct ret_destination *d;

	zassert_ok(validate_raw(v_announce_ratchet_h2, sizeof(v_announce_ratchet_h2), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, &d, NULL));
	/* A later ratchet-less announce over a direct path. */
	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 200, &d, NULL));
	zassert_true(d->has_ratchet);
	zassert_equal(d->hops, 1);
	zassert_false(d->has_transport_id);
	zassert_equal(d->last_seen_ms, 200);
}

ZTEST(destinations, test_repeat_announce_not_fresh)
{
	struct ret_packet p;
	struct ret_announce a;
	bool fresh;

	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, NULL, &fresh));
	zassert_true(fresh);
	/* Same announce again (rebroadcast vs path response). */
	zassert_ok(ret_destinations_update(&p, &a, 110, NULL, &fresh));
	zassert_false(fresh);
	/* A new announce has a new random hash. */
	zassert_ok(validate_raw(v_announce_real, sizeof(v_announce_real), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 120, NULL, &fresh));
	zassert_true(fresh);
}

ZTEST(destinations, test_older_announce_ignored)
{
	struct ret_packet p;
	struct ret_announce a;
	const struct ret_destination *d;
	uint8_t rh_new[RET_RANDOM_HASH_LEN] = { 1, 1, 1, 1, 1, 0, 0, 0, 0, 200 };
	uint8_t rh_old[RET_RANDOM_HASH_LEN] = { 2, 2, 2, 2, 2, 0, 0, 0, 0, 100 };
	uint8_t rh_newer[RET_RANDOM_HASH_LEN] = { 3, 3, 3, 3, 3, 0, 0, 0, 1, 0 };
	uint8_t ratchet_old[RET_RATCHET_LEN];
	bool fresh;

	/* ret_destinations_update trusts its caller to have validated the
	 * announce, so the random hash can be swapped to test ordering.
	 */
	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	a.random_hash = rh_new;
	zassert_ok(ret_destinations_update(&p, &a, 100, &d, &fresh));
	zassert_true(fresh);

	memset(ratchet_old, 0xAA, sizeof(ratchet_old));
	a.random_hash = rh_old;
	a.ratchet = ratchet_old;
	p.hops = 5;
	zassert_ok(ret_destinations_update(&p, &a, 200, &d, &fresh));
	zassert_false(fresh);
	zassert_false(d->has_ratchet);
	zassert_equal(d->hops, 1);
	zassert_mem_equal(d->random_hash, rh_new, RET_RANDOM_HASH_LEN);

	a.random_hash = rh_newer;
	a.ratchet = NULL;
	zassert_ok(ret_destinations_update(&p, &a, 300, &d, &fresh));
	zassert_true(fresh);
	zassert_equal(d->hops, 6);
}

ZTEST(destinations, test_invalidate_paths)
{
	struct ret_packet p, out = { 0 };
	struct ret_announce a;
	const struct ret_destination *d;

	zassert_ok(validate_raw(v_announce_ratchet_h2, sizeof(v_announce_ratchet_h2), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, &d, NULL));
	zassert_true(d->path_valid);

	ret_destinations_invalidate_paths();
	zassert_false(d->path_valid);
	zassert_false(d->has_transport_id);
	/* Keys survive: only the path is relearned. */
	zassert_true(d->has_ratchet);
	zassert_mem_equal(d->pub, v_identity_pub, RET_PUBKEY_LEN);

	/* A repeat of the same announce (e.g. a path response from a node
	 * that cached it) revalidates the path.
	 */
	zassert_ok(ret_destinations_update(&p, &a, 200, &d, NULL));
	zassert_true(d->path_valid);
	ret_destinations_address(d, &out);
	zassert_equal(out.header_type, RET_HEADER_2);
}

ZTEST(destinations, test_mark_proves)
{
	struct ret_packet p;
	struct ret_announce a;
	const struct ret_destination *d;

	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, &d, NULL));
	zassert_false(d->proves);
	ret_destinations_mark_proves(v_dest_hash);
	zassert_true(d->proves);
	/* Survives path invalidation and later announces. */
	ret_destinations_invalidate_paths();
	zassert_ok(ret_destinations_update(&p, &a, 200, &d, NULL));
	zassert_true(d->proves);
}

ZTEST(destinations, test_changed_key_rejected)
{
	struct ret_packet p;
	struct ret_announce a;
	uint8_t other_pub[RET_PUBKEY_LEN];

	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	zassert_ok(ret_destinations_update(&p, &a, 100, NULL, NULL));

	memcpy(other_pub, v_identity_pub, sizeof(other_pub));
	other_pub[0] ^= 0xFF;
	a.pub = other_pub;
	zassert_equal(ret_destinations_update(&p, &a, 200, NULL, NULL), -EPERM);
	zassert_mem_equal(ret_destinations_find(v_dest_hash)->pub, v_identity_pub, RET_PUBKEY_LEN);
}

ZTEST(destinations, test_lru_eviction)
{
	struct ret_packet p;
	struct ret_announce a;

	zassert_ok(validate_raw(v_announce, sizeof(v_announce), &p, &a));
	for (int i = 0; i <= CONFIG_RET_MAX_KNOWN_DESTINATIONS; i++) {
		a.dest_hash[0] = (uint8_t)i;
		zassert_ok(ret_destinations_update(&p, &a, 1000 + i, NULL, NULL));
	}
	/* Entry 0 was the oldest and got evicted by the last insert. */
	a.dest_hash[0] = 0;
	zassert_is_null(ret_destinations_find(a.dest_hash));
	a.dest_hash[0] = CONFIG_RET_MAX_KNOWN_DESTINATIONS;
	zassert_not_null(ret_destinations_find(a.dest_hash));
}

ZTEST_SUITE(destinations, NULL, setup, dest_before, NULL, NULL);

/* --- Receipts ------------------------------------------------------ */

struct cb_log {
	int calls;
	enum ret_receipt_status status;
	uint32_t rtt;
	uint8_t hash[RET_HASH_LEN];
};

static struct cb_log logged;

static void on_receipt(const uint8_t hash[RET_PACKET_HASH_LEN], enum ret_receipt_status st,
		       uint32_t rtt, void *user)
{
	zassert_equal_ptr(user, &logged);
	logged.calls++;
	logged.status = st;
	logged.rtt = rtt;
	memcpy(logged.hash, hash, RET_HASH_LEN);
}

static const uint8_t *sig_pub(void)
{
	return &v_identity_pub[RET_X25519_LEN];
}

static void receipt_before(void *f)
{
	ARG_UNUSED(f);
	memset(&logged, 0, sizeof(logged));
	ret_receipts_clear();
}

static int proof(const uint8_t *raw, size_t len, int64_t now)
{
	struct ret_packet p;

	zassert_ok(ret_packet_unpack(raw, len, &p));
	return ret_receipts_handle_proof(&p, now, NULL);
}

ZTEST(receipt, test_implicit_proof)
{
	zassert_ok(ret_receipts_add(v_packet_hash, sig_pub(), v_dest_hash, true, 1000, 5000, on_receipt, &logged));
	zassert_equal(ret_receipts_next_deadline(), 6000);
	zassert_ok(proof(v_proof_implicit, sizeof(v_proof_implicit), 1250));
	zassert_equal(logged.calls, 1);
	zassert_equal(logged.status, RET_RECEIPT_DELIVERED);
	zassert_equal(logged.rtt, 250);
	zassert_mem_equal(logged.hash, v_packet_hash, RET_HASH_LEN);
	zassert_equal(ret_receipts_next_deadline(), INT64_MAX);
	/* A duplicate proof matches nothing now. */
	zassert_equal(proof(v_proof_implicit, sizeof(v_proof_implicit), 1300), -ENOENT);
}

ZTEST(receipt, test_proof_reports_destination)
{
	struct ret_packet p;
	uint8_t dest[RET_TRUNC_HASH_LEN] = { 0 };

	zassert_ok(ret_receipts_add(v_packet_hash, sig_pub(), v_dest_hash, false, 0, 5000,
				    on_receipt, &logged));
	zassert_ok(ret_packet_unpack(v_proof_implicit, sizeof(v_proof_implicit), &p));
	zassert_ok(ret_receipts_handle_proof(&p, 10, dest));
	zassert_mem_equal(dest, v_dest_hash, RET_TRUNC_HASH_LEN);
}

ZTEST(receipt, test_only_watched_timeouts_counted)
{
	uint8_t h[RET_HASH_LEN];

	memcpy(h, v_packet_hash, sizeof(h));
	zassert_ok(ret_receipts_add(h, sig_pub(), v_dest_hash, false, 0, 100, on_receipt,
				    &logged));
	h[0] ^= 1;
	zassert_ok(ret_receipts_add(h, sig_pub(), v_dest_hash, true, 0, 100, on_receipt,
				    &logged));
	/* Both time out and both callbacks fire; only one counts. */
	zassert_equal(ret_receipts_expire(100), 1);
	zassert_equal(logged.calls, 2);
}

ZTEST(receipt, test_explicit_proof)
{
	zassert_ok(ret_receipts_add(v_packet_hash, sig_pub(), v_dest_hash, true, 0, 5000, on_receipt, &logged));
	zassert_ok(proof(v_proof_explicit, sizeof(v_proof_explicit), 10));
	zassert_equal(logged.status, RET_RECEIPT_DELIVERED);
}

ZTEST(receipt, test_bad_proof_keeps_receipt)
{
	uint8_t raw[sizeof(v_proof_implicit)];

	zassert_ok(ret_receipts_add(v_packet_hash, sig_pub(), v_dest_hash, true, 0, 5000, on_receipt, &logged));

	memcpy(raw, v_proof_implicit, sizeof(raw));
	raw[sizeof(raw) - 1] ^= 0x01;
	zassert_equal(proof(raw, sizeof(raw), 10), -EBADMSG);

	/* Explicit proof naming a different packet hash. */
	uint8_t ex[sizeof(v_proof_explicit)];

	memcpy(ex, v_proof_explicit, sizeof(ex));
	ex[RET_H1_HEADER_LEN + 31] ^= 0x01;
	zassert_equal(proof(ex, sizeof(ex), 10), -EBADMSG);

	/* Wrong length. */
	zassert_equal(proof(v_proof_implicit, sizeof(v_proof_implicit) - 1, 10), -EBADMSG);

	zassert_equal(logged.calls, 0);
	zassert_ok(proof(v_proof_implicit, sizeof(v_proof_implicit), 20));
	zassert_equal(logged.calls, 1);
}

ZTEST(receipt, test_proof_signed_by_other_key)
{
	uint8_t other[RET_ED25519_PUB_LEN];

	memcpy(other, sig_pub(), sizeof(other));
	other[3] ^= 0x10;
	zassert_ok(ret_receipts_add(v_packet_hash, other, v_dest_hash, true, 0, 5000, on_receipt, &logged));
	zassert_equal(proof(v_proof_implicit, sizeof(v_proof_implicit), 10), -EBADMSG);
}

ZTEST(receipt, test_unmatched_proof)
{
	zassert_equal(proof(v_proof_implicit, sizeof(v_proof_implicit), 10), -ENOENT);
}

ZTEST(receipt, test_timeout)
{
	zassert_ok(ret_receipts_add(v_packet_hash, sig_pub(), v_dest_hash, true, 1000, 5000, on_receipt, &logged));
	zassert_equal(ret_receipts_expire(5999), 0);
	zassert_equal(logged.calls, 0);
	zassert_equal(ret_receipts_expire(6000), 1);
	zassert_equal(logged.calls, 1);
	zassert_equal(logged.status, RET_RECEIPT_TIMEOUT);
	zassert_equal(logged.rtt, 5000);
	zassert_equal(proof(v_proof_implicit, sizeof(v_proof_implicit), 6100), -ENOENT);
}

ZTEST(receipt, test_fail_all_and_capacity)
{
	uint8_t h[RET_HASH_LEN];

	memcpy(h, v_packet_hash, sizeof(h));
	zassert_false(ret_receipts_full());
	for (int i = 0; i < CONFIG_RET_MAX_PENDING_RECEIPTS; i++) {
		h[31] = (uint8_t)i;
		zassert_ok(ret_receipts_add(h, sig_pub(), v_dest_hash, true, 0, 5000, on_receipt, &logged));
	}
	zassert_true(ret_receipts_full());
	zassert_equal(ret_receipts_add(h, sig_pub(), v_dest_hash, true, 0, 5000, on_receipt, &logged), -ENOMEM);

	ret_receipts_fail_all(RET_RECEIPT_DISCONNECTED, 10);
	zassert_false(ret_receipts_full());
	zassert_equal(logged.calls, CONFIG_RET_MAX_PENDING_RECEIPTS);
	zassert_equal(logged.status, RET_RECEIPT_DISCONNECTED);
	zassert_equal(ret_receipts_next_deadline(), INT64_MAX);
}

ZTEST_SUITE(receipt, NULL, setup, receipt_before, NULL, NULL);
