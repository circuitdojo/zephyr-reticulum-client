/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>

#include "ret_crypto.h"
#include "ret_receipt.h"

struct receipt {
	bool used;
	uint8_t packet_hash[RET_HASH_LEN];
	uint8_t sig_pub[RET_ED25519_PUB_LEN];
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	bool watched;
	int64_t sent_ms;
	int64_t deadline_ms;
	ret_receipt_cb_t cb;
	void *user;
};

static struct receipt receipts[CONFIG_RET_MAX_PENDING_RECEIPTS];

#define EXPLICIT_PROOF_LEN (RET_HASH_LEN + RET_ED25519_SIG_LEN)
#define IMPLICIT_PROOF_LEN RET_ED25519_SIG_LEN

static void finish(struct receipt *r, enum ret_receipt_status status, int64_t now_ms)
{
	struct receipt done = *r;

	r->used = false;
	if (done.cb != NULL) {
		done.cb(done.packet_hash, status, (uint32_t)(now_ms - done.sent_ms), done.user);
	}
}

void ret_receipts_clear(void)
{
	memset(receipts, 0, sizeof(receipts));
}

int ret_receipts_add(const uint8_t packet_hash[RET_HASH_LEN],
		     const uint8_t sig_pub[RET_ED25519_PUB_LEN],
		     const uint8_t dest_hash[RET_TRUNC_HASH_LEN], bool watched, int64_t now_ms,
		     uint32_t timeout_ms, ret_receipt_cb_t cb, void *user)
{
	for (size_t i = 0; i < ARRAY_SIZE(receipts); i++) {
		struct receipt *r = &receipts[i];

		if (r->used) {
			continue;
		}
		r->used = true;
		memcpy(r->packet_hash, packet_hash, RET_HASH_LEN);
		memcpy(r->sig_pub, sig_pub, RET_ED25519_PUB_LEN);
		memcpy(r->dest_hash, dest_hash, RET_TRUNC_HASH_LEN);
		r->watched = watched;
		r->sent_ms = now_ms;
		r->deadline_ms = now_ms + timeout_ms;
		r->cb = cb;
		r->user = user;
		return 0;
	}
	return -ENOMEM;
}

int ret_receipts_handle_proof(const struct ret_packet *pkt, int64_t now_ms,
			      uint8_t dest_out[RET_TRUNC_HASH_LEN])
{
	const uint8_t *sig;

	if (pkt->packet_type != RET_PKT_PROOF) {
		return -EINVAL;
	}

	for (size_t i = 0; i < ARRAY_SIZE(receipts); i++) {
		struct receipt *r = &receipts[i];

		if (!r->used ||
		    memcmp(r->packet_hash, pkt->dest_hash, RET_TRUNC_HASH_LEN) != 0) {
			continue;
		}

		if (pkt->data_len == EXPLICIT_PROOF_LEN) {
			if (memcmp(pkt->data, r->packet_hash, RET_HASH_LEN) != 0) {
				return -EBADMSG;
			}
			sig = &pkt->data[RET_HASH_LEN];
		} else if (pkt->data_len == IMPLICIT_PROOF_LEN) {
			sig = pkt->data;
		} else {
			return -EBADMSG;
		}

		if (!ret_ed25519_verify(sig, r->sig_pub, r->packet_hash, RET_HASH_LEN)) {
			return -EBADMSG;
		}

		if (dest_out != NULL) {
			memcpy(dest_out, r->dest_hash, RET_TRUNC_HASH_LEN);
		}
		finish(r, RET_RECEIPT_DELIVERED, now_ms);
		return 0;
	}

	return -ENOENT;
}

bool ret_receipts_full(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(receipts); i++) {
		if (!receipts[i].used) {
			return false;
		}
	}
	return true;
}

int ret_receipts_expire(int64_t now_ms)
{
	int n = 0;

	for (size_t i = 0; i < ARRAY_SIZE(receipts); i++) {
		if (receipts[i].used && receipts[i].deadline_ms <= now_ms) {
			n += receipts[i].watched ? 1 : 0;
			finish(&receipts[i], RET_RECEIPT_TIMEOUT, now_ms);
		}
	}
	return n;
}

void ret_receipts_fail_all(enum ret_receipt_status status, int64_t now_ms)
{
	for (size_t i = 0; i < ARRAY_SIZE(receipts); i++) {
		if (receipts[i].used) {
			finish(&receipts[i], status, now_ms);
		}
	}
}

int64_t ret_receipts_next_deadline(void)
{
	int64_t next = INT64_MAX;

	for (size_t i = 0; i < ARRAY_SIZE(receipts); i++) {
		if (receipts[i].used && receipts[i].deadline_ms < next) {
			next = receipts[i].deadline_ms;
		}
	}
	return next;
}
