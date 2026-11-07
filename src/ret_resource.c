/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <mpack.h>

#include "ret_crypto.h"
#include "ret_mp.h"
#include "ret_resource.h"

#define HASHMAP_EXHAUSTED 0xFF

static int read_bin_exact(mpack_reader_t *r, size_t want, const uint8_t **p)
{
	uint32_t len = mpack_expect_bin(r);

	if (mpack_reader_error(r) != mpack_ok || len != want) {
		return -EBADMSG;
	}
	*p = (const uint8_t *)mpack_read_bytes_inplace(r, len);
	mpack_done_bin(r);
	return mpack_reader_error(r) == mpack_ok ? 0 : -EBADMSG;
}

int ret_resource_adv_parse(const uint8_t *plain, size_t len, struct ret_resource_adv *adv)
{
	mpack_reader_t r;
	uint32_t keys;
	uint32_t seen = 0;

	memset(adv, 0, sizeof(*adv));
	mpack_reader_init_data(&r, (const char *)plain, len);
	keys = mpack_expect_map_max(&r, 32);
	if (mpack_reader_error(&r) != mpack_ok) {
		return -EBADMSG;
	}

	for (uint32_t k = 0; k < keys; k++) {
		char key[2] = { 0 };
		uint32_t klen = mpack_expect_str(&r);
		int err = 0;

		if (mpack_reader_error(&r) != mpack_ok) {
			mpack_reader_destroy(&r);
			return -EBADMSG;
		}
		if (klen == 1) {
			mpack_read_bytes(&r, key, 1);
		} else {
			mpack_skip_bytes(&r, klen); /* not a key we know: value skipped */
		}
		mpack_done_str(&r);

		switch (key[0]) {
		case 't': adv->t = mpack_expect_u64(&r); seen |= BIT(0); break;
		case 'd': adv->d = mpack_expect_u64(&r); seen |= BIT(1); break;
		case 'n': adv->n = mpack_expect_u64(&r); seen |= BIT(2); break;
		case 'i': adv->i = mpack_expect_u64(&r); seen |= BIT(3); break;
		case 'l': adv->l = mpack_expect_u64(&r); seen |= BIT(4); break;
		case 'f': adv->f = mpack_expect_u64(&r); seen |= BIT(5); break;
		case 'h': err = read_bin_exact(&r, RET_SHA256_LEN, &adv->h); seen |= BIT(6); break;
		case 'r':
			err = read_bin_exact(&r, RET_RESOURCE_RANDOM_LEN, &adv->r);
			seen |= BIT(7);
			break;
		case 'q':
			if (mpack_peek_tag(&r).type == mpack_type_nil) {
				mpack_expect_nil(&r);
			} else {
				err = read_bin_exact(&r, RET_TRUNC_HASH_LEN, &adv->q);
			}
			break;
		case 'm': {
			uint32_t mlen = mpack_expect_bin(&r);

			adv->m = (const uint8_t *)mpack_read_bytes_inplace(&r, mlen);
			adv->m_len = mlen;
			mpack_done_bin(&r);
			seen |= BIT(8);
			break;
		}
		default:
			err = ret_mp_skip(&r); /* 'o' and anything newer */
			break;
		}
		if (err || mpack_reader_error(&r) != mpack_ok) {
			mpack_reader_destroy(&r);
			return -EBADMSG;
		}
	}
	if (mpack_reader_destroy(&r) != mpack_ok || seen != BIT_MASK(9)) {
		return -EBADMSG;
	}
	return 0;
}

int ret_resource_rx_init(struct ret_resource_rx *rx, const struct ret_resource_adv *adv,
			 uint8_t *stream, size_t cap)
{
	uint64_t want_parts;

	if ((adv->f & RET_RESOURCE_F_COMPRESSED) || (adv->f & RET_RESOURCE_F_SPLIT) ||
	    (adv->f & RET_RESOURCE_F_METADATA) || !(adv->f & RET_RESOURCE_F_ENCRYPTED) ||
	    adv->l != 1 || adv->i != 1) {
		return -ENOTSUP;
	}
	if (adv->t > cap || adv->t > CONFIG_RET_RESOURCE_MAX_SIZE) {
		return -EFBIG;
	}
	want_parts = DIV_ROUND_UP(adv->t, RET_RESOURCE_SDU);
	/* The advertisement carries the first hashmap segment, whole. */
	if (adv->t == 0 || adv->n != want_parts ||
	    adv->m_len != MIN(adv->n, RET_RESOURCE_HASHMAP_SEG) * RET_RESOURCE_MAPHASH_LEN) {
		return -EBADMSG;
	}

	memset(rx, 0, sizeof(*rx));
	memcpy(rx->h, adv->h, sizeof(rx->h));
	memcpy(rx->r, adv->r, sizeof(rx->r));
	rx->t = (uint32_t)adv->t;
	rx->n = (uint32_t)adv->n;
	rx->stream = stream;
	rx->hashmap_height = (uint32_t)(adv->m_len / RET_RESOURCE_MAPHASH_LEN);
	memcpy(rx->hashmap, adv->m, adv->m_len);
	rx->cch = -1;
	rx->window = RET_RESOURCE_WINDOW;
	return 0;
}

int ret_resource_rx_request(struct ret_resource_rx *rx, uint8_t *out, size_t cap)
{
	uint8_t hashes[RET_RESOURCE_WINDOW_MAX * RET_RESOURCE_MAPHASH_LEN];
	size_t nh = 0;
	bool exhausted = false;
	uint32_t requested = 0;
	size_t off = 0;

	/* Resource.request_next scans parts[cch+1 : cch+1+window], the range
	 * rx_part accepts from; parts already in still use up the window.
	 */
	uint32_t start = (uint32_t)(rx->cch + 1);
	uint32_t end = MIN(start + rx->window, rx->n);

	for (uint32_t pn = start; pn < end; pn++) {
		if (rx->have[pn]) {
			continue;
		}
		if (pn < rx->hashmap_height) {
			memcpy(&hashes[nh], rx->hashmap[pn], RET_RESOURCE_MAPHASH_LEN);
			nh += RET_RESOURCE_MAPHASH_LEN;
			requested++;
		} else {
			exhausted = true;
			break;
		}
	}

	if (cap < 1 + (exhausted ? RET_RESOURCE_MAPHASH_LEN : 0) + RET_SHA256_LEN + nh) {
		return -ENOBUFS;
	}
	out[off++] = exhausted ? HASHMAP_EXHAUSTED : 0x00;
	if (exhausted) {
		memcpy(&out[off], rx->hashmap[rx->hashmap_height - 1], RET_RESOURCE_MAPHASH_LEN);
		off += RET_RESOURCE_MAPHASH_LEN;
	}
	memcpy(&out[off], rx->h, RET_SHA256_LEN);
	off += RET_SHA256_LEN;
	memcpy(&out[off], hashes, nh);
	off += nh;

	rx->outstanding = requested;
	rx->waiting_hmu = exhausted;
	return (int)off;
}

enum ret_resource_part ret_resource_rx_part(struct ret_resource_rx *rx, const uint8_t *data,
					    size_t len)
{
	uint8_t digest[RET_SHA256_LEN];
	const struct ret_iov iov[] = { { data, len }, { rx->r, sizeof(rx->r) } };
	bool matched = false;

	if (len == 0 || len > RET_RESOURCE_SDU || ret_sha256(iov, 2, digest) != 0) {
		return RET_RESOURCE_PART_IGNORED;
	}

	uint32_t start = (uint32_t)(rx->cch + 1);
	uint32_t end = MIN(start + rx->window, rx->hashmap_height);

	for (uint32_t i = start; i < end; i++) {
		if (memcmp(rx->hashmap[i], digest, RET_RESOURCE_MAPHASH_LEN) != 0 || rx->have[i]) {
			continue;
		}
		/* Every part but the last fills a whole SDU; nothing may run past t. */
		size_t off = (size_t)i * RET_RESOURCE_SDU;
		bool last = i == rx->n - 1;

		if ((!last && len != RET_RESOURCE_SDU) || off + len > rx->t ||
		    (last && off + len != rx->t)) {
			return RET_RESOURCE_PART_IGNORED;
		}
		memcpy(&rx->stream[off], data, len);
		rx->have[i] = true;
		rx->received++;
		if (rx->outstanding > 0) {
			rx->outstanding--;
		}
		while ((uint32_t)(rx->cch + 1) < rx->n && rx->have[rx->cch + 1]) {
			rx->cch++;
		}
		matched = true;
		break;
	}

	if (!matched) {
		return RET_RESOURCE_PART_IGNORED;
	}
	if (rx->received == rx->n) {
		return RET_RESOURCE_PART_COMPLETE;
	}
	if (rx->outstanding == 0) {
		if (rx->window < RET_RESOURCE_WINDOW_MAX) {
			rx->window++;
		}
		return RET_RESOURCE_PART_WINDOW;
	}
	return RET_RESOURCE_PART_ACCEPTED;
}

void ret_resource_rx_timeout(struct ret_resource_rx *rx)
{
	if (rx->window > RET_RESOURCE_WINDOW_MIN) {
		rx->window--;
	}
}

int ret_resource_rx_hmu(struct ret_resource_rx *rx, const uint8_t *plain, size_t len)
{
	mpack_reader_t r;
	uint64_t segment;
	uint32_t hlen;
	const uint8_t *hashes;

	if (!rx->waiting_hmu || len < RET_SHA256_LEN ||
	    memcmp(plain, rx->h, RET_SHA256_LEN) != 0) {
		return -EBADMSG;
	}
	mpack_reader_init_data(&r, (const char *)&plain[RET_SHA256_LEN], len - RET_SHA256_LEN);
	if (mpack_expect_array(&r) != 2) {
		mpack_reader_destroy(&r);
		return -EBADMSG;
	}
	segment = mpack_expect_u64(&r);
	hlen = mpack_expect_bin(&r);
	hashes = (const uint8_t *)mpack_read_bytes_inplace(&r, hlen);
	mpack_done_bin(&r);
	if (mpack_reader_destroy(&r) != mpack_ok || hlen == 0 ||
	    hlen % RET_RESOURCE_MAPHASH_LEN != 0 ||
	    hlen / RET_RESOURCE_MAPHASH_LEN > RET_RESOURCE_HASHMAP_SEG ||
	    segment > rx->n / RET_RESOURCE_HASHMAP_SEG) {
		return -EBADMSG;
	}

	uint32_t first = (uint32_t)segment * RET_RESOURCE_HASHMAP_SEG;
	uint32_t count = hlen / RET_RESOURCE_MAPHASH_LEN;

	if (first > rx->hashmap_height || first + count > rx->n) {
		return -EBADMSG;
	}
	memcpy(rx->hashmap[first], hashes, hlen);
	rx->hashmap_height = MAX(rx->hashmap_height, first + count);
	rx->waiting_hmu = false;
	return 0;
}

int ret_resource_rx_assemble(const struct ret_resource_rx *rx, const uint8_t key[RET_TOKEN_KEY_LEN],
			     uint8_t *out, size_t cap)
{
	uint8_t digest[RET_SHA256_LEN];
	int n = ret_token_decrypt(key, rx->stream, rx->t, out, cap);

	if (n < 0) {
		return n == -ENOBUFS ? -EFBIG : -EBADMSG;
	}
	if (n < RET_RESOURCE_RANDOM_LEN) {
		return -EBADMSG;
	}
	size_t len = (size_t)n - RET_RESOURCE_RANDOM_LEN;

	memmove(out, &out[RET_RESOURCE_RANDOM_LEN], len);

	const struct ret_iov iov[] = { { out, len }, { rx->r, sizeof(rx->r) } };

	if (ret_sha256(iov, 2, digest) != 0 || !ret_ct_equal(digest, rx->h, RET_SHA256_LEN)) {
		ret_wipe(out, (size_t)n);
		return -EBADMSG;
	}
	return (int)len;
}

int ret_resource_proof(const struct ret_resource_rx *rx, const uint8_t *data, size_t len,
		       uint8_t out[RET_RESOURCE_PROOF_LEN])
{
	const struct ret_iov iov[] = { { data, len }, { rx->h, sizeof(rx->h) } };

	memcpy(out, rx->h, RET_SHA256_LEN);
	return ret_sha256(iov, 2, &out[RET_SHA256_LEN]);
}
