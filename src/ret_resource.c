/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
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

/* --- Sending ---------------------------------------------------------- */

int ret_resource_tx_init(struct ret_resource_tx *tx, const uint8_t key[RET_TOKEN_KEY_LEN],
			 const uint8_t iv[RET_AES_BLOCK_LEN],
			 const uint8_t prefix[RET_RESOURCE_RANDOM_LEN], const uint8_t *data,
			 size_t len, uint8_t *stream, size_t cap)
{
	size_t t = RET_RESOURCE_STREAM_LEN(len);
	uint8_t *pt = &stream[RET_AES_BLOCK_LEN];
	int n;

	if (len == 0 || t > cap || DIV_ROUND_UP(t, RET_RESOURCE_SDU) > RET_RESOURCE_MAX_PARTS) {
		return -EFBIG;
	}
	memset(tx, 0, sizeof(*tx));

	/* Resource: data = random4 | data, then link.encrypt(data). The token
	 * encrypts in place from where its ciphertext goes (after the IV).
	 */
	memcpy(pt, prefix, RET_RESOURCE_RANDOM_LEN);
	memcpy(&pt[RET_RESOURCE_RANDOM_LEN], data, len);
	n = ret_token_encrypt_det(key, iv, pt, RET_RESOURCE_RANDOM_LEN + len, stream, cap);
	if (n < 0) {
		ret_wipe(stream, cap);
		return n == -ENOBUFS ? -EFBIG : n;
	}
	tx->t = (uint32_t)n;
	tx->d = (uint32_t)len;
	tx->n = DIV_ROUND_UP(tx->t, RET_RESOURCE_SDU);
	tx->stream = stream;
	return 0;
}

int ret_resource_tx_map(struct ret_resource_tx *tx, const uint8_t *data, size_t len,
			const uint8_t r[RET_RESOURCE_RANDOM_LEN])
{
	uint8_t digest[RET_SHA256_LEN];
	int err;

	memcpy(tx->r, r, RET_RESOURCE_RANDOM_LEN);

	const struct ret_iov h_iov[] = { { data, len }, { tx->r, sizeof(tx->r) } };

	err = ret_sha256(h_iov, 2, tx->h);
	if (err) {
		return err;
	}

	const struct ret_iov p_iov[] = { { data, len }, { tx->h, sizeof(tx->h) } };

	err = ret_sha256(p_iov, 2, tx->expected_proof);
	if (err) {
		return err;
	}

	for (uint32_t i = 0; i < tx->n; i++) {
		size_t plen;
		const uint8_t *part = ret_resource_tx_part(tx, i, &plen);
		const struct ret_iov iov[] = { { part, plen }, { tx->r, sizeof(tx->r) } };

		err = ret_sha256(iov, 2, digest);
		if (err) {
			return err;
		}
		/* Resource keeps the last COLLISION_GUARD_SIZE map hashes and
		 * remaps on any repeat among them.
		 */
		for (uint32_t j = i > RET_RESOURCE_COLLISION_GUARD ? i - RET_RESOURCE_COLLISION_GUARD
								  : 0;
		     j < i; j++) {
			if (memcmp(tx->hashmap[j], digest, RET_RESOURCE_MAPHASH_LEN) == 0) {
				return -EAGAIN;
			}
		}
		memcpy(tx->hashmap[i], digest, RET_RESOURCE_MAPHASH_LEN);
	}
	return 0;
}

int ret_resource_tx_adv(const struct ret_resource_tx *tx, uint8_t *out, size_t cap)
{
	mpack_writer_t w;
	size_t first = MIN(tx->n, RET_RESOURCE_HASHMAP_SEG);
	size_t used;

	/* ResourceAdvertisement.pack(), keys in its order. */
	mpack_writer_init(&w, (char *)out, cap);
	mpack_start_map(&w, 11);
	mpack_write_cstr(&w, "t");
	mpack_write_u64(&w, tx->t);
	mpack_write_cstr(&w, "d");
	mpack_write_u64(&w, tx->d);
	mpack_write_cstr(&w, "n");
	mpack_write_u64(&w, tx->n);
	mpack_write_cstr(&w, "h");
	mpack_write_bin(&w, (const char *)tx->h, sizeof(tx->h));
	mpack_write_cstr(&w, "r");
	mpack_write_bin(&w, (const char *)tx->r, sizeof(tx->r));
	mpack_write_cstr(&w, "o"); /* original hash: the first segment's own */
	mpack_write_bin(&w, (const char *)tx->h, sizeof(tx->h));
	mpack_write_cstr(&w, "i");
	mpack_write_u64(&w, 1);
	mpack_write_cstr(&w, "l");
	mpack_write_u64(&w, 1);
	mpack_write_cstr(&w, "q");
	mpack_write_nil(&w);
	mpack_write_cstr(&w, "f");
	mpack_write_u64(&w, RET_RESOURCE_F_ENCRYPTED);
	mpack_write_cstr(&w, "m");
	mpack_write_bin(&w, (const char *)tx->hashmap, first * RET_RESOURCE_MAPHASH_LEN);
	mpack_finish_map(&w);
	used = mpack_writer_buffer_used(&w);
	if (mpack_writer_destroy(&w) != mpack_ok) {
		return -ENOBUFS;
	}
	return (int)used;
}

int ret_resource_tx_request(struct ret_resource_tx *tx, const uint8_t *plain, size_t len,
			    struct ret_resource_tx_req *req)
{
	bool exhausted = len > 0 && plain[0] == HASHMAP_EXHAUSTED;
	size_t pad = exhausted ? 1 + RET_RESOURCE_MAPHASH_LEN : 1;
	uint32_t end = MIN(tx->min_height + RET_RESOURCE_COLLISION_GUARD, tx->n);

	memset(req, 0, sizeof(*req));
	if (len < pad + RET_SHA256_LEN || memcmp(&plain[pad], tx->h, RET_SHA256_LEN) != 0) {
		return -EBADMSG;
	}

	const uint8_t *wanted = &plain[pad + RET_SHA256_LEN];
	size_t n_wanted = (len - pad - RET_SHA256_LEN) / RET_RESOURCE_MAPHASH_LEN;

	/* Resource.request: the parts in the search scope whose map hash was
	 * asked for, in part order.
	 */
	for (uint32_t i = tx->min_height; i < end; i++) {
		for (size_t k = 0; k < n_wanted; k++) {
			if (memcmp(tx->hashmap[i], &wanted[k * RET_RESOURCE_MAPHASH_LEN],
				   RET_RESOURCE_MAPHASH_LEN) == 0) {
				req->parts[req->n_parts++] = (uint16_t)i;
				if (!tx->sent[i]) {
					tx->sent[i] = true;
					tx->sent_parts++;
				}
				break;
			}
		}
	}

	if (!exhausted) {
		return 0;
	}

	/* The receiver has map hashes up to the one it names: the next
	 * segment starts after it.
	 */
	uint32_t index = tx->min_height;

	for (uint32_t i = tx->min_height; i < end; i++) {
		index++;
		if (memcmp(tx->hashmap[i], &plain[1], RET_RESOURCE_MAPHASH_LEN) == 0) {
			break;
		}
	}
	tx->min_height = index > 1 + RET_RESOURCE_WINDOW_MAX ? index - 1 - RET_RESOURCE_WINDOW_MAX
							      : 0;
	if (index % RET_RESOURCE_HASHMAP_SEG != 0 || index >= tx->n) {
		return -EPROTO;
	}
	req->hmu = true;
	req->hmu_segment = index / RET_RESOURCE_HASHMAP_SEG;
	return 0;
}

const uint8_t *ret_resource_tx_part(const struct ret_resource_tx *tx, uint32_t index, size_t *len)
{
	size_t off = (size_t)index * RET_RESOURCE_SDU;

	*len = MIN((size_t)RET_RESOURCE_SDU, tx->t - off);
	return &tx->stream[off];
}

int ret_resource_tx_hmu(const struct ret_resource_tx *tx, uint32_t segment, uint8_t *out,
			size_t cap)
{
	mpack_writer_t w;
	uint32_t first = segment * RET_RESOURCE_HASHMAP_SEG;
	uint32_t last = MIN(first + RET_RESOURCE_HASHMAP_SEG, tx->n);
	size_t used;

	if (first >= last || cap < RET_SHA256_LEN) {
		return -EINVAL;
	}
	memcpy(out, tx->h, RET_SHA256_LEN);
	mpack_writer_init(&w, (char *)&out[RET_SHA256_LEN], cap - RET_SHA256_LEN);
	mpack_start_array(&w, 2);
	mpack_write_u64(&w, segment);
	mpack_write_bin(&w, (const char *)tx->hashmap[first],
			(last - first) * RET_RESOURCE_MAPHASH_LEN);
	mpack_finish_array(&w);
	used = mpack_writer_buffer_used(&w);
	if (mpack_writer_destroy(&w) != mpack_ok) {
		return -ENOBUFS;
	}
	return (int)(RET_SHA256_LEN + used);
}

bool ret_resource_tx_all_sent(const struct ret_resource_tx *tx)
{
	return tx->sent_parts == tx->n;
}

bool ret_resource_tx_proof_valid(const struct ret_resource_tx *tx, const uint8_t *data,
				 size_t len)
{
	return len == RET_RESOURCE_PROOF_LEN && memcmp(data, tx->h, RET_SHA256_LEN) == 0 &&
	       ret_ct_equal(&data[RET_SHA256_LEN], tx->expected_proof, RET_SHA256_LEN);
}
