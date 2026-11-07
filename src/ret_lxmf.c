/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <mpack.h>
#include <zephyr/sys/util.h>

#include "ret_crypto.h"
#include "ret_lxmf.h"
#include "ret_mp.h"

static const uint8_t fixarray4 = 0x94;

static size_t reader_pos(mpack_reader_t *r, size_t total)
{
	return total - mpack_reader_remaining(r, NULL);
}

/* Title and content: LXMF writes bin; accept str as well. */
static int read_bytes(mpack_reader_t *r, const uint8_t **p, size_t *len)
{
	mpack_tag_t tag = mpack_read_tag(r);
	uint32_t n;

	if (mpack_reader_error(r) != mpack_ok ||
	    (tag.type != mpack_type_bin && tag.type != mpack_type_str)) {
		return -EBADMSG;
	}
	n = mpack_tag_bytes(&tag);
	*p = (const uint8_t *)mpack_read_bytes_inplace(r, n);
	*len = n;
	if (tag.type == mpack_type_bin) {
		mpack_done_bin(r);
	} else {
		mpack_done_str(r);
	}
	return mpack_reader_error(r) == mpack_ok ? 0 : -EBADMSG;
}

/* The hashed part: dest | src | payload (without the stamp). */
static size_t hashed_iov(const struct ret_lxmf_msg *m, struct ret_iov iov[4])
{
	size_t n = 0;

	iov[n++] = (struct ret_iov){ m->dest, RET_LXMF_ADDR_LEN };
	iov[n++] = (struct ret_iov){ m->src, RET_LXMF_ADDR_LEN };
	if (m->stamped) {
		iov[n++] = (struct ret_iov){ &fixarray4, 1 };
	}
	iov[n++] = (struct ret_iov){ m->hashed_elems, m->hashed_elems_len };
	return n;
}

int ret_lxmf_unpack(const uint8_t dest[RET_LXMF_ADDR_LEN], const uint8_t *body, size_t len,
		    struct ret_lxmf_msg *m)
{
	mpack_reader_t r;
	const uint8_t *payload;
	size_t plen;
	uint32_t count;
	size_t elems_start;
	size_t fields_end;
	struct ret_iov iov[4];
	int err;

	memset(m, 0, sizeof(*m));
	if (len <= RET_LXMF_BODY_HDR) {
		return -EBADMSG;
	}
	m->dest = dest;
	m->src = body;
	m->sig = &body[RET_LXMF_ADDR_LEN];
	payload = &body[RET_LXMF_BODY_HDR];
	plen = len - RET_LXMF_BODY_HDR;

	mpack_reader_init_data(&r, (const char *)payload, plen);
	count = mpack_expect_array(&r);
	if (mpack_reader_error(&r) != mpack_ok || (count != 4 && count != 5)) {
		goto bad;
	}
	elems_start = reader_pos(&r, plen);
	m->timestamp = mpack_expect_double(&r);
	if (read_bytes(&r, &m->title, &m->title_len) != 0 ||
	    read_bytes(&r, &m->content, &m->content_len) != 0) {
		goto bad;
	}
	m->fields = &payload[reader_pos(&r, plen)];
	if (mpack_peek_tag(&r).type != mpack_type_map || ret_mp_skip(&r) != 0) {
		goto bad;
	}
	fields_end = reader_pos(&r, plen);
	m->fields_len = (size_t)(&payload[fields_end] - m->fields);
	if (count == 5 && ret_mp_skip(&r) != 0) {
		goto bad;
	}
	if (mpack_reader_error(&r) != mpack_ok || mpack_reader_remaining(&r, NULL) != 0) {
		goto bad;
	}
	mpack_reader_destroy(&r);

	/* Without a stamp the payload is hashed as received; with one,
	 * unpack_from_bytes re-packs elements 0-3, which for umsgpack's
	 * canonical encoding is 0x94 followed by their original bytes.
	 */
	m->stamped = count == 5;
	m->hashed_elems = m->stamped ? &payload[elems_start] : payload;
	m->hashed_elems_len = m->stamped ? fields_end - elems_start : plen;

	err = ret_sha256(iov, hashed_iov(m, iov), m->hash);
	return err;

bad:
	mpack_reader_destroy(&r);
	return -EBADMSG;
}

bool ret_lxmf_verify(const struct ret_lxmf_msg *m, const uint8_t src_sig_pub[RET_ED25519_PUB_LEN])
{
	struct ret_iov iov[5];
	size_t n = hashed_iov(m, iov);

	iov[n++] = (struct ret_iov){ m->hash, RET_SHA256_LEN };
	return ret_ed25519_verify_iov(m->sig, src_sig_pub, iov, n);
}

int ret_lxmf_pack(const struct ret_local_identity *id, const uint8_t src[RET_LXMF_ADDR_LEN],
		  const uint8_t dest[RET_LXMF_ADDR_LEN], double timestamp, const uint8_t *title,
		  size_t title_len, const uint8_t *content, size_t content_len, uint8_t *out,
		  size_t cap, uint8_t hash_out[RET_SHA256_LEN])
{
	const size_t hdr = RET_LXMF_ADDR_LEN + RET_LXMF_BODY_HDR;
	mpack_writer_t w;
	uint8_t *payload;
	size_t used;
	int err;

	if (cap <= hdr) {
		return -ENOBUFS;
	}
	payload = &out[hdr];

	/* [timestamp, title, content, {}] as LXMessage.pack: float64, bin. */
	mpack_writer_init(&w, (char *)payload, cap - hdr);
	mpack_start_array(&w, 4);
	mpack_write_double(&w, timestamp);
	mpack_write_bin(&w, (const char *)title, (uint32_t)title_len);
	mpack_write_bin(&w, (const char *)content, (uint32_t)content_len);
	mpack_start_map(&w, 0);
	mpack_finish_map(&w);
	mpack_finish_array(&w);
	used = mpack_writer_buffer_used(&w);
	if (mpack_writer_destroy(&w) != mpack_ok) {
		return -ENOBUFS;
	}

	memcpy(out, dest, RET_LXMF_ADDR_LEN);
	memcpy(&out[RET_LXMF_ADDR_LEN], src, RET_LXMF_ADDR_LEN);

	const struct ret_iov hashed[] = { { out, 2 * RET_LXMF_ADDR_LEN }, { payload, used } };

	err = ret_sha256(hashed, ARRAY_SIZE(hashed), hash_out);
	if (err) {
		return err;
	}

	const struct ret_iov signed_part[] = {
		{ out, 2 * RET_LXMF_ADDR_LEN }, { payload, used }, { hash_out, RET_SHA256_LEN }
	};

	ret_ed25519_sign_iov(&out[2 * RET_LXMF_ADDR_LEN], id->ed25519_sk, signed_part,
			     ARRAY_SIZE(signed_part));
	return (int)(hdr + used);
}

int ret_lxmf_app_data(const char *display_name, uint8_t *out, size_t cap)
{
	mpack_writer_t w;
	size_t used;

	mpack_writer_init(&w, (char *)out, cap);
	mpack_start_array(&w, 3);
	if (display_name != NULL) {
		mpack_write_bin(&w, display_name, (uint32_t)strlen(display_name));
	} else {
		mpack_write_nil(&w);
	}
	mpack_write_nil(&w);
	mpack_start_array(&w, 0);
	mpack_finish_array(&w);
	mpack_finish_array(&w);
	used = mpack_writer_buffer_used(&w);
	return mpack_writer_destroy(&w) == mpack_ok ? (int)used : -ENOBUFS;
}
