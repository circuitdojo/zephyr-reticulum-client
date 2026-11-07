/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include "ret_hdlc.h"

void ret_hdlc_decoder_init(struct ret_hdlc_decoder *d, uint8_t *buf, size_t cap)
{
	d->buf = buf;
	d->cap = cap;
	d->dropped = 0;
	ret_hdlc_decoder_reset(d);
}

void ret_hdlc_decoder_reset(struct ret_hdlc_decoder *d)
{
	d->len = 0;
	d->in_frame = false;
	d->escape = false;
	d->overflow = false;
}

void ret_hdlc_feed(struct ret_hdlc_decoder *d, const uint8_t *data, size_t len,
		   ret_hdlc_frame_cb cb, void *user)
{
	for (size_t i = 0; i < len; i++) {
		uint8_t b = data[i];

		if (b == RET_HDLC_FLAG) {
			if (d->in_frame && (d->len > 0 || d->escape)) {
				/* A frame ending in a lone ESC lost a byte: corrupt. */
				if (d->overflow || d->escape) {
					d->dropped++;
				} else if (cb != NULL) {
					cb(d->buf, d->len, user);
				}
			}
			d->in_frame = true;
			d->len = 0;
			d->escape = false;
			d->overflow = false;
			continue;
		}

		if (!d->in_frame) {
			continue;
		}

		if (d->escape) {
			b ^= RET_HDLC_ESC_MASK;
			d->escape = false;
		} else if (b == RET_HDLC_ESC) {
			d->escape = true;
			continue;
		}

		if (d->overflow) {
			continue;
		}
		if (d->len >= d->cap) {
			d->overflow = true;
			/* Keep len non-zero so the closing flag counts the drop. */
			continue;
		}
		d->buf[d->len++] = b;
	}
}

int ret_hdlc_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap)
{
	size_t o = 0;

	if (out_cap < 2) {
		return -ENOMEM;
	}
	out[o++] = RET_HDLC_FLAG;

	for (size_t i = 0; i < in_len; i++) {
		uint8_t b = in[i];

		if (b == RET_HDLC_FLAG || b == RET_HDLC_ESC) {
			if (o + 2 > out_cap - 1) {
				return -ENOMEM;
			}
			out[o++] = RET_HDLC_ESC;
			out[o++] = b ^ RET_HDLC_ESC_MASK;
		} else {
			if (o + 1 > out_cap - 1) {
				return -ENOMEM;
			}
			out[o++] = b;
		}
	}

	out[o++] = RET_HDLC_FLAG;
	return (int)o;
}
