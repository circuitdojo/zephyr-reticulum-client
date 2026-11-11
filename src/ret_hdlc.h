/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * HDLC-style stream framing used by Reticulum's TCP interfaces
 * (RNS/Interfaces/TCPInterface.py, class HDLC). No CRC, no address or
 * control fields: a frame is FLAG | escape(packet) | FLAG.
 */

#ifndef RET_HDLC_H_
#define RET_HDLC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RET_HDLC_FLAG     0x7E
#define RET_HDLC_ESC      0x7D
#define RET_HDLC_ESC_MASK 0x20

/** Worst-case encoded size: every byte escaped plus two flags. */
#define RET_HDLC_MAX_ENCODED(n) (2 * (n) + 2)

typedef void (*ret_hdlc_frame_cb)(const uint8_t *frame, size_t len, void *user);

struct ret_hdlc_decoder {
	uint8_t *buf;
	size_t cap;
	size_t len;
	bool in_frame;
	bool escape;
	bool overflow;
	/** Frames dropped: larger than @ref cap, or ending in a lone ESC. */
	uint32_t dropped;
};

void ret_hdlc_decoder_init(struct ret_hdlc_decoder *d, uint8_t *buf, size_t cap);

/** Drop any partial frame and wait for the next flag. */
void ret_hdlc_decoder_reset(struct ret_hdlc_decoder *d);

/**
 * Feed received stream bytes. @p cb is called once per complete,
 * non-empty frame that fits in the decoder buffer. Bytes before the
 * first flag are discarded, and the closing flag of one frame opens the
 * next, matching the Python reader.
 */
void ret_hdlc_feed(struct ret_hdlc_decoder *d, const uint8_t *data, size_t len,
		   ret_hdlc_frame_cb cb, void *user);

/**
 * Encode @p in as one frame into @p out.
 *
 * @return encoded length, or -ENOMEM if @p out_cap is too small.
 */
int ret_hdlc_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap);

#endif /* RET_HDLC_H_ */
