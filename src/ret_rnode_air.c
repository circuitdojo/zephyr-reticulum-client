/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 */

#include <errno.h>
#include <string.h>

#include "ret_rnode_air.h"

int ret_rnode_frames(size_t len)
{
	if (len == 0 || len > RET_RNODE_MTU) {
		return -EMSGSIZE;
	}
	return len > RET_RNODE_FRAME_DATA ? 2 : 1;
}

uint8_t ret_rnode_header(size_t len, uint8_t random)
{
	uint8_t header = random & RET_RNODE_SEQ_MASK;

	if (len > RET_RNODE_FRAME_DATA) {
		header |= RET_RNODE_FLAG_SPLIT;
	}
	return header;
}

int ret_rnode_frame(uint8_t header, const uint8_t *pkt, size_t len, int idx, uint8_t *out)
{
	int frames = ret_rnode_frames(len);
	size_t part;

	if (frames < 0 || idx < 0 || idx >= frames) {
		return -EINVAL;
	}
	if (idx == 0) {
		part = len < RET_RNODE_FRAME_DATA ? len : RET_RNODE_FRAME_DATA;
		memcpy(&out[RET_RNODE_HEADER_LEN], pkt, part);
	} else {
		part = len - RET_RNODE_FRAME_DATA;
		memcpy(&out[RET_RNODE_HEADER_LEN], &pkt[RET_RNODE_FRAME_DATA], part);
	}
	out[0] = header;
	return (int)(RET_RNODE_HEADER_LEN + part);
}

void ret_rnode_rx_reset(struct ret_rnode_rx *rx)
{
	rx->len = 0;
	rx->partial = false;
}

int ret_rnode_rx_feed(struct ret_rnode_rx *rx, const uint8_t *frame, size_t len,
		      const uint8_t **pkt)
{
	const uint8_t *data = &frame[RET_RNODE_HEADER_LEN];
	size_t data_len;
	uint8_t seq;

	if (len <= RET_RNODE_HEADER_LEN) {
		return -EBADMSG;
	}
	if (len > RET_RNODE_FRAME_MAX) {
		ret_rnode_rx_reset(rx);
		return -EMSGSIZE;
	}
	data_len = len - RET_RNODE_HEADER_LEN;
	seq = frame[0] & RET_RNODE_SEQ_MASK;

	if (!(frame[0] & RET_RNODE_FLAG_SPLIT)) {
		ret_rnode_rx_reset(rx);
		*pkt = data;
		return (int)data_len;
	}

	if (rx->partial && rx->seq == seq) {
		if (rx->len + data_len > RET_RNODE_MTU) {
			ret_rnode_rx_reset(rx);
			return -EMSGSIZE;
		}
		memcpy(&rx->buf[rx->len], data, data_len);
		rx->len += data_len;
		rx->partial = false;
		*pkt = rx->buf;
		return (int)rx->len;
	}

	/* A first half, or another packet's half after this one was lost. */
	memcpy(rx->buf, data, data_len);
	rx->len = data_len;
	rx->seq = seq;
	rx->partial = true;
	return 0;
}
