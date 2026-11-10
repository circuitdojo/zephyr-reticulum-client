/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <string.h>

#include <zephyr/ztest.h>

#include "ret_rnode_air.h"

static uint8_t pkt[RET_RNODE_MTU];

static void fill(size_t len)
{
	for (size_t i = 0; i < len; i++) {
		pkt[i] = (uint8_t)(i * 3 + 1);
	}
}

/* Through framing and reassembly. */
static void roundtrip(size_t len, int want_frames)
{
	static uint8_t frame[2][RET_RNODE_FRAME_MAX];
	static struct ret_rnode_rx rx;
	const uint8_t *out = NULL;
	uint8_t header = ret_rnode_header(len, 0xA7);
	int frames = ret_rnode_frames(len);
	int result = 0;

	fill(len);
	zassert_equal(frames, want_frames, "%zu bytes", len);
	zassert_equal(header & RET_RNODE_SEQ_MASK, 0xA0);
	zassert_equal(!!(header & RET_RNODE_FLAG_SPLIT), want_frames == 2);

	ret_rnode_rx_reset(&rx);
	for (int i = 0; i < frames; i++) {
		int n = ret_rnode_frame(header, pkt, len, i, frame[i]);

		zassert_true(n > 1 && n <= RET_RNODE_FRAME_MAX, "frame %d is %d", i, n);
		zassert_equal(frame[i][0], header);
		result = ret_rnode_rx_feed(&rx, frame[i], (size_t)n, &out);
		zassert_equal(result, i == frames - 1 ? (int)len : 0, "frame %d: %d", i, result);
	}
	zassert_mem_equal(out, pkt, len);
	zassert_false(rx.partial);
}

ZTEST(ret_air, test_boundaries)
{
	roundtrip(1, 1);
	roundtrip(254, 1);
	roundtrip(255, 2);
	roundtrip(508, 2);
}

ZTEST(ret_air, test_split_positions)
{
	uint8_t frame[RET_RNODE_FRAME_MAX];

	fill(300);
	zassert_equal(ret_rnode_frame(0x31, pkt, 300, 0, frame), 255);
	zassert_mem_equal(&frame[1], pkt, 254);
	zassert_equal(ret_rnode_frame(0x31, pkt, 300, 1, frame), 47);
	zassert_mem_equal(&frame[1], &pkt[254], 46);
	zassert_equal(ret_rnode_frame(0x31, pkt, 300, 2, frame), -EINVAL);
	zassert_equal(ret_rnode_frame(0x30, pkt, 100, 1, frame), -EINVAL);
}

ZTEST(ret_air, test_too_long)
{
	zassert_equal(ret_rnode_frames(509), -EMSGSIZE);
	zassert_equal(ret_rnode_frames(0), -EMSGSIZE);
}

ZTEST(ret_air, test_lost_halves)
{
	static struct ret_rnode_rx rx;
	const uint8_t *out;
	uint8_t a[10] = {0x11, 1, 2, 3};
	uint8_t b[10] = {0x21, 4, 5, 6};
	uint8_t plain[4] = {0x30, 7, 8, 9};

	ret_rnode_rx_reset(&rx);

	/* A non-split frame discards a partial. */
	zassert_equal(ret_rnode_rx_feed(&rx, a, sizeof(a), &out), 0);
	zassert_true(rx.partial);
	zassert_equal(ret_rnode_rx_feed(&rx, plain, sizeof(plain), &out), 3);
	zassert_mem_equal(out, &plain[1], 3);
	zassert_false(rx.partial);

	/* Another sequence starts over, and then completes. */
	zassert_equal(ret_rnode_rx_feed(&rx, a, sizeof(a), &out), 0);
	zassert_equal(ret_rnode_rx_feed(&rx, b, sizeof(b), &out), 0);
	zassert_equal(rx.seq, 0x20);
	zassert_equal(ret_rnode_rx_feed(&rx, b, sizeof(b), &out), 18);
	zassert_equal(out[0], 4);
	zassert_equal(out[9], 4);
}

ZTEST(ret_air, test_malformed)
{
	static struct ret_rnode_rx rx;
	static uint8_t frame[255];
	const uint8_t *out;

	ret_rnode_rx_reset(&rx);
	zassert_equal(ret_rnode_rx_feed(&rx, frame, 1, &out), -EBADMSG);
	zassert_equal(ret_rnode_rx_feed(&rx, frame, 0, &out), -EBADMSG);

	/* Halves over the MTU: 254 + 254 fits, so a third "half" is a new start. */
	frame[0] = 0x41;
	zassert_equal(ret_rnode_rx_feed(&rx, frame, 255, &out), 0);
	zassert_equal(ret_rnode_rx_feed(&rx, frame, 255, &out), 508);
	rx.len = 400;
	rx.seq = 0x40;
	rx.partial = true;
	zassert_equal(ret_rnode_rx_feed(&rx, frame, 255, &out), -EMSGSIZE);
	zassert_false(rx.partial);
}

ZTEST_SUITE(ret_air, NULL, NULL, NULL, NULL, NULL);
