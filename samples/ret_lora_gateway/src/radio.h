/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef RADIO_H_
#define RADIO_H_

#include <stddef.h>
#include <stdint.h>

struct radio_frame {
	const uint8_t *data;
	size_t len;
};

/**
 * Called for each frame received. Possibly on a system thread: copy the
 * frame and return.
 */
typedef void (*radio_rx_cb)(const uint8_t *data, size_t len);

/** Configure the radio and start receiving. */
int radio_init(radio_rx_cb cb);

/**
 * Transmit frames back to back, with nothing between them, and go back to
 * receiving. Blocks until the last one is sent.
 */
int radio_send(const struct radio_frame *frames, size_t count);

#endif /* RADIO_H_ */
