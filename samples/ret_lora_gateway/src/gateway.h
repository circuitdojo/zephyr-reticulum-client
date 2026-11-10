/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * The gateway's parts: the transport thread (main.c) owns all routing
 * state; the radio and uplink threads only move frames and post them to it.
 */

#ifndef GATEWAY_H_
#define GATEWAY_H_

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <zephyr/kernel.h>

#include "ret_transport.h"

enum gw_event {
	GW_FRAME_LORA,
	GW_FRAME_UPLINK,
	GW_UPLINK_UP,
	GW_UPLINK_DOWN,
};

/**
 * Hand a frame or an event to the transport thread. LoRa frames have a
 * queue of their own, so a busy uplink can't crowd them out.
 */
int gw_post(enum gw_event type, const uint8_t *data, size_t len, k_timeout_t timeout);

/* radio_task.c */
int radio_task_start(void);
/** Queue a packet (up to 508 bytes) for the radio. Never blocks. Transport thread only. */
int radio_task_send(const uint8_t *pkt, size_t len);
/** The radio's bitrate, by RNode's formula (RNodeInterface.updateBitrate). */
uint32_t radio_task_bitrate(void);

/* uplink.c */
int uplink_start(void);
/** Send a frame to the hub (HDLC framed). Called on the transport thread. */
int uplink_send(const uint8_t *frame, size_t len);
/** SHA-256 naming the uplink for tunnel synthesis; the same on every connect. */
void uplink_iface_hash(uint8_t hash[RET_HASH_LEN]);

/* store_zms.c */
int store_init(struct ret_transport_store **store);
/** Flash the store occupies now, in bytes. */
ssize_t store_used_bytes(void);

#endif /* GATEWAY_H_ */
