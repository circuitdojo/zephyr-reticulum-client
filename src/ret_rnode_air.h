/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: LicenseRef-Reticulum
 *
 * RNode's on-air LoRa framing (RNode_Firmware: Config.h, RNode_Firmware.ino).
 * Each LoRa frame starts with a header byte: a random sequence nibble and
 * FLAG_SPLIT. A packet that does not fit one frame goes out as two with the
 * same header.
 */

#ifndef RET_RNODE_AIR_H_
#define RET_RNODE_AIR_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Largest packet over the air (RNode's MTU). */
#define RET_RNODE_MTU         508
/** Largest LoRa frame, header included (RNode's SINGLE_MTU). */
#define RET_RNODE_FRAME_MAX   255
#define RET_RNODE_HEADER_LEN  1
/** Packet bytes one frame carries. */
#define RET_RNODE_FRAME_DATA  (RET_RNODE_FRAME_MAX - RET_RNODE_HEADER_LEN)
#define RET_RNODE_FLAG_SPLIT  0x01
#define RET_RNODE_SEQ_MASK    0xF0

/** @return frames a packet of @p len needs (1 or 2), or -EMSGSIZE. */
int ret_rnode_frames(size_t len);

/** Header for a packet of @p len. @p random supplies the sequence nibble. */
uint8_t ret_rnode_header(size_t len, uint8_t random);

/**
 * Write frame @p idx (0 or 1) of a packet.
 *
 * @param out RET_RNODE_FRAME_MAX bytes
 * @return frame length, or -EINVAL if the packet has no such frame
 */
int ret_rnode_frame(uint8_t header, const uint8_t *pkt, size_t len, int idx, uint8_t *out);

/** Reassembly of split packets. */
struct ret_rnode_rx {
	uint8_t buf[RET_RNODE_MTU];
	size_t len;
	/** Sequence nibble of the partial packet in @ref buf. */
	uint8_t seq;
	bool partial;
};

void ret_rnode_rx_reset(struct ret_rnode_rx *rx);

/**
 * Take one received LoRa frame, as RNode's receive_callback() does: a
 * split frame with nothing pending starts a packet, one with the same
 * sequence completes it, one with another sequence starts over, and a
 * frame that is not split discards a partial.
 *
 * @param pkt set to the completed packet (in @p frame or @p rx), valid until
 *            the next call
 * @return packet length, 0 if the first half was buffered, -EBADMSG for a
 *         frame with no data, or -EMSGSIZE if the halves overflow the MTU
 */
int ret_rnode_rx_feed(struct ret_rnode_rx *rx, const uint8_t *frame, size_t len,
		      const uint8_t **pkt);

#endif /* RET_RNODE_AIR_H_ */
