/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reticulum client: connects to an rnsd TCPServerInterface, learns
 * destinations from announces, sends encrypted packets and reports
 * delivery proofs.
 */

#ifndef RET_RET_CLIENT_H_
#define RET_RET_CLIENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RET_DEST_HASH_LEN   16
#define RET_PACKET_HASH_LEN 32
#define RET_MAX_PAYLOAD     383

enum ret_client_state {
	RET_STATE_DISCONNECTED,
	RET_STATE_CONNECTING,
	RET_STATE_CONNECTED,
	RET_STATE_RECONNECTING,
};

enum ret_receipt_status {
	/** A valid proof arrived. */
	RET_RECEIPT_DELIVERED,
	/** No proof before CONFIG_RET_RECEIPT_TIMEOUT_MS. */
	RET_RECEIPT_TIMEOUT,
	/** Not sent: unknown destination, receipt table full, encryption or
	 *  socket failure (a socket failure also drops the connection).
	 */
	RET_RECEIPT_FAILED,
	/** Sent, but the connection dropped before a proof arrived. */
	RET_RECEIPT_DISCONNECTED,
};

struct ret_announce_info {
	uint8_t dest_hash[RET_DEST_HASH_LEN];
	uint8_t identity_hash[RET_DEST_HASH_LEN];
	uint8_t name_hash[10];
	/** Path length in hops. */
	uint8_t hops;
	bool has_ratchet;
	const uint8_t *app_data;
	size_t app_data_len;
};

/**
 * Called on the client thread for every validated announce, once per
 * announce: repeats of it (same random hash) update the path silently.
 */
typedef void (*ret_announce_cb_t)(const struct ret_announce_info *info, void *user);

/**
 * Called on the client thread when a send resolves. @p packet_hash is
 * all zero for RET_RECEIPT_FAILED before the packet was built.
 */
typedef void (*ret_receipt_cb_t)(const uint8_t packet_hash[RET_PACKET_HASH_LEN],
				 enum ret_receipt_status status, uint32_t rtt_ms, void *user);

typedef void (*ret_state_cb_t)(enum ret_client_state state, void *user);

struct ret_client_config {
	/** NULL selects CONFIG_RET_SERVER_HOST. */
	const char *host;
	/** 0 selects CONFIG_RET_SERVER_PORT. */
	uint16_t port;
	ret_announce_cb_t on_announce;
	ret_state_cb_t on_state;
	void *user;
};

struct ret_client;

/** Return the single client instance, configured with @p cfg. */
struct ret_client *ret_client_create(const struct ret_client_config *cfg);

/** Start the client thread; it connects and reconnects on its own. */
int ret_client_start(struct ret_client *client);

/**
 * Queue @p data (at most RET_MAX_PAYLOAD bytes, copied) for encrypted
 * delivery to a destination learned from an announce. @p cb fires once
 * with the outcome. The client wipes its own copies after sending, but
 * the plaintext stays in the send queue's ring buffer until that slot is
 * reused.
 *
 * @retval -EMSGSIZE payload too large
 * @retval -EAGAIN send queue full
 */
int ret_client_send(struct ret_client *client, const uint8_t dest_hash[RET_DEST_HASH_LEN],
		    const uint8_t *data, size_t len, ret_receipt_cb_t cb, void *user);

/**
 * SHA-256("app.aspect...")[:10], for matching announces by name. Usable
 * before ret_client_start().
 */
int ret_client_name_hash(const char *full_name, uint8_t out[10]);

enum ret_client_state ret_client_state(const struct ret_client *client);

#ifdef __cplusplus
}
#endif

#endif /* RET_RET_CLIENT_H_ */
