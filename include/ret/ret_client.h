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
	/** Not sent: no path to the destination within
	 *  CONFIG_RET_PATH_REQUEST_TIMEOUT_MS, not connected, a table full,
	 *  or an encryption or socket failure (which also drops the
	 *  connection).
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

/**
 * Called on the client thread with the decrypted payload of a packet sent
 * to the client's own destination. @p data is wiped after the callback
 * returns; copy what you need. The packet is proved to its sender right
 * after the callback.
 */
typedef void (*ret_data_cb_t)(const uint8_t *data, size_t len, void *user);

struct ret_client_config {
	/** NULL selects CONFIG_RET_SERVER_HOST. */
	const char *host;
	/** 0 selects CONFIG_RET_SERVER_PORT. */
	uint16_t port;
	ret_announce_cb_t on_announce;
	ret_state_cb_t on_state;
	/**
	 * Full name ("app.aspect...") of the client's own IN SINGLE
	 * destination, which makes it reachable: it is announced on every
	 * connect, path requests for it are answered, and packets sent to
	 * it are decrypted, passed to @ref on_data and proved. Its address
	 * comes from an identity generated on first start and persisted in
	 * settings. NULL for a send-only client.
	 */
	const char *dest_name;
	/** Optional app_data carried in the destination's announces. */
	const uint8_t *announce_app_data;
	size_t announce_app_data_len;
	ret_data_cb_t on_data;
	void *user;
};

struct ret_client;

/** Return the single client instance, configured with @p cfg. */
struct ret_client *ret_client_create(const struct ret_client_config *cfg);

/** Start the client thread; it connects and reconnects on its own. */
int ret_client_start(struct ret_client *client);

/**
 * Queue @p data (at most RET_MAX_PAYLOAD bytes, copied) for encrypted
 * delivery to @p dest_hash. @p cb fires once with the outcome.
 *
 * The destination's keys come from its announce. If there is no current
 * path (it has not announced since we connected, or never announced to
 * us), the send is held and a path request goes out; the destination's
 * announce in reply releases it. So a known destination hash can be used
 * before any announce arrives. Through an rnsd without transport enabled,
 * only destinations owned by that rnsd's local clients answer (see
 * docs/protocol.md). The client wipes its own copies after sending, but
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

/**
 * The client's own destination hash (its address), valid after
 * ret_client_start() when a dest_name was configured.
 *
 * @retval -ENOENT no destination configured or client not started
 */
int ret_client_dest_hash(const struct ret_client *client, uint8_t out[RET_DEST_HASH_LEN]);

/** Queue an announce of the client's own destination. */
int ret_client_announce(struct ret_client *client);

/* --- Links (one at a time, initiator side) -------------------------- */

enum ret_link_event {
	/** Handshake complete: requests can be sent. */
	RET_LINK_EVT_ACTIVE,
	/** Closed by either side, or the connection dropped. */
	RET_LINK_EVT_CLOSED,
	/** Could not be established (no path, no proof, bad proof, busy). */
	RET_LINK_EVT_FAILED,
};

/** Called on the client thread; @p reason is 0 or a negative errno. */
typedef void (*ret_link_cb_t)(enum ret_link_event event, int reason, void *user);

/**
 * Called on the client thread with a request's outcome: @p status 0 and
 * the response as its encoded msgpack bytes, or -ETIMEDOUT, -ECONNRESET
 * (link closed) or -ENOTCONN.
 */
typedef void (*ret_link_response_cb_t)(int status, const uint8_t *response, size_t len,
				       void *user);

/**
 * Open a link to a destination learned from an announce (a path request
 * goes out first if there is no current path). @p cb reports
 * RET_LINK_EVT_ACTIVE, then later RET_LINK_EVT_CLOSED, or
 * RET_LINK_EVT_FAILED.
 */
int ret_client_link_open(struct ret_client *client, const uint8_t dest_hash[RET_DEST_HASH_LEN],
			 ret_link_cb_t cb, void *user);

/**
 * Send a request on the open link. @p data_mp is one encoded msgpack value
 * (NULL for nil) and must fit a single request packet.
 */
int ret_client_link_request(struct ret_client *client, const char *path, const uint8_t *data_mp,
			    size_t len, ret_link_response_cb_t cb, void *user);

/**
 * Identify on the open link with the client's own identity. A no-op if no
 * link is active when the client thread gets to it.
 */
int ret_client_link_identify(struct ret_client *client);

/** Close the open link (LINKCLOSE to the peer). */
int ret_client_link_close(struct ret_client *client);

#ifdef __cplusplus
}
#endif

#endif /* RET_RET_CLIENT_H_ */
