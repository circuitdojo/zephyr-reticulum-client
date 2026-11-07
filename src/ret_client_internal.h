/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * Client internals shared by ret_client.c and the link driver
 * (ret_client_link.c). Everything here is owned by the client thread.
 */

#ifndef RET_CLIENT_INTERNAL_H_
#define RET_CLIENT_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>

#include <zephyr/kernel.h>

#include <ret/ret_client.h>

#include "ret_destinations.h"
#include "ret_hdlc.h"
#include "ret_identity.h"
#include "ret_link.h"
#include "ret_packet.h"

enum send_kind {
	REQ_SEND,
	REQ_ANNOUNCE,
	REQ_LINK_OPEN,
	REQ_LINK_REQUEST,
	REQ_LINK_IDENTIFY,
	REQ_LINK_CLOSE,
};

/* Longest request path accepted by ret_client_link_request(). */
#define RET_LINK_PATH_MAX 32

/** A request queued from any thread to the client thread. */
struct send_req {
	uint8_t kind;
	uint8_t dest_hash[RET_DEST_HASH_LEN];
	uint16_t len;
	/* Payload (REQ_SEND) or encoded request data (REQ_LINK_REQUEST). */
	uint8_t data[RET_LINK_MDU];
	char path[RET_LINK_PATH_MAX + 1];
	ret_receipt_cb_t cb;
	ret_link_cb_t link_cb;
	ret_link_response_cb_t response_cb;
	void *user;
};

/* A send waiting for a path to its destination. */
struct held_send {
	bool used;
	int64_t deadline_ms;
	int64_t next_request_ms;
	struct send_req req;
};

enum link_state {
	LINK_NONE,
	LINK_WAIT_PATH,
	LINK_PENDING,
	LINK_ACTIVE,
	LINK_STALE,
};

struct link_request {
	bool used;
	uint8_t id[RET_TRUNC_HASH_LEN];
	int64_t deadline_ms;
	ret_link_response_cb_t cb;
	void *user;
};

/** The one link this client may have open (initiator side). */
struct link {
	enum link_state state;
	uint8_t dest[RET_TRUNC_HASH_LEN];
	uint8_t id[RET_TRUNC_HASH_LEN];
	/* The destination's Ed25519 key, pinned when the request goes out:
	 * the destinations table may evict the entry mid-handshake.
	 */
	uint8_t dest_sig_pub[RET_ED25519_PUB_LEN];
	struct ret_link_keys keys;
	uint8_t key[RET_TOKEN_KEY_LEN];
	int64_t opened_ms;
	int64_t deadline_ms;
	int64_t next_path_request_ms;
	int64_t last_rx_ms;
	int64_t last_tx_ms;
	int64_t last_keepalive_ms;
	int64_t stale_since_ms;
	uint32_t rtt_ms;
	uint32_t keepalive_ms;
	ret_link_cb_t cb;
	void *user;
	struct link_request req[CONFIG_RET_LINK_MAX_REQUESTS];
};

struct ret_client {
	struct ret_client_config cfg;
	const char *host;
	uint16_t port;
	enum ret_client_state state;
	bool started;
	int sock;
	int efd;
	struct ret_hdlc_decoder hdlc;
	/** Valid packets received on the current connection. */
	uint32_t rx_packets;
	int64_t last_rx_ms;
	int consecutive_timeouts;
	/** Set from inside frame handling when a send broke the connection. */
	bool conn_broken;
	/** A connect is in progress: queued sends are held until it is done. */
	bool connecting;
	struct held_send held[CONFIG_RET_MAX_HELD_SENDS];
	struct link link;

	/* The client's own destination, when cfg.dest_name is set. */
	bool has_local;
	struct ret_local_identity id;
	uint8_t local_dest[RET_TRUNC_HASH_LEN];
	uint8_t local_name_hash[RET_NAME_HASH_LEN];
	uint8_t path_request_dest[RET_TRUNC_HASH_LEN];
	/** Last emission time used, and the persisted reservation above it. */
	uint64_t aclk;
	uint64_t aclk_reserved;
	int64_t next_announce_ms;
	int64_t last_path_response_ms;
	uint8_t path_request_tags[4][RET_PATH_REQUEST_TAG_LEN];
	size_t path_request_tag_next;
	uint8_t recent[CONFIG_RET_RECENT_PACKETS][RET_HASH_LEN];
	size_t recent_next;
	uint8_t rx_plain[RET_MTU];
	uint8_t rx_frame[RET_MTU];
	uint8_t rx_chunk[256];
	uint8_t tx_raw[RET_MTU];
	uint8_t tx_frame[RET_HDLC_MAX_ENCODED(RET_MTU)];
	struct send_req req;
};

/* --- Provided by ret_client.c -------------------------------------- */

/** HDLC-frame c->tx_raw[0..raw_len) and send it. -ECONNRESET: link dropped. */
int ret_client_send_frame(struct ret_client *c, size_t raw_len);

/** Send a path request for @p dest_hash. */
int ret_client_send_path_request(struct ret_client *c, const uint8_t dest_hash[RET_TRUNC_HASH_LEN]);

/* --- Provided by ret_client_link.c --------------------------------- */

void ret_link_drv_open(struct ret_client *c, const struct send_req *r);
void ret_link_drv_request(struct ret_client *c, const struct send_req *r);
void ret_link_drv_identify(struct ret_client *c);
void ret_link_drv_close(struct ret_client *c);

/** A packet addressed to the open link's id. */
void ret_link_drv_on_packet(struct ret_client *c, const struct ret_packet *pkt);

/** A validated announce refreshed @p d's path. */
void ret_link_drv_on_path(struct ret_client *c, const struct ret_destination *d);

/** Timers: establishment, path wait, requests, keepalive, stale. */
void ret_link_drv_service(struct ret_client *c);
int64_t ret_link_drv_next_event(const struct ret_client *c);

/** The connection is gone: tear the link down without a LINKCLOSE. */
void ret_link_drv_teardown(struct ret_client *c);

#endif /* RET_CLIENT_INTERNAL_H_ */
