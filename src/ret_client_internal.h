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
#include "ret_lxmf_seen.h"
#include "ret_resource.h"

enum send_kind {
	REQ_SEND,
	REQ_ANNOUNCE,
	REQ_LINK_OPEN,
	REQ_LINK_REQUEST,
	REQ_LINK_IDENTIFY,
	REQ_LINK_CLOSE,
	REQ_LXMF_SYNC,
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
	ret_lxmf_sync_cb_t sync_cb;
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
	LINK_WAIT_PATH, /* out: requesting a path to the destination */
	LINK_PENDING,   /* out: LINKREQUEST sent, waiting for the proof */
	LINK_HANDSHAKE, /* in: proof sent, waiting for the initiator's RTT */
	LINK_ACTIVE,
	LINK_STALE,
};

enum link_role {
	LINK_OUT, /* opened by this client */
	LINK_IN,  /* opened by another node to the client's destination */
};

struct link_request {
	bool used;
	/* Its response is arriving as a resource: no deadline meanwhile. */
	bool receiving;
	uint8_t id[RET_TRUNC_HASH_LEN];
	int64_t deadline_ms;
	ret_link_response_cb_t cb;
	void *user;
};

/** What every link has, whichever side opened it. */
struct link {
	enum link_state state;
	enum link_role role;
	uint8_t id[RET_TRUNC_HASH_LEN];
	uint8_t key[RET_TOKEN_KEY_LEN];
	/* out: LINKREQUEST sent; in: LINKREQUEST received (proof sent). */
	int64_t opened_ms;
	/* Path wait or establishment deadline. */
	int64_t deadline_ms;
	int64_t last_rx_ms;
	int64_t last_tx_ms;
	int64_t stale_since_ms;
	uint32_t rtt_ms;
	uint32_t keepalive_ms;
};

/** The one link this client may open (initiator side). */
struct link_out {
	struct link l;
	uint8_t dest[RET_TRUNC_HASH_LEN];
	/* The destination's Ed25519 key, pinned when the request goes out:
	 * the destinations table may evict the entry mid-handshake.
	 */
	uint8_t dest_sig_pub[RET_ED25519_PUB_LEN];
	struct ret_link_keys keys;
	int64_t next_path_request_ms;
	int64_t last_keepalive_ms;
	ret_link_cb_t cb;
	void *user;
	struct link_request req[CONFIG_RET_LINK_MAX_REQUESTS];
};

enum res_state {
	RES_IDLE,
	RES_RECEIVING,
	/* Assembled: its data in plain[] is being handed over; stream[] is spent. */
	RES_DELIVERING,
};

enum res_purpose {
	RES_RESPONSE, /* to a request on the outbound link */
	RES_DELIVERY, /* data sent to us over an inbound link (LXMF DIRECT) */
};

/** The one incoming resource, on any link. */
struct link_resource {
	enum res_state state;
	enum res_purpose purpose;
	struct link *link;
	/* RES_RESPONSE: the request it answers. */
	struct link_request *req;
	int64_t deadline_ms;
	/* No resource may hold the buffers longer than this. */
	int64_t give_up_ms;
	uint8_t retries;
	struct ret_resource_rx rx;
	uint8_t stream[CONFIG_RET_RESOURCE_MAX_SIZE];
	uint8_t plain[CONFIG_RET_RESOURCE_MAX_SIZE];
};

/** A sender whose key is persisted (ret/lk/<n>), for after a reboot. */
struct lxmf_known {
	bool used;
	uint8_t dest[RET_TRUNC_HASH_LEN];
	uint8_t pub[RET_PUBKEY_LEN];
	/* Store order: the lowest goes first when the table is full. */
	uint32_t seq;
};

/* Unknown senders whose announce (path response) we wait for. */
#define RET_LXMF_WANTED 4

/* Ids per /get request: [wants, [], limit] must fit one link packet. */
#define RET_LXMF_SYNC_BATCH 10
/* Too-large message ids remembered within one sync, so a re-list skips them. */
#define RET_LXMF_SYNC_SKIPPED 8

/* The next step, performed from the client loop (never from a callback). */
enum sync_pending {
	SYNC_PEND_NONE,
	SYNC_PEND_IDENTIFY, /* then list */
	SYNC_PEND_REQUEST,
	SYNC_PEND_CLOSE,
};

enum sync_phase {
	SYNC_LINKING,
	SYNC_LISTING,
	SYNC_FETCHING,
	SYNC_ACKING,
	SYNC_CLOSING,
};

/** A propagation node sync in progress (ret_client_lxmf_sync.c). */
struct lxmf_sync {
	bool active;
	enum sync_phase phase;
	enum sync_pending pending;
	/* The request to send: /get data, encoded msgpack. */
	uint8_t req[RET_LINK_MDU];
	size_t req_len;
	/* Messages acknowledged since the last listing. */
	size_t acked_since_list;
	ret_lxmf_sync_cb_t cb;
	void *user;
	int status;
	unsigned int received;
	/* The working list, from the node's /get [nil, nil]. */
	uint8_t ids[CONFIG_RET_LXMF_SYNC_MAX_IDS][RET_SHA256_LEN];
	size_t n_ids;
	size_t next;
	bool list_truncated;
	/* The batch in flight: ids[next .. next+wanted), which were served. */
	size_t wanted;
	uint32_t served;
	uint8_t acks[RET_LXMF_SYNC_BATCH][RET_SHA256_LEN];
	size_t n_acks;
	uint8_t skipped[RET_LXMF_SYNC_SKIPPED][RET_SHA256_LEN];
	size_t n_skipped;
	/* Decrypting an item while the resource buffers are taken. */
	uint8_t item_plain[RET_LINK_MDU];
	/* Requests refused because a delivery resource held the buffers. */
	uint8_t busy_retries;
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
	/** ret_client_suspend() asked for (any thread); resume clears it. */
	atomic_t want_suspended;
	struct held_send held[CONFIG_RET_MAX_HELD_SENDS];
	struct link_out out;
#if CONFIG_RET_INBOUND_LINKS > 0
	/* Links other nodes opened to the client's destination. */
	struct link in[CONFIG_RET_INBOUND_LINKS];
#endif
	struct link_resource res;

	/* LXMF (cfg.on_lxmf): announce app_data, recent message hashes, and
	 * the last path request sent for an unknown sender.
	 */
	uint8_t lxmf_app_data[128];
	int64_t lxmf_last_path_request_ms;
	struct lxmf_known lxmf_known[CONFIG_RET_LXMF_KNOWN_SENDERS];
	uint32_t lxmf_known_seq;
	uint8_t lxmf_wanted[RET_LXMF_WANTED][RET_TRUNC_HASH_LEN];
	size_t lxmf_wanted_next;
	struct lxmf_sync sync;
	struct ret_lxmf_seen_entry lxmf_seen_entries[CONFIG_RET_LXMF_SEEN_ENTRIES];
	struct ret_lxmf_seen lxmf_seen;

	/* The client's own destination: cfg.dest_name, or lxmf.delivery for
	 * an LXMF client. Chosen at start; cfg itself stays as given.
	 */
	const char *dest_name;
	const uint8_t *app_data;
	size_t app_data_len;
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

/** Recently delivered packet hashes: a repeat is proved, not redelivered. */
bool ret_client_seen_packet(const struct ret_client *c, const uint8_t hash[RET_HASH_LEN]);
void ret_client_remember_packet(struct ret_client *c, const uint8_t hash[RET_HASH_LEN]);

/**
 * Data that arrived over an inbound link (one packet, or a Resource):
 * LXMF DIRECT delivery with on_lxmf, else on_data.
 */
void ret_client_on_link_data(struct ret_client *c, const uint8_t *data, size_t len);

/** HDLC-frame c->tx_raw[0..raw_len) and send it. -ECONNRESET: link dropped. */
int ret_client_send_frame(struct ret_client *c, size_t raw_len);

/** Send a path request for @p dest_hash. */
int ret_client_send_path_request(struct ret_client *c, const uint8_t dest_hash[RET_TRUNC_HASH_LEN]);

/* --- Provided by ret_client_lxmf.c --------------------------------- */

/** Validate the LXMF configuration and set the destination up for it. */
int ret_lxmf_drv_setup(struct ret_client *c);

/** Load the remembered messages (settings are up). */
int ret_lxmf_drv_load(struct ret_client *c);

enum lxmf_outcome {
	LXMF_DELIVERED,
	LXMF_DUPLICATE,
	LXMF_TOO_OLD,
	LXMF_BAD_SIGNATURE,
	LXMF_MALFORMED,
};

/** A validated announce: keep an awaited sender's key. */
void ret_lxmf_drv_on_announce(struct ret_client *c, const struct ret_destination *d);

/** Check, remember and deliver a message body (packed[16:]) for us. */
enum lxmf_outcome ret_lxmf_drv_deliver(struct ret_client *c, const uint8_t *body, size_t len);

/** An LXMF message delivered DIRECT over a link: the full packed message. */
void ret_lxmf_drv_on_direct(struct ret_client *c, const uint8_t *packed, size_t len);

/** The decrypted payload of a packet for our lxmf.delivery address. */
void ret_lxmf_drv_on_data(struct ret_client *c, const uint8_t *plain, size_t len);

/* --- Provided by ret_client_lxmf_sync.c ---------------------------- */

void ret_lxmf_sync_drv_start(struct ret_client *c, const struct send_req *r);

/** Perform the sync's pending step (client loop). */
void ret_lxmf_sync_drv_service(struct ret_client *c);
int64_t ret_lxmf_sync_drv_next_event(const struct ret_client *c);

/** A sync is running: the link is not the application's. */
bool ret_lxmf_sync_drv_owns_link(const struct ret_client *c);

/* --- Provided by ret_client_link.c --------------------------------- */

/**
 * A buffer of CONFIG_RET_RESOURCE_MAX_SIZE bytes, free for use inside a
 * link response callback: the resource stream buffer, whose content is
 * spent once a response is delivered (responses themselves live in other
 * buffers). NULL while a resource is arriving (on any link): the response
 * being handled then came in one packet. Wipe what you put there.
 */
uint8_t *ret_link_drv_scratch(struct ret_client *c, size_t *cap);

/** The link with this id, of either role, or NULL. */
struct link *ret_link_drv_find(struct ret_client *c, const uint8_t id[RET_TRUNC_HASH_LEN]);


void ret_link_drv_open(struct ret_client *c, const struct send_req *r);
void ret_link_drv_request(struct ret_client *c, const struct send_req *r);
void ret_link_drv_identify(struct ret_client *c);
void ret_link_drv_close(struct ret_client *c);

/** A LINKREQUEST for the client's destination: accept it (responder). */
void ret_link_drv_on_request(struct ret_client *c, const struct ret_packet *pkt,
			     const uint8_t *raw, size_t raw_len);

/** A packet addressed to link @p l; @p raw is the frame (proofs hash it). */
void ret_link_drv_on_packet(struct ret_client *c, struct link *l, const struct ret_packet *pkt,
			    const uint8_t *raw, size_t raw_len);

/** A validated announce refreshed @p d's path. */
void ret_link_drv_on_path(struct ret_client *c, const struct ret_destination *d);

/** Timers: establishment, path wait, requests, keepalive, stale. */
void ret_link_drv_service(struct ret_client *c);
int64_t ret_link_drv_next_event(const struct ret_client *c);

/** The connection is gone: tear every link down without a LINKCLOSE. */
void ret_link_drv_teardown(struct ret_client *c);

/** Suspending: LINKCLOSE every link that has a key, then end it. */
void ret_link_drv_close_all(struct ret_client *c);

#endif /* RET_CLIENT_INTERNAL_H_ */
