/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * A Reticulum transport node (RNS/Transport.py with enable_transport):
 * routes packets between interfaces, rebroadcasts announces (also on the
 * interface they came in on, so one radio repeats for nodes out of each
 * other's range), answers and forwards path requests, and keeps the path,
 * announce, link and reverse tables. See docs/protocol.md, "Transport node".
 *
 * Pure code: no threads, no clock. The caller passes the time in, calls
 * ret_transport_jobs() periodically, serialises all calls, and sends
 * frames through each interface's callback. Paths live in a store (flash
 * on a device); the RAM path table caches them.
 */

#ifndef RET_TRANSPORT_H_
#define RET_TRANSPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ret_identity.h"
#include "ret_ifac.h"
#include "ret_packet.h"

/** An RNode's hardware MTU, the largest an interface here may have. */
#define RET_TRANSPORT_HW_MTU_MAX 508
/*
 * Largest packet accepted once any access code is stripped: RNS checks
 * against HW_MTU + ifac_size (16 with IFAC off, up to 64 with it on).
 */
#define RET_TRANSPORT_PACKET_MAX (RET_TRANSPORT_HW_MTU_MAX + RET_IFAC_MAX_SIZE)
/** Largest frame on an interface: a packet plus its access code. */
#define RET_TRANSPORT_FRAME_MAX  (RET_TRANSPORT_PACKET_MAX + RET_IFAC_MAX_SIZE)

/** Interface modes (RNS Interface.MODE_*). */
enum ret_iface_mode {
	RET_IFACE_MODE_FULL = 1,
	RET_IFACE_MODE_POINT_TO_POINT = 2,
	RET_IFACE_MODE_ACCESS_POINT = 3,
	RET_IFACE_MODE_ROAMING = 4,
	RET_IFACE_MODE_BOUNDARY = 5,
	RET_IFACE_MODE_GATEWAY = 6,
	RET_IFACE_MODE_INTERNAL = 7,
};

/** Path states (Transport.STATE_*). */
enum ret_path_state {
	RET_PATH_STATE_UNKNOWN = 0,
	RET_PATH_STATE_UNRESPONSIVE = 1,
	RET_PATH_STATE_RESPONSIVE = 2,
};

struct ret_transport_iface;

/**
 * Send a frame (access code already added). Called from inside
 * ret_transport_inbound() and ret_transport_jobs(); it must copy the frame
 * and must not call back into the transport.
 */
typedef int (*ret_transport_send_fn)(struct ret_transport_iface *iface, const uint8_t *frame,
				     size_t len);

struct ret_transport_queued_announce {
	bool used;
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	uint8_t hops;
	uint16_t len;
	int64_t time;
	uint64_t emitted;
};

struct ret_transport_held_announce {
	bool used;
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	/** Hop count once received (incremented). */
	uint8_t hops;
	uint16_t len;
	/** As received, access code stripped. */
	uint8_t raw[RET_MTU];
};

#define RET_TRANSPORT_FREQ_SAMPLES 48

struct ret_transport_freq {
	int64_t t[RET_TRANSPORT_FREQ_SAMPLES];
	uint8_t head;
	uint8_t count;
};

struct ret_transport_iface {
	/* Set by the caller before ret_transport_init(). */
	const char *name;
	enum ret_iface_mode mode;
	/** Bits per second (RNode: from the radio settings). */
	uint32_t bitrate;
	/** At most RET_TRANSPORT_HW_MTU_MAX. */
	uint16_t hw_mtu;
	/**
	 * RNS AUTOCONFIGURE_MTU or FIXED_MTU: a link request forwarded onto
	 * this interface has its MTU signalling clamped to hw_mtu. False, as
	 * for an RNode, strips the signalling instead.
	 */
	bool mtu_signalling;
	/** Announce cap in hundredths of a percent (RNS announce_cap; 200 = 2%). */
	uint16_t announce_cap;
	/** Access code for this interface, or NULL for an open one. */
	const struct ret_ifac *ifac;
	ret_transport_send_fn send;
	void *user;

	/* Transport state. */
	bool online;
	uint8_t index;
	int64_t created;
	int64_t announce_allowed_at;
	struct ret_transport_queued_announce queue[CONFIG_RET_TRANSPORT_ANNOUNCE_QUEUE];
	struct ret_transport_freq ia_freq;
	struct ret_transport_freq ip_freq;
	bool ic_burst_active;
	int64_t ic_burst_activated;
	int64_t ic_burst_sustained;
	int64_t ic_held_release;
	bool ic_pr_burst_active;
	int64_t ic_pr_burst_activated;
	int64_t ic_pr_burst_sustained;
	uint8_t ic_pr_burst_cooldown;
	struct ret_transport_held_announce held[CONFIG_RET_TRANSPORT_HELD_ANNOUNCES];
	uint32_t rx_frames;
	uint32_t tx_frames;
	uint32_t drops;
};

/** A path, as the store keeps it. Times are ms in the boot that wrote them. */
struct ret_transport_path_meta {
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	/** Transport ID of the next hop, or the destination itself when direct. */
	uint8_t next_hop[RET_TRUNC_HASH_LEN];
	uint8_t hops;
	/** Index of the receiving interface. */
	uint8_t iface;
	uint8_t state;
	uint8_t n_blobs;
	uint8_t blobs[CONFIG_RET_TRANSPORT_RANDOM_BLOBS][RET_RANDOM_HASH_LEN];
	/** An announce rate entry exists (Transport.announce_rate_table). */
	bool rate_known;
	uint8_t rate_violations;
	uint32_t boot;
	int64_t timestamp;
	int64_t expires;
	int64_t rate_last;
	int64_t rate_blocked_until;
};

/**
 * Where paths and their announces live. Every call may fail with a
 * negative errno; -ENOENT means no such path.
 */
struct ret_transport_store {
	/**
	 * Read a path; @p announce (may be NULL) receives the announce as
	 * received, up to @p cap bytes, its length in @p len.
	 */
	int (*load)(struct ret_transport_store *s, const uint8_t dest_hash[RET_TRUNC_HASH_LEN],
		    struct ret_transport_path_meta *meta, uint8_t *announce, size_t cap,
		    size_t *len);
	/** Write a path. With @p announce NULL, keep the stored announce. */
	int (*save)(struct ret_transport_store *s, const struct ret_transport_path_meta *meta,
		    const uint8_t *announce, size_t len);
	int (*remove)(struct ret_transport_store *s, const uint8_t dest_hash[RET_TRUNC_HASH_LEN]);
	/**
	 * Call @p cb for each path until it returns non-zero. The transport
	 * does not call the store from @p cb.
	 */
	int (*foreach)(struct ret_transport_store *s,
		       int (*cb)(const struct ret_transport_path_meta *meta, void *user), void *user);
};

struct ret_transport_path {
	bool used;
	/** Changed since stored (the timestamp, refreshed by forwarding). */
	bool dirty;
	int64_t last_used;
	struct ret_transport_path_meta m;
};

struct ret_transport_announce_entry {
	int64_t timestamp;
	int64_t retransmit_at;
	uint8_t retries;
	uint8_t hops;
	uint8_t local_rebroadcasts;
	bool block_rebroadcasts;
	/** Interface index, or -1 for all. */
	int8_t attached;
};

struct ret_transport_announce {
	bool used;
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	struct ret_transport_announce_entry e;
	/** An entry a path response displaced, restored once it has gone out. */
	bool has_held;
	struct ret_transport_announce_entry held;
};

struct ret_transport_link {
	bool used;
	bool validated;
	uint8_t link_id[RET_TRUNC_HASH_LEN];
	uint8_t next_hop[RET_TRUNC_HASH_LEN];
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	uint8_t nh_iface;
	uint8_t rcvd_iface;
	uint8_t remaining_hops;
	uint8_t taken_hops;
	int64_t timestamp;
	int64_t proof_timeout;
};

struct ret_transport_reverse {
	bool used;
	uint8_t hash[RET_TRUNC_HASH_LEN];
	uint8_t rcvd_iface;
	uint8_t out_iface;
	int64_t timestamp;
};

struct ret_transport_pr {
	bool used;
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	int64_t time;
};

struct ret_transport_discovery {
	bool used;
	bool engaged;
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	/** Bit per interface index. */
	uint8_t ifaces;
	int64_t timeout;
};

struct ret_transport_pending_pr {
	uint8_t dest_hash[RET_TRUNC_HASH_LEN];
	/** Interface index not to ask on, or -1. */
	int8_t blocked;
};

#define RET_TRANSPORT_PR_TAG_LEN (RET_TRUNC_HASH_LEN + RET_PATH_REQUEST_TAG_LEN)
#define RET_TRANSPORT_PENDING_PRS 32

struct ret_transport {
	const struct ret_local_identity *identity;
	struct ret_transport_store *store;
	struct ret_transport_iface *ifaces[CONFIG_RET_TRANSPORT_MAX_IFACES];
	uint8_t n_ifaces;
	uint32_t boot;
	int64_t now;
	uint8_t pr_dest[RET_TRUNC_HASH_LEN];
	uint8_t tunnel_dest[RET_TRUNC_HASH_LEN];

	struct ret_transport_path paths[CONFIG_RET_TRANSPORT_PATHS];
	struct ret_transport_announce announces[CONFIG_RET_TRANSPORT_ANNOUNCES];
	struct ret_transport_link links[CONFIG_RET_TRANSPORT_LINKS];
	struct ret_transport_reverse reverse[CONFIG_RET_TRANSPORT_REVERSE];
	/** Our own path requests (Transport.path_requests). */
	struct ret_transport_pr own_prs[CONFIG_RET_TRANSPORT_PATH_REQUESTS];
	struct ret_transport_pr inflight[CONFIG_RET_TRANSPORT_PATH_REQUESTS];
	struct ret_transport_discovery discovery[CONFIG_RET_TRANSPORT_PATH_REQUESTS];
	struct ret_transport_pending_pr pending_prs[RET_TRANSPORT_PENDING_PRS];
	uint8_t pending_head;
	uint8_t pending_count;

	/* Packet hashes (16 bytes each) in two halves, as packet_hashlist(_prev). */
	uint8_t hashes[2][CONFIG_RET_TRANSPORT_HASHLIST][RET_TRUNC_HASH_LEN];
	uint16_t hash_count[2];
	uint8_t hash_cur;
	uint8_t tags[2][CONFIG_RET_TRANSPORT_PR_TAGS][RET_TRANSPORT_PR_TAG_LEN];
	uint16_t tag_count[2];
	uint8_t tag_cur;

	int64_t announces_checked;
	int64_t tables_culled;
	int64_t ifaces_checked;
	int64_t pending_pr_at;

	uint8_t work[RET_TRANSPORT_FRAME_MAX];
	uint8_t build[RET_TRANSPORT_PACKET_MAX];
	uint8_t stored[RET_MTU];
	uint8_t tx[RET_TRANSPORT_FRAME_MAX];
};

/**
 * Start a transport node: our transport ID is @p identity's hash. Paths in
 * @p store are loaded into RAM up to its size; paths written in another
 * @p boot get fresh timestamps, as their times are meaningless now.
 *
 * Interfaces start offline: report them with ret_transport_iface_online().
 *
 * @retval -EINVAL no store, or no or too many interfaces
 */
int ret_transport_init(struct ret_transport *t, const struct ret_local_identity *identity,
		       struct ret_transport_store *store, struct ret_transport_iface *const *ifaces,
		       size_t n_ifaces, uint32_t boot, int64_t now);

void ret_transport_iface_online(struct ret_transport *t, struct ret_transport_iface *iface,
				bool online, int64_t now);

/** Process a frame received on @p iface. */
void ret_transport_inbound(struct ret_transport *t, struct ret_transport_iface *iface,
			   const uint8_t *frame, size_t len, int64_t now);

/**
 * Timed work: announce retransmits and queues, held announces, table
 * culling, queued path requests.
 *
 * @return the time by which to call again
 */
int64_t ret_transport_jobs(struct ret_transport *t, int64_t now);

/**
 * Send tunnel synthesis on @p iface (Transport.synthesize_tunnel), as a
 * TCPClientInterface does on each connect, so the hub keeps the paths it
 * learned through us across reconnects. @p iface_hash identifies the
 * interface (RNS: SHA256 of its name); keep it the same across connects.
 */
int ret_transport_synthesize_tunnel(struct ret_transport *t, struct ret_transport_iface *iface,
				    const uint8_t iface_hash[RET_HASH_LEN], int64_t now);

/**
 * The path to @p dest_hash, loading it from the store if needed, or NULL.
 * Valid until the next call into the transport.
 */
const struct ret_transport_path_meta *ret_transport_path(struct ret_transport *t,
							 const uint8_t dest_hash[RET_TRUNC_HASH_LEN]);

#endif /* RET_TRANSPORT_H_ */
