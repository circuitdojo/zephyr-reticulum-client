/*
 * Copyright (c) 2026 Circuit Dojo LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * RNS Links, initiator side (RNS/Link.py): building the link request,
 * validating the responder's proof, deriving the link key, and the link
 * packet payloads. Pure functions; the client thread drives the state.
 */

#ifndef RET_LINK_H_
#define RET_LINK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ret_identity.h"
#include "ret_packet.h"

/* Packet contexts used on links (RNS/Packet.py). */
#define RET_CTX_RESOURCE      0x01
#define RET_CTX_RESOURCE_ADV  0x02
#define RET_CTX_RESOURCE_REQ  0x03
#define RET_CTX_RESOURCE_HMU  0x04
#define RET_CTX_RESOURCE_PRF  0x05
#define RET_CTX_RESOURCE_ICL  0x06
#define RET_CTX_RESOURCE_RCL  0x07
#define RET_CTX_REQUEST       0x09
#define RET_CTX_RESPONSE      0x0A
#define RET_CTX_KEEPALIVE     0xFA
#define RET_CTX_LINKIDENTIFY  0xFB
#define RET_CTX_LINKCLOSE     0xFC
#define RET_CTX_LRRTT         0xFE
#define RET_CTX_LRPROOF       0xFF

/** Largest plaintext per link packet at MTU 500: floor((500-1-19-48)/16)*16-1. */
#define RET_LINK_MDU          431
#define RET_LINK_REQUEST_LEN  (RET_X25519_LEN + RET_ED25519_PUB_LEN + 3)
#define RET_LINK_IDENTIFY_LEN (RET_PUBKEY_LEN + RET_SIG_LEN)

#define RET_LINK_MODE_AES256_CBC  1
/* sig | responder X25519 pub | signalling. */
#define RET_LINK_LRPROOF_LEN      (RET_SIG_LEN + RET_X25519_LEN + 3)
/* packet hash | signature. */
#define RET_LINK_PACKET_PROOF_LEN (RET_HASH_LEN + RET_SIG_LEN)
/* An RTT report above this is not believed. */
#define RET_LINK_RTT_MAX_S        3600.0

/** The initiator's per-link ephemeral keys. */
struct ret_link_keys {
	uint8_t x25519_prv[RET_X25519_LEN];
	uint8_t x25519_pub[RET_X25519_LEN];
	uint8_t ed25519_sk[64];
	uint8_t ed25519_pub[RET_ED25519_PUB_LEN];
};

int ret_link_keys_generate(struct ret_link_keys *k);

/** From fixed key material (tests). */
void ret_link_keys_load(struct ret_link_keys *k, const uint8_t x25519_prv[RET_X25519_LEN],
			const uint8_t ed25519_seed[32]);

/**
 * LINKREQUEST payload: X25519 pub | Ed25519 pub | signalling (MTU 500,
 * mode AES-256-CBC). MTU 500 is always signalled: rnsd's TCP interface
 * advertises a far larger hardware MTU, and the responder adopts whatever
 * is signalled, which would let it send frames our HDLC limit drops.
 */
void ret_link_request_data(const struct ret_link_keys *k, uint8_t out[RET_LINK_REQUEST_LEN]);

/**
 * link_id from a packed LINKREQUEST: the truncated hash of its hashable
 * part without the signalling bytes (which transports may rewrite).
 */
int ret_link_id_from_request(const uint8_t *raw, size_t len, uint8_t link_id[RET_TRUNC_HASH_LEN]);

/**
 * Validate the responder's LRPROOF (sig | resp X25519 pub [| signalling])
 * and derive the link key: HKDF-SHA256(64, X25519(ours, resp), salt =
 * link_id).
 *
 * @retval 0 valid; @p key and @p mtu set
 * @retval -EBADMSG malformed or bad signature: not from the destination,
 *         so the initiator ignores it and keeps waiting (as RNS does)
 * @retval -EPROTO validly framed but for an unsupported link mode
 */
int ret_link_proof_validate(const uint8_t link_id[RET_TRUNC_HASH_LEN],
			    const uint8_t dest_ed25519_pub[RET_ED25519_PUB_LEN],
			    const struct ret_link_keys *k, const struct ret_packet *proof,
			    uint8_t key[RET_TOKEN_KEY_LEN], uint16_t *mtu);

/** HKDF-SHA256(64, X25519(@p prv, @p peer_pub), salt = link_id): both sides. */
int ret_link_derive_key(const uint8_t prv[RET_X25519_LEN], const uint8_t peer_pub[RET_X25519_LEN],
			const uint8_t link_id[RET_TRUNC_HASH_LEN], uint8_t key[RET_TOKEN_KEY_LEN]);

/* --- Responder side ------------------------------------------------- */

/** An initiator's LINKREQUEST; pointers reference the packet data. */
struct ret_link_peer_request {
	const uint8_t *x25519_pub;
	const uint8_t *ed25519_pub;
	/** Signalled MTU, or RET_MTU when the request has no signalling. */
	uint32_t mtu;
	bool signalled;
};

/**
 * Parse a LINKREQUEST (64 bytes, or 67 with signalling) as
 * Link.validate_request does.
 *
 * @retval -EBADMSG not a link request, or a wrong size
 * @retval -EPROTO a link mode other than AES-256-CBC
 */
int ret_link_request_parse(const struct ret_packet *pkt, struct ret_link_peer_request *req);

/**
 * The responder's LRPROOF packet for @p link_id, signed by the
 * destination's identity, confirming @p mtu (Link.prove()).
 *
 * @return packet length, or a negative errno
 */
int ret_link_proof_build(const struct ret_local_identity *id,
			 const uint8_t link_id[RET_TRUNC_HASH_LEN],
			 const uint8_t resp_x25519_pub[RET_X25519_LEN], uint32_t mtu, uint8_t *out,
			 size_t cap);

/**
 * The proof for a received link packet: a PROOF on the link carrying
 * packet_hash | Ed25519(identity, packet_hash), unencrypted
 * (Link.prove_packet()).
 *
 * @return packet length, or a negative errno
 */
int ret_link_packet_proof_build(const struct ret_local_identity *id,
				const uint8_t link_id[RET_TRUNC_HASH_LEN],
				const uint8_t packet_hash[RET_HASH_LEN], uint8_t *out, size_t cap);

/**
 * The initiator's LRRTT plaintext: one msgpack number, seconds.
 *
 * @retval -EBADMSG not exactly one finite number in [0, RET_LINK_RTT_MAX_S]
 */
int ret_link_rtt_parse(const uint8_t *plain, size_t len, uint32_t *rtt_ms);

/**
 * Build a link DATA packet (H1, BROADCAST, LINK, hops 0) with @p context.
 * With @p key the plaintext is token-encrypted; without (KEEPALIVE,
 * resource parts) it is sent as is.
 *
 * @return packet length, or a negative errno
 */
int ret_link_packet_build(const uint8_t link_id[RET_TRUNC_HASH_LEN],
			  const uint8_t key[RET_TOKEN_KEY_LEN], uint8_t context, const uint8_t *pt,
			  size_t len, uint8_t *out, size_t cap);

/** A resource proof: h | SHA256(data | h). */
#define RET_LINK_RESOURCE_PROOF_LEN (2 * RET_SHA256_LEN)

/**
 * Build the PROOF packet (context RESOURCE_PRF, unencrypted) that confirms a
 * received resource.
 *
 * @return packet length, or a negative errno
 */
int ret_link_resource_proof_build(const uint8_t link_id[RET_TRUNC_HASH_LEN],
				  const uint8_t proof[RET_LINK_RESOURCE_PROOF_LEN], uint8_t *out,
				  size_t cap);

/** As ret_link_packet_build() with a caller-supplied IV (tests). */
int ret_link_packet_build_det(const uint8_t link_id[RET_TRUNC_HASH_LEN],
			      const uint8_t key[RET_TOKEN_KEY_LEN], uint8_t context,
			      const uint8_t *pt, size_t len, const uint8_t iv[RET_AES_BLOCK_LEN],
			      uint8_t *out, size_t cap);

/** LRRTT plaintext: msgpack float64 of the RTT in seconds (9 bytes). */
int ret_link_rtt_plain(double rtt_s, uint8_t *out, size_t cap);

/**
 * Request plaintext: msgpack [timestamp (float64), path_hash (bin16),
 * data], with @p data_mp an already-encoded msgpack value (nil if NULL).
 *
 * @return length, or -ENOBUFS
 */
int ret_link_request_plain(double timestamp, const char *path, const uint8_t *data_mp,
			   size_t data_len, uint8_t *out, size_t cap);

/**
 * Parse response plaintext msgpack [request_id (bin16), response]; the
 * response is returned as its encoded msgpack bytes.
 *
 * @retval -EBADMSG not a well-formed response
 */
int ret_link_response_parse(const uint8_t *plain, size_t len,
			    uint8_t request_id[RET_TRUNC_HASH_LEN], const uint8_t **response,
			    size_t *response_len);

/** LINKIDENTIFY plaintext: identity pub | Ed25519 sig over (link_id | pub). */
void ret_link_identify_plain(const struct ret_local_identity *id,
			     const uint8_t link_id[RET_TRUNC_HASH_LEN],
			     uint8_t out[RET_LINK_IDENTIFY_LEN]);

/** Keepalive interval for a link with this RTT: clamp(rtt*360/1.75, 5, 360) s. */
uint32_t ret_link_keepalive_ms(uint32_t rtt_ms);

#endif /* RET_LINK_H_ */
