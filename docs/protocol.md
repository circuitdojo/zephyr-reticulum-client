# Reticulum wire protocol (as implemented)

Checked against the RNS 1.5.7 source (`RNS/Packet.py`, `Identity.py`,
`Transport.py`, `Cryptography/{HKDF,Token}.py`, `Interfaces/TCPInterface.py`).
When upgrading the pinned `rns` in `tools/rns_peer`, re-check these and
regenerate the test vectors.

**TCP framing (`Interfaces/TCPInterface.py`)**
- HDLC framing, no CRC: `0x7E | escape(pkt) | 0x7E`.
- Escaping: `0x7D → 7D 5D` first, then `0x7E → 7D 5E`.
- KISS is off by default.
- The receiver must tolerate back-to-back flags (empty frames) and drop frames larger than the 500-byte MTU.

**Packet header (`Packet.py`)**
- Byte 0 is the flags byte:

  | Bit(s) | Field |
  |---|---|
  | 7 | IFAC (must be 0) |
  | 6 | header_type (0 = H1, 1 = H2) |
  | 5 | context_flag |
  | 4 | transport_type (0 = BROADCAST, 1 = TRANSPORT) |
  | 3–2 | dest_type (SINGLE 0, GROUP 1, PLAIN 2, LINK 3) |
  | 1–0 | packet_type (DATA 0, ANNOUNCE 1, LINKREQUEST 2, PROOF 3) |

- Byte 1 is hops.
- H1 layout: `dest_hash[16] | context[1] | data`.
- H2 layout: `transport_id[16] | dest_hash[16] | context[1] | data`.
- The receiver treats `hops + 1` as the path length (Transport increments hops on inbound).

**Hashes**
- `full_hash` = SHA-256. Truncated hash = first 16 bytes.
- `name_hash` = SHA-256(`"app.aspect…"`)[:10].
- `identity_hash` = SHA-256(pub[64])[:16].
- `dest_hash` = SHA-256(name_hash ‖ identity_hash)[:16].
- Public key = X25519 pub[32] ‖ Ed25519 pub[32].
- Packet hash = SHA-256(`(raw[0] & 0x0F)` ‖ `raw[2:]`). For H2 packets, use `raw[18:]` instead, so the hash does not change when the header is rewritten.

**Announce (`Identity.validate_announce`)**
- Layout: `data = pub[64] | name_hash[10] | random_hash[10] | ratchet[32] (only if context_flag) | sig[64] | app_data`.
- Validation:
  1. Ed25519-verify `sig` over `dest_hash ‖ pub ‖ name_hash ‖ random_hash ‖ ratchet ‖ app_data`.
  2. Check that `dest_hash` equals SHA-256(name_hash ‖ identity_hash)[:16].
  3. Reject any announce whose pubkey differs from the one already stored for that destination.

**Encryption to a SINGLE destination (`Identity.encrypt`, `Token.py`, `HKDF.py`)**
1. Generate an ephemeral X25519 keypair.
2. `shared = X25519(eph_prv, ratchet_pub if known else dest_x25519_pub)`.
3. `derived = HKDF-SHA256(len = 64, ikm = shared, salt = identity_hash, info = "")`. This is RFC 5869.
4. Split the key: `signing_key = derived[:32]`, `enc_key = derived[32:]`. The cipher is AES-256-CBC.
5. Output: `eph_pub[32] | IV[16] | AES-256-CBC(PKCS7(pt)) | HMAC-SHA256(signing_key, IV ‖ ct)[32]`.
- With the 500-byte MTU, the maximum plaintext is 383 bytes.

**Proof (`Identity.prove`, `ProofDestination`, `PacketReceipt.validate_proof`)**
- The proof is a PROOF-type packet, `dest_type` SINGLE, addressed to `packet_hash[:16]`.
- Data is either implicit (`sig[64]`, the default) or explicit (`packet_hash[32] | sig[64]`).
- Validation: Ed25519-verify `sig` over the full 32-byte `packet_hash`, using the destination's Ed25519 key.

**Routing through rnsd**
- `Transport.outbound` rule: if path hops > 1, convert the packet to H2/TRANSPORT with `transport_id` set to the announce's transport_id. Otherwise send it as H1/BROADCAST. ret-client copies this rule.
- rnsd with `enable_transport = False` still works for this setup:
  - It forwards packets addressed to destinations owned by its local clients (`for_local_client`, Transport.py:1968/2006).
  - It routes the proof back through its reverse table (Transport.py:2734).
  - It rebroadcasts announces from local clients out to TCP clients (Transport.py:2351).

**Gotcha:** Monocypher's default `crypto_eddsa_*` uses BLAKE2b. Use `crypto_ed25519_check` from `src/optional/monocypher-ed25519.c`, which uses SHA-512 per RFC 8032.

## Path requests (Transport.request_path, path_request_handler)

- A non-transport node sends a HEADER_1 PLAIN DATA packet to
  `H(name_hash("rnstransport.path.request"))[:16]` with data
  `dest_hash[16] | tag[16]`. It must be exactly 32 bytes: with more, bytes
  16..32 are read as the requesting transport ID.
- rnsd with `enable_transport = False` forwards a request from a TCP client
  to its local (shared-instance) clients; the owning client answers with an
  announce with context PATH_RESPONSE (0x0B), which rnsd relays back. A
  destination rnsd only knows through another interface gets no answer.
  The same limit applies to announces, so through a non-transport rnsd the
  client can reach only destinations owned by rnsd's local clients.
- rnsd batches every further request for the same destination for
  `PATH_REQUEST_GATE_TIMEOUT` = 45 s unless one was answered (and for
  local-client destinations it does not mark them answered). Retries
  within 45 s are dropped; the client's request timeout defaults to 60 s.

## Proof strategy

- `Destination.proof_strategy` defaults to PROVE_NONE. Most destinations
  never prove, so a missing proof is not by itself a sign of a dead link.

## Being a destination

- Private key: X25519 private key (32) || Ed25519 seed (32), as
  `Identity.get_private_key()`. Address = H(name_hash | H(pub)[:16])[:16].
- Announce: as above without a ratchet; `random_hash` is 5 random bytes then
  the emission time as 5 big-endian bytes. A node keeps the destination's
  newest emission time and ignores announces not newer than it (Transport.py
  ~L2236), and its path does not expire for days, so the emission time must
  be monotonic across reboots: ret-client persists it ("announce clock"),
  reserving values in blocks so it does not write flash on every announce.
- A non-transport rnsd passes a TCP client's announce on to its local
  clients when it updates its path table with it.
- Receiving: decrypt with HKDF salt = our identity hash; verify the HMAC
  before decrypting (Token.decrypt order).
- Proving: implicit proof, as above, signed with our Ed25519 key.
- Path requests for our address arrive as PLAIN DATA to the path request
  destination; answer with an announce with context PATH_RESPONSE.

## Links (initiator side; RNS/Link.py)

- **LINKREQUEST:** H1 (or H2 per the path rule), dest type SINGLE, packet type LINKREQUEST, unencrypted.
  - Data is `eph X25519 pub (32) | eph Ed25519 pub (32) | signalling (3)`.
  - Signalling is `(mtu & 0x1FFFFF) | ((mode << 5) << 16)` big-endian. With MTU 500 and mode AES-256-CBC (1) that is `20 01 F4`.
  - Always signal 500. rnsd's TCP interface advertises a far larger hardware MTU, and the responder adopts what it is told.
- **link_id:** `SHA256(hashable part without the signalling bytes)[:16]`, i.e. `SHA256(0x02 | dest | 0x00 | both pubs)[:16]`. It is independent of hops and of an H2 transport ID.
- **LRPROOF from the destination:** dest type LINK, PROOF, dest = link_id, context `0xFF`.
  - Data is `sig (64) | responder ephemeral X25519 pub (32) | signalling (3, optional)`.
  - The signature covers `link_id | resp pub | dest Ed25519 pub | signalling`.
- **Link key:** `HKDF-SHA256(64, X25519(eph prv, resp pub), salt = link_id)`. Link packets are a Token under this key (IV | CBC | HMAC), without SINGLE's ephemeral-key prefix.
- **Link packets:** always H1, BROADCAST, dest type LINK, hops 0, dest = link_id.
  - Unencrypted: KEEPALIVE (`0xFA`, data `FF`), resource parts, PROOFs.
  - Encrypted: everything else (REQUEST `0x09`, RESPONSE `0x0A`, LINKIDENTIFY `0xFB`, LINKCLOSE `0xFC`, LRRTT `0xFE`, RESOURCE_* control).
- **LRRTT:** sent right after the proof, as msgpack float64 seconds. The responder ignores requests until it arrives.
- **Request:** msgpack `[timestamp float64, SHA256(path)[:16] bin, data]`.
  - `request_id` is the truncated hash of the encrypted request packet.
  - Response is `[request_id bin16, response]`.
  - A response larger than the link MDU (431) travels as a Resource; see below.
- **Identify:** `identity pub (64) | Ed25519 sig(link_id | pub)`.
- **Close:** LINKCLOSE carrying the encrypted link_id.
- **Keepalive:** the initiator sends at `clamp(rtt * 360 / 1.75, 5, 360)` s. The responder only answers, and marks the link stale after 2× that without traffic. rnsd drops idle link-table entries after 900 s.

## Resources (receiving side; RNS/Resource.py)

ret-client receives Resources only as responses to its own requests (advertisement flag `p`, with `q` = request_id). Any other advertisement is refused.

- **Stream:** `Token(random4 | data)` under the link key. It is cut into parts of SDU 464 (MTU 500 − 35 header − 1 IFAC). Parts are sent as link DATA, context RESOURCE `0x01`, without another link token.
- **Hashes:**
  - `r` is a random 4 bytes.
  - The resource hash is `h = SHA256(data | r)`, over the plaintext, after the random prefix is removed.
  - The map hash of each part is `SHA256(part | r)[:4]`.
- **Advertisement:** RESOURCE_ADV `0x02`, encrypted. It is a msgpack map:
  - `t` transfer size (stream length), `d` data size, `n` parts
  - `h`, `r`, `o` original hash
  - `i` segment index, `l` total segments (1 and 1 unless split)
  - `q` request_id or nil
  - `f` flags: `e`=1 encrypted, `c`=2 compressed, `s`=4 split, `u`=8 request, `p`=16 response, `x`=32 metadata
  - `m` the first 74 map hashes (concatenated)
- **Request:** RESOURCE_REQ `0x03`, encrypted.
  - `00 | h | map hashes` for the next missing parts across the window. The window starts at 4, grows by one per completed window up to 10, and shrinks on timeout down to 2.
  - When the window runs past the known hashmap: `FF | last known map hash | h | map hashes`. The sender answers with a hashmap update.
- **Hashmap update:** RESOURCE_HMU `0x04`, encrypted: `h | msgpack [segment, bin(74 map hashes)]`.
- **Completion:**
  1. Decrypt the whole stream: verify the HMAC, unpad, drop `random4`.
  2. Check `SHA256(data | r) == h`.
  3. Send RESOURCE_PRF `0x05` as an unencrypted PROOF packet on the link: `h | SHA256(data | h)`.
  4. The data is the packed response, `[request_id, response]`.
- **Cancel:** RESOURCE_ICL `0x06` (sender) and RESOURCE_RCL `0x07` (receiver) are encrypted and carry `h`. RNS's receiver sends RCL when it gives up, and so does ret-client.
- **Timeouts (receiver):** wait `rtt × 4 + grace` for parts (plus 0.5 s per retry used), then re-request. Give up and refuse after 16 retries without progress. The request's own deadline is suspended while its resource arrives.
- **Refused with RCL:**
  - compressed (`c`): bz2 decompression needs megabytes of RAM
  - split (`l` > 1), metadata, or unencrypted
  - larger than `CONFIG_RET_RESOURCE_MAX_SIZE` (stream bytes)

  The request then fails with `-ENOTSUP` or `-EFBIG`, never silently. RNS compresses only when that makes the data smaller, and encrypted payloads such as LXMF messages don't compress, so the propagation sync flow should not meet compressed resources.
