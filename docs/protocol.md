# Reticulum wire protocol (as implemented)

Checked against the RNS 1.5.7 source (`RNS/Packet.py`, `Identity.py`,
`Transport.py`, `Cryptography/{HKDF,Token}.py`, `Interfaces/TCPInterface.py`).
When upgrading the pinned `rns` in `tools/rns_peer`, re-check these and
regenerate the test vectors.

**TCP framing (`Interfaces/TCPInterface.py`)**
- HDLC framing, no CRC: `0x7E | escape(pkt) | 0x7E`.
- Escaping: `0x7D → 7D 5D` first, then `0x7E → 7D 5E`.
- KISS is off by default.
- The receiver must tolerate back-to-back flags (empty frames) and drop frames larger than the 500-byte MTU (plus the access code on a protected interface).

**Packet header (`Packet.py`)**
- Byte 0 is the flags byte:

  | Bit(s) | Field |
  |---|---|
  | 7 | IFAC (set only on the wire of a protected interface; see "Interface access codes") |
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

## Interface access codes (Reticulum.py interface setup; Transport.handle_outgoing_ifac, handle_ifac)

An interface with `network_name` and/or `passphrase` (a "protected" interface) signs every packet and drops packets without a valid code, both ways. ret-client does the same with `CONFIG_RET_IFAC` (`src/ret_ifac.c`), matching RNS byte for byte (vectors from RNS's own functions).

- **Key:** `origin = SHA256(network_name)` if set, then `SHA256(passphrase)` if set. `ifac_key = HKDF-SHA256(64, ikm = SHA256(origin), salt = IFAC_SALT adf54d88…cff8, info = "")`. `Identity.from_bytes(ifac_key)` signs: X25519 key then Ed25519 seed.
- **Size:** `ifac_size` in bytes: config `ifac_size` bits / 8, 16 for TCP interfaces by default. The packet MTU stays 500 (RNS reserves `IFAC_MIN_SIZE` 1); the frame grows by the size.
- **Sending:** `ifac = Ed25519_sign(raw)[-size:]`. `mask = HKDF(len(raw) + size, ikm = ifac, salt = ifac_key)`. Frame = `[raw0 | 0x80, raw1] | ifac | raw[2:]`, XORed with the mask except the code bytes, then byte 0 `| 0x80` again.
- **Receiving:** take the code at `[2, 2 + size)`, unmask the rest with `HKDF(len(frame), ikm = code, salt = ifac_key)`, clear the flag, drop the code, and sign the result again: its last `size` bytes must equal the code. Only the signature's tail travels, so checking costs a full signature.
- **Mismatch:** a protected interface drops packets without the flag or with a wrong code; an open one drops flagged packets. RNS logs "Invalid IFAC" on the server side; ret-client logs the first drop per connection.
- **Cost:** one Ed25519 signature per packet sent and per packet received, every announce the hub forwards included.

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

## Transport node (RNS/Transport.py with enable_transport; src/ret_transport.c)

A node with several interfaces (a LoRa radio and a TCP uplink) routes as an RNS instance with
`enable_transport = yes`. Stock rnsd and RNode peers need nothing special. Byte formats are tested
against RNS-built vectors (`transport_vectors()` in `gen_vectors.py`).

**Inbound** (`preprocess_inbound`, `packet_filter`, `_inbound`):
- **Order:** strip IFAC, check `len <= HW_MTU + ifac_size` (16 when IFAC is off), unpack (hops
  under 128, data not empty), filter, then `hops += 1`.
- **Filter:**
  - Drop non-announces addressed through another transport ID.
  - KEEPALIVE, RESOURCE, RESOURCE_REQ, RESOURCE_PRF, CACHE_REQUEST and CHANNEL contexts always
    pass.
  - PLAIN and GROUP packets pass only at hops ≤ 1 (before the increment) and are never relayed.
  - Everything else is deduplicated by packet hash. A repeated SINGLE announce still passes,
    which rebroadcast detection needs.
- **Announces:** the signature and destination hash are checked first. An announce for an unknown
  destination we aren't looking for is held while its interface bursts.
- **Path requests:** deduplicated by `dest | tag`. While one is in flight (45 s), further requests
  for the destination only record their interface, to be answered by the announce.
- **HEADER_2 to our transport ID:** look up the path (none: drop).
  - More than one hop left: rewrite the transport ID to the next hop.
  - One hop left: `flags = HEADER_1 | BROADCAST | flags & 0x0F` (the context flag is dropped, as
    RNS does), then the transport ID is removed.
  - A link request goes into the link table, with proof timeout `now + 4000/bitrate s +
    6 s × max(1, hops left)`. Its 3 MTU signalling bytes (data exactly 67 bytes) are removed
    onto an interface without MTU autoconfiguration (an RNode). Elsewhere they are set to
    `min(next hop, previous hop) HW_MTU` when smaller; a mode other than AES-256-CBC drops it.
  - Other packets go into the reverse table under their truncated hash.
- **Link table:** packets to a link ID go out by hop count.
  - Same interface both ways: if hops equal the remaining or the taken hops.
  - From the next hop: if hops equal the remaining hops.
  - From the requester: if hops equal the taken hops.
  - Not before the link's proof.
- **LRPROOF:** checked against the destination's announced Ed25519 key over `link_id |
  responder X25519 | that key | signalling`, then forwarded to the requester; the link is then
  valid. A valid proof that arrives with a different hop count first updates the path's hops
  (rebalance).
- **Other proofs:** pop the reverse entry, and forward it only if it arrived on the packet's
  outbound interface.

**Announces:**
- **Rebroadcast detection** (H2 announces for a destination in the announce table):
  - Same distance as ours: counts a local rebroadcast; two after our first send end our retries.
  - One hop further while our retry is pending: ours was passed on, so stop.
- **Accepting a path:**
  - A new destination is accepted.
  - With hops no more than the path's: only a new random blob newer than every stored one.
  - With more hops: a new blob once the path has expired; or one newer than the path; or the
    same emission time when the path is unresponsive.
  - The emission time is `random_hash[5:10]`, big-endian.
- **Rate limit:** the target is 3600 s, grace 5, penalty 0 (the transport defaults). A blocked
  announce updates the path but is not rebroadcast.
- **Rebroadcast:** path responses (context 0x0B) are never rebroadcast. Other accepted
  announces go out HEADER_2 with our transport ID after 0–0.5 s, and again 5.5 s later. They go
  on every interface, including the one they came in on.
- **Discovery:** requests waiting for this destination get an immediate PATH_RESPONSE on each
  requesting interface.
- **Expiry:** paths expire after 7 days, 1 day on access-point interfaces, 6 hours on roaming
  ones. They are dropped once unused for that long.

**Outbound** (our announces, path requests, tunnel synthesis):
- Mode rules apply only when no interface is attached. Access-point interfaces get no
  rebroadcasts; roaming and boundary interfaces filter by the path's interface mode.
- **Announce cap:** the next announce may go `len × 8 / bitrate / cap` later (default cap 2%).
  Until then announces queue, fewest hops first, dropped after 3 hours. At 7 kbps a 223-byte
  rebroadcast blocks the radio for about 12.7 s. Attached announces (path responses) skip the
  cap.

**Path requests** (`path_request`):
- **Known path:** answered after 0.4 s with one PATH_RESPONSE on the requesting interface.
  Not answered when the requester is the path's next hop, or back out a roaming interface the
  path came from.
- **Unknown path,** on an access-point, gateway, roaming or internal interface (boundary:
  towards boundary and gateway interfaces only): forwarded on the other online interfaces with
  the same tag, as `dest | our transport ID | tag`. A forwarded request on an interface is
  dropped while that interface's announce queue is non-empty or its cap blocks.
- **Other modes:** unknown paths are not searched for.

**Jobs:**
- **Every 1 s:** announce retransmits.
- **Every 5 s:**
  - Cull the tables: reverse entries at 480 s, validated links at 900 s, unproven links at their
    proof timeout, paths unused past their expiry, path requests at 45 s.
  - Ingress-control upkeep, and the release of one held announce.
- **Unproven link timeouts:** a request for the path is queued (one every 0.5 s). If the path
  was one hop, it is marked unresponsive and the request goes on the other interfaces.

**Tunnel synthesis** (`synthesize_tunnel`, sent on each uplink connect): HEADER_1 PLAIN DATA to
`rnstransport.tunnel.synthesize`, data `pub(64) | interface hash(32) | random(16) |
Ed25519 signature of the first 112 bytes`. rnsd then keeps the paths it learned through us for
8 hours across reconnects.

**Differences from RNS:**
- **Tables are bounded,** and the oldest entry makes room.
  - The path table is a RAM cache over a store (flash). A miss loads the path from the store, and
    a path evicted from RAM stays in the store.
  - Only cached paths are culled. Stored ones go when the store needs room.
  - A path whose stored announce is gone is dropped, since it can't be announced, answered or
    used to check link proofs.
  - Paths written in another boot are loaded as just heard, so they last their full time.
  - Stored records that don't fit this build are removed.
- **Announce queue:** a queued announce goes out from the stored announce, which may be newer
  than the one queued, with the queued hop count.
- **Per path:** 8 random blobs (RNS keeps 64), and the rate-limit state.
- **Packet hashes:** two halves of 16-byte truncated hashes.
- **Not implemented:** local destinations other than `rnstransport.path.request`, remote
  management, probes, blackholes, interface discovery, gravity, egress control and a persisted
  hash list.

**RNode on-air framing** (RNode firmware `Config.h`, `RNode_Firmware.ino`; src/ret_rnode_air.c):
- **Header byte:** each LoRa frame starts with one, a random nibble in bits 7-4 and `FLAG_SPLIT`
  0x01.
- **Splitting:** a packet up to 254 bytes is one frame. Up to the MTU of 508 it is two frames with
  the same header: 254 bytes, then the rest.
- **Reassembly:**
  - A split frame with nothing pending starts a packet, and one with the same sequence completes
    it.
  - A split frame with another sequence restarts it.
  - A frame that isn't split discards any partial packet.
- **SX126x:** sync word 0x1424, explicit header, CRC on, no IQ inversion, preamble at least 18
  symbols.

## Proof strategy

- `Destination.proof_strategy` defaults to PROVE_NONE. Most destinations
  never prove, so a missing proof is not by itself a sign of a dead link.

## Being a destination

- Private key: X25519 private key (32) || Ed25519 seed (32), as
  `Identity.get_private_key()`. Address = H(name_hash | H(pub)[:16])[:16].
- Announce: as above, with a ratchet unless `CONFIG_RET_RATCHETS` is off;
  `random_hash` is 5 random bytes then
  the emission time as 5 big-endian bytes. A node keeps the destination's
  newest emission time and ignores announces not newer than it (Transport.py
  ~L2236), and its path does not expire for days, so the emission time must
  be monotonic across reboots: ret-client persists it ("announce clock"),
  reserving values in blocks so it does not write flash on every announce.
- **Ratchets** (`Destination.enable_ratchets`, `rotate_ratchets`;
  `Identity.decrypt`):
  - A ratchet is an X25519 key pair. The announce carries the newest one's
    public key after `random_hash`, inside the signed data, and sets the
    context flag. Its id is `SHA256(pub)[:10]`.
  - A sender that validated the announce encrypts SINGLE packets to the
    ratchet instead of the identity's X25519 key (the HKDF salt is still the
    identity hash) and remembers it for 30 days (`RATCHET_EXPIRY`). LXMF
    propagated messages are encrypted the same way, so a sync decrypts them
    with ratchets too.
  - The receiver tries each ratchet private key, newest first, then the
    identity key. The token's HMAC tells which one fits; nothing in the
    packet names the ratchet.
  - RNS rotates inside `announce()` when the newest is older than
    `RATCHET_INTERVAL` (30 min), and at the first announce after a restart
    (the rotation time is not persisted); it keeps 512. ret-client rotates at most
    once per `CONFIG_RET_RATCHET_INTERVAL_S` (a day) and keeps
    `CONFIG_RET_RATCHET_COUNT` (8), so a message stays decryptable for about
    count × interval after the sender last heard us. Rotation needs the wall
    clock; without it the current ratchet keeps being announced.
  - A new ratchet is stored (`ret/rt/<n>`) before the announce carrying it
    goes out: senders keep using the last one they heard, so it must
    survive a reboot. Proofs and links are unaffected (identity key).
  - If that write fails, ret-client announces the current (stored) ratchet and
    tries again at the next announce. RNS instead drops its ratchets
    (`_persist_ratchets` sets them to None and raises): that announce is not
    sent, later ones carry no ratchet, and senders keep encrypting to the old
    one for 30 days, which it can no longer decrypt.
  - Forward secrecy is only as good as the erase: a replaced settings record
    can stay in flash until the backend compacts it.
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
- **Data with a proof** (LXMF DIRECT): DATA, context NONE, encrypted. The responder proves it (PROVE_ALL, as LXMF's delivery destination does) with a PROOF on the link: dest = link_id, context NONE, unencrypted, `packet_hash | Ed25519 sig(packet_hash)` by the **destination's identity** key (`Link.prove_packet`). ret-client checks it against the Ed25519 key pinned when the link request went out, and also accepts the implicit form (the signature alone), as `PacketReceipt.validate_link_proof` does. A proof that does not verify is ignored, not fatal. The proof is due within `rtt × 6` (`TRAFFIC_TIMEOUT_FACTOR`) plus 1 s of grace; RNS's floor is 5 ms.
- **Close:** LINKCLOSE carrying the encrypted link_id.
- **Keepalive:** the initiator sends at `clamp(rtt * 360 / 1.75, 5, 360)` s. The responder only answers, and marks the link stale after 2× that without traffic. rnsd drops idle link-table entries after 900 s.

## Links (responder side; RNS/Link.py validate_request, prove)

Other nodes may open links to the client's own destination: `CONFIG_RET_INBOUND_LINKS` of them at once (default 2). This is how LXMF DIRECT delivery reaches the device.

- **LINKREQUEST:** 64 bytes (`init X25519 pub | init Ed25519 pub`) or 67 (plus signalling). A request without signalling means AES-256-CBC, MTU 500. A request for any other mode is dropped and the initiator times out, as with RNS. A signalled MTU below 500 is refused, because Resource parts are sized for 500 (SDU 464).
- **link_id:** as on the initiator side, `SHA256(hashable part without signalling)[:16]`. A request whose link_id is already in use is ignored.
- **Keys:** a fresh ephemeral X25519 key; key = `HKDF(64, X25519(eph, init pub), salt=link_id)`. The private key is wiped once the key is derived.
- **LRPROOF:** dest type LINK, PROOF, context `0xFF`, unencrypted. Data = `sig | eph X25519 pub | signalling`. The signature, by the **destination identity's** Ed25519 key, covers `link_id | eph pub | identity Ed25519 pub | signalling`.
  - ret-client always confirms MTU 500 (`20 01 F4`): with no signalling, with 500, or with something larger, such as TCP's 262144. The initiator adopts the confirmed MTU.
  - rnsd checks this signature (and the hop count) before it validates the link-table entry.
- **HANDSHAKE:** until the initiator's LRRTT, a msgpack number in seconds. RTT = `max(measured since the request, reported)`. The establishment timeout is `6 s × hops + 360 s`.
  - ret-client takes only LRRTT and LINKCLOSE in this state. RNS processes anything once the proof is out, but its initiator always sends LRRTT first, and the path keeps order.
- **Keepalive:** the responder never sends one. It answers the initiator's `0xFF` with `0xFE` when it sent nothing within the keepalive interval. Stale after `2 × keepalive` without traffic, then closed after `rtt × 4 + 5 s`, as on the initiator side.
- **DATA (context NONE):** decrypted, delivered once (repeats are recognised by packet hash), and always proved.
  - The proof is a PROOF on the link, context NONE, unencrypted: `packet_hash | Ed25519(identity, packet_hash)`, as `Link.prove_packet()` builds it.
  - Data goes to `on_lxmf` as a DIRECT LXMF message when the client is an LXMF node, else to `on_data`.
- **Not supported:** LINKIDENTIFY, REQUEST and RESPONSE from the initiator are ignored, so there are no request handlers. Inbound links have no application callbacks.
- **Table full:** a link that has waited more than 10 s in handshake is replaced, so spoofed requests can't hold every slot, yet can't evict a real handshake still waiting for its RTT. Otherwise the request is dropped. Repeats of a link request (by packet hash) are ignored, as RNS's packet filter drops them.
- **Undecryptable RTT:** ignored, since anyone who saw the request knows the link_id. An RTT that decrypts but isn't a number closes the link, as `Link.rtt_packet` does.
- **Suspend and disconnect:** suspend closes every link (LINKCLOSE); a lost connection ends them.

## Resources (RNS/Resource.py)

ret-client receives Resources in two cases:
- as responses to its own requests on the outbound link (advertisement flag `p`, with `q` = request_id)
- as deliveries on inbound links: no request id, neither the `u` nor the `p` flag, as LXMF DIRECT sends a packed message too large for one packet. Only LXMF nodes accept these.

Any other advertisement is refused.

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

  The request then fails with `-ENOTSUP` or `-EFBIG`, never silently. RNS compresses only when that makes the data smaller, and encrypted payloads such as LXMF messages don't compress, so the propagation sync flow should not meet compressed resources. On an inbound link the sender sees the refusal; LXMF marks the message REJECTED for good, which is right for something that can never fit.
- **One at a time:** only one Resource uses the buffers at once, arriving on any link or leaving on the outbound one (see Sending below). None is received for more than 3 minutes, however its parts trickle in.
  - **A delivery that fails in transit** (timed out, or corrupt): its inbound link is closed rather than refused, so the LXMF sender retries.
  - **A delivery advertised while another resource is arriving:** the inbound link is **closed** rather than refused. RCL would make LXMF reject the message permanently; a closed link makes it retry 10 s or more later.
  - **A sync response advertised while a delivery holds the buffers:** the sync sends the same `/get` again once they're free, up to 3 times. `/get` is idempotent: nothing is deleted until acknowledged.

### Sending

ret-client sends one kind of Resource: single segment, uncompressed, encrypted, no metadata, neither request nor response (flags `e` only, `q` nil), on its outbound link. This is how LXMF DIRECT sends a packed message larger than one link packet. The layout is the receiving side's, built byte for byte as `Resource.__init__` and `ResourceAdvertisement.pack` do (checked against RNS-built vectors):

- **Stream:** `Token(random4 | data)` with a fresh IV, cut into SDU-464 parts. The stream lives in the resource buffer, so `CONFIG_RET_RESOURCE_MAX_SIZE` bounds it.
- **Hashes:** `h = SHA256(data | r)`; the expected proof is `SHA256(data | h)`. Map hashes must be unique within `COLLISION_GUARD_SIZE` (2 × 10 + 74 = 94) parts; on a collision `r` is drawn again, as Resource remaps.
- **Advertisement:** the map in `ResourceAdvertisement.pack`'s key order: `t, d, n, h, r, o (= h), i = 1, l = 1, q = nil, f = 1, m` (the first 74 map hashes).
- **Requests:** the parts whose map hashes are asked for, looked for from the receiver's last known consecutive height across the collision guard, are sent (or sent again) in part order. A request flagged `FF | last map hash` also gets the next hashmap segment as an HMU; the last map hash must end a 74-hash segment, or the transfer is cancelled (Resource's "sequencing error"). A repeated request packet (same packet hash) is ignored, as `Link.receive` does with `req_hashlist`.
- **Completion:** RESOURCE_PRF with `h | expected proof` completes it. RESOURCE_RCL from the receiver means refused; LXMF treats that as final.
- **Timeouts (Resource's sender watchdog):**
  - advertised, no request: re-advertise after `rtt × 6 + 1 s`, 4 times, then cancel
  - transferring, no request: cancel after `rtt × 6 × 16 + 10 s + 68 s` (the receiver's own retry delays). The rtt is measured from the advertisement to the first request.
  - every part sent, no proof: wait `rtt × 3 + 10 s`, 3 times, then cancel. RNS queries the network cache for the proof between waits; there is none to ask here.
- **Cancel:** RESOURCE_ICL carrying `h`.

## LXMF (LXMF/LXMessage.py, LXMRouter.py; lxmf 1.2.1)

- **Addresses:** `lxmf.delivery` SINGLE destinations. Name hash `SHA256("lxmf.delivery")[:10]`.
- **Announce app_data:** msgpack `[display name (bin) or nil, stamp cost or nil, [functionality]]`.
  - Senders before LXMF 0.5.0 announce the bare UTF-8 name instead; `LXMF.display_name_from_app_data` tells them apart by the first byte (a fixarray `0x90`–`0x9f` or array16 `0xdc` is the new format). It reads the name only from bin (a str name gives none), removes NULs and strips whitespace (`str.strip()`, Unicode spaces included). `ret_lxmf_display_name()` does the same, except that it reads only the first array element and drops NULs from the bare-name form too.
  - ret-client announces stamp cost nil, so senders need no proof-of-work.
  - It announces an empty functionality list, without `SF_COMPRESSION` (0x00), so no sender compresses a delivery to it.
- **Packed message:** `dest (16) | src (16) | Ed25519 signature (64) | payload`.
  - The payload is msgpack `[timestamp float64, title bin, content bin, fields map(, stamp bin)]`. Title and content are written as bin, but str is accepted on receive.
  - `message hash = SHA256(dest | src | payload without the stamp)`, also called the message id.
  - The signature covers `dest | src | payload without the stamp | message hash`.
  - With a stamp, LXMF re-packs the first four elements. For umsgpack's canonical encoding that is `0x94` followed by their original bytes, which is what ret-client hashes. LXMF itself is the only producer of stamped messages.
- **Opportunistic delivery:** one SINGLE DATA packet to the destination, carrying `packed[16:]`. The receiver rebuilds `dest | plaintext` and proves the packet.
- **DIRECT delivery:** the sender opens a link to the destination and sends the **whole** packed message, `dest` included.
  - It goes as one link DATA packet when it fits the link MDU (431), otherwise as a Resource.
  - The resource is uncompressed, because our announce lists no functionality.
  - ret-client checks `packed[:16]` is its own address, then handles `packed[16:]` like an opportunistic body.
  - LXMF uses DIRECT by default (NomadNet unless the contact is set to opportunistic), and always for content over 287 bytes. Ratchets play no part in the choice: LXMRouter never looks at them.
  - The sender keeps the link for up to 10 minutes of inactivity and reuses it.
- **DIRECT sending** (`ret_lxmf_send`, or `ret_lxmf_send_method`): the same, from the device.
  - `RET_LXMF_METHOD_AUTO` picks opportunistic when title plus content fit 287 bytes, otherwise DIRECT, as LXMessage falls back from opportunistic. DIRECT carries up to `RET_LXMF_DIRECT_MAX_CONTENT` (about 8 KB at the default `CONFIG_RET_RESOURCE_MAX_SIZE`).
  - The packed message goes as one link packet if it fits the link MDU (431), otherwise as a Resource (Sending, above). Its proof confirms delivery.
  - Messages wait in a queue until the client's one outbound link is free: no application link and no sync. The application's link calls fail with `-EBUSY` while a delivery holds the link; a sync waits for the message in flight, then gets the link.
  - Each attempt opens a new link (`CONFIG_RET_LXMF_DIRECT_ATTEMPTS`, default 3, 10 s apart, LXMRouter's `DELIVERY_RETRY_WAIT`). A refused resource is final. After a delivery the link stays up 10 s for the next message to the same recipient, then closes.
  - No link identify: LXMF needs none for delivery (it only opens a backchannel).
  - At most 287 bytes of title plus content (`ENCRYPTED_PACKET_MAX_CONTENT`): `packed[16:]` then fills the 383-byte SINGLE plaintext exactly.
- **Timestamps** are wall-clock seconds. They are hashed, so two identical messages with the same timestamp are the same message: receivers drop the repeat.
- **Receiving:**
  - The signature is checked against the source's announced Ed25519 key.
  - LXMRouter delivers messages from an unknown source flagged `SOURCE_UNKNOWN`. ret-client also delivers them, marked unverified.
  - ret-client drops a signature that fails. LXMRouter would hand it on marked `SIGNATURE_INVALID`.
  - **Repeats and replays:** ret-client remembers received messages (hash and timestamp, in settings) so neither a repeat nor a replayed packet is delivered twice, across reboots too. LXMRouter keeps delivered ids for 180 days.
    - Messages older than `CONFIG_RET_LXMF_MAX_AGE_DAYS` (30, LXMRouter's `MESSAGE_EXPIRY`) are refused; no node keeps one longer.
    - When the table (`CONFIG_RET_LXMF_SEEN_ENTRIES`) is full of younger entries, the oldest is evicted and a persisted floor rises to its timestamp. Reusing an expired entry raises the floor too. Messages at or below the floor are refused, so a forgotten message cannot come back, even after a reboot without a clock. An unreadable table is reset, with an error logged: unlike the identity it is expendable.
    - Timestamps more than `CONFIG_RET_LXMF_MAX_FUTURE_S` (1 h) ahead of the clock, or non-finite, are refused: evicted later, they would lift the floor above every genuine message.
    - Only verified messages evict entries. Unverified ones (anyone can make them) take a free or expired entry or go unremembered. While the table is full of verified entries, unverified messages are delivered but not remembered, so a replay of one is delivered again (still marked unverified). A flood of verified messages from a freshly announced identity can still fill the table and raise the floor to about "now". With the clock set, a raised floor is capped at now + `CONFIG_RET_LXMF_MAX_FUTURE_S`. A floor beyond that, raised before the clock was set from timestamps nothing vouched for, is ignored, and the age limit still applies.
  - A message from an unknown source triggers a path request for it, rate-limited to one per path-request interval.
  - **Known senders:** a sender's key normally comes from its announce, which a device that was asleep or rebooted has not heard. ret-client keeps the keys of senders that messaged it (`CONFIG_RET_LXMF_KNOWN_SENDERS`, in settings) and verifies against them when no current announce is known. A key is kept once a message verified against a current announce, or when the announce answering the path request for an unverified sender arrives. The address binds the key (`SHA256(name_hash | SHA256(pub)[:16])`), so a stored key that doesn't produce its address is discarded. When the table is full, the least recently verified sender is replaced. Anyone can still churn the table, either with throwaway identities that announce and message, or by sending unverified messages whose source is someone else's address. They can't impersonate anyone, but an evicted contact's messages arrive unverified until its next announce.

## LXMF propagation sync (LXMRouter message_get_request; lxmf 1.2.1)

The node is an `lxmf.propagation` destination. It serves the messages stored for the `lxmf.delivery` address of the identity that identified on the link.

1. Link to the node, then LINKIDENTIFY with the client's identity. A request without identity is answered `0xf0` (`ERROR_NO_IDENTITY`); one the node's allow-list rejects gets `0xf1`.
2. `/get [nil, nil]`: the response is the list of transient ids (bin32), smallest message first. More than about 12 ids arrive as a Resource. The whole list must fit `CONFIG_RET_RESOURCE_MAX_SIZE`, or the sync fails with `-EFBIG` (about 240 ids at 8 KB).
3. `/get [wants, [], limit_kb]`, with at most 10 wants so the request fits one packet:
   - The response is a list of items, each `dest (16) | SINGLE token of packed[16:]`. The node strips its propagation stamp first.
   - The node fills the batch cumulatively: it skips any item that would take the total past `limit_kb * 1000` bytes (counting 16 bytes per item, 24 overall, and the stored size including its stamp). A batch can therefore come back short. ret-client asks for what was left out again. A batch that served nothing means every remaining id is over the limit, since the list is in ascending size order. Those messages are skipped for the rest of the sync and stay at the node.
   - A re-list that follows a pass which acknowledged nothing ends the sync, so a node full of oversized messages cannot keep it looping.
4. `/get [nil, haves]`: each have is `SHA256(item as served)`. The node deletes those messages. ret-client acknowledges every served item, including undecryptable or refused ones.
5. When the list is done (re-listing when `CONFIG_RET_LXMF_SYNC_MAX_IDS` truncated it), close the link.

- Retrieving needs no proof-of-work. Depositing needs a propagation stamp (a cost-13+ proof-of-work over a 256 KB workblock), which is out of the nRF91's reach, so the device sends opportunistically only.
- Items are decrypted with the client's identity and then go through the same path as opportunistic messages: replay check, signature check, delivery.
- A sender whose announce the device never saw (usual after a sleep) is delivered unverified, with a path request for it.

