# Changelog

## [Unreleased]

### Added

- LXMF DIRECT sending: `ret_lxmf_send()` sends a message too long for one packet over a link to
  the recipient, as one link packet or as a Resource (up to `RET_LXMF_DIRECT_MAX_CONTENT`, about
  8 KB), so long messages are no longer refused. `ret_lxmf_send_method()` forces opportunistic
  or DIRECT. Messages queue (`CONFIG_RET_LXMF_DIRECT_QUEUE`, `CONFIG_RET_LXMF_DIRECT_POOL`; 0
  turns DIRECT sending off) until the outbound link is free, and each is attempted up to
  `CONFIG_RET_LXMF_DIRECT_ATTEMPTS` times; a sync waits for the message in flight. New receipt
  status `RET_RECEIPT_REJECTED` for a message the recipient refused.
- Resources, sending side (`ret_resource_tx_*`), byte for byte as RNS builds them, and link
  packet proofs (`ret_link_packet_proof_validate()`).
- The samples' replies quote up to 1 KB of the message (`ret_lxmf`, `ret_lxmf_sleep`), so they go
  DIRECT when long. e2e: `lxmf-direct` checks the device's DIRECT packet and Resource arrive
  intact; `sleep` checks a 604-byte reply is delivered DIRECT before the device suspends.

### Changed

- `RET_LXMF_MAX_CONTENT` is now `RET_LXMF_OPPORTUNISTIC_MAX_CONTENT`.
- `ret_lxmf_sync()` no longer fails with `-EBUSY` while a DIRECT delivery holds the link: it
  waits for it.

- Links other nodes open to the client's destination (responder side, `CONFIG_RET_INBOUND_LINKS`,
  default 2), as RNS's `Link.validate_request()` handles them: LRPROOF signed by the identity
  (MTU 500 confirmed), RTT, keepalive answers, stale and close; link DATA delivered (to
  `on_lxmf` or `on_data`) and proved. Suspend closes every link.
- LXMF DIRECT delivery: messages sent over such a link, as NomadNet and most LXMF clients do by
  default, in one packet or as a Resource. A delivery arriving while another resource is
  received closes the link so the sender retries; one too large is refused. A sync request
  refused while a delivery holds the resource buffers is sent again.
- e2e: `echo` adds the peer opening a link to the device; new `lxmf-direct` (DIRECT echoes, a
  3000-byte Resource delivered, a 12000-byte one refused).

- Sleep: `ret_client_suspend()` / `ret_client_resume()` and `samples/ret_lxmf_sleep`, a sleepy
  LXMF node modelled on lion_sleep (suspend client and peripherals, modem in PSM, wake, sync,
  answer, sleep). e2e scenario `sleep`: three wakes, mail deposited while asleep collected at
  the next.
- Known LXMF senders: the keys of senders that messaged the device are kept in settings, so
  their messages verify after a sleep or reboot. e2e `store-forward` checks it across a reboot.

- LXMF propagation sync: `ret_lxmf_sync()` collects the messages an LXMF propagation node
  (lxmd) holds for the device, then acknowledges them so the node deletes them. Batches are
  bounded by `CONFIG_RET_LXMF_SYNC_LIMIT_KB`; larger messages are left at the node and logged.
  `ret_lxmf` syncs on every connect (`CONFIG_RET_LXMF_SAMPLE_PROPAGATION_NODE`) and optionally
  periodically. e2e scenario `store-forward` against a real lxmd.
- Persistent LXMF replay protection: received messages are remembered in settings (hash and
  timestamp), messages older than 30 days are refused, and a floor rises on eviction so a
  forgotten message cannot be replayed. Replaces the in-RAM repeat ring.

- LXMF messaging (lxmf 1.2.1), opportunistic both ways.
  - `cfg.on_lxmf` makes the client an `lxmf.delivery` node: announced with LXMF app_data, inbound
    messages verified against the sender's announced key (unknown senders delivered as
    unverified, bad signatures dropped, repeats dropped).
  - `ret_lxmf_send()` packs and signs a message (wall-clock timestamp from `SYS_CLOCK_REALTIME`)
    and sends it as one packet.
  - Message format tested byte for byte against the real LXMF, including stamped messages.
- `samples/ret_lxmf`: an always-connected LXMF node (contact, replies, display name). On the
  nRF9151 it takes network time from the modem (date_time, NTP if the network sends none).
  - e2e scenario `lxmf` against a real LXMRouter, signatures validated both ways.
- Ed25519 signing and verification over scatter lists (`ret_ed25519_sign_iov`/`_verify_iov`).

- Resources, receiving side: link request responses larger than one packet arrive as a Resource,
  are reassembled into `CONFIG_RET_RESOURCE_MAX_SIZE` (default 8 KB) of buffers, verified and
  proved.
  - Windowed part requests, with hashmap updates for large transfers, timeouts and retries.
  - Compressed, split or oversized resources are refused with RESOURCE_RCL, and the request fails
    with `-ENOTSUP`/`-EFBIG`.
  - Tested against RNS-built vectors (including a 78-part transfer), and end to end with a
    4000-byte response from a real RNS destination plus a compressed one that must be refused.

- Links, initiator side: `ret_client_link_open/request/identify/close`.
  - Handshake with proof validation and the RTT packet.
  - Single-packet requests and responses with timeouts.
  - Identify, keepalive, stale detection and close; the link is torn down when the connection
    drops.
  - A path request goes out first if the destination has no current path.
  - Tested against RNS-built vectors, and end to end against a real RNS destination (including
    15 s idle on keepalives).

- mpack (msgpack) as a pinned west dependency, for the Link, Resource and
  LXMF work ahead. Tests check its encoding is byte-identical to RNS's
  umsgpack for the shapes RNS/LXMF use.

- CI `nrf9151` job: builds `ret_basic` for the nRF9151 Feather in the NCS
  workspace (sysbuild, no compiler warnings) and uploads `merged.hex` as a
  run artifact. The CI image gains the `arm-zephyr-eabi` toolchain.

- nRF9151 Feather support (NCS): LTE through the modem's offloaded sockets,
  PSA Crypto from TF-M, settings on LittleFS on the external NOR flash.
  Verified on hardware over LTE: messages and proofs both ways, identity
  kept across resets, client thread stack peak 2632 of 6144 bytes.
- `scripts/flash.py`: flashes a hardware build with the Zephyr Tools load
  sequence (merged.hex, recovery unlock, UICR check, probe-rs download and
  reset), with tests ported from Zephyr Tools' own suites.
- `tools/rnsd-hw`: rnsd config for testing a board over LTE.
- e2e `bootdown` scenario: rnsd down at boot, up shortly after.

- The client's own destination (`ret_client_config.dest_name`): an identity
  created on first start and persisted in settings gives it a stable
  address. It is announced on every connect (and every
  `CONFIG_RET_ANNOUNCE_INTERVAL_S`, or on `ret_client_announce()`), path
  requests for it are answered, and packets sent to it are decrypted,
  passed to `on_data`, duplicate-filtered and proved.
- Persisted announce clock, so announces stay newer than those a node saw
  before a reboot. Values are reserved in blocks
  (`CONFIG_RET_ANNOUNCE_CLOCK_BLOCK`), one flash write per block.
- Path requests for the client's destination are answered once per tag and
  at most every `CONFIG_RET_PATH_RESPONSE_INTERVAL_MS`; tagless requests are
  ignored.
- `ret_basic` announces `retclient.node` and logs replies;
  `CONFIG_RET_SAMPLE_EXPECT_REPLIES` makes success require one per message.
- `peer.py --reply` and the e2e `echo` scenario: messages and proofs in
  both directions.
- Forgejo CI (`.forgejo/workflows/ci.yml`, `ci/Dockerfile`): ruff, golden
  vector check, unit tests, warning-free build and the full e2e.

- Path requests: a send to a destination with no current path is held
  (`CONFIG_RET_MAX_HELD_SENDS`) while a path request goes out, repeated
  every `CONFIG_RET_PATH_REQUEST_INTERVAL_MS` (15 s), and released by the
  destination's announce or path response, or failed after
  `CONFIG_RET_PATH_REQUEST_TIMEOUT_MS` (60 s, above rnsd's 45 s path
  request gate). A known destination hash can
  therefore be used before any announce reaches the client.
- Paths are marked stale on every reconnect (rnsd may have restarted with
  a new transport identity and an empty path table) and are requested
  again on demand; keys are kept.
- Receipt watchdog: reconnect after `CONFIG_RET_RECONNECT_AFTER_TIMEOUTS`
  consecutive receipt timeouts (default 3) from destinations that have
  proved before (RNS destinations do not prove by default), and optionally
  after
  `CONFIG_RET_RX_SILENCE_TIMEOUT_S` without receiving anything.
- `SO_SNDTIMEO` on the TCP socket (`CONFIG_RET_SEND_TIMEOUT_MS`) and TCP
  keepalive (`CONFIG_RET_TCP_KEEPALIVE`) where the socket layer supports
  it; a rejected socket option fails the connection attempt.
- `ret_basic`: `CONFIG_RET_SAMPLE_DEST_HASH` sends to a known destination
  without waiting for its announce.
- e2e scenarios `late` (destination announced before the device started),
  `stall` (peer stops proving: watchdog reconnects) and `restart` (rnsd
  restarted mid-run).
- Zephyr module scaffold: `RET_CORE` (protocol, no networking) and
  `RET_CLIENT` (TCP client to rnsd), `ret_basic` sample for native_sim.
- ztest suites (`ret_codec`, `ret_crypto`, `ret_protocol`): RFC/NIST
  known-answer tests and golden vectors generated from RNS 1.5.7 by
  `tools/rns_peer/gen_vectors.py`.
- `scripts/twister.sh`: runs twister under Python 3.14.
- `tools/run_e2e.sh`: builds `ret_basic` and runs it against an isolated
  rnsd and the Python test peer (`tools/rns_peer/peer.py`) in three
  scenarios: plain, ratchets, no-prove.

### Changed

- Moved to NCS v3.5 (via nfed `v3.5.x`, v3.5.0-preview3) and vanilla Zephyr v4.4.2, the line
  NCS 3.5 is built on. Zephyr SDK 1.0.1 (CI image).
  - `RET_CORE` selects `PSA_CRYPTO`, which both now have: TF-M provides it on the nRF9151,
    Mbed TLS / TF-PSA-Crypto on native_sim.
  - No Partition Manager: the samples' flash layout is a devicetree overlay
    (`samples/common/circuitdojo_feather_nrf9151_ns_flash.dtsi`) giving the bootloader's space
    to TF-M and the app; settings stay on the external NOR's `lfs_partition`.
  - `scripts/flash.py` follows Zephyr Tools 0.7.0: images from `domains.yaml` in flash order
    (`tfm_merged.hex` plus nfed's UICR debug-access image), UICR checked across images, CTRL-AP
    erase, `--dry-run`. It needs `pyyaml` now.

- The TCP connect is non-blocking and polled with the client's queue and
  deadlines, trying each resolved address in turn; sends queued while
  connecting are held instead of failed.
- Building with NCS's minimal TF-M profile is refused: it leaves out the
  SHA-256, HMAC and AES the client needs.

- Builds pass `--no-sysbuild`, so output paths match in the vanilla Zephyr
  and NCS workspaces; the dev workspace now uses `west-vanilla.yml`.
- `on_announce` fires once per announce; repeats of the same announce
  (rebroadcast and path response) only refresh the path, and announces
  emitted before the last one seen are ignored as replays.
- A socket send failure reports `RET_RECEIPT_FAILED` (the receipt is
  registered only after a successful send).
- Reconnect backoff resets only after a connection that received packets
  or stayed up for 10 s.
- `ret_client_name_hash()` works before `ret_client_start()`.

### Fixed

- Samples logged received text with `%.*s`; deferred logging copies `%s` up to a terminator
  whatever the precision, so it read past unterminated message buffers. They log bounded,
  terminated copies now.

- `run_e2e.sh` no longer leaves test peers running after a scenario.
- A socket send that hits `SO_SNDTIMEO` now fails and drops the
  connection instead of being retried forever.
- Client thread no longer drops the connection when poll is interrupted
  (EINTR).
- Sends still queued when a socket send fails are now failed with a
  callback instead of being stranded.
