# Changelog

## [Unreleased]

### Changed

- **License:** ret-client is now under the Reticulum License (`LICENSE`), as the
  Reticulum and LXMF reference implementations it follows, with Mark Qvist's copyright notice
  kept. Source headers change from `Apache-2.0` to `LicenseRef-Reticulum`.
- **Readme:** credits Mark Qvist as the creator of Reticulum, LXMF and RNode, and covers the
  current features, samples and dependencies.

### Added

- `ret_lora_gateway` keeps paths in ZMS (`src/store_zms.c`), one record per
  destination, with settings in ZMS too.
  - **Index:** a RAM index of stored paths (8 bytes each: record ID and owner tag) keeps
    misses off flash.
  - **Collisions:** a destination whose first ID is taken uses a second. One whose IDs are
    both taken isn't stored, so no path is replaced by another destination's.
  - **Boot:** the index is built in one pass over the log.
  - **Bad records:** unreadable records are deleted rather than failing the boot.
  - **Measured on the Feather's W25Q128 at 200 paths, against LittleFS:**

    | | ZMS | LittleFS |
    |---|---|---|
    | insert | 17 ms | 342 ms |
    | hit | 2.3 ms | 205 ms |
    | miss | 45 µs | 79 ms |
    | flash per path | about 600 B | 4.5 KB |

    ZMS also needs about 8 times fewer erases, and 18 KB less code.
  - **RAM cost:** the 1,024-entry lookup cache (8 KB), the index (4 KB at 512 paths) and
    boot-time scratch (2 KB). The store benchmark measures 29.9 KB on the Feather, against
    16.6 KB with LittleFS.
  - **Why not LittleFS:** an earlier store kept a file per path on LittleFS (measured above). It
    was dropped before release: ZMS is much faster and denser, for 12 KB more RAM.
- `samples/ret_lora_gateway/bench`: a path store benchmark for native_sim (flash simulator
  counters) and the Feather (timings, including a warm-reboot boot measurement).

- `samples/ret_lora_gateway`: a LoRa gateway built on the transport node, for native_sim so
  far (simulated radio).
  - **Interfaces:** the LoRa radio (RNode framing, gateway mode, 2% announce cap) and an HDLC TCP
    uplink to any stock rnsd, optionally with IFAC. The hub needs no special interface or
    configuration.
  - **Routing:** LoRa to LoRa through the gateway, including with the hub down, and LoRa to the
    hub's network.
  - **Storage:** paths are kept in ZMS across reboots (see the entry above), the identity in
    settings, and tunnel synthesis restores the hub's paths after it restarts.
  - **e2e:** `lora-gateway`, against a stock rnsd and RNS LoRa peers on a simulated air
    (`tools/rns_peer/air.py`).
- `peer.py --send-to`, `--send-count`, `--send-size`: send to a destination and report proofs.

- Transport node (`CONFIG_RET_TRANSPORT`, `src/ret_transport.c`): routes between interfaces as
  an RNS instance with `enable_transport`, for a LoRa gateway that needs nothing special on the
  hub.
  - **Forwarding:** along known paths (HEADER_2 rewrite, last-hop strip), including back out
    the receiving interface.
  - **Announces:** rebroadcast on every interface, with RNS's retry, rebroadcast detection,
    acceptance and rate rules, a per-interface announce cap and queue, and ingress control.
  - **Path requests:** answered from the path table, and forwarded for gateway-mode interfaces.
  - **Links and proofs:** relayed through link and reverse tables. Link MTU signalling is
    clamped or stripped, and LRPROOFs are checked against the destination's key.
  - **Tunnel synthesis** for a TCP uplink.
  - **Storage:** paths and announces are kept in an application store; RAM caches them
    (`ret_transport_store_ram.c` keeps them in RAM).
  - Byte formats are tested against RNS-built vectors, and behaviour with a hand-run clock
    (`tests/lib/ret_transport`).
- RNode on-air framing (`src/ret_rnode_air.c`): splitting packets up to 508 bytes into LoRa frames
  and reassembling them, as RNode firmware does (`tests/lib/ret_lora`).
- `ret_packet_unpack_max()`, for interfaces whose MTU exceeds 500 bytes.
- `ret_path_request_build_transport()`, a transport node's path request.
- `ret_link_signalling()` and `ret_announce_emitted()`, now exported.

- Interface access codes (`CONFIG_RET_IFAC`): the client joins an rnsd interface protected with
  `network_name` and/or `passphrase`, as RNS does (byte for byte against RNS's own functions).
  Set them with `ret_client_config.ifac_network_name` / `ifac_passphrase` or
  `CONFIG_RET_IFAC_NETWORK_NAME` / `CONFIG_RET_IFAC_PASSPHRASE`; `CONFIG_RET_IFAC_SIZE` must match
  the interface's `ifac_size` (16 bytes for TCP). Costs one Ed25519 signature per packet each
  way. e2e: `ifac` on a protected test interface, with the right and a wrong passphrase.
- `samples/ret_chat`: LXMF chat over the console with the Zephyr shell: see who announced
  (`heard`), name addresses (`contact`, kept in settings), send by name (`msg send`: opportunistic
  or DIRECT by length, delivery reported), and read the inbox (`msg inbox`, `msg read`, RAM only).
  `src/chat.c` is the shell-free layer a station UI could reuse. e2e: `chat` drives its shell
  through stdin against `lxmf_peer.py`.
- `ret_lxmf_display_name()`: the display name in an LXMF announce's app_data, as
  `LXMF.display_name_from_app_data()` reads it (including the pre-0.5.0 bare-name form).
- `run_e2e.sh` refuses to start only when a test tool is attached to `tools/rnsd-test`, so a
  hardware hub (`tools/rnsd-hw`, `tools/lxmd-hw`) can keep running.
- Ratchets for the client's own destination (`CONFIG_RET_RATCHETS`, default on): every announce
  carries the newest ratchet, senders encrypt to it, and the client decrypts inbound packets and
  synced LXMF messages with any of the last `CONFIG_RET_RATCHET_COUNT` (8), rotated once per
  `CONFIG_RET_RATCHET_INTERVAL_S` (a day) while the wall clock is set. Stored as `ret/rt/<n>`,
  written before the announce that carries a new one. Announces grow by 32 bytes, which the
  `announce_app_data` limit accounts for. e2e: `lxmf` and `store-forward` check the peers
  encrypt to the device's ratchet; `sleep` rotates at a wake and still decrypts with the older one.
  A new ratchet that can't be stored delays the rotation, not the announce.
- `tools/lxmd-hw`: an lxmd propagation node config for board tests, attached to `tools/rnsd-hw`,
  for `ret_lxmf_sleep`'s (and `ret_lxmf`'s) sync. Its identity stays local, so its hash is stable.
- `tests/lib/ret_storage`: the settings records (identity, ratchets, known senders, remembered
  messages) tested against real NVS settings on native_sim.
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

### Fixed

- Resetting an unreadable LXMF replay table (`ret/lx`) or sender key table (`ret/lk`) deleted only
  the records loaded before the bad one: a settings callback error stops the load, so the older
  records were never seen. They stayed in flash and came back on the next boot.

### Changed

- `src/ret_tcp.c` builds with `NET_SOCKETS` rather than `RET_CLIENT`, and takes its socket
  options as `struct ret_tcp_opts`, so the client and the gateway share it.
- `west-vanilla.yml` moves to Zephyr v4.5.0 for ZMS's iterator. The gateway's partitions use
  v4.5's schema: memory-mapped ones carry `zephyr,mapped-partition`, and code uses the
  `PARTITION_*` macros.
- The gateway's path limit defaults to 512.

- nRF9151 samples trim Zephyr's native IP stack: the modem runs TCP/IP and DNS, so native TCP,
  the DNS resolver and most packet buffers were unused. About 16 KB of RAM and 23 KB of flash
  freed per sample. The stack itself stays: NCS's LTE net_if records the modem's addresses
  through it (`CONFIG_NET_NATIVE=n` fails with `ipv4_addr_add, error: -19`).
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
