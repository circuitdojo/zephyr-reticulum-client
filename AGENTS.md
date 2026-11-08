# Working in this repo

ret-client is a Zephyr module implementing a [Reticulum](https://reticulum.network)
client. It connects to a Python `rnsd` TCPServerInterface and supports:
- HDLC stream framing
- receiving and validating announces
- sending encrypted DATA packets to SINGLE destinations
- validating delivery proofs
- links, both sides: opening them (with requests) and accepting them from other nodes
- Resources, both ways: receiving (responses, deliveries) and sending (LXMF DIRECT)
- LXMF messaging: opportunistic and DIRECT, both ways

Samples:
- `samples/ret_basic`: raw Reticulum packets and a link test. The e2e workhorse.
- `samples/ret_lxmf`: an always-connected LXMF node. It announces `lxmf.delivery`, sends to a
  contact and answers what it receives, and syncs from a propagation node.
- `samples/ret_lxmf_sleep`: the sleepy node, modelled on `lion-client/samples/lion_sleep`. Each
  wake it resumes, syncs, answers, messages its contact, waits for proofs, then suspends the
  client (socket closed) and the peripherals (NOR, UART, PMIC BUCK2) and sleeps. The modem drops
  into PSM between wakes.

Targets:
- `native_sim`: NSOS host sockets, PSA Crypto from mbedTLS.
- `circuitdojo_feather_nrf9151/nrf9151/ns`: modem-offloaded sockets, PSA Crypto from TF-M. See
  "Hardware (nRF9151 Feather)" below.

It is structured like `lion-client`.

Only commit code related to the changes at hand. Stage files by name. Never
`git add -A` / `git add .`.

`docs/protocol.md` is the wire-format reference, checked against RNS 1.5.7.
Read it before touching packet, crypto or announce code.

## Build

Everything builds from the **workspace root** (`nrf9160-feather-examples-and-drivers/`),
not from inside this repo. Its manifest is one of this repo's:
- `west-vanilla.yml`: vanilla Zephyr v4.4.2 (the line NCS v3.5 is built on), Mbed TLS,
  TF-PSA-Crypto, picolibc, Monocypher and mpack. native_sim only.
- `west-ncs.yml`: nfed `v3.5.x`, which imports NCS v3.5 (v3.5.0-preview3 at the time of
  writing). Needed for the nRF9151.

Switch with `west config manifest.file <file>` and `west update`. Code must build in both. Since
Zephyr 4.4 both have `PSA_CRYPTO`, which `RET_CORE` selects: its provider is TF-M on the nRF9151
and Mbed TLS / TF-PSA-Crypto on native_sim. native_sim builds pass `--no-sysbuild` to keep output
paths identical. Hardware builds use sysbuild, which NCS requires.

Toolchain environment:

```bash
source ~/.zephyrtools/env/bin/activate
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
# Zephyr 4.4 / NCS 3.5 want SDK 1.0.x (zephyr/SDK_VERSION); CI pins 1.0.1.
export ZEPHYR_SDK_INSTALL_DIR=$HOME/.zephyrtools/toolchain/zephyr-sdk-1.0.0
```

```bash
# Unit tests (no rnsd needed). The wrapper forces the "fork" start method:
# twister fails under the Zephyr Tools venv's Python 3.14 default.
ret-client/scripts/twister.sh -T ret-client/tests -p native_sim --inline-logs -O build/twister-ret

# Sample
west build -b native_sim ret-client/samples/ret_basic -d build/ret_basic -p --no-sysbuild
./build/ret_basic/zephyr/zephyr.exe --seed-random

# End to end against an isolated rnsd + Python test peer (goals 1-4)
ret-client/tools/run_e2e.sh
```

## Hardware (nRF9151 Feather)

Needs the NCS workspace (`west-ncs.yml`).

```bash
# Per-device settings (server address etc.): copy the template; env/* is gitignored.
cp ret-client/samples/ret_basic/env/example.conf ret-client/samples/ret_basic/env/<name>.conf
west build -b circuitdojo_feather_nrf9151/nrf9151/ns ret-client/samples/ret_basic \
    -d build/ret_nrf9151 -p -- -DEXTRA_CONF_FILE=env/<name>.conf

# Flash: always through scripts/flash.py, never `west flash`
uv run ret-client/scripts/flash.py build/ret_nrf9151

# flash.py's tests (ported from Zephyr Tools' uicr/flash-hex suites)
uv run --with pytest --with pyyaml pytest ret-client/scripts
```

The 9151 builds are `west build` runs of the samples (sysbuild: TF-M, nfed's UICR image), not
twister tests; the unit tests are native_sim only. CI's `nrf9151` job does the same. (nfed
`v3.5.x`'s board YAML carries the HWMv2 identifier, so twister could target the board now.)

**Flashing** must follow the Zephyr Tools load sequence (`~/Git/zephyr-tools` 0.7.0,
`src/commands/flash.ts`, `src/build/flash-hex.ts`). `scripts/flash.py` reproduces it
(`--dry-run` prints the images and commands without touching the probe):
1. Pick the images as Zephyr Tools does. NCS 3.5 sysbuild (no Partition Manager): each domain in
   `domains.yaml` `flash_order` names its hex in `<domain>/zephyr/runners.yaml`. The app domain
   gives `tfm_merged.hex` (TF-M plus the app); the other images (here nfed's
   `uicr_debug_access_open`, which keeps the debug port open without a bootloader) are merged
   into `zephyr-tools/bootloaders.hex` and flashed first with `--preverify`. A Partition Manager
   build (NCS <= 3.4) flashes `merged.hex`. `west flash` programs only the app and leaves
   whatever TF-M was on the chip, and every PSA call then fails.
2. Run `recovery --unlock-only --no-reset`, the nRF91 recovery tool from Zephyr Tools setup.
3. Check UICR across all images. If the device already has every UICR word, strip them from the
   download (an image left empty, like the UICR image, is skipped). Otherwise a full chip erase
   is required (`--erase` or a typed confirmation): `recovery --erase-only --force`, a CTRL-AP
   ERASEALL, which wipes internal flash and keeps the debug port open for probe-rs.
4. Run `probe-rs download` per image, then `probe-rs reset`.

**Board config** is in `samples/ret_basic/boards/circuitdojo_feather_nrf9151_ns.conf`.
- **TF-M:** must be `TFM_PROFILE_TYPE_NOT_SET`. NCS's minimal profile builds the secure image
  with random generation only and ignores `PSA_WANT_*`, so SHA-256, HMAC and AES calls fail
  with `PSA_ERROR_NOT_SUPPORTED` (-134). `port/zephyr/CMakeLists.txt` refuses to build with it.
  To check what TF-M really contains, look at the symbols in `ret_basic/tfm/bin/tfm_s.elf`,
  not the non-secure API headers.
- **Moving a board from an NCS 3.2 build:** flash once with `--erase`. The Partition Manager put
  different data at the TF-M storage partitions (0xf0000 on), and a board whose UICR already
  matches skips the erase. Settings on the NOR, and so the address, survive it.
- **Flash layout:** NCS 3.5 has no Partition Manager; partitions are devicetree. nfed's board
  reserves room for MCUboot. The samples flash without a bootloader, so each one's
  `boards/circuitdojo_feather_nrf9151_ns.overlay` includes
  `samples/common/circuitdojo_feather_nrf9151_ns_flash.dtsi`, which gives that space to TF-M
  (128 kB) and the app (832 kB). The TF-M storage partitions and the external NOR's
  `lfs_partition` stay where the board puts them.
- **Settings:** stored in `/lfs/ret-settings` on LittleFS on the external W25Q128 NOR, as in
  lion_sleep. Internal flash holds only firmware, so a re-layout, reflash or UICR erase keeps
  the board's identity (its address). Deleting that file gives the board a new address.
- **External flash size:** the `jedec,spi-nor` devicetree `size` is in bits. nfed declared the
  W25Q128 as 2 MiB until its `jared/nor-flash-size` fix (`0x8000000` = 128 Mbit).
  `CONFIG_SPI_NOR_SFDP_RUNTIME=y` reads the real geometry from the chip, so older nfed
  revisions still work.
- **Logging:** `CONFIG_LOG_MODE_IMMEDIATE=y`. Deferred logging drops the thread analyzer's first
  lines and can lose a fault report before a reset.
- **PMIC:** the board's startup code configures the nPM1300, so `MFD_NPM13XX` must stay
  enabled.
- **Stack:** the thread analyzer prints stack use every 60 s.

**Test setup:** an rnsd reachable over LTE (`tools/rnsd-hw`: 0.0.0.0:4242, behind a router port
forward) and the peer:

```bash
uv run --project ret-client/tools/rns_peer rnsd --config ret-client/tools/rnsd-hw -vv
uv run --project ret-client/tools/rns_peer ret-client/tools/rns_peer/peer.py \
    --config ret-client/tools/rnsd-hw --reply --announce-interval 30
```

The console is the Feather's onboard probe UART (`/dev/ttyACM0`, 115200).

For `ret_lxmf`, build with `-DEXTRA_CONF_FILE=env/<name>.conf` from
`samples/ret_lxmf/env/example.conf` (server plus an optional `CONFIG_RET_LXMF_SAMPLE_CONTACT`). It
waits for network time (date_time: modem, else NTP) before sending, because LXMF timestamps are
wall-clock time. Run `tools/rns_peer/lxmf_peer.py --config ret-client/tools/rnsd-hw` as its contact,
or message its address from NomadNet or Sideband.

`ret_lxmf_sleep` needs `CONFIG_RET_SLEEP_PROPAGATION_NODE` in its `env/` overlay: the lxmd from
`tools/lxmd-hw`, attached to `tools/rnsd-hw`. Its identity stays in that directory (gitignored),
so the hash is stable; `lxmf_send.py --make-node-identity ret-client/tools/lxmd-hw/identity`
prints it before the first start:

```bash
uv run --project ret-client/tools/rns_peer lxmd --config ret-client/tools/lxmd-hw \
    --rnsconfig ret-client/tools/rnsd-hw -p
```

Measure sleep current with the PPK between wakes. The
sample prints stack use (thread analyzer) once per wake, after the sync: that is the client
thread's deepest path.

The Python tools under `tools/rns_peer` are a `uv` project pinned to `rns==1.5.7` and
`lxmf==1.2.1` (`uv run --project ret-client/tools/rns_peer ...`). Always use `uv`, never bare pip.

## Layout

- `port/zephyr/{Kconfig,CMakeLists.txt}`: `RET_CORE` is the protocol with no networking (the
  unit tests enable only this). `RET_CLIENT` adds the TCP client thread.
- `include/ret/ret_client.h`: the public API.
- `src/ret_hdlc.c`, `src/ret_packet.c`: framing and the header codec. Pure code.
- `src/ret_crypto.h`: the crypto interface.
  - `ret_crypto_psa.c` implements it with PSA (SHA-256, HMAC, AES) and Monocypher (X25519,
    Ed25519).
  - `ret_crypto_common.c` builds HKDF and PKCS7 on top of it.
  - Use `crypto_ed25519_check` (SHA-512, RFC 8032), never Monocypher's default
    `crypto_eddsa_*` (BLAKE2b).
- `src/ret_identity.c`: name, identity and destination hashes, and encrypt-to-destination.
- `src/ret_announce.c`, `src/ret_destinations.c`, `src/ret_receipt.c`: announce validation,
  the known-destination table plus the outbound H1/H2 rule, and proofs.
- `src/ret_link.c`: link packet formats (request, link_id, proof validation and key, link
  packets, request/response/identify/RTT payloads). Pure functions, tested against RNS-built
  vectors in `tests/lib/ret_link`.
- `src/ret_resource.c`: Resources. Receiving (responses and deliveries larger than a packet):
  advertisement parsing, windowed part requests, hashmap updates, assembly against the resource
  hash, and the proof; compressed, split and oversized resources are refused, not decompressed.
  Sending (`ret_resource_tx_*`, LXMF DIRECT): stream, hashmap with the collision guard,
  advertisement, answering requests (parts, hashmap updates) and checking the proof, byte for
  byte as RNS builds them. Pure functions, tested in `tests/lib/ret_resource` against vectors
  from RNS's own Resource class.
- `src/ret_lxmf.c`: the LXMF message format: unpack (a stamp is dropped from the hash as LXMF does),
  signature check, pack and sign, and the `lxmf.delivery` announce app_data. Pure functions,
  tested against vectors from the real LXMF in `tests/lib/ret_lxmf`. Signing and verifying work on
  scatter lists (`ret_ed25519_*_iov`), because the signed part is not contiguous in a message.
- `src/ret_client_lxmf.c`: LXMF on the client (`cfg.on_lxmf`). Inbound messages are parsed and
  verified on the client thread against the sender's announced key. An unknown sender's message
  is delivered marked unverified, and a path request goes out for it (at most one per
  `CONFIG_RET_PATH_REQUEST_INTERVAL_MS`). A bad signature is dropped. Repeats and replays are
  refused through `src/ret_lxmf_seen.c` (pure, tested in `tests/lib/ret_lxmf`): hashes plus
  timestamps persisted as `ret/lx/*` in settings, a 30-day age limit, and a floor raised on
  eviction. `ret_lxmf_send()` packs and signs on the caller's thread
  (identity and address are immutable after start), stamps it with `SYS_CLOCK_REALTIME`, and
  returns -ENODATA while the wall clock is unset. Up to 287 bytes of title plus content go
  opportunistic, through `ret_client_send()`; longer ones (or `RET_LXMF_METHOD_DIRECT`) go to
  the DIRECT queue below.
- Known senders: the keys of senders that messaged us are kept as `ret/lk/*`
  (`CONFIG_RET_LXMF_KNOWN_SENDERS`; the least recently verified is replaced first, an order kept in
  RAM and taken from storage order after a reboot), so after a sleep or reboot their
  messages still verify. A key is kept when a message from it verified against a current
  announce, or when the announce answering the path request for an unverified sender arrives.
  Records are checked against their address on load; an unreadable set is reset.
- `ret_client_suspend()` / `ret_client_resume()`: suspend closes the link (LINKCLOSE), fails
  waiting sends, closes the socket and reports `RET_STATE_SUSPENDED`; the thread then only
  answers requests. Resume reconnects (announce, fresh paths).
- `src/ret_client_lxmf_sync.c`: `ret_lxmf_sync()`, propagation node sync: link, identify, `/get`
  list, fetch in batches of 10 under `CONFIG_RET_LXMF_SYNC_LIMIT_KB` (re-asking for what a full
  batch left out), acknowledge, close. Link callbacks only record the next step;
  `ret_lxmf_sync_drv_service()` performs it from the client loop through the link driver
  directly, never through the request queue (a full queue cannot strand a sync). While a sync
  runs, the application's link requests fail with -EBUSY. Items are decrypted into the resource
  stream buffer (`ret_link_drv_scratch()`), which is spent by the time a response is delivered.
- `src/ret_client_lxmf_direct.c`: LXMF DIRECT sending. `ret_lxmf_send()` packs and signs on the
  caller's thread straight into a pool (`CONFIG_RET_LXMF_DIRECT_POOL`, 0 to turn it off); the
  client thread takes the head when the outbound link is free (no application link, no sync),
  links to the recipient, sends a packet or a Resource (`ret_link_drv_send_packet/_resource`),
  waits for its proof, keeps the link 10 s for the next message, and retries on a new link
  (`CONFIG_RET_LXMF_DIRECT_ATTEMPTS`). Like the sync, callbacks only record; its service function
  acts from the client loop. While it holds the link, application link calls get -EBUSY and a
  sync waits (`SYNC_WAITING`).
- `src/ret_client_link.c`: the link driver, run on the client thread; shared state is in
  `src/ret_client_internal.h`.
  - What every link shares works on `struct link`: sending, closing, stale timers, and the one
    Resource at a time, arriving or leaving (`CONFIG_RET_RESOURCE_MAX_SIZE` each for the stream
    and plaintext buffers).
  - The client's own link (`struct link_out`, initiator): path wait, handshake, RTT, requests with
    timeouts, response resources, identify, keepalives, and one proved send at a time (a DATA
    packet whose link proof is awaited, or a Resource we send).
  - Links other nodes open to the client's destination (`struct link in[]`,
    `CONFIG_RET_INBOUND_LINKS`, responder): LRPROOF, RTT, keepalive answers, DATA delivered and
    proved, LXMF DIRECT delivery resources. A delivery arriving while another resource is received
    closes that link (the LXMF sender retries; RCL would reject the message for good).
- `src/ret_client.c`: a single static instance and one thread polling the socket plus an
  eventfd. Sends are queued with `k_msgq`. All protocol state is confined to that thread.
  - With `dest_name` configured the client has its own destination (address): an identity
    created on first start and persisted in settings (`src/ret_storage.c`, keys `ret/id` and
    `ret/aclk`). It announces on every connect, answers path requests for itself, and
    decrypts, delivers (`on_data`) and proves packets sent to it.
  - Ratchets (`CONFIG_RET_RATCHETS`): the announce carries the newest of
    `CONFIG_RET_RATCHET_COUNT` X25519 keys kept as `ret/rt/<n>`, rotated in `send_announce()` once
    the newest is `CONFIG_RET_RATCHET_INTERVAL_S` old and the wall clock is set. The new key is
    stored before any announce carries it. Inbound packets and synced messages
    (`ret_client_decrypt()`) try every ratchet, newest first, then the identity key. Unreadable
    ratchet records fail `ret_client_start()`, like the identity; a newly generated identity
    deletes old ones. If a new ratchet can't be stored, the announce carries the current one and
    the next announce retries: rotation waits, reachability doesn't.
  - `src/ret_storage.c` is tested in `tests/lib/ret_storage` against real settings (NVS on
    native_sim's simulated flash). A settings callback that returns an error stops the load
    there, so the loaders note errors and return 0 to see every record.
  - The announce clock (emission time in each announce) must never go backwards across a
    reboot: receivers ignore announces that are not newer than the last one they saw. `ret/aclk`
    stores a reservation. Values are used from RAM, flash is written once per
    `CONFIG_RET_ANNOUNCE_CLOCK_BLOCK` announces, and a boot resumes above the reservation.
  - A settings record that can't be read fails `ret_client_start()`. It is never treated as
    "no identity", which would silently replace the address.
  - Path requests for our address are answered once per tag, at most every
    `CONFIG_RET_PATH_RESPONSE_INTERVAL_MS`. Tagless requests are ignored, as in RNS.
  - A send with no current path is held while path requests go out.
  - Paths go stale on every reconnect.
  - A receipt watchdog reconnects after consecutive timeouts.
- `port/mpack/mpack-config.h`: configuration for mpack (msgpack, pinned in both manifests): no
  stdio, no allocating node API, no extensions. mpack's encoder writes the same smallest forms as
  RNS's umsgpack, which LXMF signatures depend on; `tests/lib/ret_msgpack` checks this against
  umsgpack output. It's built without a heap (`MPACK_STDLIB 0`, `MPACK_BUILDER 0`). Write floats
  with `mpack_write_double` only: umsgpack always writes float64, and `mpack_write_float`'s
  float32 would break signatures.
- `tests/lib/*`: ztest suites. `vectors_rns.h` files are generated by
  `tools/rns_peer/gen_vectors.py` from the real RNS implementation. Regenerate them rather
  than editing by hand.
- `tools/rnsd-test/`: config dir for an isolated rnsd (instance `ret-test`, TCP on 127.0.0.1:4243). It
  leaves the user's own instance on 4242 alone.

Kconfig notes carried over from lion-client:
- Never select `NRF_SECURITY`. It needs a Nordic SoC and breaks native_sim.
- Board-specific settings go in `samples/*/boards/<board>.conf`.

## Workflow

1. **Branch per change.** The default branch is `main`. Start each milestone, feature or
   fix on its own branch: `git switch -c jared/<name> main`, or use a worktree under
   `.claude/worktrees/<name>`.
2. **Build it with tests.**
   - Protocol code gets ztest coverage. Interop with RNS is proven with golden vectors from
     `gen_vectors.py`, not hand-written bytes.
   - Network behaviour is proven with `tools/run_e2e.sh` against a real rnsd.
   - Hardware can't be reached from tests. Say what to check on the board when a change
     affects nRF91 behaviour.
3. **Changelog.** Add the change under `## [Unreleased]` in `CHANGELOG.md` on the same
   branch.
4. **Gates, before every commit.** Run what CI will run:
   - `ret-client/scripts/twister.sh -T ret-client/tests -p native_sim --inline-logs -O build/twister-ret`
   - `west build -b native_sim ret-client/samples/ret_basic -d build/ret_basic -p --no-sysbuild`, which
     must build without warnings.
   - `ret-client/tools/run_e2e.sh` when anything on the wire path changed: framing, packet,
     crypto, announce, receipt or client.
   - When Python changed: `uv run --group dev ruff check` and `ruff format --check` in
     `tools/rns_peer`, plus `uv run --with pytest --with pyyaml pytest ret-client/scripts`.
   - When the hardware path changed: the nRF9151 build in the NCS workspace, and a board run
     (flash with `scripts/flash.py`).
5. **Independent review.** Before committing a finished milestone or fix, run a review in a
   fresh context: a review subagent, or `/code-review`, on the branch diff, with the intent
   of the change.
   - Ask for correctness first: wire-format mismatches with RNS, buffer bounds, secret
     wiping, thread confinement, and missing tests.
   - Verify each finding against the code before acting on it.
   - Fix the real ones. List any you deliberately skipped in the commit body or the PR.
6. **Commit.** Commit at each milestone once the gates and review are done.
   - Use Conventional Commit subjects (`feat(announce): …`, `fix(hdlc): …`, `test(crypto): …`,
     `chore: …`). The body explains the why.
   - Be concise. No Claude or AI signatures.
   - Push, open PRs and release only when the user asks.
7. **PR.** Write the PR description to a scratch file: what changed and why, how it was
   verified, and review findings you skipped. Then run
   `scripts/forgejo.sh pr "<title>" <file>`. It pushes the branch and opens the PR
   against `main`. `scripts/forgejo.sh ci` waits for the PR's CI run, once CI exists.
8. **After merge:** delete the branch, and remove the worktree if you used one.

## CI

`.forgejo/workflows/ci.yml` runs on every PR and push to `main` on the bigbox runner,
in the `ret-client-ci` image (`ci/Dockerfile`). It has two jobs:
- `native_sim` (vanilla workspace): ruff, a golden-vector regeneration diff, the flash.py
  tests, the unit tests, warning-free sample builds and the full e2e.
- `nrf9151` (NCS workspace, after `native_sim`): warning-free sysbuilds of the three samples for
  the Feather. It uploads `tfm_merged.hex` (TF-M plus app) for `ret_basic` and `ret_lxmf`, with nfed's
  `uicr_debug_access_open.hex`, as the `samples-nrf9151` artifact.

Runner setup (image build, volume allowlist) is in `docs/ci-forgejo.md`. After pushing a
PR, `scripts/forgejo.sh ci` waits for the run.

## Forgejo credentials

The remote is `origin` at `forgejo.internal.circuitdojo.com/circuitdojo/ret-client`.
Tokens live in the main checkout's `.env`, which is gitignored. Never commit or print them.
- `FORGEJO_TOKEN`: the API token `scripts/forgejo.sh` uses for PRs, CI status and issues.
  It reads the token from `.env` itself, including from a worktree.
- `PACKAGES_TOKEN`: the Forgejo package registry, for publishing release artifacts.

## Debugging against rnsd

- native_sim keeps settings (the client identity) in a flash file: `--flash=<path>`, or
  `flash.bin` in the working directory by default. Delete it for a fresh identity.
- Always run native_sim binaries with `--seed-random`. Otherwise the test
  RNG repeats the same sequence every run, so ephemeral keys, IVs and packet
  hashes repeat, and a long-running rnsd silently drops the packets as
  duplicates.

- Isolated instance: `uv run --project ret-client/tools/rns_peer rnsd --config ret-client/tools/rnsd-test -vvv`.
- Test destination: `uv run --project ret-client/tools/rns_peer ret-client/tools/rns_peer/peer.py --config ret-client/tools/rnsd-test`.
  - `--ratchets` exercises the ratchet path.
  - `--no-prove` exercises receipt timeouts.
  - `--stop-proving-after N` simulates a link that dies after N proofs.
  - `--reply` answers every message with `echo: ...` to the client's `retclient.node`.
  - It always serves link request handlers and logs link established, identified and closed:
    - `/echo` answers `pong:<data>:<identity|anonymous>`.
    - `/big` answers a 4000-byte (or `<data>`-byte) payload as an uncompressed Resource, and logs
      `RESOURCE PROVED`.
    - `/bigz` answers the same with compression allowed, which ret-client must refuse; it logs
      `RESOURCE REFUSED`.
  - `--print-hash` prints the destination hash for `CONFIG_RET_SAMPLE_DEST_HASH`.
- LXMF peer: `tools/rns_peer/lxmf_peer.py --config ret-client/tools/rnsd-test`, a real `LXMRouter`.
  It answers messages starting with `hello` with `echo: ...`, and logs whether each received
  signature validated and the app_data of each `lxmf.delivery` announce. `--print-hash` prints
  its address for `CONFIG_RET_LXMF_SAMPLE_CONTACT`. `--reply-method direct` sends the echoes over
  a link to the device, and `--mid-reply`/`--big-reply`/`--huge-reply BYTES` add larger messages
  (`REPLY REJECTED` when the device refuses one). Long received contents are logged as their
  words and length (`re: big (1024 bytes)`).
- `peer.py --link-client N` opens a link to the client's own destination (the device as
  responder), sends N packets that must be proved, idles 15 s on keepalives, sends one more and
  closes.
- `run_e2e.sh` scenarios: `plain`, `ratchets`, `no-prove` (an announce-driven build), `echo`
  (a link: open, identify, request, a resource response and a refused compressed one, 15 s idle on
  keepalives, request, close; then bidirectional
  replies to the client's own destination, proved both ways, while the peer holds its own link
  to the device), `lxmf` (`ret_lxmf` against `lxmf_peer.py`: messages and echoes both ways,
  signatures validated on both sides), `lxmf-direct` (the same with DIRECT echoes over a link
  to the device, a 3000-byte message delivered as a Resource, a 12000-byte one refused; and the
  device's own DIRECT replies, a 314-byte one as a link packet and a 1024-byte one as a Resource),
  `store-forward` (a fresh `lxmd` from `tools/lxmd-test`: messages deposited with
  `tools/rns_peer/lxmf_send.py` while the device is down are collected by its sync, and the
  node's store ends with only an oversized one; a third boot verifies a new message with the
  sender key kept in flash), `sleep` (`ret_lxmf_sleep`: three wakes with mail deposited while
  it sleeps, a long reply delivered DIRECT before suspending; it runs after `store-forward`,
  whose kept sender key in the shared flash verifies the last message),
  plus `late` (path request, and sends held during the connect), `stall` (receipt watchdog),
  `bootdown` (rnsd down at boot) and `restart` (rnsd restarted mid-run) using a known-hash
  build. Each known-hash scenario starts a fresh rnsd, because
  rnsd drops repeat path requests for a destination for 45 s.
  Pass names to run a subset. Logs go to `build/ret_e2e-logs/`.
- Run the venv's `python` and `rnsd` (`tools/rns_peer/.venv/bin/`) when backgrounding them.
  Killing a backgrounded `uv run` leaves the child running, and a stray peer stays attached
  to rnsd and corrupts later runs.
- `CONFIG_RET_LOG_LEVEL_DBG=y` logs every received frame, the destination hashes and the
  packet hash of every send.
