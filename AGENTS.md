# Working in this repo

ret-client is a Zephyr module implementing a [Reticulum](https://reticulum.network)
client. It connects to a Python `rnsd` TCPServerInterface and supports:
- HDLC stream framing
- receiving and validating announces
- sending encrypted DATA packets to SINGLE destinations
- validating delivery proofs

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
- `west-vanilla.yml`: vanilla Zephyr v4.2.2, mbedTLS, picolibc, Monocypher and mpack. native_sim
  only.
- `west-ncs.yml`: NCS v3.2.1, needed for the nRF9151.

Switch with `west config manifest.file <file>` and `west update`. Code must build in both: they
differ in Kconfig (for example, only NCS has `PSA_CRYPTO`). native_sim builds pass
`--no-sysbuild` to keep output paths identical. Hardware builds use sysbuild, which NCS
requires.

Toolchain environment:

```bash
source ~/.zephyrtools/env/bin/activate
export ZEPHYR_TOOLCHAIN_VARIANT=zephyr
export ZEPHYR_SDK_INSTALL_DIR=$HOME/.zephyrtools/toolchain/zephyr-sdk-0.16.4
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
uv run --with pytest pytest ret-client/scripts
```

The 9151 build is not in twister: nfed's board YAML still carries the pre-HWMv2 identifier
(`circuitdojo_feather_nrf9151_ns`), and twister does not pick the board up. Build it with
`west build` as above. That is also the plan for its CI job.

**Flashing** must follow the Zephyr Tools load sequence (`~/Git/zephyr-tools`,
`src/commands/flash.ts`). `scripts/flash.py` reproduces it:
1. Program `build/<dir>/merged.hex`: TF-M plus the app, chosen as Zephyr Tools does for a
   Partition Manager build. `west flash` programs only the app and leaves whatever TF-M was on
   the chip, and every PSA call then fails.
2. Run `recovery --unlock-only`, the nRF91 recovery tool from Zephyr Tools setup.
3. Check UICR. If the device already has the hex's UICR words, strip them from the download.
   Otherwise a full chip erase is required (`--erase` or a typed confirmation), and it wipes
   internal flash.
4. Run `probe-rs download`, then `probe-rs reset`.

**Board config** is in `samples/ret_basic/boards/circuitdojo_feather_nrf9151_ns.conf`.
- **TF-M:** must be `TFM_PROFILE_TYPE_NOT_SET`. NCS's minimal profile builds the secure image
  with random generation only and ignores `PSA_WANT_*`, so SHA-256, HMAC and AES calls fail
  with `PSA_ERROR_NOT_SUPPORTED` (-134). `port/zephyr/CMakeLists.txt` refuses to build with it.
  To check what TF-M really contains, look at the symbols in `ret_basic/tfm/bin/tfm_s.elf`,
  not the non-secure API headers.
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

The Python tools under `tools/rns_peer` are a `uv` project pinned to `rns==1.5.7`
(`uv run --project ret-client/tools/rns_peer ...`). Always use `uv`, never bare pip.

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
- `src/ret_client.c`: a single static instance and one thread polling the socket plus an
  eventfd. Sends are queued with `k_msgq`. All protocol state is confined to that thread.
  - With `dest_name` configured the client has its own destination (address): an identity
    created on first start and persisted in settings (`src/ret_storage.c`, keys `ret/id` and
    `ret/aclk`). It announces on every connect, answers path requests for itself, and
    decrypts, delivers (`on_data`) and proves packets sent to it.
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
     `tools/rns_peer`, plus `uv run --with pytest pytest ret-client/scripts`.
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
  tests, the unit tests, a warning-free sample build and the full e2e.
- `nrf9151` (NCS workspace, after `native_sim`): a warning-free sysbuild of `ret_basic` for the
  Feather. It uploads `merged.hex` as the `ret_basic-nrf9151` artifact.

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
  - `--print-hash` prints the destination hash for `CONFIG_RET_SAMPLE_DEST_HASH`.
- `run_e2e.sh` scenarios: `plain`, `ratchets`, `no-prove` (an announce-driven build), `echo`
  (bidirectional: replies to the client's own destination, proved both ways),
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
