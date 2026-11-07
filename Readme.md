# ret-client

Zephyr module for talking to a [Reticulum](https://reticulum.network) network
through a Python `rnsd` TCPServerInterface.

Current scope: receive and validate announces, send encrypted packets to
SINGLE destinations, validate delivery proofs. First target is `native_sim`
(host sockets, no root); nRF9151 Feather next.

## Build

From a west workspace containing this repo (`west init -m <repo> --mf west-vanilla.yml`
for native_sim only, `west-ncs.yml` for nRF91):

```bash
west build -b native_sim ret-client/samples/ret_basic -d build/ret_basic -p --no-sysbuild
./build/ret_basic/zephyr/zephyr.exe --seed-random
```

For the nRF9151 Feather (NCS workspace), see "Hardware" in `AGENTS.md`:
build with sysbuild and flash `merged.hex` with `scripts/flash.py`, which
follows the Zephyr Tools load sequence.

The sample connects to `127.0.0.1:4242`, waits for an announce from
`retclient.echo`, then sends it `hello #N` every 10 s and logs each delivery
proof. `--seed-random` is required on native_sim: without it the test RNG
repeats every run and rnsd drops the repeated packets as duplicates. See `AGENTS.md` for tests, the Python test peer and the end-to-end
script.

## Dependencies

- Zephyr 4.2 (vanilla) or NCS 3.2
- [Monocypher](https://monocypher.org) 4.0.2 (X25519, Ed25519), fetched by west
- PSA Crypto API (mbedTLS / nrf_security) for SHA-256, HMAC, AES-256-CBC
