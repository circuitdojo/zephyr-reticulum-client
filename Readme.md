# ret-client

A Zephyr module that implements a [Reticulum](https://reticulum.network) client, LXMF
messaging and a Reticulum transport node in C, for small devices such as the nRF9151 Feather.

## Credits

[Reticulum](https://github.com/markqvist/Reticulum) and
[LXMF](https://github.com/markqvist/LXMF) are created by **Mark Qvist**, as is the
[RNode](https://github.com/markqvist/RNode_Firmware) firmware whose LoRa framing the gateway
sample speaks. ret-client is an independent implementation of his protocols. The Python
reference implementation is the specification: byte formats are tested against vectors produced
by RNS's own functions, and every feature is tested end to end against a real `rnsd`. Without
Mark's design, reference code and documentation, none of this would exist. See the
[Reticulum manual](https://reticulum.network/manual/) to learn about the network itself.

ret-client is not part of, or endorsed by, the Reticulum project.

Also built on:
- [Zephyr](https://zephyrproject.org) and the [nRF Connect SDK](https://github.com/nrfconnect/sdk-nrf)
- [Monocypher](https://monocypher.org) by Loup Vaillant (X25519, Ed25519)
- [MPack](https://github.com/ludocode/mpack) by Nicholas Fraser (MessagePack, for LXMF)

## What it does

- Connects to an `rnsd` `TCPServerInterface` (HDLC framing), optionally with an interface
  access code (IFAC).
- Announces, path requests, encrypted packets to SINGLE destinations, delivery proofs and
  ratchets.
- Links, both sides (opening, with requests, and accepting), and Resources both ways.
- LXMF: opportunistic and DIRECT messages both ways, and sync from a propagation node.
- A transport node (`CONFIG_RET_TRANSPORT`), behaving as RNS's `Transport.py` with
  `enable_transport = yes`: routing, announce rebroadcast and caps, path discovery, link and
  reverse tables, and tunnel synthesis.

The protocol as implemented, with the RNS functions each part follows, is in
[`docs/protocol.md`](docs/protocol.md).

## Samples

| Sample | |
|---|---|
| `samples/ret_basic` | raw Reticulum packets and a link test |
| `samples/ret_lxmf` | an always-connected LXMF node |
| `samples/ret_lxmf_sleep` | a sleepy LXMF node: wake, sync, answer, suspend |
| `samples/ret_chat` | LXMF chat over the Zephyr shell |
| `samples/ret_lora_gateway` | a transport node bridging a LoRa radio (RNode framing) and an LTE/TCP uplink to a stock `rnsd` |

## Build

From a west workspace containing this repo (`west init -m <repo> --mf west-vanilla.yml` for
native_sim only, `west-ncs.yml` for the nRF91):

```bash
west build -b native_sim ret-client/samples/ret_basic -d build/ret_basic -p --no-sysbuild
./build/ret_basic/zephyr/zephyr.exe --seed-random
```

`--seed-random` is required on native_sim: without it the test RNG repeats every run and `rnsd`
drops the repeated packets as duplicates. The sample connects to `127.0.0.1:4242`.

For the nRF9151 Feather, see "Hardware" in [`AGENTS.md`](AGENTS.md): build with sysbuild and
flash with `scripts/flash.py`. `AGENTS.md` also covers the unit tests, the Python test peers and
the end-to-end script (`tools/run_e2e.sh`).

## Dependencies

- Zephyr 4.5 (vanilla, `west-vanilla.yml`) or NCS 3.5 (through nfed, `west-ncs.yml`)
- Monocypher 4.0.2 and MPack 1.1.1, fetched by west
- PSA Crypto API (mbedTLS / nrf_security) for SHA-256, HMAC and AES-256-CBC
- For the tests: Python with `rns` 1.5.7 and `lxmf` 1.2.1 (`tools/rns_peer`, managed with `uv`)

## License

ret-client follows the Reticulum and LXMF reference implementations closely, so it is
distributed under the same [Reticulum License](LICENSE), with Mark Qvist's copyright notice
kept. Source files carry `SPDX-License-Identifier: LicenseRef-Reticulum`.

The license is MIT-style with two conditions: the software must not be used in systems meant to
harm people, and must not be used to create AI or machine-learning training datasets. Read
[`LICENSE`](LICENSE) for the exact terms.

Monocypher (BSD-2-Clause or CC0) and MPack (MIT) are fetched by west under their own licenses.
