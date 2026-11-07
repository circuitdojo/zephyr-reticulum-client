# Changelog

## [Unreleased]

### Added

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

- `on_announce` fires once per announce; repeats of the same announce
  (rebroadcast and path response) only refresh the path, and announces
  emitted before the last one seen are ignored as replays.
- A socket send failure reports `RET_RECEIPT_FAILED` (the receipt is
  registered only after a successful send).
- Reconnect backoff resets only after a connection that received packets
  or stayed up for 10 s.
- `ret_client_name_hash()` works before `ret_client_start()`.

### Fixed

- Client thread no longer drops the connection when poll is interrupted
  (EINTR).
- Sends still queued when a socket send fails are now failed with a
  callback instead of being stranded.

