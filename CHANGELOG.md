# Changelog

## [Unreleased]

### Added

- Zephyr module scaffold: `RET_CORE` (protocol, no networking) and
  `RET_CLIENT` (TCP client to rnsd), `ret_basic` sample for native_sim.
- ztest suites (`ret_codec`, `ret_crypto`, `ret_protocol`): RFC/NIST
  known-answer tests and golden vectors generated from RNS 1.5.7 by
  `tools/rns_peer/gen_vectors.py`.
- `scripts/twister.sh`: runs twister under Python 3.14.
