"""Reticulum test destination for ret-client.

Attaches to a running rnsd shared instance, registers the IN SINGLE
destination `retclient.echo`, announces it periodically and prints every
payload it receives. Proves every packet unless --no-prove is given.

    uv run --project ret-client/tools/rns_peer ret-client/tools/rns_peer/peer.py \
        --config ret-client/tools/rnsd-test

Lines meant for scripts start with a fixed tag: PEER READY, ANNOUNCED,
RECEIVED.
"""

import argparse
import os
import time

import RNS

APP_NAME = "retclient"
ASPECT = "echo"
APP_DATA = b"ret-test"


def out(line: str) -> None:
    print(line, flush=True)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", help="Reticulum config dir (default: ~/.reticulum)")
    ap.add_argument(
        "--identity",
        default=os.path.join(here, "peer_identity"),
        help="identity file, created on first run",
    )
    ap.add_argument("--announce-interval", type=float, default=10.0)
    ap.add_argument("--ratchets", action="store_true", help="announce with ratchets")
    ap.add_argument("--no-prove", action="store_true", help="never send delivery proofs")
    ap.add_argument(
        "--stop-proving-after",
        type=int,
        metavar="N",
        help="prove the first N packets, then stop (a link that looks dead)",
    )
    ap.add_argument(
        "--print-hash",
        action="store_true",
        help="print the destination hash (creating the identity if needed) and exit",
    )
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()

    if os.path.isfile(args.identity):
        identity = RNS.Identity.from_file(args.identity)
    else:
        identity = RNS.Identity()
        identity.to_file(args.identity)

    if args.print_hash:
        print(RNS.Destination.hash(identity, APP_NAME, ASPECT).hex())
        return

    RNS.Reticulum(configdir=args.config, loglevel=RNS.LOG_NOTICE + args.verbose)

    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT)
    if args.ratchets:
        dest.enable_ratchets(args.identity + ".ratchets")
        # Without enforcement RNS falls back to the identity key, so a
        # client ignoring the announced ratchet would still be delivered.
        dest.enforce_ratchets()
    dest.set_proof_strategy(
        RNS.Destination.PROVE_NONE if args.no_prove else RNS.Destination.PROVE_ALL
    )

    received = 0

    def on_packet(data: bytes, packet: RNS.Packet) -> None:
        nonlocal received
        received += 1
        out(f"RECEIVED {data.decode(errors='replace')}")
        # RNS decides whether to prove after this callback returns.
        if args.stop_proving_after is not None and received > args.stop_proving_after:
            dest.set_proof_strategy(RNS.Destination.PROVE_NONE)

    dest.set_packet_callback(on_packet)

    mode = []
    if args.ratchets:
        mode.append("ratchets")
    if args.no_prove:
        mode.append("no-prove")
    if args.stop_proving_after is not None:
        mode.append(f"stop-proving-after={args.stop_proving_after}")
    out(f"PEER READY {dest.hash.hex()} {' '.join(mode)}".rstrip())

    try:
        while True:
            dest.announce(app_data=APP_DATA)
            out("ANNOUNCED")
            time.sleep(args.announce_interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
