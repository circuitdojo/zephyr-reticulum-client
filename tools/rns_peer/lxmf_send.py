"""Deposit LXMF messages at a propagation node, for ret-client's sync tests.

Attaches to a running rnsd shared instance, waits for the announce of the
lxmf.delivery destination to send to (its identity is needed to encrypt),
then sends --count PROPAGATED messages through --node and waits until the
node has accepted each. Python computes the propagation stamps.

    uv run --project ret-client/tools/rns_peer ret-client/tools/rns_peer/lxmf_send.py \\
        --config ret-client/tools/rnsd-test --node <lxmf.propagation hash> \\
        --to-name ret-lxmf --count 3

Lines meant for scripts start with a fixed tag:
  NODE READY, SENDER READY <lxmf address>, TARGET <address>, DEPOSITED <content>,
  DEPOSIT FAILED <content>
--make-node-identity <path> creates an identity file for lxmd and prints
the lxmf.propagation hash it will serve.
"""

import argparse
import os
import sys
import tempfile
import threading
import time

import LXMF
import RNS
from LXMF.LXMessage import LXMessage


def out(line: str) -> None:
    print(line, flush=True)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", help="Reticulum config dir (default: ~/.reticulum)")
    ap.add_argument("--node", help="lxmf.propagation destination hash")
    ap.add_argument("--to-name", help="send to the lxmf.delivery announcing this display name")
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--prefix", default="stored #", help="content prefix, numbered from 1")
    ap.add_argument(
        "--size",
        type=int,
        default=0,
        help="pad each message's content with '.' to this many bytes",
    )
    ap.add_argument(
        "--big",
        type=int,
        default=0,
        metavar="BYTES",
        help="then one more message of this size (content 'big ...')",
    )
    ap.add_argument(
        "--go-file",
        help="once the target is known, wait for this file to exist before depositing",
    )
    ap.add_argument(
        "--identity",
        default=os.path.join(here, "lxmf_sender_identity"),
        help="the sender's identity file, created on first run",
    )
    ap.add_argument(
        "--then",
        type=int,
        default=0,
        metavar="N",
        help="a second round: wait for <go-file>.2, then deposit N 'later #n' messages",
    )
    ap.add_argument(
        "--linger",
        action="store_true",
        help="stay attached after depositing (answering path requests) until killed",
    )
    ap.add_argument("--make-node-identity", metavar="PATH")
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    if args.make_node_identity:
        identity = RNS.Identity()
        identity.to_file(args.make_node_identity)
        print(RNS.Destination.hash(identity, "lxmf", "propagation").hex())
        return
    if not args.node or not args.to_name:
        ap.error("--node and --to-name are required")

    if os.path.isfile(args.identity):
        identity = RNS.Identity.from_file(args.identity)
    else:
        identity = RNS.Identity()
        identity.to_file(args.identity)

    RNS.Reticulum(configdir=args.config, loglevel=RNS.LOG_NOTICE)
    router = LXMF.LXMRouter(
        identity=RNS.Identity(), storagepath=tempfile.mkdtemp(prefix="ret-lxmf-send-")
    )
    source = router.register_delivery_identity(identity, display_name="ret-sender")
    node = bytes.fromhex(args.node)
    router.set_outbound_propagation_node(node)
    # A freshly started lxmd can take many seconds to answer its first
    # path request: have the path before anyone starts timing deposits.
    deadline = time.time() + args.timeout
    while not RNS.Transport.has_path(node):
        if time.time() > deadline:
            out("DEPOSIT FAILED no path to the node")
            sys.exit(1)
        RNS.Transport.request_path(node)
        time.sleep(1)
    out("NODE READY")
    out(f"SENDER READY {source.hash.hex()}")

    target = {}
    found = threading.Event()

    class Announces:
        aspect_filter = "lxmf.delivery"
        receive_path_responses = True

        def received_announce(self, destination_hash, announced_identity, app_data, **_):
            if LXMF.display_name_from_app_data(app_data) == args.to_name and not found.is_set():
                target["hash"] = destination_hash
                target["identity"] = announced_identity
                found.set()

    RNS.Transport.register_announce_handler(Announces())
    if not found.wait(args.timeout):
        out(f"DEPOSIT FAILED no announce from {args.to_name}")
        sys.exit(1)
    out(f"TARGET {target['hash'].hex()}")

    dest = RNS.Destination(
        target["identity"], RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
    )

    def wait_go(path):
        if not path:
            return
        deadline = time.time() + args.timeout
        while not os.path.exists(path):
            if time.time() > deadline:
                out("DEPOSIT FAILED no go file")
                sys.exit(1)
            time.sleep(0.2)

    texts = [f"{args.prefix}{n} ".ljust(args.size, ".") for n in range(1, args.count + 1)]
    if args.big:
        texts.append("big ".ljust(args.big, "."))
    wait_go(args.go_file)
    ok = deposit(router, dest, source, texts, args.timeout)
    if args.then:
        wait_go(f"{args.go_file}.2" if args.go_file else None)
        ok = (
            deposit(
                router, dest, source, [f"later #{n}" for n in range(1, args.then + 1)], args.timeout
            )
            and ok
        )
    out("DEPOSITS DONE")
    while args.linger:
        time.sleep(1)
    sys.exit(0 if ok else 1)


def deposit(router, dest, source, texts, timeout) -> bool:
    ok = True
    for text in texts:
        msg = LXMessage(dest, source, text, "", desired_method=LXMessage.PROPAGATED)
        router.handle_outbound(msg)
        deadline = time.time() + timeout
        while msg.state not in (LXMessage.SENT, LXMessage.DELIVERED, LXMessage.FAILED):
            if time.time() > deadline:
                break
            time.sleep(0.2)
        label = text.rstrip(".").rstrip()
        if msg.state in (LXMessage.SENT, LXMessage.DELIVERED):
            out(f"DEPOSITED {label}")
        else:
            out(f"DEPOSIT FAILED {label} (state {msg.state})")
            ok = False
    return ok


if __name__ == "__main__":
    main()
