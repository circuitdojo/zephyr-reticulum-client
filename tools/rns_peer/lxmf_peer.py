"""LXMF test peer for ret-client's ret_lxmf sample.

Attaches to a running rnsd shared instance, registers an lxmf.delivery
destination with a real LXMF router (LXMRouter), announces it periodically
and logs every message it receives. Each message whose content starts with
"hello" is answered with "echo: <content>" (opportunistic), so the device
receives LXMF too.

    uv run --project ret-client/tools/rns_peer ret-client/tools/rns_peer/lxmf_peer.py \\
        --config ret-client/tools/rnsd-test

Lines meant for scripts start with a fixed tag:
  PEER READY <lxmf address>
  ANNOUNCED
  LXMF RECEIVED <validated|unverified:<reason>> <source> <title>|<content>
  LXMF DEVICE ANNOUNCE <address> <display name>
  REPLY SENT <content>, REPLY DELIVERED <content>, REPLY FAILED <content>
"""

import argparse
import os
import tempfile
import threading
import time

import LXMF
import RNS
from LXMF.LXMessage import LXMessage

DISPLAY_NAME = "ret-lxmf-peer"


def out(line: str) -> None:
    print(line, flush=True)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", help="Reticulum config dir (default: ~/.reticulum)")
    ap.add_argument(
        "--identity",
        default=os.path.join(here, "lxmf_peer_identity"),
        help="identity file, created on first run",
    )
    ap.add_argument("--announce-interval", type=float, default=10.0)
    ap.add_argument(
        "--print-hash",
        action="store_true",
        help="print the lxmf.delivery address (creating the identity if needed) and exit",
    )
    ap.add_argument("-v", "--verbose", action="count", default=0)
    args = ap.parse_args()

    if os.path.isfile(args.identity):
        identity = RNS.Identity.from_file(args.identity)
    else:
        identity = RNS.Identity()
        identity.to_file(args.identity)

    if args.print_hash:
        print(RNS.Destination.hash(identity, "lxmf", "delivery").hex())
        return

    RNS.Reticulum(configdir=args.config, loglevel=RNS.LOG_NOTICE + args.verbose)
    storage = tempfile.mkdtemp(prefix="ret-lxmf-peer-")
    router = LXMF.LXMRouter(identity=RNS.Identity(), storagepath=storage)
    dest = router.register_delivery_identity(identity, display_name=DISPLAY_NAME)

    class DeviceAnnounces:
        aspect_filter = "lxmf.delivery"
        receive_path_responses = True

        def received_announce(self, destination_hash, announced_identity, app_data, **_):
            if destination_hash == dest.hash:
                return
            name = LXMF.display_name_from_app_data(app_data)
            cost = LXMF.stamp_cost_from_app_data(app_data)
            out(f"LXMF DEVICE ANNOUNCE {destination_hash.hex()} {name} stamp_cost={cost}")

    RNS.Transport.register_announce_handler(DeviceAnnounces())

    def reply(source_hash: bytes, text: str) -> None:
        # The device's identity comes from its announce; ask if not yet seen.
        deadline = time.time() + 30
        while RNS.Identity.recall(source_hash) is None:
            if time.time() > deadline:
                out(f"REPLY FAILED {text}")
                return
            if not RNS.Transport.has_path(source_hash):
                RNS.Transport.request_path(source_hash)
            time.sleep(0.5)
        target = RNS.Destination(
            RNS.Identity.recall(source_hash),
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            "lxmf",
            "delivery",
        )
        msg = LXMessage(target, dest, text, "", desired_method=LXMessage.OPPORTUNISTIC)
        msg.register_delivery_callback(lambda m: out(f"REPLY DELIVERED {text}"))
        msg.register_failed_callback(lambda m: out(f"REPLY FAILED {text}"))
        router.handle_outbound(msg)
        out(f"REPLY SENT {text}")

    def delivered(message: LXMessage) -> None:
        if message.signature_validated:
            state = "validated"
        else:
            state = f"unverified:{message.unverified_reason}"
        content = message.content_as_string()
        out(
            f"LXMF RECEIVED {state} {message.source_hash.hex()} "
            f"{message.title_as_string()}|{content}"
        )
        if content.startswith("hello"):
            threading.Thread(
                target=reply, args=(message.source_hash, f"echo: {content}"), daemon=True
            ).start()

    router.register_delivery_callback(delivered)
    out(f"PEER READY {dest.hash.hex()}")

    while True:
        router.announce(dest.hash)
        out("ANNOUNCED")
        time.sleep(args.announce_interval)


if __name__ == "__main__":
    main()
