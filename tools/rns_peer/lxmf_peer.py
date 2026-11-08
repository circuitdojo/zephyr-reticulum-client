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
    (content over 64 characters: its words without the trailing '.' padding
    and its length, "re: big (2048 bytes)", so an intact padded message
    reads cleanly)
  LXMF DEVICE ANNOUNCE <address> <display name>
  REPLY SENT <content>, REPLY DELIVERED <content>, REPLY FAILED <content>,
  REPLY REJECTED <content> (the recipient refused it); long contents are
  labelled by their first word
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
        "--reply-method",
        choices=["opportunistic", "direct"],
        default="opportunistic",
        help="how echoes are sent (direct: over a link to the device)",
    )
    ap.add_argument(
        "--big-reply",
        type=int,
        default=0,
        metavar="BYTES",
        help="after the first echo, also send a message of this size ('big ...')",
    )
    ap.add_argument(
        "--huge-reply",
        type=int,
        default=0,
        metavar="BYTES",
        help="and one of this size ('huge ...'), expected to be refused",
    )
    ap.add_argument(
        "--mid-reply",
        type=int,
        default=0,
        metavar="BYTES",
        help="and one of this size ('mid ...'): the device's quote of it is too long "
        "for one opportunistic packet but fits one link packet",
    )
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
        method = LXMessage.DIRECT if args.reply_method == "direct" else LXMessage.OPPORTUNISTIC
        label = text if len(text) <= 64 else text.split(" ")[0]

        def failed(m):
            state = "REJECTED" if m.state == LXMessage.REJECTED else "FAILED"
            out(f"REPLY {state} {label}")

        msg = LXMessage(target, dest, text, "", desired_method=method)
        msg.register_delivery_callback(lambda m: out(f"REPLY DELIVERED {label}"))
        msg.register_failed_callback(failed)
        router.handle_outbound(msg)
        out(f"REPLY SENT {label}")

    def delivered(message: LXMessage) -> None:
        if message.signature_validated:
            state = "validated"
        else:
            state = f"unverified:{message.unverified_reason}"
        content = message.content_as_string()
        shown = content
        if len(content) > 64:
            shown = f"{content.rstrip('.').strip()} ({len(content)} bytes)"
        out(
            f"LXMF RECEIVED {state} {message.source_hash.hex()} {message.title_as_string()}|{shown}"
        )
        if content.startswith("hello"):
            src = message.source_hash
            first = content == "hello #1"

            def replies():
                reply(src, f"echo: {content}")
                if first and args.mid_reply:
                    reply(src, "mid ".ljust(args.mid_reply, "."))
                if first and args.big_reply:
                    reply(src, "big ".ljust(args.big_reply, "."))
                if first and args.huge_reply:
                    reply(src, "huge ".ljust(args.huge_reply, "."))

            threading.Thread(target=replies, daemon=True).start()

    router.register_delivery_callback(delivered)
    out(f"PEER READY {dest.hash.hex()}")

    while True:
        router.announce(dest.hash)
        out("ANNOUNCED")
        time.sleep(args.announce_interval)


if __name__ == "__main__":
    main()
