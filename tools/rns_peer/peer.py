"""Reticulum test destination for ret-client.

Attaches to a running rnsd shared instance, registers the IN SINGLE
destination `retclient.echo`, announces it periodically and prints every
payload it receives. Proves every packet unless --no-prove is given.

    uv run --project ret-client/tools/rns_peer ret-client/tools/rns_peer/peer.py \
        --config ret-client/tools/rnsd-test

With --reply it also answers every message with "echo: <message>" to the
client's own destination (`retclient.node`, learned from its announce) and
reports the client's delivery proof for each reply.

Lines meant for scripts start with a fixed tag: PEER READY, ANNOUNCED,
RECEIVED, CLIENT ANNOUNCE, REPLY SENT, REPLY PROVED, REPLY FAILED, LINK ESTABLISHED,
LINK IDENTIFIED, LINK REQUEST, LINK CLOSED, RESOURCE PROVED, RESOURCE
REFUSED. The destination serves link
request handlers:
  /echo  "pong:<data>:<identity hash or anonymous>"
  /big   <data> bytes (an int, default 4000) of big_payload(), sent as an
         uncompressed Resource: larger than a packet
  /bigz  the same with compression allowed: RNS sends it bz2-compressed,
         which ret-client must refuse
"""

import argparse
import os
import threading
import time

import RNS

APP_NAME = "retclient"
ASPECT = "echo"
APP_DATA = b"ret-test"
CLIENT_NAME = "retclient.node"


def big_payload(size: int) -> bytes:
    """/big's response; the sample checks it byte for byte."""
    return bytes((i * 7 + 3) & 0xFF for i in range(size))


REPLY_PATH_WAIT_S = 30.0


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
        "--reply",
        action="store_true",
        help=f'answer each message with "echo: ..." to the client\'s {CLIENT_NAME}',
    )
    ap.add_argument(
        "--link-client",
        type=int,
        default=0,
        metavar="N",
        help=f"open a link to the client's {CLIENT_NAME}, send N packets (proved), idle 15 s on "
        "keepalives, send one more, close",
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

    client_dest_hash = None
    client_known = threading.Event()

    class ClientAnnounces:
        aspect_filter = CLIENT_NAME
        receive_path_responses = True

        def received_announce(self, destination_hash, announced_identity, app_data, **_):
            nonlocal client_dest_hash
            client_dest_hash = destination_hash
            client_known.set()
            out(f"CLIENT ANNOUNCE {destination_hash.hex()}")

    if args.reply or args.link_client:
        RNS.Transport.register_announce_handler(ClientAnnounces())

    def wait_proved(link, text: str) -> bool:
        receipt = RNS.Packet(link, text.encode()).send()
        deadline = time.time() + 15
        while receipt and receipt.status != RNS.PacketReceipt.DELIVERED:
            if time.time() > deadline or receipt.status == RNS.PacketReceipt.FAILED:
                return False
            time.sleep(0.1)
        return bool(receipt)

    def link_client(n: int) -> None:
        """The device as a link responder: our link to its destination."""
        if not client_known.wait(REPLY_PATH_WAIT_S):
            out("CLIENT LINK FAILED no announce")
            return
        target = RNS.Destination(
            RNS.Identity.recall(client_dest_hash),
            RNS.Destination.OUT,
            RNS.Destination.SINGLE,
            *CLIENT_NAME.split("."),
        )
        link = RNS.Link(target)
        deadline = time.time() + 30
        while link.status != RNS.Link.ACTIVE:
            if time.time() > deadline or link.status == RNS.Link.CLOSED:
                out("CLIENT LINK FAILED not established")
                return
            time.sleep(0.1)
        out(f"CLIENT LINK ACTIVE mtu {link.mtu}")
        for i in range(1, n + 1):
            if not wait_proved(link, f"link #{i}"):
                out(f"CLIENT LINK DATA FAILED {i}")
                return
            out(f"CLIENT LINK DATA PROVED {i}")
        # Past the 2 x 5 s stale time: only keepalive answers keep it up.
        time.sleep(15)
        if link.status != RNS.Link.ACTIVE or not wait_proved(link, f"link #{n + 1}"):
            out("CLIENT LINK DATA FAILED after idle")
            return
        out(f"CLIENT LINK DATA PROVED {n + 1}")
        link.teardown()
        out("CLIENT LINK CLOSED")

    if args.link_client:
        threading.Thread(target=link_client, args=(args.link_client,), daemon=True).start()

    def reply(text: str) -> None:
        if not client_known.wait(REPLY_PATH_WAIT_S):
            out(f"REPLY FAILED no announce from {CLIENT_NAME}: {text}")
            return
        identity = RNS.Identity.recall(client_dest_hash)
        target = RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE, *CLIENT_NAME.split(".")
        )
        receipt = RNS.Packet(target, text.encode()).send()
        if not receipt:
            out(f"REPLY FAILED send: {text}")
            return
        out(f"REPLY SENT {text}")
        reported = threading.Lock()
        done = []

        def report(line: str) -> None:
            with reported:
                if not done:
                    done.append(line)
                    out(line)

        receipt.set_delivery_callback(lambda r: report(f"REPLY PROVED {text}"))
        receipt.set_timeout_callback(lambda r: report(f"REPLY FAILED timeout: {text}"))
        # RNS does not call a callback set after the proof already arrived.
        if receipt.status == RNS.PacketReceipt.DELIVERED:
            report(f"REPLY PROVED {text}")

    received = 0

    def echo_request(path, data, request_id, link_id, remote_identity, requested_at):
        who = remote_identity.hash.hex() if remote_identity else "anonymous"
        out(f"LINK REQUEST {path} from {who}")
        return b"pong:" + (data if isinstance(data, bytes) else b"") + b":" + who.encode()

    dest.register_request_handler("/echo", echo_request, allow=RNS.Destination.ALLOW_ALL)

    def big_request(path, data, request_id, link_id, remote_identity, requested_at):
        size = data if isinstance(data, int) and 0 < data <= 65536 else 4000
        out(f"LINK REQUEST {path} {size}")
        return big_payload(size)

    dest.register_request_handler(
        "/big", big_request, allow=RNS.Destination.ALLOW_ALL, auto_compress=False
    )
    dest.register_request_handler(
        "/bigz", big_request, allow=RNS.Destination.ALLOW_ALL, auto_compress=True
    )

    def on_link(link: RNS.Link) -> None:
        out("LINK ESTABLISHED")
        link.set_link_closed_callback(lambda lk: out("LINK CLOSED"))
        link.set_remote_identified_callback(
            lambda lk, ident: out(f"LINK IDENTIFIED {ident.hash.hex()}")
        )

        # Response resources carry no callback: watch the link's own hooks
        # to report whether the client proved or refused them.
        concluded = link.resource_concluded
        cancel = link.cancel_outgoing_resource

        def on_concluded(resource):
            concluded(resource)
            if resource.initiator and resource.status == RNS.Resource.COMPLETE:
                out(f"RESOURCE PROVED {resource.total_size}")

        def on_cancel(resource):
            cancel(resource)
            if resource.status == RNS.Resource.REJECTED:
                out(f"RESOURCE REFUSED {resource.total_size}")

        link.resource_concluded = on_concluded
        link.cancel_outgoing_resource = on_cancel

    dest.set_link_established_callback(on_link)

    def on_packet(data: bytes, packet: RNS.Packet) -> None:
        nonlocal received
        received += 1
        text = data.decode(errors="replace")
        out(f"RECEIVED {text}")
        # RNS decides whether to prove after this callback returns.
        if args.stop_proving_after is not None and received > args.stop_proving_after:
            dest.set_proof_strategy(RNS.Destination.PROVE_NONE)
        if args.reply:
            # Not from this callback: RNS is still processing the packet.
            threading.Thread(target=reply, args=(f"echo: {text}",), daemon=True).start()

    dest.set_packet_callback(on_packet)

    mode = []
    if args.ratchets:
        mode.append("ratchets")
    if args.no_prove:
        mode.append("no-prove")
    if args.reply:
        mode.append("reply")
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
