"""A simulated LoRa channel for the e2e test.

Each radio is a UDP port. A datagram is one LoRa frame, and it reaches the
radios linked to its sender, so a test can choose who hears whom.

    air.py --port 5100 --node bridge=5101 --node n1=5102 --link bridge-n1
"""

import argparse
import socket


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--node", action="append", default=[], metavar="NAME=PORT")
    ap.add_argument("--link", action="append", default=[], metavar="A-B")
    args = ap.parse_args()

    nodes = {name: int(port) for name, port in (n.split("=") for n in args.node)}
    names = {port: name for name, port in nodes.items()}
    hears: dict[str, set[str]] = {name: set() for name in nodes}
    for link in args.link:
        a, b = link.split("-")
        hears[a].add(b)
        hears[b].add(a)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.port))
    print("AIR READY", flush=True)

    while True:
        frame, (_, port) = sock.recvfrom(2048)
        sender = names.get(port)
        if sender is None:
            print(f"unknown radio on port {port}", flush=True)
            continue
        for name in hears[sender]:
            sock.sendto(frame, ("127.0.0.1", nodes[name]))
        print(f"{sender} -> {sorted(hears[sender])} {len(frame)} bytes", flush=True)


if __name__ == "__main__":
    main()
