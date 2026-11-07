"""Generate golden test vectors for ret-client from the real RNS implementation.

Every vector is produced by, or checked against, RNS itself (pinned in
pyproject.toml), so a C test that matches these bytes interoperates with
rnsd. Randomness (ephemeral keys, IVs, announce random hashes) is fixed so
the C side can reproduce encryption byte for byte.

    uv run --project ret-client/tools/rns_peer \
        ret-client/tools/rns_peer/gen_vectors.py ret-client/tests/common/vectors_rns.h
"""

import hashlib
import os
import sys
import tempfile
from unittest import mock

import RNS
from RNS.Cryptography import Token, X25519PrivateKey, hkdf

NAME = "retclient.echo"
APP_DATA = b"ret-test"
PLAINTEXT = b"hello #1"


def fixed(tag: str, n: int) -> bytes:
    """Deterministic bytes derived from a label."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{tag}:{counter}".encode()).digest()
        counter += 1
    return out[:n]


def hand_random_hash() -> bytes:
    """Random hash for hand-built announces: 5 random bytes, then the
    emission time (big-endian seconds), set before the real announces'
    FIXED_TIME so those count as newer."""
    return fixed("random_hash", 5) + int(FIXED_TIME - 100).to_bytes(5, "big")


def full_hash(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def unpack(raw: bytes) -> RNS.Packet:
    p = RNS.Packet(None, raw)
    assert p.unpack(), "RNS failed to unpack packet"
    return p


def build_announce(identity, dest_hash, name_hash, ratchet_pub, header2):
    random_hash = hand_random_hash()
    pub = identity.get_public_key()
    ratchet = ratchet_pub or b""
    signed = dest_hash + pub + name_hash + random_hash + ratchet + APP_DATA
    sig = identity.sign(signed)
    data = pub + name_hash + random_hash + ratchet + sig + APP_DATA

    context_flag = 1 if ratchet_pub else 0
    if header2:
        flags = (1 << 6) | (context_flag << 5) | (1 << 4) | (0 << 2) | 1
        raw = bytes([flags, 1]) + fixed("transport_id", 16) + dest_hash + b"\x00" + data
    else:
        flags = (0 << 6) | (context_flag << 5) | (0 << 4) | (0 << 2) | 1
        raw = bytes([flags, 0]) + dest_hash + b"\x00" + data

    pkt = unpack(raw)
    # Validation succeeds before RNS tries to persist the ratchet, which
    # needs a running instance; skip only the persistence.
    with mock.patch.object(RNS.Identity, "_remember_ratchet"):
        assert RNS.Identity.validate_announce(pkt), "RNS rejected generated announce"
    return raw


def encrypt_det(identity, target_pub_bytes, eph_prv, iv, plaintext):
    """Identity.encrypt with fixed ephemeral key and IV."""
    eph = X25519PrivateKey.from_private_bytes(eph_prv)
    eph_pub = eph.public_key().public_bytes()
    shared = eph.exchange(RNS.Cryptography.X25519PublicKey.from_public_bytes(target_pub_bytes))
    derived = hkdf(
        length=RNS.Identity.DERIVED_KEY_LENGTH,
        derive_from=shared,
        salt=identity.get_salt(),
        context=identity.get_context(),
    )
    with mock.patch("RNS.Cryptography.Token.os.urandom", return_value=iv):
        ct = Token(derived).encrypt(plaintext)
    return eph_pub + ct


FIXED_TIME = 1_800_000_000.0


def offline_rns():
    """Let Destination/Identity code run without a Reticulum instance.

    The stub owner claims a shared instance, which makes RNS skip writing
    known destinations and ratchets to storage.
    """
    RNS.Transport.owner = mock.Mock(is_connected_to_shared_instance=True)


def real_announce(identity, ratchet_prv, path_response):
    """Announce built by Destination.announce() itself, with its random
    inputs (random hash, timestamp, ratchet key) pinned."""
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, *NAME.split("."))
    with (
        mock.patch.object(RNS.Identity, "get_random_hash", return_value=fixed("rh", 32)),
        mock.patch.object(RNS.Identity, "_generate_ratchet", return_value=ratchet_prv),
        mock.patch.object(RNS.Identity, "_remember_ratchet"),
        mock.patch("time.time", return_value=FIXED_TIME),
    ):
        dest.enable_ratchets(os.path.join(tempfile.mkdtemp(), "ratchets"))
        pkt = dest.announce(app_data=APP_DATA, path_response=path_response, send=False)
        pkt.pack()
        raw = pkt.raw
        assert RNS.Identity.validate_announce(unpack(raw)), "RNS rejected its own announce"
    RNS.Transport.deregister_destination(dest)
    return raw


def real_proof(identity, data_raw, implicit):
    """Proof packet as Identity.prove() builds it for a received packet."""
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, *NAME.split("."))
    pkt = unpack(data_raw)
    pkt.destination = dest
    pkt.receiving_interface = None
    sent = []

    def capture(self):
        self.pack()
        sent.append(self.raw)
        return True

    with (
        mock.patch.object(RNS.Reticulum, "should_use_implicit_proof", return_value=implicit),
        mock.patch.object(RNS.Packet, "send", capture),
    ):
        identity.prove(pkt)
    RNS.Transport.deregister_destination(dest)
    return sent[0]


def link_vectors(identity, dest_hash):
    """A link from a client to `identity`'s destination, with pinned keys."""
    from RNS.Cryptography import Ed25519PrivateKey, X25519PublicKey

    mp = RNS.vendor.umsgpack
    signalling = RNS.Link.signalling_bytes(500, RNS.Link.MODE_AES256_CBC)

    # Initiator: ephemeral X25519 + Ed25519, LINKREQUEST to the destination.
    lx_prv = fixed("link_x25519", 32)
    led_seed = fixed("link_ed25519", 32)
    lx_pub = X25519PrivateKey.from_private_bytes(lx_prv).public_key().public_bytes()
    led_pub = Ed25519PrivateKey.from_private_bytes(led_seed).public_key().public_bytes()
    flags_lr = (0 << 6) | (0 << 4) | (RNS.Destination.SINGLE << 2) | RNS.Packet.LINKREQUEST
    linkrequest = bytes([flags_lr, 0]) + dest_hash + b"\x00" + lx_pub + led_pub + signalling
    link_id = RNS.Link.link_id_from_lr_packet(unpack(linkrequest))

    # Responder: ephemeral X25519, LRPROOF signed by the destination identity.
    rx_prv = fixed("link_resp_x25519", 32)
    rx_pub = X25519PrivateKey.from_private_bytes(rx_prv).public_key().public_bytes()
    sig_pub = identity.get_public_key()[32:]
    sig = identity.sign(link_id + rx_pub + sig_pub + signalling)
    flags_lp = (0 << 6) | (0 << 4) | (RNS.Destination.LINK << 2) | RNS.Packet.PROOF
    lrproof = bytes([flags_lp, 0]) + link_id + bytes([RNS.Packet.LRPROOF]) + sig + rx_pub
    lrproof += signalling

    # Variants: no signalling (96-byte proof), and a mode RNS doesn't enable.
    sig_nosig = identity.sign(link_id + rx_pub + sig_pub)
    lrproof_nosig = bytes([flags_lp, 0]) + link_id + bytes([RNS.Packet.LRPROOF]) + sig_nosig
    lrproof_nosig += rx_pub
    mode0 = bytes([signalling[0] & 0x1F]) + signalling[1:]  # mode bits 0 (AES-128)
    sig_mode0 = identity.sign(link_id + rx_pub + sig_pub + mode0)
    lrproof_mode0 = bytes([flags_lp, 0]) + link_id + bytes([RNS.Packet.LRPROOF]) + sig_mode0
    lrproof_mode0 += rx_pub + mode0

    # Both sides derive the same key: HKDF(64, X25519, salt=link_id).
    shared = X25519PrivateKey.from_private_bytes(lx_prv).exchange(
        X25519PublicKey.from_public_bytes(rx_pub)
    )
    shared_r = X25519PrivateKey.from_private_bytes(rx_prv).exchange(
        X25519PublicKey.from_public_bytes(lx_pub)
    )
    assert shared == shared_r
    key = hkdf(length=64, derive_from=shared, salt=link_id, context=None)

    def link_packet(context, plaintext, iv_tag, encrypt=True):
        if encrypt:
            with mock.patch("RNS.Cryptography.Token.os.urandom", return_value=fixed(iv_tag, 16)):
                body = Token(key).encrypt(plaintext)
        else:
            body = plaintext
        flags = (0 << 6) | (0 << 4) | (RNS.Destination.LINK << 2) | RNS.Packet.DATA
        return bytes([flags, 0]) + link_id + bytes([context]) + body

    rtt = link_packet(RNS.Packet.LRRTT, mp.packb(0.25), "iv_rtt")
    path_hash = full_hash(b"/echo")[:16]
    request_plain = mp.packb([1800000000.5, path_hash, b"ping"])
    request = link_packet(RNS.Packet.REQUEST, request_plain, "iv_req")
    request_id = unpack(request).getTruncatedHash()
    response = link_packet(RNS.Packet.RESPONSE, mp.packb([request_id, b"pong"]), "iv_resp")

    client = RNS.Identity.from_bytes(fixed("client_x25519", 32) + fixed("client_ed25519", 32))
    client_pub = client.get_public_key()
    identify_plain = client_pub + client.sign(link_id + client_pub)
    identify = link_packet(RNS.Packet.LINKIDENTIFY, identify_plain, "iv_ident")
    keepalive = link_packet(RNS.Packet.KEEPALIVE, b"\xff", "", encrypt=False)
    linkclose = link_packet(RNS.Packet.LINKCLOSE, link_id, "iv_close")

    return {
        "v_link_x25519_prv": lx_prv,
        "v_link_ed25519_seed": led_seed,
        "v_link_signalling": signalling,
        "v_link_request": linkrequest,
        "v_link_id": link_id,
        "v_link_resp_x25519_prv": rx_prv,
        "v_link_proof": lrproof,
        "v_link_proof_nosig": lrproof_nosig,
        "v_link_proof_mode0": lrproof_mode0,
        "v_link_key": key,
        "v_link_rtt": rtt,
        "v_link_path_hash": path_hash,
        "v_link_request_plain": request_plain,
        "v_link_req": request,
        "v_link_request_id": request_id,
        "v_link_response": response,
        "v_link_client_prv": fixed("client_x25519", 32) + fixed("client_ed25519", 32),
        "v_link_identify": identify,
        "v_link_keepalive": keepalive,
        "v_link_close": linkclose,
        "v_link_iv_rtt": fixed("iv_rtt", 16),
        "v_link_iv_req": fixed("iv_req", 16),
        "v_link_iv_ident": fixed("iv_ident", 16),
        "v_link_iv_close": fixed("iv_close", 16),
    }


def c_array(name: str, b: bytes) -> str:
    rows = []
    for i in range(0, len(b), 12):
        rows.append("\t" + " ".join(f"0x{x:02x}," for x in b[i : i + 12]))
    return f"static const uint8_t {name}[{len(b)}] = {{\n" + "\n".join(rows) + "\n};\n"


def main() -> None:
    out_path = sys.argv[1]
    offline_rns()

    prv = fixed("identity_x25519", 32) + fixed("identity_ed25519", 32)
    identity = RNS.Identity.from_bytes(prv)
    pub = identity.get_public_key()
    id_hash = identity.hash
    assert id_hash == full_hash(pub)[:16]

    name_hash = full_hash(NAME.encode())[:10]
    dest_hash = full_hash(name_hash + id_hash)[:16]

    ratchet_prv = fixed("ratchet", 32)
    ratchet_pub = X25519PrivateKey.from_private_bytes(ratchet_prv).public_key().public_bytes()

    announce = build_announce(identity, dest_hash, name_hash, None, header2=False)
    announce_ratchet = build_announce(identity, dest_hash, name_hash, ratchet_pub, header2=True)

    # Correctly signed, but for a destination hash that is not
    # H(name_hash | identity_hash): RNS must reject it on the hash check.
    wrong_dest = fixed("wrong_dest", 16)
    random_hash = hand_random_hash()
    signed = wrong_dest + pub + name_hash + random_hash + APP_DATA
    wrong_sig = identity.sign(signed)
    announce_wrong_dest = (
        bytes([0x01, 0x00])
        + wrong_dest
        + b"\x00"
        + pub
        + name_hash
        + random_hash
        + wrong_sig
        + APP_DATA
    )
    with mock.patch.object(RNS.Identity, "_remember_ratchet"):
        assert not RNS.Identity.validate_announce(unpack(announce_wrong_dest))

    # Path request as Transport.request_path() builds it on a non-transport
    # node: PLAIN DATA to rnstransport.path.request, data = dest | tag.
    pr_hash = RNS.Destination.hash(None, "rnstransport", "path", "request")
    pr_tag = fixed("path_request_tag", 16)
    pr_dest = RNS.Destination(
        None, RNS.Destination.OUT, RNS.Destination.PLAIN, "rnstransport", "path", "request"
    )
    pr_pkt = RNS.Packet(
        pr_dest,
        dest_hash + pr_tag,
        packet_type=RNS.Packet.DATA,
        transport_type=RNS.Transport.BROADCAST,
        header_type=RNS.Packet.HEADER_1,
    )
    pr_pkt.pack()
    path_request = pr_pkt.raw
    assert path_request[2:18] == pr_hash

    hkdf_ikm = fixed("hkdf_ikm", 32)
    hkdf_out = hkdf(length=64, derive_from=hkdf_ikm, salt=id_hash, context=None)

    eph_prv = fixed("ephemeral", 32)
    iv = fixed("iv", 16)
    token = encrypt_det(identity, pub[:32], eph_prv, iv, PLAINTEXT)
    assert identity.decrypt(token) == PLAINTEXT, "RNS failed to decrypt token"

    token_ratchet = encrypt_det(identity, ratchet_pub, eph_prv, iv, PLAINTEXT)
    assert identity.decrypt(token_ratchet, ratchets=[ratchet_prv]) == PLAINTEXT

    # DATA packet (H1/BROADCAST/SINGLE/DATA) and its H2 rewrite.
    data_h1 = bytes([0x00, 0x00]) + dest_hash + b"\x00" + token
    data_h2 = (
        bytes([(1 << 6) | (1 << 4), 0x00]) + fixed("transport_id", 16) + dest_hash + b"\x00" + token
    )
    packet_hash = unpack(data_h1).get_hash()
    assert unpack(data_h2).get_hash() == packet_hash

    proof_implicit = real_proof(identity, data_h1, implicit=True)
    proof_explicit = real_proof(identity, data_h1, implicit=False)
    assert unpack(proof_implicit).destination_hash == packet_hash[:16]
    assert len(proof_implicit) == 19 + 64 and len(proof_explicit) == 19 + 96

    announce_real = real_announce(identity, ratchet_prv, path_response=False)
    announce_path_response = real_announce(identity, ratchet_prv, path_response=True)
    assert announce_path_response[18] == RNS.Packet.PATH_RESPONSE

    # Largest possible announce: H1, no ratchet, app data filling the MTU.
    max_app = b"m" * (RNS.Reticulum.MTU - 19 - 148)
    random_hash = hand_random_hash()
    max_sig = identity.sign(dest_hash + pub + name_hash + random_hash + max_app)
    announce_max = (
        bytes([0x01, 0x00])
        + dest_hash
        + b"\x00"
        + pub
        + name_hash
        + random_hash
        + max_sig
        + max_app
    )
    assert len(announce_max) == RNS.Reticulum.MTU
    with mock.patch.object(RNS.Identity, "_remember_ratchet"):
        assert RNS.Identity.validate_announce(unpack(announce_max))

    # --- Link handshake and link packets (RNS/Link.py layouts) ---
    link = link_vectors(identity, dest_hash)

    # msgpack as RNS/LXMF write it (RNS.vendor.umsgpack): the C side must
    # reproduce these bytes exactly, since LXMF signs re-serialized data.
    mp = RNS.vendor.umsgpack
    mp_ints = [0, 127, 128, 255, 256, 65535, 65536, 2**32 - 1, 2**32, 2**63 - 1, 2**64 - 1]
    mp_ints += [-1, -32, -33, -128, -129, -32768, -32769, -(2**31), -(2**31) - 1, -(2**63)]
    mp_vectors = {
        "v_mp_ints": mp.packb(mp_ints),
        "v_mp_str_lengths": mp.packb(["", "a" * 31, "a" * 32, "a" * 255, "a" * 256]),
        "v_mp_bin_lengths": mp.packb([b"", b"\x01" * 255, b"\x02" * 256]),
        "v_mp_scalars": mp.packb([1800000000.25, None, True, False]),
        "v_mp_array16": mp.packb(list(range(16))),
        "v_mp_map16": mp.packb({i: i * 2 for i in range(16)}),
        # Only the 5-byte header of a 65536-byte bin (bin32 form).
        "v_mp_bin32_header": mp.packb(b"\x00" * 65536)[:5],
        "v_mp_link_request": mp.packb([1800000000.5, full_hash(b"/get")[:16], [None, None]]),
        # LXMF-shaped (hand-built to LXMessage.pack / LXMRouter announce layouts).
        "v_mp_lxmf_payload": mp.packb([1800000000.125, b"title", b"hello", {}]),
        "v_mp_lxmf_app_data": mp.packb([b"ret-node", None, []]),
        # The 11 keys in ResourceAdvertisement.pack order (RNS/Resource.py).
        "v_mp_resource_adv": mp.packb(
            {
                "t": 1300,
                "d": 1200,
                "n": 3,
                "h": fixed("adv_h", 32),
                "r": fixed("adv_r", 4),
                "o": fixed("adv_h", 32),
                "i": 1,
                "l": 1,
                "q": fixed("adv_q", 16),
                "f": 0x11,
                "m": fixed("adv_m", 12),
            }
        ),
    }

    lines = [
        "/*",
        f" * Generated by tools/rns_peer/gen_vectors.py from RNS {RNS._version.__version__}.",
        " * Do not edit.",
        " *",
        " * uv run --project ret-client/tools/rns_peer \\",
        " *     ret-client/tools/rns_peer/gen_vectors.py ret-client/tests/common/vectors_rns.h",
        " */",
        "",
        "#ifndef VECTORS_RNS_H_",
        "#define VECTORS_RNS_H_",
        "",
        "#include <stdint.h>",
        "",
        f'#define V_NAME "{NAME}"',
        f'#define V_APP_DATA "{APP_DATA.decode()}"',
        f'#define V_PLAINTEXT "{PLAINTEXT.decode()}"',
        "",
        c_array("v_identity_prv", prv),
        c_array("v_identity_pub", pub),
        c_array("v_identity_hash", id_hash),
        c_array("v_name_hash", name_hash),
        c_array("v_dest_hash", dest_hash),
        c_array("v_ratchet_pub", ratchet_pub),
        c_array("v_transport_id", fixed("transport_id", 16)),
        c_array("v_announce", announce),
        c_array("v_announce_ratchet_h2", announce_ratchet),
        c_array("v_announce_wrong_dest", announce_wrong_dest),
        c_array("v_announce_real", announce_real),
        c_array("v_announce_path_response", announce_path_response),
        c_array("v_announce_max", announce_max),
        c_array("v_path_request_dest", pr_hash),
        c_array("v_path_request_tag", pr_tag),
        c_array("v_path_request", path_request),
        c_array("v_hkdf_ikm", hkdf_ikm),
        c_array("v_hkdf_out", hkdf_out),
        c_array("v_eph_prv", eph_prv),
        c_array("v_iv", iv),
        c_array("v_token", token),
        c_array("v_token_ratchet", token_ratchet),
        c_array("v_data_h1", data_h1),
        c_array("v_data_h2", data_h2),
        c_array("v_packet_hash", packet_hash),
        c_array("v_proof_implicit", proof_implicit),
        c_array("v_proof_explicit", proof_explicit),
        *[c_array(name, data) for name, data in link.items()],
        *[c_array(name, data) for name, data in mp_vectors.items()],
        c_array("v_mp_adv_h", fixed("adv_h", 32)),
        c_array("v_mp_adv_r", fixed("adv_r", 4)),
        c_array("v_mp_adv_q", fixed("adv_q", 16)),
        c_array("v_mp_adv_m", fixed("adv_m", 12)),
        "#endif /* VECTORS_RNS_H_ */",
        "",
    ]
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
