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
import time
from unittest import mock

import RNS
from RNS.Cryptography import Token, X25519PrivateKey, hkdf

NAME = "retclient.echo"
IFAC_NETNAME = "ret-test"
IFAC_PASSPHRASE = "correct horse battery staple"
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

    res = resource_vectors(key, link_id, request_id, "res", 1200)
    res.update(resource_vectors(key, link_id, request_id, "resbig", 36000))
    assert len(res["v_resbig_stream"]) > 74 * 464
    # A delivery (LXMF DIRECT): neither request nor response, raw data.
    res.update(resource_vectors(key, link_id, None, "resdel", 3000))
    res.update(responder_vectors(identity, linkrequest, rx_prv, key, link_packet))
    # RNS's own LRPROOF is the hand-built one the initiator tests use.
    assert res["v_link_lrproof_rns"] == lrproof

    return res | {
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


def responder_vectors(identity, linkrequest, rx_prv, key, link_packet):
    """The responder side, from RNS's own code: Link.validate_request() and
    Link.prove() with the ephemeral X25519 key pinned, and
    Link.prove_packet() for a received link DATA packet."""
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, *NAME.split("."))
    sent = []

    def capture(self):
        self.pack()
        sent.append(self.raw)
        return True

    fixed_key = X25519PrivateKey.from_private_bytes(rx_prv)
    quiet = mock.Mock(
        get_packet_rssi=lambda h: None, get_packet_snr=lambda h: None, get_packet_q=lambda h: None
    )

    def respond(lr_raw, force_mtu=None):
        sent.clear()
        pkt = unpack(lr_raw)
        pkt.destination = dest
        pkt.receiving_interface = None
        with (
            mock.patch("RNS.Link.X25519PrivateKey.generate", return_value=fixed_key),
            mock.patch.object(RNS.Packet, "send", capture),
            mock.patch.object(RNS.Transport, "register_link"),
            mock.patch.object(RNS.Link, "start_watchdog"),
            mock.patch.object(RNS.Reticulum, "get_instance", return_value=quiet),
        ):
            link = RNS.Link.validate_request(dest, pkt.data, pkt)
            assert link is not None and len(sent) == 1
            if force_mtu is not None:
                # What ret-client confirms whatever is asked: 500.
                sent.clear()
                link.mtu = force_mtu
                link.prove()
        assert link.derived_key == key
        return link, sent[-1]

    signalling = linkrequest[-3:]
    lr_nosig = linkrequest[:-3]
    lr_big = linkrequest[:-3] + RNS.Link.signalling_bytes(262144, RNS.Link.MODE_AES256_CBC)
    lr_mode0 = linkrequest[:-3] + bytes([signalling[0] & 0x1F]) + signalling[1:]

    link, lrproof = respond(linkrequest)
    _, lrproof_nosig = respond(lr_nosig)
    _, lrproof_big500 = respond(lr_big, force_mtu=500)
    assert lrproof_big500 == lrproof  # same link_id, key and confirmed MTU

    # A link DATA packet (context NONE) and RNS's proof of it.
    data_plain = b"link data for the responder"
    data_pkt = link_packet(RNS.Packet.NONE, data_plain, "iv_data")
    rx = unpack(data_pkt)
    rx.link = link
    sent.clear()
    with mock.patch.object(RNS.Packet, "send", capture):
        link.prove_packet(rx)
    data_proof = sent[-1]
    tx = sender_resource_vectors(link, "restx", 1500)
    tx.update(sender_resource_vectors(link, "restxbig", 36000))
    RNS.Transport.deregister_destination(dest)

    return {
        "v_link_request_nosig": lr_nosig,
        "v_link_request_mtu_big": lr_big,
        "v_link_request_mode0": lr_mode0,
        "v_link_lrproof_rns": lrproof,
        "v_link_lrproof_rns_nosig": lrproof_nosig,
        "v_link_data": data_pkt,
        "v_link_data_plain": data_plain,
        "v_link_data_hash": rx.packet_hash,
        "v_link_data_proof": data_proof,
    } | tx


def sender_resource_vectors(link, tag, data_len):
    """A Resource RNS sends on `link` (RNS/Resource.py, uncompressed, not a
    request or response, as LXMF DIRECT sends a packed message), with its
    randoms pinned: the stream prefix, the random hash and the token IV.
    The advertisement, stream, hashmap and expected proof are RNS's own; for
    more than 74 parts, so is the hashmap update a request for more map
    hashes gets."""
    mp = RNS.vendor.umsgpack
    data = bytes((i * 11 + 5) & 0xFF for i in range(data_len))
    prefix, r, iv = fixed(tag + "_prefix", 32), fixed(tag + "_r", 32), fixed(tag + "_iv", 16)
    link.rtt = 0.25
    with (
        mock.patch.object(RNS.Identity, "get_random_hash", side_effect=[prefix, r]),
        mock.patch("RNS.Cryptography.Token.os.urandom", return_value=iv),
    ):
        res = RNS.Resource(data, link, advertise=False, auto_compress=False)
    assert not res.compressed and res.random_hash == r[:4]
    stream = b"".join(p.data for p in res.parts)
    out = {
        f"v_{tag}_data": data,
        f"v_{tag}_prefix": prefix[:4],
        f"v_{tag}_r": r[:4],
        f"v_{tag}_iv": iv,
        f"v_{tag}_stream": stream,
        f"v_{tag}_h": res.hash,
        f"v_{tag}_hashmap": res.hashmap,
        f"v_{tag}_expected_proof": res.expected_proof,
        f"v_{tag}_adv_plain": RNS.ResourceAdvertisement(res).pack(),
    }
    if len(res.parts) > 74:
        # The receiver ran out of map hashes after part 73: RNS answers a
        # request flagged 0xFF | last map hash with parts and segment 1.
        sent = []

        def capture(self):
            sent.append((self.context, self.data))
            return True

        req = bytes([0xFF]) + res.hashmap[73 * 4 : 74 * 4] + res.hash + res.hashmap[70 * 4 : 74 * 4]
        res.adv_sent = time.time()
        link.status = RNS.Link.ACTIVE  # ensure_link()
        with (
            mock.patch.object(RNS.Packet, "send", capture),
            mock.patch.object(RNS.Packet, "resend", capture),
            mock.patch.object(RNS.Resource, "watchdog_job"),
        ):
            res.request(req)
        hmu = [d for ctx, d in sent if ctx == RNS.Packet.RESOURCE_HMU]
        parts = [d for ctx, d in sent if ctx == RNS.Packet.RESOURCE]
        assert len(hmu) == 1 and parts == [stream[i * 464 : (i + 1) * 464] for i in range(70, 74)]
        assert hmu[0] == res.hash + mp.packb([1, res.hashmap[74 * 4 :]])
        del out[f"v_{tag}_data"]  # regenerated from the formula in the test
        out[f"v_{tag}_req"] = req
        out[f"v_{tag}_hmu_plain"] = hmu[0]
    return out


def resource_vectors(key, link_id, request_id, tag, payload_len):
    """A Resource on the link with `key`, laid out as RNS/Resource.py builds
    it: stream = Token(random4 | data), parts of SDU 464, h = SHA256(data |
    r), map hash = SHA256(part | r)[:4]. With a `request_id` it is the
    response [request_id, payload]; without, a delivery of the raw payload
    (as LXMF DIRECT sends a packed message)."""
    mp = RNS.vendor.umsgpack
    sdu = 464
    payload = bytes((i * 7 + 3) & 0xFF for i in range(payload_len))
    data = mp.packb([request_id, payload]) if request_id is not None else payload
    r = fixed(tag + "_r", 4)
    with mock.patch("RNS.Cryptography.Token.os.urandom", return_value=fixed(tag + "_iv", 16)):
        stream = Token(key).encrypt(fixed(tag + "_prefix", 4) + data)
    h = full_hash(data + r)
    parts = [stream[i : i + sdu] for i in range(0, len(stream), sdu)]
    hashmap = b"".join(full_hash(p + r)[:4] for p in parts)
    adv = {
        "t": len(stream),
        "d": len(data),
        "n": len(parts),
        "h": h,
        "r": r,
        "o": h,
        "i": 1,
        "l": 1,
        "q": request_id,
        "f": 0x01 | 0x10 if request_id is not None else 0x01,  # encrypted (, response)
        "m": hashmap[: 74 * 4],
    }
    adv_plain = mp.packb(adv)
    with mock.patch("RNS.Cryptography.Token.os.urandom", return_value=fixed(tag + "_adv_iv", 16)):
        adv_token = Token(key).encrypt(adv_plain)
    flags = (RNS.Destination.LINK << 2) | RNS.Packet.DATA
    adv_packet = bytes([flags, 0]) + link_id + bytes([RNS.Packet.RESOURCE_ADV]) + adv_token
    proof = h + full_hash(data + h)
    # Resource.prove(): a PROOF packet on the link, RESOURCE_PRF, unencrypted.
    flags_prf = (RNS.Destination.LINK << 2) | RNS.Packet.PROOF
    proof_packet = bytes([flags_prf, 0]) + link_id + bytes([RNS.Packet.RESOURCE_PRF]) + proof
    out = {
        f"v_{tag}_data": data,
        f"v_{tag}_stream": stream,
        f"v_{tag}_r": r,
        f"v_{tag}_h": h,
        f"v_{tag}_hashmap": hashmap,
        f"v_{tag}_adv_plain": adv_plain,
        f"v_{tag}_adv_packet": adv_packet,
        f"v_{tag}_proof": proof,
        f"v_{tag}_proof_packet": proof_packet,
    }
    if len(parts) > 74:
        # The assembled data is checked against h; no need to carry it twice.
        del out[f"v_{tag}_data"]
        # Hashmap update for segment 1, as Resource sends it: h | [1, hashes].
        out[f"v_{tag}_hmu_plain"] = h + mp.packb([1, hashmap[74 * 4 :]])
    return out


def lxmf_version() -> str:
    import LXMF._version

    return LXMF._version.__version__


def lxmf_vectors():
    """LXMF messages as LXMF/LXMessage.py packs them (lxmf==1.2.1), between
    a device identity and a sender identity, both lxmf.delivery."""
    import LXMF
    from LXMF.LXMessage import LXMessage

    mp = RNS.vendor.umsgpack
    dev = RNS.Identity.from_bytes(fixed("lxmf_dev_x25519", 32) + fixed("lxmf_dev_ed25519", 32))
    snd = RNS.Identity.from_bytes(fixed("lxmf_snd_x25519", 32) + fixed("lxmf_snd_ed25519", 32))

    def delivery(identity):
        return RNS.Destination(
            identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "lxmf", "delivery"
        )

    dev_dest, snd_dest = delivery(dev), delivery(snd)
    for ident, d in ((dev, dev_dest), (snd, snd_dest)):
        RNS.Identity.remember(fixed("remember", 32), d.hash, ident.get_public_key())

    def message(src, dst, ts, title, content, fields):
        m = LXMessage(dst, src, content, title, fields, desired_method=LXMessage.OPPORTUNISTIC)
        m.timestamp = ts
        m.pack()
        return m

    inbound = message(snd_dest, dev_dest, 1800000000.25, "hi", "hello device", {})
    # A sender with a stamp: the same message, stamp appended to the payload
    # (it is not covered by the hash or signature).
    payload = mp.unpackb(inbound.packed[96:])
    stamped = inbound.packed[:96] + mp.packb(payload + [fixed("stamp", 32)])
    with_fields = message(snd_dest, dev_dest, 1800000002.0, "", "f", {0x0F: b"x", 2: "y"})
    outbound = message(dev_dest, snd_dest, 1800000001.5, "", "reply from device", {})

    # Another implementation's shape: str title and content, non-empty
    # fields and a stamp. Signed as LXMessage.pack signs (over the payload
    # without the stamp); unpack_from_bytes must validate it.
    str_payload = [1800000003.5, "Tïtle", "content as str", {1: "y"}]
    str_hashed = dev_dest.hash + snd_dest.hash + mp.packb(str_payload)
    str_hash = full_hash(str_hashed)
    str_packed = (
        dev_dest.hash
        + snd_dest.hash
        + snd.sign(str_hashed + str_hash)
        + mp.packb(str_payload + [fixed("stamp2", 32)])
    )

    # unpack_from_bytes asks the (absent) Reticulum instance about blackholes.
    no_blackholes = mock.Mock(is_blackholed=lambda identity: False)
    with mock.patch.object(RNS.Reticulum, "get_instance", return_value=no_blackholes):
        for packed in (inbound.packed, stamped, with_fields.packed, outbound.packed, str_packed):
            m = LXMessage.unpack_from_bytes(packed)
            assert m.signature_validated
        assert LXMessage.unpack_from_bytes(stamped).hash == inbound.hash
        assert LXMessage.unpack_from_bytes(str_packed).hash == str_hash

    app_data = mp.packb([b"ret-node", None, []])
    assert LXMF.display_name_from_app_data(app_data) == "ret-node"
    assert LXMF.stamp_cost_from_app_data(app_data) is None

    # Display names as other LXMF nodes announce them (LXMRouter.
    # get_announce_app_data: [name, stamp cost, [SF_COMPRESSION]]), and as
    # senders before LXMF 0.5.0 did (the bare UTF-8 name). Each is paired
    # with what LXMF.display_name_from_app_data() reads from it.
    names = {
        # NULs removed, whitespace stripped, a stamp cost and functionality.
        "padded": mp.packb([b"  Mom's phone\x00 ", 8, [LXMF.SF_COMPRESSION]]),
        "utf8": mp.packb(["Zoë 📡".encode(), None, [LXMF.SF_COMPRESSION]]),
        "legacy": "Old node ✓".encode(),
        # Unicode whitespace (str.isspace) stripped too, and more leading
        # whitespace than ret_chat keeps of a name.
        "unicode_ws": mp.packb([("\u00a0\u3000" + " " * 40 + "Bob\u2009\x00\u205f").encode()]),
        # array16 form (more than 15 elements) is still the new format.
        "array16": mp.packb([b"Wide", None] + [None] * 14),
    }
    dn = {}
    for key, data in names.items():
        name = LXMF.display_name_from_app_data(data)
        assert name is not None, key
        dn[f"v_lxmf_dn_{key}"] = data
        dn[f"v_lxmf_dn_{key}_name"] = name.encode()
    assert names["array16"][0] == 0xDC
    no_name = mp.packb([None, None, [LXMF.SF_COMPRESSION]])
    assert LXMF.display_name_from_app_data(no_name) is None
    dn["v_lxmf_dn_none"] = no_name

    return {
        "v_lxmf_dev_prv": dev.get_private_key(),
        "v_lxmf_dev_dest": dev_dest.hash,
        "v_lxmf_snd_pub": snd.get_public_key(),
        "v_lxmf_snd_dest": snd_dest.hash,
        "v_lxmf_in_packed": inbound.packed,
        "v_lxmf_in_hash": inbound.hash,
        "v_lxmf_in_stamped": stamped,
        "v_lxmf_fields_packed": with_fields.packed,
        "v_lxmf_fields_hash": with_fields.hash,
        "v_lxmf_out_packed": outbound.packed,
        "v_lxmf_str_packed": str_packed,
        "v_lxmf_str_hash": str_hash,
        "v_lxmf_app_data": app_data,
        **dn,
    }


class IfacInterface:
    """Just what Transport's IFAC functions read from an interface,
    keyed as Reticulum.py (interface setup) derives it."""

    def __init__(self, netname, passphrase, size):
        origin = b""
        if netname is not None:
            origin += RNS.Identity.full_hash(netname.encode("utf-8"))
        if passphrase is not None:
            origin += RNS.Identity.full_hash(passphrase.encode("utf-8"))
        self.ifac_key = RNS.Cryptography.hkdf(
            length=64,
            derive_from=RNS.Identity.full_hash(origin),
            salt=RNS.Reticulum.IFAC_SALT,
            context=None,
        )
        self.ifac_identity = RNS.Identity.from_bytes(self.ifac_key)
        self.ifac_size = size
        self.violations = 0

    def ifac_violation(self, _reason):
        self.violations += 1


def ifac_vectors(announce, data):
    """Interface access codes as Transport applies and checks them."""
    both = IfacInterface(IFAC_NETNAME, IFAC_PASSPHRASE, 16)
    name_only = IfacInterface(IFAC_NETNAME, None, 16)
    pass_only = IfacInterface(None, IFAC_PASSPHRASE, 16)
    short = IfacInterface(IFAC_NETNAME, IFAC_PASSPHRASE, 8)
    out = {
        "v_ifac_key": both.ifac_key,
        "v_ifac_key_name": name_only.ifac_key,
        "v_ifac_key_pass": pass_only.ifac_key,
        "v_ifac_announce": RNS.Transport.handle_outgoing_ifac(both, announce),
        "v_ifac_data": RNS.Transport.handle_outgoing_ifac(both, data),
        "v_ifac_data_8": RNS.Transport.handle_outgoing_ifac(short, data),
    }
    for iface, key, plain in (
        (both, "v_ifac_announce", announce),
        (both, "v_ifac_data", data),
        (short, "v_ifac_data_8", data),
    ):
        ok, raw = RNS.Transport.handle_ifac(out[key], iface)
        assert ok and raw == plain, key
        # The legacy byte-by-byte form produces the same bytes.
        assert RNS.Transport.handle_outgoing_ifac_legacy(iface, plain) == out[key], key
    bad = bytearray(out["v_ifac_data"])
    bad[-1] ^= 1
    assert RNS.Transport.handle_ifac(bytes(bad), both)[0] is False
    assert RNS.Transport.handle_ifac(out["v_ifac_data"], pass_only)[0] is False
    return out


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
    lxmf = lxmf_vectors()

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
        f" * Generated by tools/rns_peer/gen_vectors.py from RNS {RNS._version.__version__},",
        f" * LXMF {lxmf_version()}.",
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
        f'#define V_IFAC_NETNAME "{IFAC_NETNAME}"',
        f'#define V_IFAC_PASSPHRASE "{IFAC_PASSPHRASE}"',
        "",
        c_array("v_identity_prv", prv),
        c_array("v_identity_pub", pub),
        c_array("v_identity_hash", id_hash),
        c_array("v_name_hash", name_hash),
        c_array("v_dest_hash", dest_hash),
        c_array("v_ratchet_pub", ratchet_pub),
        c_array("v_ratchet_prv", ratchet_prv),
        c_array("v_ratchet_id", RNS.Identity._get_ratchet_id(ratchet_pub)),
        c_array("v_transport_id", fixed("transport_id", 16)),
        c_array("v_announce", announce),
        c_array("v_announce_ratchet_h2", announce_ratchet),
        c_array("v_announce_wrong_dest", announce_wrong_dest),
        c_array("v_announce_real", announce_real),
        c_array("v_announce_path_response", announce_path_response),
        c_array("v_announce_max", announce_max),
        *[c_array(k, v) for k, v in ifac_vectors(announce, data_h1).items()],
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
        *[c_array(name, data) for name, data in lxmf.items()],
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
