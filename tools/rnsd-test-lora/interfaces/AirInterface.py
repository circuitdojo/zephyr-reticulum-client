"""A LoRa node on tools/rns_peer/air.py, for the e2e test.

Frames packets exactly as RNode firmware does on the air, written
independently of src/ret_rnode_air.c.
"""

import os
import socket
import threading

from RNS.Interfaces.Interface import Interface


class AirInterface(Interface):
    HW_MTU = 508
    DEFAULT_IFAC_SIZE = 8
    FRAME_DATA = 254
    FLAG_SPLIT = 0x01
    SEQ_MASK = 0xF0
    # SF9, 500 kHz, CR 4/5, as the bridge reports.
    BITRATE = 7031

    def __init__(self, owner, configuration):
        super().__init__()
        c = Interface.get_config_obj(configuration)
        self.name = c["name"]
        self.owner = owner
        self.HW_MTU = AirInterface.HW_MTU
        self.bitrate = AirInterface.BITRATE
        self.online = True
        self.IN = True
        self.OUT = False
        self.air = ("127.0.0.1", int(c["air_port"]))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", int(c["local_port"])))
        self.partial = None
        self.seq = 0

    def __str__(self):
        return f"AirInterface[{self.name}]"

    def final_init(self):
        threading.Thread(target=self.read_loop, daemon=True).start()

    def process_outgoing(self, data):
        header = os.urandom(1)[0] & self.SEQ_MASK
        if len(data) > self.FRAME_DATA:
            header |= self.FLAG_SPLIT
            self.sock.sendto(bytes([header]) + data[: self.FRAME_DATA], self.air)
            self.sock.sendto(bytes([header]) + data[self.FRAME_DATA :], self.air)
        else:
            self.sock.sendto(bytes([header]) + data, self.air)
        self.txb += len(data)

    def read_loop(self):
        while True:
            frame = self.sock.recv(2048)
            header, data = frame[0], frame[1:]
            seq = header & self.SEQ_MASK
            if not header & self.FLAG_SPLIT:
                self.partial = None
                self.deliver(data)
            elif self.partial is not None and self.seq == seq:
                packet, self.partial = self.partial + data, None
                self.deliver(packet)
            else:
                self.partial, self.seq = data, seq

    def deliver(self, packet):
        self.rxb += len(packet)
        self.owner.inbound(packet, self)


interface_class = AirInterface
