"""P2P and BitTorrent traffic module."""

import random
import struct
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# BitTorrent protocol constants
BT_PROTOCOL = b"BitTorrent protocol"
BT_RESERVED = b"\x00" * 8

# Common torrent tracker ports
TRACKER_PORTS = [6881, 6889, 6969, 1337, 80, 443]

# DHT bootstrap nodes patterns
DHT_BOOTSTRAP = [
    "router.bittorrent.com",
    "router.utorrent.com",
    "dht.transmissionbt.com",
    "dht.aelitis.com",
]


class P2PTorrentModule(TrafficModule):
    """Traffic module for P2P and BitTorrent protocol patterns.

    Generates network traffic that simulates BitTorrent peer-to-peer
    communication including handshakes, DHT queries, and tracker requests.
    """

    def __init__(self) -> None:
        """Initialize the P2P/torrent module."""
        self._p2p_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="p2p_torrent",
            description="P2P/BitTorrent detection (handshakes, DHT, trackers)",
            category=TrafficCategory.VIDEO_FILTER,
            protocols=["TCP", "UDP"],
            ports=[6881, 6889, 6969],
        )

    def _generate_bt_handshake(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate BitTorrent handshake packet."""
        # BitTorrent handshake: <pstrlen><pstr><reserved><info_hash><peer_id>
        pstrlen = bytes([19])  # Length of "BitTorrent protocol"
        info_hash = bytes(random.randint(0, 255) for _ in range(20))  # Random hash
        peer_id = b"-qB4500-" + bytes(random.randint(0, 255) for _ in range(12))

        handshake = pstrlen + BT_PROTOCOL + BT_RESERVED + info_hash + peer_id

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=handshake)
        )
        yield packet

    def _generate_dht_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate DHT (Distributed Hash Table) query."""
        # Bencoded DHT ping query
        transaction_id = bytes(random.randint(0, 255) for _ in range(2))
        node_id = bytes(random.randint(0, 255) for _ in range(20))

        # Bencoded format: d1:ad2:id20:<node_id>e1:q4:ping1:t2:<tid>1:y1:qe
        dht_ping = (
            b"d1:ad2:id20:" + node_id + b"e1:q4:ping1:t2:" + transaction_id + b"1:y1:qe"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=6881)
            / Raw(load=dht_ping)
        )
        yield packet

    def _generate_dht_find_node(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate DHT find_node query."""
        transaction_id = bytes(random.randint(0, 255) for _ in range(2))
        node_id = bytes(random.randint(0, 255) for _ in range(20))
        target_id = bytes(random.randint(0, 255) for _ in range(20))

        # find_node query
        dht_find = (
            b"d1:ad2:id20:" + node_id + b"6:target20:" + target_id +
            b"e1:q9:find_node1:t2:" + transaction_id + b"1:y1:qe"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=6881)
            / Raw(load=dht_find)
        )
        yield packet

    def _generate_tracker_request(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate HTTP tracker announce request."""
        info_hash = bytes(random.randint(0, 255) for _ in range(20)).hex()
        peer_id = bytes(random.randint(0, 255) for _ in range(20)).hex()

        # HTTP tracker announce
        http_request = (
            f"GET /announce?info_hash=%{info_hash[:40]}&"
            f"peer_id=%{peer_id[:40]}&"
            f"port={random.randint(6881, 6889)}&"
            f"uploaded=0&downloaded=0&left=1000000&"
            f"event=started HTTP/1.1\r\n"
            f"Host: tracker.example.com\r\n"
            f"User-Agent: qBittorrent/4.5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_udp_tracker(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate UDP tracker protocol connect request."""
        # UDP tracker protocol
        # Connect: protocol_id (64-bit) + action (32-bit) + transaction_id (32-bit)
        protocol_id = struct.pack(">Q", 0x41727101980)  # Magic constant
        action = struct.pack(">I", 0)  # Connect = 0
        transaction_id = struct.pack(">I", random.randint(0, 0xFFFFFFFF))

        connect_request = protocol_id + action + transaction_id

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=6969)
            / Raw(load=connect_request)
        )
        yield packet

    def _generate_peer_exchange(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Peer Exchange (PEX) message."""
        # Extension protocol PEX message
        # Extended message: length + msg_type (20) + ext_msg_type + payload
        pex_payload = b"d5:added12:" + bytes(12) + b"7:added.f1:\x00e"

        # BitTorrent message wrapper
        msg = struct.pack(">IB", len(pex_payload) + 2, 20) + b"\x01" + pex_payload

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=msg)
        )
        yield packet

    def _generate_magnet_resolution(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate magnet link resolution traffic."""
        # DHT get_peers for info_hash
        info_hash = bytes(random.randint(0, 255) for _ in range(20))
        node_id = bytes(random.randint(0, 255) for _ in range(20))
        transaction_id = bytes(random.randint(0, 255) for _ in range(2))

        dht_get_peers = (
            b"d1:ad2:id20:" + node_id + b"9:info_hash20:" + info_hash +
            b"e1:q9:get_peers1:t2:" + transaction_id + b"1:y1:qe"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=6881)
            / Raw(load=dht_get_peers)
        )
        yield packet

    def _generate_piece_request(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate BitTorrent piece request message."""
        # Request message: <len=0013><id=6><index><begin><length>
        index = random.randint(0, 1000)
        begin = random.randint(0, 16) * 16384
        length = 16384

        request_msg = struct.pack(">IBIII", 13, 6, index, begin, length)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=request_msg)
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate P2P/torrent packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with P2P/torrent patterns
        """
        port = dst_port or random.choice(TRACKER_PORTS)
        self._p2p_count += 1

        # Rotate through different P2P patterns
        pattern = self._p2p_count % 8

        if pattern == 0:
            yield from self._generate_bt_handshake(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_dht_query(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_dht_find_node(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_tracker_request(src_ip, dst_ip, port)
        elif pattern == 4:
            yield from self._generate_udp_tracker(src_ip, dst_ip)
        elif pattern == 5:
            yield from self._generate_peer_exchange(src_ip, dst_ip, port)
        elif pattern == 6:
            yield from self._generate_magnet_resolution(src_ip, dst_ip, port)
        else:
            yield from self._generate_piece_request(src_ip, dst_ip, port)

