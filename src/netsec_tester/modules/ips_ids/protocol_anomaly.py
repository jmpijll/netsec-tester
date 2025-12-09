"""Protocol anomaly traffic module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class ProtocolAnomalyModule(TrafficModule):
    """Traffic module for protocol anomaly patterns.

    Generates malformed packets and protocol violations
    to trigger IPS/IDS anomaly detection.
    """

    def __init__(self) -> None:
        """Initialize the protocol anomaly module."""
        self._anomaly_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="protocol_anomaly",
            description="Protocol violations (malformed headers, invalid flags, fragmentation)",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "UDP", "ICMP"],
            ports=[80, 443, 53],
        )

    def _generate_invalid_tcp_flags(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate packets with invalid TCP flag combinations."""
        # SYN+FIN (invalid - connection start and end)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="SF",  # SYN+FIN
            )
        )
        yield packet

        # SYN+RST (invalid - start and abort)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="SR",  # SYN+RST
            )
        )
        yield packet

        # All flags set (Christmas tree + more)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="FSRPAUEC",  # All flags
            )
        )
        yield packet

    def _generate_malformed_http_headers(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate HTTP requests with malformed headers."""
        malformed_requests = [
            # Missing HTTP version
            f"GET /\r\nHost: {dst_ip}\r\n\r\n",
            # Invalid HTTP method
            f"INVALID / HTTP/1.1\r\nHost: {dst_ip}\r\n\r\n",
            # Extremely long header
            f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nX-Long: {'A' * 8192}\r\n\r\n",
            # Null bytes in header
            f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nX-Null: test\x00value\r\n\r\n",
            # Invalid characters
            f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nX-Bad: \xff\xfe\r\n\r\n",
            # Duplicate Content-Length (HTTP smuggling indicator)
            f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nContent-Length: 10\r\nContent-Length: 20\r\n\r\n",
            # Invalid HTTP version
            f"GET / HTTP/9.9\r\nHost: {dst_ip}\r\n\r\n",
            # No CRLF (just LF)
            f"GET / HTTP/1.1\nHost: {dst_ip}\n\n",
        ]

        request = random.choice(malformed_requests)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=request.encode("latin-1", errors="replace"))
        )
        yield packet

    def _generate_oversized_headers(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate packets with oversized headers/options."""
        # TCP with maximum options
        tcp_options = [
            ("MSS", 1460),
            ("NOP", None),
            ("NOP", None),
            ("WScale", 14),
            ("SAckOK", b""),
            ("Timestamp", (12345, 0)),
            ("NOP", None),
            ("NOP", None),
        ]

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="S",
                options=tcp_options,
            )
        )
        yield packet

    def _generate_ip_fragment_anomaly(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate fragmented packet anomalies."""
        # Overlapping fragments (teardrop-like)
        # Fragment 1: offset 0, MF=1
        packet1 = (
            IP(src=src_ip, dst=dst_ip, flags="MF", frag=0)
            / ICMP(type=8, code=0)
            / Raw(load=b"X" * 24)
        )
        yield packet1

        # Fragment 2: overlapping offset
        packet2 = (
            IP(src=src_ip, dst=dst_ip, flags=0, frag=2)  # Overlaps with first
            / Raw(load=b"Y" * 24)
        )
        yield packet2

    def _generate_tiny_fragments(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate tiny TCP fragments (evasion technique)."""
        # Very small first fragment containing only TCP header
        # This is a known IDS evasion technique
        http_request = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"

        # First tiny fragment
        packet = (
            IP(src=src_ip, dst=dst_ip, flags="MF", frag=0)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request[:8])
        )
        yield packet

        # Second fragment with rest of data
        packet = (
            IP(src=src_ip, dst=dst_ip, frag=1)
            / Raw(load=http_request[8:])
        )
        yield packet

    def _generate_ping_of_death(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate oversized ICMP packets (Ping of Death pattern)."""
        # Large ICMP packet (historical attack, triggers signature)
        large_payload = b"X" * 1472  # Near MTU limit

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / ICMP(type=8, code=0)
            / Raw(load=large_payload)
        )
        yield packet

    def _generate_land_attack(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate LAND attack pattern (same src/dst)."""
        # Source and destination are the same (historical attack)
        packet = (
            IP(src=dst_ip, dst=dst_ip)  # src = dst
            / TCP(sport=port, dport=port, flags="S")  # same ports
        )
        yield packet

    def _generate_invalid_checksum(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate packets with invalid checksums."""
        # Create packet then corrupt checksum
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="S", chksum=0x1234)
        )
        yield packet

    def _generate_reserved_flags(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate packets with reserved/ECN flags set unusually."""
        # Reserved bits set (historically unused)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="SEC",  # SYN + ECE + CWR
                reserved=7,  # Reserved bits
            )
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate protocol anomaly packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with protocol anomalies
        """
        port = dst_port or 80
        self._anomaly_count += 1

        # Rotate through different anomaly types
        anomaly_type = self._anomaly_count % 9

        if anomaly_type == 0:
            yield from self._generate_invalid_tcp_flags(src_ip, dst_ip, port)
        elif anomaly_type == 1:
            yield from self._generate_malformed_http_headers(src_ip, dst_ip, port)
        elif anomaly_type == 2:
            yield from self._generate_oversized_headers(src_ip, dst_ip, port)
        elif anomaly_type == 3:
            yield from self._generate_ip_fragment_anomaly(src_ip, dst_ip)
        elif anomaly_type == 4:
            yield from self._generate_tiny_fragments(src_ip, dst_ip, port)
        elif anomaly_type == 5:
            yield from self._generate_ping_of_death(src_ip, dst_ip)
        elif anomaly_type == 6:
            yield from self._generate_land_attack(src_ip, dst_ip, port)
        elif anomaly_type == 7:
            yield from self._generate_invalid_checksum(src_ip, dst_ip, port)
        else:
            yield from self._generate_reserved_flags(src_ip, dst_ip, port)

