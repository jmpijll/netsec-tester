"""ICMP covert channel traffic module."""

import base64
import random
import string
from typing import Iterator

from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class ICMPCovertModule(TrafficModule):
    """Traffic module for ICMP covert channel patterns.

    Generates ICMP traffic that simulates data exfiltration
    via ICMP echo requests/replies with encoded payloads.
    """

    def __init__(self) -> None:
        """Initialize the ICMP covert module."""
        self._icmp_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="icmp_covert",
            description="ICMP covert channels (data in ICMP payload, oversized pings)",
            category=TrafficCategory.EXFILTRATION,
            protocols=["ICMP"],
            ports=[],  # ICMP doesn't use ports
        )

    def _generate_data_in_payload(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ICMP with encoded data in payload."""
        # Simulate exfiltrated data
        fake_data = ''.join(random.choices(string.ascii_letters + string.digits, k=64))
        encoded_data = base64.b64encode(fake_data.encode())

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / ICMP(type=8, code=0, id=random.randint(0, 65535), seq=random.randint(0, 65535))
            / Raw(load=encoded_data)
        )
        yield packet

    def _generate_oversized_ping(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate oversized ICMP packets (data exfil indicator)."""
        # Large payload - unusual for normal pings
        large_payload = bytes(random.randint(0, 255) for _ in range(1000))

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / ICMP(type=8, code=0, id=random.randint(0, 65535), seq=random.randint(0, 65535))
            / Raw(load=large_payload)
        )
        yield packet

    def _generate_icmp_tunnel(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ICMP tunnel-like traffic pattern."""
        # Multiple sequential ICMP packets with varying payload sizes
        seq_base = random.randint(1, 1000)

        for i in range(5):
            # Data chunks in sequence
            chunk_data = f"CHUNK{i:03d}:" + ''.join(random.choices(string.hexdigits, k=32))

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / ICMP(type=8, code=0, id=1234, seq=seq_base + i)
                / Raw(load=chunk_data.encode())
            )
            yield packet

    def _generate_ping_with_timestamp(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ICMP timestamp request (less common, potential covert channel)."""
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / ICMP(type=13, code=0)  # Timestamp request
            / Raw(load=b"\x00" * 12)  # Originate, Receive, Transmit timestamps
        )
        yield packet

    def _generate_address_mask(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ICMP address mask request (unusual, stealth detection)."""
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / ICMP(type=17, code=0)  # Address mask request
            / Raw(load=b"\x00\x00\x00\x00")  # Mask placeholder
        )
        yield packet

    def _generate_hex_encoded_payload(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ICMP with hex-encoded data in payload."""
        fake_data = "password=secret123&user=admin"
        hex_encoded = fake_data.encode().hex()

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / ICMP(type=8, code=0, id=random.randint(0, 65535), seq=random.randint(0, 65535))
            / Raw(load=hex_encoded.encode())
        )
        yield packet

    def _generate_rapid_pings(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate rapid ICMP sequence (high-frequency exfil indicator)."""
        icmp_id = random.randint(1000, 9999)

        # Multiple rapid pings with sequential data
        for i in range(10):
            payload = f"SEQ:{i:05d}:DATA:{random.randint(0, 99999):05d}"

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / ICMP(type=8, code=0, id=icmp_id, seq=i)
                / Raw(load=payload.encode())
            )
            yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate ICMP covert channel packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port (ignored for ICMP)

        Yields:
            Scapy packets with ICMP covert channel patterns
        """
        self._icmp_count += 1

        # Rotate through different ICMP covert patterns
        pattern = self._icmp_count % 7

        if pattern == 0:
            yield from self._generate_data_in_payload(src_ip, dst_ip)
        elif pattern == 1:
            yield from self._generate_oversized_ping(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_icmp_tunnel(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_ping_with_timestamp(src_ip, dst_ip)
        elif pattern == 4:
            yield from self._generate_address_mask(src_ip, dst_ip)
        elif pattern == 5:
            yield from self._generate_hex_encoded_payload(src_ip, dst_ip)
        else:
            yield from self._generate_rapid_pings(src_ip, dst_ip)

