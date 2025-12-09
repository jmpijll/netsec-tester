"""DoS/DDoS attack pattern traffic module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class DoSPatternsModule(TrafficModule):
    """Traffic module for DoS/DDoS attack patterns.

    Generates traffic that mimics various denial-of-service attacks
    to trigger IPS/IDS detection signatures.
    """

    def __init__(self) -> None:
        """Initialize the DoS patterns module."""
        self._attack_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dos_patterns",
            description="DoS/DDoS attack patterns (SYN flood, slowloris, amplification)",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "UDP", "ICMP"],
            ports=[80, 443, 53, 123],
        )

    def _generate_syn_flood(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate SYN flood attack packets."""
        # Multiple SYN packets with random source ports
        for _ in range(5):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=random.randint(1024, 65535),
                    dport=port,
                    flags="S",
                    seq=random.randint(0, 4294967295),
                    window=64240,
                )
            )
            yield packet

    def _generate_udp_flood(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate UDP flood attack packets."""
        ports = [53, 80, 443, 123, 161]
        for _ in range(3):
            port = random.choice(ports)
            # Random payload to vary packet size
            payload = bytes(random.randint(64, 512))
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(1024, 65535), dport=port)
                / Raw(load=payload)
            )
            yield packet

    def _generate_icmp_flood(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ICMP flood / Ping flood packets."""
        for _ in range(3):
            # Large ICMP echo request
            payload = b"X" * random.randint(64, 1024)
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / ICMP(type=8, code=0, id=random.randint(0, 65535))
                / Raw(load=payload)
            )
            yield packet

    def _generate_smurf_pattern(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate Smurf attack pattern (ICMP to broadcast)."""
        # ICMP echo to broadcast address pattern
        # Using .255 as broadcast indicator
        broadcast_ip = ".".join(dst_ip.split(".")[:3]) + ".255"
        packet = (
            IP(src=src_ip, dst=broadcast_ip)
            / ICMP(type=8, code=0)
            / Raw(load=b"X" * 64)
        )
        yield packet

    def _generate_slowloris(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Slowloris attack patterns."""
        # Incomplete HTTP headers - keeps connection open
        incomplete_headers = [
            "GET / HTTP/1.1\r\n",
            "Host: target\r\n",
            "User-Agent: Mozilla/5.0\r\n",
            "Accept: */*\r\n",
            "X-Custom-Header-1: value\r\n",
            "X-Custom-Header-2: value\r\n",
            # Note: No final \r\n to keep connection open
        ]

        for header in incomplete_headers[:3]:
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
                / Raw(load=header.encode())
            )
            yield packet

    def _generate_slow_post(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Slow POST attack patterns."""
        # HTTP POST with very large Content-Length but slow data
        http_request = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 1000000\r\n"  # Claims huge body
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"a=1"  # Sends only tiny amount
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_http_flood(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate HTTP flood attack patterns."""
        # Multiple rapid HTTP requests
        paths = ["/", "/index.html", "/api/v1/data", "/search?q=test", "/login"]

        for path in paths[:3]:
            http_request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {dst_ip}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
                / Raw(load=http_request.encode())
            )
            yield packet

    def _generate_dns_amplification(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate DNS amplification attack patterns."""
        # ANY query to open resolver - generates large response
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname="example.com", qtype="ANY"),  # ANY query
            )
        )
        yield packet

        # TXT record query for amplification
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname="google.com", qtype="TXT"),
            )
        )
        yield packet

    def _generate_ntp_amplification(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate NTP amplification attack patterns."""
        # NTP monlist command (CVE-2013-5211)
        ntp_monlist = bytes([0x17, 0x00, 0x03, 0x2a]) + b"\x00" * 4
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=123)
            / Raw(load=ntp_monlist)
        )
        yield packet

    def _generate_ssdp_amplification(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate SSDP amplification attack patterns."""
        # SSDP M-SEARCH request
        ssdp_request = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            'MAN: "ssdp:discover"\r\n'
            "MX: 2\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        )
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=1900)
            / Raw(load=ssdp_request.encode())
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate DoS/DDoS pattern packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with DoS attack patterns
        """
        port = dst_port or 80
        self._attack_count += 1

        # Rotate through different attack types
        attack_type = self._attack_count % 10

        if attack_type == 0:
            yield from self._generate_syn_flood(src_ip, dst_ip, port)
        elif attack_type == 1:
            yield from self._generate_udp_flood(src_ip, dst_ip)
        elif attack_type == 2:
            yield from self._generate_icmp_flood(src_ip, dst_ip)
        elif attack_type == 3:
            yield from self._generate_smurf_pattern(src_ip, dst_ip)
        elif attack_type == 4:
            yield from self._generate_slowloris(src_ip, dst_ip, port)
        elif attack_type == 5:
            yield from self._generate_slow_post(src_ip, dst_ip, port)
        elif attack_type == 6:
            yield from self._generate_http_flood(src_ip, dst_ip, port)
        elif attack_type == 7:
            yield from self._generate_dns_amplification(src_ip, dst_ip)
        elif attack_type == 8:
            yield from self._generate_ntp_amplification(src_ip, dst_ip)
        else:
            yield from self._generate_ssdp_amplification(src_ip, dst_ip)

