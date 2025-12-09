"""Fast-flux DNS detection traffic module."""

import random
import string
from typing import Iterator

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Fast-flux botnet domain patterns
FAST_FLUX_DOMAINS = [
    "flux.botnet.com",
    "fast.malware.net",
    "rotate.evil.org",
    "dynamic.c2.io",
]


class FastFluxModule(TrafficModule):
    """Traffic module for fast-flux DNS patterns.

    Generates DNS queries that simulate fast-flux botnet
    domain resolution patterns.
    """

    def __init__(self) -> None:
        """Initialize the fast-flux module."""
        self._query_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="fast_flux",
            description="Fast-flux botnet detection (rapid IP changes, multiple NS records)",
            category=TrafficCategory.DNS_FILTER,
            protocols=["UDP"],
            ports=[53],
        )

    def _generate_rapid_resolution(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate rapid repeated DNS queries (flux detection pattern)."""
        domain = random.choice(FAST_FLUX_DOMAINS)

        # Multiple rapid queries - characteristic of fast-flux checking
        for i in range(5):
            qname = f"node{i}.{domain}"

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(
                    rd=1,
                    qd=DNSQR(qname=qname, qtype="A"),
                )
            )
            yield packet

    def _generate_ns_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate NS record queries (multiple NS = flux indicator)."""
        domain = random.choice(FAST_FLUX_DOMAINS)

        # Query for NS records
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="NS"),
            )
        )
        yield packet

    def _generate_geographic_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate queries suggesting geographically distributed flux."""
        domain = random.choice(FAST_FLUX_DOMAINS)

        # Geolocation-based subdomain (flux networks often use these)
        regions = ["us", "eu", "asia", "au", "sa"]
        region = random.choice(regions)

        qname = f"{region}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_double_flux(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate double-flux pattern (both A and NS rotate)."""
        domain = random.choice(FAST_FLUX_DOMAINS)
        node_id = ''.join(random.choices(string.ascii_lowercase, k=8))

        # Query A record
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=f"{node_id}.{domain}", qtype="A"),
            )
        )
        yield packet

        # Query NS record for same domain
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="NS"),
            )
        )
        yield packet

    def _generate_low_ttl_pattern(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate queries indicating low TTL (short-lived records)."""
        domain = random.choice(FAST_FLUX_DOMAINS)

        # Sequential node IDs suggest flux network enumeration
        for i in range(3):
            qname = f"bot{i:04d}.{domain}"

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(
                    rd=1,
                    qd=DNSQR(qname=qname, qtype="A"),
                )
            )
            yield packet

    def _generate_wildcard_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate wildcard subdomain queries (flux networks use these)."""
        domain = random.choice(FAST_FLUX_DOMAINS)

        # Random subdomain - flux networks often have wildcard DNS
        random_sub = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        qname = f"{random_sub}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_soa_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate SOA queries to check domain authority."""
        domain = random.choice(FAST_FLUX_DOMAINS)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype="SOA"),
            )
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate fast-flux detection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address (DNS server)
            dst_port: Destination port (ignored, always 53)

        Yields:
            Scapy packets with fast-flux patterns
        """
        self._query_count += 1

        # Rotate through different fast-flux patterns
        pattern = self._query_count % 7

        if pattern == 0:
            yield from self._generate_rapid_resolution(src_ip, dst_ip)
        elif pattern == 1:
            yield from self._generate_ns_query(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_geographic_query(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_double_flux(src_ip, dst_ip)
        elif pattern == 4:
            yield from self._generate_low_ttl_pattern(src_ip, dst_ip)
        elif pattern == 5:
            yield from self._generate_wildcard_query(src_ip, dst_ip)
        else:
            yield from self._generate_soa_query(src_ip, dst_ip)

