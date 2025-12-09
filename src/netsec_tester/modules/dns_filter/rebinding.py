"""DNS rebinding attack traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# DNS rebinding attack domains
REBINDING_DOMAINS = [
    "rebind.attacker.com",
    "switch.malicious.net",
    "dual.evil.org",
    "flip.badactor.io",
]

# Internal IP ranges that rebinding targets
INTERNAL_IPS = [
    "127.0.0.1",
    "192.168.1.1",
    "192.168.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "169.254.169.254",  # AWS metadata
]


class DNSRebindingModule(TrafficModule):
    """Traffic module for DNS rebinding attack patterns.

    Generates DNS queries that simulate DNS rebinding attacks
    attempting to access internal resources.
    """

    def __init__(self) -> None:
        """Initialize the DNS rebinding module."""
        self._query_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dns_rebinding",
            description="DNS rebinding attacks (short TTL, IP switching patterns)",
            category=TrafficCategory.DNS_FILTER,
            protocols=["UDP"],
            ports=[53],
        )

    def _generate_short_ttl_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate queries indicating short TTL pattern."""
        # Multiple rapid queries for the same domain
        # (indicates TTL exhaustion and re-resolution)
        domain = random.choice(REBINDING_DOMAINS)

        for _ in range(3):
            qname = f"target.{domain}"

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=53)
                / DNS(
                    rd=1,
                    qd=DNSQR(qname=qname, qtype="A"),
                )
            )
            yield packet

    def _generate_subdomain_rebind(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate subdomain-based rebinding queries."""
        # Subdomain encodes the internal IP to switch to
        domain = random.choice(REBINDING_DOMAINS)
        target_ip = random.choice(INTERNAL_IPS)

        # Encode IP in subdomain (common rebinding pattern)
        ip_encoded = target_ip.replace(".", "-")
        qname = f"{ip_encoded}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_service_rebind(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate service-specific rebinding queries."""
        domain = random.choice(REBINDING_DOMAINS)

        # Target common internal services
        services = [
            "router.admin",
            "nas.local",
            "printer.internal",
            "camera.home",
            "metadata.aws",
            "consul.service",
            "kubernetes.default",
        ]

        service = random.choice(services)
        qname = f"{service}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_singularity_pattern(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate DNS rebinding pattern like Singularity tool."""
        # Singularity-style rebinding domain format
        domain = random.choice(REBINDING_DOMAINS)
        target_ip = random.choice(INTERNAL_IPS)
        target_port = random.choice([80, 443, 8080, 3000, 8000])

        # Format: <ip>-<port>.rebind.domain
        ip_encoded = target_ip.replace(".", "-")
        qname = f"{ip_encoded}-{target_port}.s.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_timebound_rebind(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate time-based rebinding queries."""
        domain = random.choice(REBINDING_DOMAINS)
        target_ip = random.choice(INTERNAL_IPS)

        # Include timestamp-like value (triggers on specific timing)
        timestamp = random.randint(1000000, 9999999)
        ip_encoded = target_ip.replace(".", "-")
        qname = f"t{timestamp}.{ip_encoded}.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="A"),
            )
        )
        yield packet

    def _generate_aaaa_rebind(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate IPv6 rebinding queries."""
        domain = random.choice(REBINDING_DOMAINS)

        # Query for AAAA record (IPv6 rebinding)
        qname = f"ipv6.{domain}"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(
                rd=1,
                qd=DNSQR(qname=qname, qtype="AAAA"),
            )
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate DNS rebinding attack packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address (DNS server)
            dst_port: Destination port (ignored, always 53)

        Yields:
            Scapy packets with DNS rebinding patterns
        """
        self._query_count += 1

        # Rotate through different rebinding patterns
        pattern = self._query_count % 6

        if pattern == 0:
            yield from self._generate_short_ttl_query(src_ip, dst_ip)
        elif pattern == 1:
            yield from self._generate_subdomain_rebind(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_service_rebind(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_singularity_pattern(src_ip, dst_ip)
        elif pattern == 4:
            yield from self._generate_timebound_rebind(src_ip, dst_ip)
        else:
            yield from self._generate_aaaa_rebind(src_ip, dst_ip)

