"""Domain Generation Algorithm (DGA) pattern module."""

import hashlib
import random
import string
from datetime import datetime
from typing import Iterator

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Top-level domains commonly used by DGAs
DGA_TLDS = [
    ".com", ".net", ".org", ".info", ".biz",
    ".ru", ".cn", ".tk", ".pw", ".cc",
    ".top", ".xyz", ".club", ".online", ".site",
]


class DGAModule(TrafficModule):
    """Traffic module for Domain Generation Algorithm patterns.

    Generates DNS queries that mimic various DGA families
    to trigger DGA detection mechanisms.
    """

    def __init__(self) -> None:
        """Initialize the DGA module."""
        self._query_count = 0
        self._seed = random.randint(0, 1000000)

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dga",
            description="Domain Generation Algorithm patterns for DNS filtering",
            category=TrafficCategory.DNS_FILTER,
            protocols=["UDP", "DNS"],
            ports=[53],
        )

    def _generate_random_dga(self, length: int = 12) -> str:
        """Generate a random-looking DGA domain."""
        chars = string.ascii_lowercase
        domain = "".join(random.choices(chars, k=length))
        tld = random.choice(DGA_TLDS)
        return domain + tld

    def _generate_conficker_style(self) -> str:
        """Generate Conficker-style DGA domain."""
        # Conficker uses date-based seeding
        today = datetime.now()
        seed = today.year * 10000 + today.month * 100 + today.day + self._query_count
        random.seed(seed)

        length = random.randint(8, 11)
        domain = "".join(random.choices(string.ascii_lowercase, k=length))
        tld = random.choice([".com", ".net", ".org", ".info", ".biz"])

        # Reset random seed
        random.seed()
        return domain + tld

    def _generate_cryptolocker_style(self) -> str:
        """Generate CryptoLocker-style DGA domain."""
        # Uses hash-based generation
        seed_str = f"{datetime.now().strftime('%Y%m%d')}{self._query_count}"
        hash_val = hashlib.md5(seed_str.encode()).hexdigest()

        # Take characters from hash
        domain = ""
        for i in range(0, 16, 2):
            char_code = int(hash_val[i : i + 2], 16) % 26
            domain += chr(ord("a") + char_code)

        tld = random.choice([".com", ".net", ".org", ".ru"])
        return domain + tld

    def _generate_necurs_style(self) -> str:
        """Generate Necurs-style DGA domain."""
        # Necurs uses longer, more random-looking domains
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"

        # Alternating consonant-vowel pattern with variations
        length = random.randint(12, 20)
        domain = ""
        for i in range(length):
            if i % 3 == 0:
                domain += random.choice(consonants)
            else:
                domain += random.choice(vowels if random.random() > 0.3 else consonants)

        tld = random.choice(DGA_TLDS)
        return domain + tld

    def _generate_qakbot_style(self) -> str:
        """Generate Qakbot-style DGA domain."""
        # Qakbot uses alphanumeric domains
        chars = string.ascii_lowercase + string.digits
        length = random.randint(8, 15)
        domain = "".join(random.choices(chars, k=length))
        tld = random.choice([".com", ".net", ".org", ".biz"])
        return domain + tld

    def _generate_suppobox_style(self) -> str:
        """Generate Suppobox-style DGA domain with dictionary words."""
        # Some DGAs combine dictionary words
        words = [
            "cloud", "data", "web", "net", "soft", "tech", "info",
            "host", "server", "system", "online", "digital", "smart",
            "fast", "secure", "safe", "global", "world", "best",
        ]
        domain = random.choice(words) + random.choice(words)
        if random.random() > 0.5:
            domain += str(random.randint(1, 99))
        tld = random.choice([".com", ".net", ".org"])
        return domain + tld

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate DGA domain query packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port (default 53)

        Yields:
            Scapy DNS packets with DGA domains
        """
        port = dst_port or 53
        self._query_count += 1

        # Rotate through different DGA styles
        dga_type = self._query_count % 6

        if dga_type == 0:
            domain = self._generate_random_dga()
        elif dga_type == 1:
            domain = self._generate_conficker_style()
        elif dga_type == 2:
            domain = self._generate_cryptolocker_style()
        elif dga_type == 3:
            domain = self._generate_necurs_style()
        elif dga_type == 4:
            domain = self._generate_qakbot_style()
        else:
            domain = self._generate_suppobox_style()

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=port)
            / DNS(
                id=random.randint(0, 65535),
                rd=1,
                qd=DNSQR(qname=domain, qtype=1),  # A record
            )
        )

        yield packet

        # DGA malware typically queries multiple domains rapidly
        # Generate a few more DGA domains
        for _ in range(2):
            domain = self._generate_random_dga(random.randint(8, 16))
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=port)
                / DNS(
                    id=random.randint(0, 65535),
                    rd=1,
                    qd=DNSQR(qname=domain, qtype=1),
                )
            )
            yield packet

