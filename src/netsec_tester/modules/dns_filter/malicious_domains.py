"""Malicious domain pattern module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Patterns that mimic malicious domain characteristics
# These are synthetic domains designed to trigger detection, not real malware domains
MALICIOUS_DOMAIN_PATTERNS = [
    # Phishing-style domains (typosquatting patterns)
    "g00gle.com",
    "micros0ft.com",
    "paypa1.com",
    "amaz0n.com",
    "faceb00k.com",
    "app1e.com",
    "netf1ix.com",
    "1inkedin.com",
    "twltter.com",
    "instaqram.com",

    # Homograph-style (using similar looking characters)
    "googIe.com",  # capital I instead of l
    "rnicrosoft.com",  # rn instead of m
    "paypaI.com",
    "arnazon.com",

    # Subdomain abuse patterns
    "login.secure.account.verify.example.com",
    "microsoft.com.verify.example.net",
    "paypal.com.secure.example.org",
    "signin.google.com.example.info",

    # Suspicious TLDs often used in malware
    "malware-test.tk",
    "phishing-test.pw",
    "suspicious-domain.cc",
    "bad-actor.top",
    "malicious-test.xyz",

    # Long suspicious domains
    "secure-login-verification-account-update.com",
    "microsoft-security-alert-warning-action.net",
    "paypal-account-verification-required-now.org",

    # Known malware domain patterns (sanitized/test versions)
    "evil-test-domain.com",
    "malware-c2-test.net",
    "botnet-test-server.org",
    "ransomware-test-domain.info",

    # Fast-flux style (many subdomains)
    "a1b2c3.flux.example.com",
    "x9y8z7.dynamic.example.net",
    "node123.fast.example.org",

    # Punycode/IDN suspicious patterns
    "xn--googl-gra.com",  # IDN encoded
    "xn--pypal-4ve.com",

    # Cryptocurrency scam patterns
    "bitcoin-giveaway-test.com",
    "eth-airdrop-test.net",
    "crypto-wallet-verify-test.org",

    # Tech support scam patterns
    "microsoft-support-alert-test.com",
    "windows-virus-warning-test.net",
    "apple-security-alert-test.org",
]

# Categories for domain filtering tests
CATEGORY_DOMAINS = {
    "malware": [
        "malware-distribution-test.com",
        "virus-download-test.net",
        "trojan-test-server.org",
    ],
    "phishing": [
        "credential-harvest-test.com",
        "fake-login-page-test.net",
        "phishing-simulation-test.org",
    ],
    "botnet": [
        "botnet-c2-test.com",
        "zombie-network-test.net",
        "ddos-test-controller.org",
    ],
    "spam": [
        "spam-sender-test.com",
        "bulk-email-test.net",
        "unsolicited-mail-test.org",
    ],
}


class MaliciousDomainsModule(TrafficModule):
    """Traffic module for malicious domain patterns.

    Generates DNS queries for domains that match patterns
    commonly associated with malware, phishing, and other threats.
    """

    def __init__(self) -> None:
        """Initialize the malicious domains module."""
        self._query_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="malicious_domains",
            description="Malicious domain patterns (phishing, malware, C2)",
            category=TrafficCategory.DNS,
            protocols=["UDP", "DNS"],
            ports=[53],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate malicious domain query packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port (default 53)

        Yields:
            Scapy DNS packets querying malicious-pattern domains
        """
        port = dst_port or 53
        self._query_count += 1

        # Select domain pattern
        pattern_type = self._query_count % 3

        if pattern_type == 0:
            # Use predefined malicious patterns
            domain = MALICIOUS_DOMAIN_PATTERNS[
                self._query_count % len(MALICIOUS_DOMAIN_PATTERNS)
            ]
        elif pattern_type == 1:
            # Use category-based domains
            category = random.choice(list(CATEGORY_DOMAINS.keys()))
            domain = random.choice(CATEGORY_DOMAINS[category])
        else:
            # Generate dynamic suspicious domain
            suspicious_words = ["secure", "verify", "login", "account", "update", "alert"]
            brand_words = ["microsoft", "google", "paypal", "amazon", "apple"]
            tlds = [".com", ".net", ".org", ".info", ".xyz"]

            domain = (
                random.choice(brand_words)
                + "-"
                + random.choice(suspicious_words)
                + "-"
                + str(random.randint(1, 999))
                + random.choice(tlds)
            )

        # Create DNS A record query
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

        # Also query for MX and TXT records (common in malware recon)
        for qtype in [15, 16]:  # MX, TXT
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / UDP(sport=random.randint(49152, 65535), dport=port)
                / DNS(
                    id=random.randint(0, 65535),
                    rd=1,
                    qd=DNSQR(qname=domain, qtype=qtype),
                )
            )
            yield packet

