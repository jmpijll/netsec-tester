"""Web filtering category test module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Web filtering test URLs organized by category
# These are patterns/test domains, not real malicious sites
CATEGORY_TEST_URLS = {
    "adult": [
        ("adult-content-test.example.com", "/"),
        ("pornography-test.example.net", "/videos"),
        ("explicit-content-test.example.org", "/gallery"),
    ],
    "gambling": [
        ("online-casino-test.example.com", "/slots"),
        ("sports-betting-test.example.net", "/"),
        ("poker-room-test.example.org", "/tables"),
    ],
    "malware": [
        ("malware-host-test.example.com", "/download.exe"),
        ("virus-distribution-test.example.net", "/payload.bin"),
        ("exploit-kit-test.example.org", "/landing"),
    ],
    "phishing": [
        ("phishing-test.example.com", "/login"),
        ("credential-harvest-test.example.net", "/signin"),
        ("fake-bank-test.example.org", "/secure"),
    ],
    "proxy_anonymizer": [
        ("web-proxy-test.example.com", "/browse"),
        ("anonymizer-test.example.net", "/surf"),
        ("vpn-service-test.example.org", "/connect"),
    ],
    "hacking": [
        ("hacking-tools-test.example.com", "/exploits"),
        ("security-bypass-test.example.net", "/tools"),
        ("vulnerability-test.example.org", "/poc"),
    ],
    "weapons": [
        ("firearms-test.example.com", "/"),
        ("weapons-sales-test.example.net", "/shop"),
        ("ammunition-test.example.org", "/products"),
    ],
    "drugs": [
        ("drug-marketplace-test.example.com", "/"),
        ("pharmacy-illegal-test.example.net", "/pills"),
        ("controlled-substances-test.example.org", "/order"),
    ],
    "streaming_media": [
        ("video-streaming-test.example.com", "/watch"),
        ("music-streaming-test.example.net", "/listen"),
        ("live-stream-test.example.org", "/live"),
    ],
    "social_networking": [
        ("social-network-test.example.com", "/feed"),
        ("social-media-test.example.net", "/timeline"),
        ("community-test.example.org", "/posts"),
    ],
    "gaming": [
        ("online-games-test.example.com", "/play"),
        ("gaming-platform-test.example.net", "/"),
        ("game-downloads-test.example.org", "/games"),
    ],
    "file_sharing": [
        ("file-sharing-test.example.com", "/upload"),
        ("torrent-site-test.example.net", "/"),
        ("p2p-test.example.org", "/download"),
    ],
}

# User agents for different scenarios
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]


class WebCategoryModule(TrafficModule):
    """Traffic module for web filtering category tests.

    Generates HTTP requests to URLs in various categories
    to test web filtering policies.
    """

    def __init__(self) -> None:
        """Initialize the web category module."""
        self._request_count = 0
        self._categories = list(CATEGORY_TEST_URLS.keys())

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="web_categories",
            description="Web filtering category tests (adult, gambling, malware, etc.)",
            category=TrafficCategory.WEB_FILTER,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 8080],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate web category test packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy HTTP packets for category testing
        """
        port = dst_port or 80
        self._request_count += 1

        # Select category and URL
        category = self._categories[self._request_count % len(self._categories)]
        host, path = random.choice(CATEGORY_TEST_URLS[category])

        user_agent = random.choice(USER_AGENTS)

        # Create HTTP GET request
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Accept-Encoding: gzip, deflate\r\n"
            f"Connection: keep-alive\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet

        # Also generate HTTPS SNI indication (TLS ClientHello simulation)
        # This helps test SNI-based filtering
        # Note: This is a simplified representation
        if port == 443 or random.random() > 0.5:
            # Generate a request that includes the SNI in a header for detection
            https_request = (
                f"CONNECT {host}:443 HTTP/1.1\r\n"
                f"Host: {host}:443\r\n"
                f"User-Agent: {user_agent}\r\n"
                f"Proxy-Connection: keep-alive\r\n"
                f"\r\n"
            )

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
                / Raw(load=https_request.encode())
            )

            yield packet
