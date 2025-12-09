"""Benign web browsing traffic module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Common legitimate websites and paths
LEGITIMATE_SITES = [
    ("www.example.com", "/"),
    ("www.example.org", "/about"),
    ("www.example.net", "/contact"),
    ("news.example.com", "/articles"),
    ("blog.example.com", "/posts"),
    ("shop.example.com", "/products"),
    ("docs.example.com", "/api"),
    ("support.example.com", "/help"),
]

# Realistic User-Agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

# Common Accept headers
ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
]


class WebBrowsingModule(TrafficModule):
    """Traffic module for normal web browsing patterns.

    Generates realistic HTTP traffic that mimics normal
    user browsing behavior.
    """

    def __init__(self) -> None:
        """Initialize the web browsing module."""
        self._request_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="web_browsing",
            description="Normal web browsing traffic patterns",
            category=TrafficCategory.BENIGN,
            protocols=["TCP", "HTTP"],
            ports=[80, 443],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate benign web browsing packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets mimicking normal web browsing
        """
        port = dst_port or 80
        self._request_count += 1

        # Select site
        host, path = random.choice(LEGITIMATE_SITES)
        user_agent = random.choice(USER_AGENTS)
        accept = random.choice(ACCEPT_HEADERS)

        # Main page request
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: {accept}\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Connection: keep-alive\r\n"
            f"Upgrade-Insecure-Requests: 1\r\n"
            f"Cache-Control: max-age=0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet

        # CSS request
        css_request = (
            f"GET /static/css/style.css HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: text/css,*/*;q=0.1\r\n"
            f"Referer: https://{host}{path}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=css_request.encode())
        )

        yield packet

        # JavaScript request
        js_request = (
            f"GET /static/js/app.js HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: */*\r\n"
            f"Referer: https://{host}{path}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=js_request.encode())
        )

        yield packet

        # Image request
        img_request = (
            f"GET /images/logo.png HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: image/avif,image/webp,image/apng,image/*,*/*;q=0.8\r\n"
            f"Referer: https://{host}{path}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=img_request.encode())
        )

        yield packet

