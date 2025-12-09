"""Suspicious URL pattern test module."""

import random
from typing import Iterator
import urllib.parse

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Suspicious URL patterns that may trigger web filtering
SUSPICIOUS_URL_PATTERNS = [
    # Executable downloads
    "/download/setup.exe",
    "/files/installer.msi",
    "/update/patch.exe",
    "/driver/update.exe",
    "/software/crack.exe",

    # Script downloads
    "/scripts/payload.ps1",
    "/tools/script.vbs",
    "/batch/autorun.bat",
    "/macro/document.docm",

    # Archive with suspicious names
    "/files/invoice_pdf.zip",
    "/download/document.rar",
    "/attachment/urgent.7z",
    "/files/password_protected.zip",

    # Paths with suspicious keywords
    "/admin/config.php",
    "/wp-admin/admin-ajax.php",
    "/cgi-bin/shell.cgi",
    "/.git/config",
    "/.env",
    "/backup/database.sql",

    # URL shortener patterns
    "/r/abc123",
    "/go/xyz789",
    "/l/shortlink",

    # Redirect chains
    "/redirect?url=http://evil.com",
    "/redir?to=http://malware.com/payload",
    "/out?link=http://phishing.com",

    # Encoded suspicious content
    "/page?q=%3Cscript%3E",
    "/search?term=%27%20OR%20%271",
    "/api?cmd=..%2F..%2Fetc%2Fpasswd",

    # Cryptocurrency-related suspicious paths
    "/wallet/connect",
    "/eth/claim",
    "/btc/giveaway",
    "/airdrop/register",

    # Tech support scam patterns
    "/support/virus-detected",
    "/alert/security-warning",
    "/microsoft/activate",

    # Suspicious file paths
    "/tmp/shell.php",
    "/uploads/backdoor.php",
    "/images/../../etc/passwd",
    "/static/webshell.jsp",
]

# Suspicious query parameters
SUSPICIOUS_PARAMS = [
    ("cmd", "whoami"),
    ("exec", "cat /etc/passwd"),
    ("file", "../../../etc/shadow"),
    ("url", "http://evil.com/malware.exe"),
    ("redirect", "http://phishing.com"),
    ("callback", "javascript:alert(1)"),
    ("template", "{{constructor.constructor('alert(1)')()}}"),
    ("data", "base64encodedpayload"),
]


class URLPatternsModule(TrafficModule):
    """Traffic module for suspicious URL pattern tests.

    Generates HTTP requests with URL patterns commonly
    associated with malicious activity.
    """

    def __init__(self) -> None:
        """Initialize the URL patterns module."""
        self._request_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="url_patterns",
            description="Suspicious URL patterns for web filtering",
            category=TrafficCategory.WEB,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 8080],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate suspicious URL pattern packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy HTTP packets with suspicious URLs
        """
        port = dst_port or 80
        self._request_count += 1

        # Select pattern type
        pattern_type = self._request_count % 3

        if pattern_type == 0:
            # Use predefined suspicious path
            path = SUSPICIOUS_URL_PATTERNS[
                self._request_count % len(SUSPICIOUS_URL_PATTERNS)
            ]
        elif pattern_type == 1:
            # Add suspicious query parameters to normal path
            param_name, param_value = random.choice(SUSPICIOUS_PARAMS)
            encoded_value = urllib.parse.quote(param_value)
            path = f"/api/endpoint?{param_name}={encoded_value}"
        else:
            # Generate dynamic suspicious URL
            suspicious_files = ["shell.php", "backdoor.jsp", "cmd.asp", "eval.cgi"]
            suspicious_dirs = ["/admin", "/uploads", "/tmp", "/cgi-bin", "/.hidden"]
            path = random.choice(suspicious_dirs) + "/" + random.choice(suspicious_files)

        # Create HTTP GET request
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet

        # Generate POST request with suspicious content
        if self._request_count % 2 == 0:
            post_data = random.choice(
                [
                    "action=download&file=../../etc/passwd",
                    "cmd=system&arg=id",
                    "page=<script>alert(1)</script>",
                    "upload=shell.php&content=<?php system($_GET['c']); ?>",
                ]
            )

            post_request = (
                f"POST /api/action HTTP/1.1\r\n"
                f"Host: {dst_ip}\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(post_data)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{post_data}"
            )

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
                / Raw(load=post_request.encode())
            )

            yield packet

