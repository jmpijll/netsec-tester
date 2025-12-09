"""EICAR test file module for antivirus testing."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# EICAR test string - industry standard AV test
# This is safe and only triggers AV detection, not actual malware
EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Various ways to transfer the EICAR string
TRANSFER_METHODS = [
    "direct",  # Direct in HTTP body
    "base64",  # Base64 encoded
    "chunked",  # Chunked transfer encoding
    "attachment",  # As file attachment
]


class EICARModule(TrafficModule):
    """Traffic module for EICAR antivirus test.

    Generates HTTP traffic containing the EICAR test string
    in various formats to test AV scanning capabilities.
    The EICAR string is an industry-standard test pattern
    that triggers AV detection without being actual malware.
    """

    def __init__(self) -> None:
        """Initialize the EICAR module."""
        self._transfer_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="eicar",
            description="EICAR antivirus test file transfers",
            category=TrafficCategory.ANTIVIRUS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 21],
        )

    def _generate_chunked_body(self, content: str) -> str:
        """Generate chunked transfer encoding body."""
        chunk_size = len(content)
        return f"{chunk_size:x}\r\n{content}\r\n0\r\n\r\n"

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate EICAR test packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy HTTP packets containing EICAR test string
        """
        port = dst_port or 80
        self._transfer_count += 1

        method = TRANSFER_METHODS[self._transfer_count % len(TRANSFER_METHODS)]

        if method == "direct":
            # Direct transfer as downloadable file
            body = EICAR_TEST_STRING
            http_response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Disposition: attachment; filename=\"eicar.com\"\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )

        elif method == "base64":
            # Base64 encoded in response
            import base64

            encoded = base64.b64encode(EICAR_TEST_STRING.encode()).decode()
            body = f'{{"file": "{encoded}"}}'
            http_response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )

        elif method == "chunked":
            # Chunked transfer encoding
            body = self._generate_chunked_body(EICAR_TEST_STRING)
            http_response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )

        else:  # attachment
            # Multipart form data (file upload simulation)
            boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="test.exe"\r\n'
                f"Content-Type: application/octet-stream\r\n"
                f"\r\n"
                f"{EICAR_TEST_STRING}\r\n"
                f"--{boundary}--\r\n"
            )
            http_response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
                f"{body}"
            )

        # Create packet as if it's a response (simulating download)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._transfer_count % 25000), dport=port, flags="PA")
            / Raw(load=http_response.encode())
        )

        yield packet

        # Also generate a request that would download an executable
        file_extensions = [".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".msi"]
        ext = random.choice(file_extensions)

        http_request = (
            f"GET /download/update{ext} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: application/octet-stream\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._transfer_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet

