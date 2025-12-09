"""Archive-based evasion detection traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Suspicious archive extensions
ARCHIVE_EXTENSIONS = [
    ".zip",
    ".rar",
    ".7z",
    ".tar.gz",
    ".tar",
    ".gz",
    ".cab",
    ".iso",
    ".img",
    ".arj",
    ".ace",
]

# Password-protected archive indicators
PASSWORD_INDICATORS = [
    "password=infected",
    "pass=malware",
    "pwd=virus",
    "key=sample",
]


class ArchiveEvasionModule(TrafficModule):
    """Traffic module for archive-based evasion detection.

    Generates HTTP traffic that simulates archive-based malware evasion
    techniques including nested archives, password protection, and polyglots.
    """

    def __init__(self) -> None:
        """Initialize the archive evasion module."""
        self._archive_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="archive_evasion",
            description="Archive evasion (nested archives, password protected, polyglot files)",
            category=TrafficCategory.ANTIVIRUS,
            protocols=["TCP"],
            ports=[80, 443, 8080],
        )

    def _generate_nested_archive(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate nested archive download pattern."""
        # Deeply nested archive filename
        nesting_patterns = [
            "archive.zip.zip.zip",
            "file.tar.gz.tar.gz",
            "payload.rar.zip.7z",
            "document.zip.rar.zip",
        ]

        filename = random.choice(nesting_patterns)

        http_request = (
            f"GET /downloads/{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: application/zip,application/x-rar-compressed\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_password_archive(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate password-protected archive download pattern."""
        ext = random.choice(ARCHIVE_EXTENSIONS)
        password_hint = random.choice(PASSWORD_INDICATORS)

        # Archive with password in URL or filename
        patterns = [
            f"/malware{ext}?{password_hint}",
            f"/sample_infected{ext}",
            f"/protected{ext}?pwd=test",
        ]

        path = random.choice(patterns)

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

    def _generate_polyglot_file(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate polyglot file download pattern."""
        # Files that appear as multiple types
        polyglot_files = [
            "image.jpg.exe",
            "document.pdf.scr",
            "picture.png.bat",
            "file.gif.com",
            "photo.bmp.pif",
            "data.txt.vbs",
        ]

        filename = random.choice(polyglot_files)

        http_request = (
            f"GET /uploads/{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: image/*,application/*\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_archive_bomb_indicator(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate archive bomb (zip bomb) download pattern."""
        # Files known as zip bombs
        bomb_names = [
            "42.zip",
            "zbsm.zip",
            "bomb.zip",
            "recursive.zip",
            "quine.zip",
        ]

        filename = random.choice(bomb_names)

        http_request = (
            f"GET /{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: application/zip\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_iso_mount(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate ISO/IMG download pattern (used to bypass MOTW)."""
        # ISO/IMG files bypass Mark of the Web
        iso_files = [
            "software.iso",
            "installer.img",
            "update.iso",
            "document.iso",
        ]

        filename = random.choice(iso_files)

        http_request = (
            f"GET /download/{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: application/octet-stream\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_double_extension(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate double extension archive pattern."""
        # Double extensions to hide real type
        double_ext_files = [
            "invoice.pdf.zip",
            "photo.jpg.rar",
            "document.doc.7z",
            "report.xlsx.tar.gz",
        ]

        filename = random.choice(double_ext_files)

        http_request = (
            f"GET /attachments/{filename} HTTP/1.1\r\n"
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

    def _generate_rtlo_filename(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Right-to-Left Override filename pattern."""
        # RTLO character U+202E makes filename appear reversed
        # This simulates the URL-encoded version
        rtlo_files = [
            "document%E2%80%AEexe.pdf",
            "image%E2%80%AEexe.jpg",
            "file%E2%80%AEexe.txt",
        ]

        filename = random.choice(rtlo_files)

        http_request = (
            f"GET /files/{filename} HTTP/1.1\r\n"
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

    def _generate_encrypted_container(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate encrypted container download pattern."""
        # Encrypted container files
        container_files = [
            "data.tc",  # TrueCrypt
            "vault.hc",  # VeraCrypt
            "secrets.aes",
            "encrypted.gpg",
        ]

        filename = random.choice(container_files)

        http_request = (
            f"GET /secure/{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: application/octet-stream\r\n"
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
        """Generate archive evasion detection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with archive evasion patterns
        """
        port = dst_port or 80
        self._archive_count += 1

        # Rotate through different evasion techniques
        technique = self._archive_count % 8

        if technique == 0:
            yield from self._generate_nested_archive(src_ip, dst_ip, port)
        elif technique == 1:
            yield from self._generate_password_archive(src_ip, dst_ip, port)
        elif technique == 2:
            yield from self._generate_polyglot_file(src_ip, dst_ip, port)
        elif technique == 3:
            yield from self._generate_archive_bomb_indicator(src_ip, dst_ip, port)
        elif technique == 4:
            yield from self._generate_iso_mount(src_ip, dst_ip, port)
        elif technique == 5:
            yield from self._generate_double_extension(src_ip, dst_ip, port)
        elif technique == 6:
            yield from self._generate_rtlo_filename(src_ip, dst_ip, port)
        else:
            yield from self._generate_encrypted_container(src_ip, dst_ip, port)
