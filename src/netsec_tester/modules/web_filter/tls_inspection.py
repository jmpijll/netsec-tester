"""TLS inspection and SNI filtering traffic module."""

import random
import struct
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Categories of domains for SNI-based filtering
BLOCKED_SNI_DOMAINS = {
    "adult": [
        "adult-content.com",
        "xxx-site.net",
        "explicit.org",
    ],
    "gambling": [
        "online-casino.com",
        "bet365.com",
        "pokerstars.net",
    ],
    "malware": [
        "malware-download.com",
        "virus-host.net",
        "trojan-server.org",
    ],
    "phishing": [
        "paypa1-login.com",
        "amaz0n-secure.net",
        "g00gle-verify.org",
    ],
    "proxy": [
        "free-vpn-proxy.com",
        "hide-my-ip.net",
        "anonymous-surf.org",
    ],
}

# JA3 fingerprint patterns (simplified - these are hash components)
# Real JA3 is MD5 of: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
JA3_SUSPICIOUS_PATTERNS = [
    # Tor browser pattern indicators
    {"version": 0x0303, "ciphers": [0xc02c, 0xc02b, 0x009f, 0x009e]},
    # Malware-like patterns (limited cipher suites)
    {"version": 0x0301, "ciphers": [0x002f, 0x0035]},
    # Old/vulnerable patterns
    {"version": 0x0300, "ciphers": [0x000a, 0x0009]},
]


class TLSInspectionModule(TrafficModule):
    """Traffic module for TLS inspection patterns.

    Generates TLS Client Hello packets with various SNI values
    and fingerprints for testing SSL/TLS inspection.
    """

    def __init__(self) -> None:
        """Initialize the TLS inspection module."""
        self._hello_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="tls_inspection",
            description="TLS/SNI inspection (blocked categories, JA3 fingerprints)",
            category=TrafficCategory.WEB_FILTER,
            protocols=["TCP"],
            ports=[443, 8443, 993, 995, 465],
        )

    def _build_client_hello(self, sni: str, ja3_pattern: dict | None = None) -> bytes:
        """Build a TLS Client Hello packet with SNI."""
        # Use default pattern if not specified
        if ja3_pattern is None:
            ja3_pattern = {"version": 0x0303, "ciphers": [0xc02f, 0xc030, 0x009e, 0x009f]}

        # SNI extension
        sni_bytes = sni.encode()
        sni_ext = (
            struct.pack(">HH", 0x0000, len(sni_bytes) + 5)  # Extension type 0 (SNI)
            + struct.pack(">H", len(sni_bytes) + 3)  # SNI list length
            + struct.pack("B", 0x00)  # Host name type
            + struct.pack(">H", len(sni_bytes))  # Host name length
            + sni_bytes
        )

        # Cipher suites
        ciphers = ja3_pattern["ciphers"]
        cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)
        cipher_section = struct.pack(">H", len(cipher_bytes)) + cipher_bytes

        # Compression methods (null only)
        compression = b"\x01\x00"

        # Extensions (SNI + some others)
        extensions = sni_ext
        # Add supported versions extension
        extensions += struct.pack(">HHB", 0x002b, 3, 2) + struct.pack(">H", 0x0303)

        extensions_section = struct.pack(">H", len(extensions)) + extensions

        # Client Hello
        client_hello = (
            struct.pack(">H", ja3_pattern["version"])  # Client version
            + bytes(32)  # Random
            + b"\x00"  # Session ID length
            + cipher_section
            + compression
            + extensions_section
        )

        # Handshake header
        handshake = (
            struct.pack("B", 0x01)  # Client Hello type
            + struct.pack(">I", len(client_hello))[1:]  # 3-byte length
            + client_hello
        )

        # TLS record
        record = (
            struct.pack("B", 0x16)  # Handshake record
            + struct.pack(">H", 0x0301)  # Legacy version
            + struct.pack(">H", len(handshake))
            + handshake
        )

        return record

    def _generate_blocked_sni(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TLS Client Hello with blocked category SNI."""
        category = random.choice(list(BLOCKED_SNI_DOMAINS.keys()))
        sni = random.choice(BLOCKED_SNI_DOMAINS[category])

        client_hello = self._build_client_hello(sni)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=client_hello)
        )
        yield packet

    def _generate_suspicious_ja3(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TLS Client Hello with suspicious JA3 fingerprint."""
        ja3_pattern = random.choice(JA3_SUSPICIOUS_PATTERNS)
        sni = "legitimate-looking.com"

        client_hello = self._build_client_hello(sni, ja3_pattern)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=client_hello)
        )
        yield packet

    def _generate_cert_anomaly(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TLS handshake suggesting certificate anomalies."""
        # SNI mismatch indicator (different port than expected)
        sni = "www.google.com"  # Legit SNI to non-Google IP

        client_hello = self._build_client_hello(sni)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=client_hello)
        )
        yield packet

    def _generate_tls_downgrade(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate TLS downgrade attack patterns."""
        # Old TLS/SSL versions
        old_versions = [
            {"version": 0x0300, "ciphers": [0x000a, 0x002f]},  # SSL 3.0
            {"version": 0x0301, "ciphers": [0x002f, 0x0035]},  # TLS 1.0
        ]

        ja3_pattern = random.choice(old_versions)
        sni = "secure-bank.com"

        client_hello = self._build_client_hello(sni, ja3_pattern)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=client_hello)
        )
        yield packet

    def _generate_esni_pattern(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Encrypted SNI / ECH patterns."""
        # ESNI/ECH extension indicator
        sni = ""  # Empty SNI with ESNI extension

        # Build custom Client Hello with ESNI extension
        client_hello_data = (
            struct.pack(">H", 0x0303)  # Version
            + bytes(32)  # Random
            + b"\x00"  # Session ID length
            + struct.pack(">H", 4) + struct.pack(">HH", 0xc02f, 0xc030)  # Ciphers
            + b"\x01\x00"  # Compression
        )

        # ESNI extension (0xffce) or ECH (0xfe0d)
        esni_ext = struct.pack(">HH", 0xffce, 32) + bytes(32)  # Fake ESNI data

        extensions = esni_ext
        client_hello_data += struct.pack(">H", len(extensions)) + extensions

        # Handshake header
        handshake = (
            struct.pack("B", 0x01)
            + struct.pack(">I", len(client_hello_data))[1:]
            + client_hello_data
        )

        # TLS record
        record = (
            struct.pack("B", 0x16)
            + struct.pack(">H", 0x0301)
            + struct.pack(">H", len(handshake))
            + handshake
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=record)
        )
        yield packet

    def _generate_self_signed_indicator(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate pattern to self-signed certificate domains."""
        # Domains commonly using self-signed certs
        self_signed_domains = [
            "192-168-1-1.local",
            "localhost.localdomain",
            "internal.corp.local",
            "dev.test.local",
        ]

        sni = random.choice(self_signed_domains)
        client_hello = self._build_client_hello(sni)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=client_hello)
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate TLS inspection test packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with TLS patterns
        """
        port = dst_port or 443
        self._hello_count += 1

        # Rotate through different TLS patterns
        pattern = self._hello_count % 6

        if pattern == 0:
            yield from self._generate_blocked_sni(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_suspicious_ja3(src_ip, dst_ip, port)
        elif pattern == 2:
            yield from self._generate_cert_anomaly(src_ip, dst_ip, port)
        elif pattern == 3:
            yield from self._generate_tls_downgrade(src_ip, dst_ip, port)
        elif pattern == 4:
            yield from self._generate_esni_pattern(src_ip, dst_ip, port)
        else:
            yield from self._generate_self_signed_indicator(src_ip, dst_ip, port)

