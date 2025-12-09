"""Ransomware indicator traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Known ransomware file extensions
RANSOMWARE_EXTENSIONS = [
    ".encrypted",
    ".locky",
    ".cerber",
    ".zepto",
    ".crypt",
    ".locked",
    ".crypted",
    ".enc",
    ".fucked",
    ".wannacry",
    ".wncry",
    ".wcry",
    ".wncryt",
    ".cryptolocker",
    ".cryptowall",
    ".crypz",
    ".crypto",
    ".aaa",
    ".abc",
    ".xyz",
    ".zzz",
    ".micro",
    ".ttt",
    ".xxx",
    ".vvv",
    ".ecc",
    ".ezz",
    ".exx",
    ".sage",
    ".osiris",
    ".odin",
    ".thor",
]

# Ransom note filenames
RANSOM_NOTES = [
    "HOW_TO_DECRYPT.txt",
    "DECRYPT_INSTRUCTIONS.html",
    "READ_ME_FOR_DECRYPT.txt",
    "YOUR_FILES_ARE_ENCRYPTED.txt",
    "HELP_DECRYPT.html",
    "_RECOVERY_+.txt",
    "_HELP_instructions.html",
    "DECRYPT_YOUR_FILES.html",
    "ATTENTION!!!.txt",
    "HOW_TO_RECOVER_FILES.txt",
    "RECOVER-FILES.txt",
    "!README!.txt",
    "@Please_Read_Me@.txt",
    "DECRYPT-FILES.txt",
    "_readme.txt",
]

# Ransomware C2 domain patterns
RANSOMWARE_DOMAINS = [
    "decrypt-service.onion",
    "pay-ransom.tor",
    "unlock-files.i2p",
    "recovery-payment.com",
    "decrypt-key-purchase.net",
]


class RansomwareModule(TrafficModule):
    """Traffic module for ransomware indicator patterns.

    Generates HTTP traffic that simulates ransomware network indicators
    including ransom note downloads, key exchange, and file extension patterns.
    """

    def __init__(self) -> None:
        """Initialize the ransomware module."""
        self._indicator_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="ransomware_indicators",
            description="Ransomware detection (file extensions, ransom notes, key exchange)",
            category=TrafficCategory.ANTIVIRUS,
            protocols=["TCP"],
            ports=[80, 443, 8080],
        )

    def _generate_ransom_note_download(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate ransom note file download request."""
        note_name = random.choice(RANSOM_NOTES)

        http_request = (
            f"GET /{note_name} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_encrypted_file_access(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate requests for encrypted file extensions."""
        extension = random.choice(RANSOMWARE_EXTENSIONS)
        filename = f"important_document{extension}"

        http_request = (
            f"GET /uploads/{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_key_exchange(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate ransomware key exchange patterns."""
        # POST to C2 with victim ID and encrypted key
        victim_id = f"VICTIM-{random.randint(100000, 999999)}"
        fake_key = "".join(random.choices("0123456789ABCDEF", k=64))

        post_body = f"id={victim_id}&key={fake_key}&version=2.1"

        http_request = (
            f"POST /gate.php HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{post_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_payment_page_access(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate payment page access patterns."""
        payment_paths = [
            "/pay.php",
            "/decrypt.php",
            "/ransom.php",
            "/unlock.php",
            "/payment/btc",
            "/recover-files",
        ]

        path = random.choice(payment_paths)

        http_request = (
            f"GET {path}?id=VICTIM123456 HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_tor_proxy_access(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Tor proxy access patterns (ransomware often uses Tor)."""
        # Access to .onion via clearnet proxy
        onion_proxies = [
            "onion.to",
            "onion.link",
            "tor2web.org",
        ]

        proxy = random.choice(onion_proxies)
        domain = random.choice(RANSOMWARE_DOMAINS).replace(".onion", "")

        http_request = (
            f"GET /{domain}.{proxy}/pay HTTP/1.1\r\n"
            f"Host: {proxy}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_bitcoin_address_check(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Bitcoin address lookup patterns."""
        # Fake Bitcoin address (valid format)
        btc_address = "1" + "".join(
            random.choices("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", k=33)
        )

        http_request = (
            f"GET /api/address/{btc_address} HTTP/1.1\r\n"
            f"Host: blockchain.info\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_shadow_copy_indicator(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate shadow copy deletion network indicators."""
        # Some ransomware contacts C2 after deleting shadow copies
        post_body = "action=shadow_deleted&status=success&count=5"

        http_request = (
            f"POST /report.php HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{post_body}"
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
        """Generate ransomware indicator packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with ransomware indicators
        """
        port = dst_port or 80
        self._indicator_count += 1

        # Rotate through different indicator types
        indicator = self._indicator_count % 7

        if indicator == 0:
            yield from self._generate_ransom_note_download(src_ip, dst_ip, port)
        elif indicator == 1:
            yield from self._generate_encrypted_file_access(src_ip, dst_ip, port)
        elif indicator == 2:
            yield from self._generate_key_exchange(src_ip, dst_ip, port)
        elif indicator == 3:
            yield from self._generate_payment_page_access(src_ip, dst_ip, port)
        elif indicator == 4:
            yield from self._generate_tor_proxy_access(src_ip, dst_ip, port)
        elif indicator == 5:
            yield from self._generate_bitcoin_address_check(src_ip, dst_ip, port)
        else:
            yield from self._generate_shadow_copy_indicator(src_ip, dst_ip, port)
