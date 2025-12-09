"""Brute force attack pattern traffic module."""

import base64
import random
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Common usernames for brute force
COMMON_USERNAMES = [
    "admin", "root", "user", "test", "guest", "administrator",
    "oracle", "postgres", "mysql", "ftp", "www", "mail",
    "support", "info", "sales", "backup", "operator",
]

# Common passwords for brute force
COMMON_PASSWORDS = [
    "password", "123456", "admin", "root", "test", "guest",
    "letmein", "welcome", "monkey", "dragon", "master",
    "qwerty", "login", "passw0rd", "admin123", "root123",
]


class BruteForceModule(TrafficModule):
    """Traffic module for brute force attack patterns.

    Generates traffic that mimics authentication brute force
    attacks against various services.
    """

    def __init__(self) -> None:
        """Initialize the brute force module."""
        self._attempt_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="brute_force",
            description="Brute force patterns (SSH, FTP, HTTP auth, SMTP, RDP)",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP"],
            ports=[21, 22, 25, 80, 443, 3389],
        )

    def _generate_ssh_brute_force(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate SSH brute force patterns."""
        username = random.choice(COMMON_USERNAMES)
        password = random.choice(COMMON_PASSWORDS)

        # SSH banner exchange
        ssh_banner = f"SSH-2.0-OpenSSH_brute\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=22, flags="PA")
            / Raw(load=ssh_banner.encode())
        )
        yield packet

        # Multiple rapid connection attempts indicate brute force
        for _ in range(3):
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=random.randint(49152, 65535),
                    dport=22,
                    flags="S",
                )
            )
            yield packet

    def _generate_ftp_brute_force(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate FTP brute force patterns."""
        username = random.choice(COMMON_USERNAMES)
        password = random.choice(COMMON_PASSWORDS)

        # FTP USER command
        user_cmd = f"USER {username}\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=21, flags="PA")
            / Raw(load=user_cmd.encode())
        )
        yield packet

        # FTP PASS command
        pass_cmd = f"PASS {password}\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=21, flags="PA")
            / Raw(load=pass_cmd.encode())
        )
        yield packet

    def _generate_http_basic_auth_brute(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate HTTP Basic Auth brute force patterns."""
        username = random.choice(COMMON_USERNAMES)
        password = random.choice(COMMON_PASSWORDS)

        # Base64 encode credentials
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

        http_request = (
            f"GET /admin/ HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Authorization: Basic {credentials}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_http_form_brute(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate HTTP form-based login brute force patterns."""
        username = random.choice(COMMON_USERNAMES)
        password = random.choice(COMMON_PASSWORDS)

        post_body = f"username={username}&password={password}&submit=Login"

        http_request = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{post_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_smtp_auth_brute(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate SMTP AUTH brute force patterns."""
        username = random.choice(COMMON_USERNAMES)
        password = random.choice(COMMON_PASSWORDS)

        # SMTP EHLO
        ehlo = "EHLO bruteforce\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=25, flags="PA")
            / Raw(load=ehlo.encode())
        )
        yield packet

        # AUTH LOGIN
        auth_login = "AUTH LOGIN\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=25, flags="PA")
            / Raw(load=auth_login.encode())
        )
        yield packet

        # Base64 encoded username
        b64_user = base64.b64encode(username.encode()).decode() + "\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=25, flags="PA")
            / Raw(load=b64_user.encode())
        )
        yield packet

        # Base64 encoded password
        b64_pass = base64.b64encode(password.encode()).decode() + "\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=25, flags="PA")
            / Raw(load=b64_pass.encode())
        )
        yield packet

    def _generate_rdp_brute_force(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate RDP brute force patterns."""
        # RDP connection initiation (simplified)
        # Multiple rapid RDP connection attempts
        for _ in range(3):
            # RDP X.224 Connection Request
            rdp_init = bytes([
                0x03, 0x00,  # TPKT version
                0x00, 0x13,  # Length
                0x0e,  # X.224 length
                0xe0,  # Connection request
                0x00, 0x00,  # DST-REF
                0x00, 0x00,  # SRC-REF
                0x00,  # Class
            ]) + b"Cookie: mstshash=user\r\n"

            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=random.randint(49152, 65535), dport=3389, flags="PA")
                / Raw(load=rdp_init)
            )
            yield packet

    def _generate_mysql_brute_force(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate MySQL brute force patterns."""
        username = random.choice(COMMON_USERNAMES)

        # MySQL authentication packet (simplified)
        # Client capabilities + username
        mysql_auth = (
            b"\x85\xa6\x03\x00"  # Client capabilities
            + b"\x00\x00\x00\x01"  # Max packet size
            + b"\x21"  # Charset
            + b"\x00" * 23  # Reserved
            + username.encode() + b"\x00"  # Username
            + b"\x00"  # Auth response length
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=3306, flags="PA")
            / Raw(load=mysql_auth)
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate brute force pattern packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with brute force patterns
        """
        port = dst_port or 80
        self._attempt_count += 1

        # Rotate through different brute force types
        attack_type = self._attempt_count % 7

        if attack_type == 0:
            yield from self._generate_ssh_brute_force(src_ip, dst_ip)
        elif attack_type == 1:
            yield from self._generate_ftp_brute_force(src_ip, dst_ip)
        elif attack_type == 2:
            yield from self._generate_http_basic_auth_brute(src_ip, dst_ip, port)
        elif attack_type == 3:
            yield from self._generate_http_form_brute(src_ip, dst_ip, port)
        elif attack_type == 4:
            yield from self._generate_smtp_auth_brute(src_ip, dst_ip)
        elif attack_type == 5:
            yield from self._generate_rdp_brute_force(src_ip, dst_ip)
        else:
            yield from self._generate_mysql_brute_force(src_ip, dst_ip)

