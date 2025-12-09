"""Benign email traffic simulation module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# SMTP commands for simulation
SMTP_COMMANDS = [
    "EHLO client.example.com",
    "MAIL FROM:<user@example.com>",
    "RCPT TO:<recipient@example.org>",
    "DATA",
    "QUIT",
]

# Sample email headers
EMAIL_HEADERS = """From: sender@example.com
To: recipient@example.org
Subject: Test Email Message
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit
Message-ID: <12345@example.com>
X-Mailer: Mozilla Thunderbird

This is a test email message for network testing purposes.
"""


class EmailModule(TrafficModule):
    """Traffic module for email protocol simulation.

    Generates traffic patterns that mimic SMTP, POP3, and IMAP
    protocols for testing email filtering policies.
    """

    def __init__(self) -> None:
        """Initialize the email module."""
        self._message_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="email",
            description="Email protocol patterns (SMTP, POP3, IMAP)",
            category=TrafficCategory.BENIGN,
            protocols=["TCP", "SMTP", "POP3", "IMAP"],
            ports=[25, 110, 143, 465, 587, 993, 995],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate email protocol packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with email protocol patterns
        """
        port = dst_port or 25
        self._message_count += 1

        protocol = self._message_count % 3

        if protocol == 0 or port in [25, 465, 587]:
            # SMTP traffic
            yield from self._generate_smtp(src_ip, dst_ip, port)
        elif protocol == 1 or port in [110, 995]:
            # POP3 traffic
            yield from self._generate_pop3(src_ip, dst_ip, port)
        else:
            # IMAP traffic
            yield from self._generate_imap(src_ip, dst_ip, port)

    def _generate_smtp(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
    ) -> Iterator[Packet]:
        """Generate SMTP protocol packets."""
        # EHLO command
        ehlo = f"EHLO client.example.com\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
            / Raw(load=ehlo.encode())
        )
        yield packet

        # MAIL FROM
        mail_from = f"MAIL FROM:<user{random.randint(1, 100)}@example.com>\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
            / Raw(load=mail_from.encode())
        )
        yield packet

        # RCPT TO
        rcpt_to = f"RCPT TO:<recipient{random.randint(1, 100)}@example.org>\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
            / Raw(load=rcpt_to.encode())
        )
        yield packet

        # DATA
        data_cmd = "DATA\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
            / Raw(load=data_cmd.encode())
        )
        yield packet

        # Email content
        email_content = EMAIL_HEADERS + "\r\n.\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
            / Raw(load=email_content.encode())
        )
        yield packet

    def _generate_pop3(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
    ) -> Iterator[Packet]:
        """Generate POP3 protocol packets."""
        pop3_commands = [
            "USER testuser\r\n",
            "PASS testpassword\r\n",
            "STAT\r\n",
            "LIST\r\n",
            "RETR 1\r\n",
            "QUIT\r\n",
        ]

        for cmd in pop3_commands[:3]:  # Send first few commands
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
                / Raw(load=cmd.encode())
            )
            yield packet

    def _generate_imap(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
    ) -> Iterator[Packet]:
        """Generate IMAP protocol packets."""
        imap_commands = [
            f"a{self._message_count:04d} LOGIN testuser testpassword\r\n",
            f"a{self._message_count:04d} SELECT INBOX\r\n",
            f"a{self._message_count:04d} FETCH 1 (FLAGS BODY[HEADER])\r\n",
            f"a{self._message_count:04d} LOGOUT\r\n",
        ]

        for cmd in imap_commands[:3]:  # Send first few commands
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=40000 + (self._message_count % 25000), dport=port, flags="PA")
                / Raw(load=cmd.encode())
            )
            yield packet

