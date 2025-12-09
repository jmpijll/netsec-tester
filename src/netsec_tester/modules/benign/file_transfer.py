"""Benign file transfer traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# FTP commands for simulation
FTP_COMMANDS = [
    "USER anonymous",
    "PASS anonymous@",
    "PWD",
    "TYPE I",
    "PASV",
    "LIST",
    "RETR",
    "STOR",
    "QUIT",
]

# Safe file names for transfer simulation
SAFE_FILES = [
    "document.pdf",
    "report.xlsx",
    "presentation.pptx",
    "image.jpg",
    "data.csv",
    "backup.tar.gz",
    "archive.zip",
    "readme.txt",
]


class FileTransferModule(TrafficModule):
    """Traffic module for file transfer protocol simulation.

    Generates traffic patterns that mimic FTP and SFTP
    protocols for testing file transfer policies.
    """

    def __init__(self) -> None:
        """Initialize the file transfer module."""
        self._transfer_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="file_transfer",
            description="File transfer patterns (FTP, SFTP-like)",
            category=TrafficCategory.BENIGN,
            protocols=["TCP", "FTP"],
            ports=[21, 22, 990],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate file transfer packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with file transfer patterns
        """
        port = dst_port or 21
        self._transfer_count += 1

        # Generate FTP session
        yield from self._generate_ftp_session(src_ip, dst_ip, port)

    def _generate_ftp_session(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
    ) -> Iterator[Packet]:
        """Generate FTP protocol packets."""
        filename = random.choice(SAFE_FILES)

        # FTP login sequence
        commands = [
            "USER anonymous\r\n",
            "PASS anonymous@example.com\r\n",
            "PWD\r\n",
            "TYPE I\r\n",
            "PASV\r\n",
        ]

        for cmd in commands:
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(sport=40000 + (self._transfer_count % 25000), dport=port, flags="PA")
                / Raw(load=cmd.encode())
            )
            yield packet

        # File operation - alternate between LIST, RETR, and STOR
        operation = self._transfer_count % 3

        if operation == 0:
            # Directory listing
            cmd = "LIST\r\n"
        elif operation == 1:
            # Download file
            cmd = f"RETR {filename}\r\n"
        else:
            # Upload file
            cmd = f"STOR {filename}\r\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._transfer_count % 25000), dport=port, flags="PA")
            / Raw(load=cmd.encode())
        )
        yield packet

        # Quit
        quit_cmd = "QUIT\r\n"
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._transfer_count % 25000), dport=port, flags="PA")
            / Raw(load=quit_cmd.encode())
        )
        yield packet

        # Also generate HTTP-based file transfer (download simulation)
        http_request = (
            f"GET /files/{filename} HTTP/1.1\r\n"
            f"Host: files.example.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._transfer_count % 25000), dport=80, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet
