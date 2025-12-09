"""AV signature trigger module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Patterns that trigger AV heuristics and signatures
# These are safe patterns designed to trigger detection, not actual malware
AV_TRIGGER_PATTERNS = [
    # Suspicious PE header patterns (partial, non-functional)
    {
        "name": "PE_Header_Pattern",
        "content": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff",
        "extension": ".exe",
    },
    # Suspicious script patterns
    {
        "name": "PowerShell_Encoded",
        "content": b"powershell -enc JABzAD0AbgBlAHcALQBvAGIA",
        "extension": ".ps1",
    },
    {
        "name": "VBS_Shell",
        "content": b'Set objShell = CreateObject("WScript.Shell")\nobjShell.Run "cmd.exe"',
        "extension": ".vbs",
    },
    # Packed/obfuscated patterns
    {
        "name": "UPX_Packed",
        "content": b"UPX0\x00\x00\x00\x00\x00\x00\x00\x00",
        "extension": ".exe",
    },
    # Macro patterns
    {
        "name": "Office_Macro",
        "content": b"Sub AutoOpen()\n    Shell",
        "extension": ".docm",
    },
    # Shellcode-like patterns (NOP sled simulation)
    {
        "name": "NOP_Sled",
        "content": b"\x90" * 50 + b"\xcc",
        "extension": ".bin",
    },
    # Suspicious string patterns
    {
        "name": "Keylogger_String",
        "content": b"GetAsyncKeyState\x00GetKeyState\x00keylog",
        "extension": ".dll",
    },
    {
        "name": "Backdoor_String",
        "content": b"cmd.exe /c\x00reverse_shell\x00connect_back",
        "extension": ".exe",
    },
    # Archive bomb indicators
    {
        "name": "Zip_Bomb_Pattern",
        "content": b"PK\x03\x04" + b"\x00" * 50,
        "extension": ".zip",
    },
    # Cryptocurrency miner patterns
    {
        "name": "Miner_String",
        "content": b"stratum+tcp://\x00xmrig\x00cryptonight",
        "extension": ".exe",
    },
]

# Suspicious filenames that trigger AV
SUSPICIOUS_FILENAMES = [
    "invoice.pdf.exe",
    "document.doc.scr",
    "photo.jpg.exe",
    "setup_crack.exe",
    "keygen.exe",
    "patch.exe",
    "activator.exe",
    "loader.exe",
    "dropper.exe",
    "payload.bin",
]


class AVSignaturesModule(TrafficModule):
    """Traffic module for AV signature trigger patterns.

    Generates traffic containing patterns that trigger
    antivirus heuristics and signatures for testing.
    """

    def __init__(self) -> None:
        """Initialize the AV signatures module."""
        self._pattern_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="av_signatures",
            description="AV signature and heuristic trigger patterns",
            category=TrafficCategory.ANTIVIRUS,
            protocols=["TCP", "HTTP", "FTP"],
            ports=[80, 443, 21],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate AV signature trigger packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with AV trigger patterns
        """
        port = dst_port or 80
        self._pattern_count += 1

        # Select pattern
        pattern = AV_TRIGGER_PATTERNS[self._pattern_count % len(AV_TRIGGER_PATTERNS)]
        filename = random.choice(SUSPICIOUS_FILENAMES)

        # Create HTTP response with suspicious content
        content = pattern["content"]
        http_response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f'Content-Disposition: attachment; filename="{filename}"\r\n'
            f"Content-Length: {len(content)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode() + content

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._pattern_count % 25000), dport=port, flags="PA")
            / Raw(load=http_response)
        )

        yield packet

        # Generate request for suspicious file
        http_request = (
            f"GET /files/{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: application/octet-stream\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._pattern_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet
