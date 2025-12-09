"""Reconnaissance and scanning pattern traffic module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Common ports for scanning
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017,
]

# Vulnerability scanner User-Agents
SCANNER_USER_AGENTS = [
    "Nessus SOAP",
    "Mozilla/5.0 (compatible; Nessus SOAP)",
    "OpenVAS",
    "Nikto/2.1.6",
    "sqlmap/1.4.7",
    "DirBuster-1.0-RC1",
    "Acunetix-Scanner",
    "w3af.org",
    "Wapiti",
    "Arachni/v1.5.1",
    "WPScan v3.8.18",
    "Nuclei - Open-source project",
    "masscan/1.0",
    "ZmEu",
    "Morfeus Fucking Scanner",
]

# OS fingerprinting patterns (simplified signatures)
OS_FINGERPRINT_PATTERNS = [
    # Windows patterns
    {"ttl": 128, "window": 65535, "options": [("MSS", 1460), ("NOP", None), ("WScale", 8)]},
    # Linux patterns
    {"ttl": 64, "window": 29200, "options": [("MSS", 1460), ("SAckOK", b""), ("WScale", 7)]},
    # FreeBSD patterns
    {"ttl": 64, "window": 65535, "options": [("MSS", 1460), ("NOP", None), ("WScale", 6)]},
    # Cisco patterns
    {"ttl": 255, "window": 4128, "options": [("MSS", 1460)]},
]


class ReconnaissanceModule(TrafficModule):
    """Traffic module for reconnaissance and scanning patterns.

    Generates traffic that mimics port scanning, OS fingerprinting,
    and vulnerability scanning tools to trigger IPS detection.
    """

    def __init__(self) -> None:
        """Initialize the reconnaissance module."""
        self._scan_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="reconnaissance",
            description="Port scanning, OS fingerprinting, and vulnerability scanner patterns",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "UDP", "ICMP"],
            ports=[22, 80, 443, 445, 3389],
        )

    def _generate_syn_scan(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate SYN scan packets."""
        # Scan multiple ports rapidly
        ports_to_scan = random.sample(COMMON_PORTS, min(5, len(COMMON_PORTS)))
        for port in ports_to_scan:
            packet = (
                IP(src=src_ip, dst=dst_ip)
                / TCP(
                    sport=random.randint(49152, 65535),
                    dport=port,
                    flags="S",
                    seq=random.randint(0, 4294967295),
                )
            )
            yield packet

    def _generate_null_scan(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate NULL scan packets (no flags set)."""
        port = random.choice(COMMON_PORTS)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="",  # No flags
                seq=random.randint(0, 4294967295),
            )
        )
        yield packet

    def _generate_fin_scan(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate FIN scan packets."""
        port = random.choice(COMMON_PORTS)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="F",
                seq=random.randint(0, 4294967295),
            )
        )
        yield packet

    def _generate_xmas_scan(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate XMAS scan packets (FIN, PSH, URG flags)."""
        port = random.choice(COMMON_PORTS)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="FPU",  # FIN, PUSH, URG
                seq=random.randint(0, 4294967295),
            )
        )
        yield packet

    def _generate_udp_scan(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate UDP scan packets."""
        udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900]
        port = random.choice(udp_ports)
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=port)
        )
        yield packet

    def _generate_os_fingerprint(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate OS fingerprinting probes."""
        # TCP SYN with specific options for fingerprinting
        fp = random.choice(OS_FINGERPRINT_PATTERNS)
        port = random.choice([80, 443, 22])

        packet = (
            IP(src=src_ip, dst=dst_ip, ttl=fp["ttl"])
            / TCP(
                sport=random.randint(49152, 65535),
                dport=port,
                flags="S",
                window=fp["window"],
                options=fp["options"],
            )
        )
        yield packet

        # ICMP echo for TTL-based fingerprinting
        packet = IP(src=src_ip, dst=dst_ip, ttl=64) / ICMP(type=8, code=0)
        yield packet

    def _generate_banner_grab(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate service banner grabbing attempts."""
        # Simple connection followed by service-specific probe
        probes = {
            22: b"SSH-2.0-OpenSSH_probe\r\n",
            21: b"HELP\r\n",
            25: b"EHLO scanner\r\n",
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            110: b"USER test\r\n",
            143: b"a001 CAPABILITY\r\n",
            3306: b"\x00\x00\x01\x85\xa6\x03\x00",  # MySQL handshake
        }

        probe = probes.get(port, b"HELP\r\n")
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=probe)
        )
        yield packet

    def _generate_vuln_scanner_request(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate vulnerability scanner HTTP requests."""
        user_agent = random.choice(SCANNER_USER_AGENTS)

        # Common vulnerability scanner paths
        scan_paths = [
            "/.git/config",
            "/.env",
            "/wp-config.php.bak",
            "/phpinfo.php",
            "/server-status",
            "/manager/html",
            "/admin/",
            "/phpmyadmin/",
            "/.svn/entries",
            "/backup.sql",
            "/web.config",
            "/crossdomain.xml",
            "/.htaccess",
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/cgi-bin/test-cgi",
            "/scripts/..%c0%af../winnt/system32/cmd.exe",
        ]

        path = random.choice(scan_paths)
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
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
        """Generate reconnaissance packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with scanning patterns
        """
        port = dst_port or 80
        self._scan_count += 1

        # Rotate through different scan types
        scan_type = self._scan_count % 8

        if scan_type == 0:
            yield from self._generate_syn_scan(src_ip, dst_ip)
        elif scan_type == 1:
            yield from self._generate_null_scan(src_ip, dst_ip)
        elif scan_type == 2:
            yield from self._generate_fin_scan(src_ip, dst_ip)
        elif scan_type == 3:
            yield from self._generate_xmas_scan(src_ip, dst_ip)
        elif scan_type == 4:
            yield from self._generate_udp_scan(src_ip, dst_ip)
        elif scan_type == 5:
            yield from self._generate_os_fingerprint(src_ip, dst_ip)
        elif scan_type == 6:
            yield from self._generate_banner_grab(src_ip, dst_ip, port)
        else:
            yield from self._generate_vuln_scanner_request(src_ip, dst_ip, port)

