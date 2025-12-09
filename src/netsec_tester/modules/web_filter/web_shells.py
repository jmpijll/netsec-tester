"""Web shell detection traffic module."""

import base64
import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Common web shell filenames
WEBSHELL_FILENAMES = [
    "c99.php",
    "r57.php",
    "b374k.php",
    "wso.php",
    "shell.php",
    "cmd.php",
    "backdoor.php",
    "webshell.php",
    "config.php.bak",
    "wp-config.php.old",
    "shell.aspx",
    "cmd.aspx",
    "tunnel.aspx",
    "webshell.jsp",
    "cmd.jsp",
    "shell.jspx",
    ".htaccess.php",
    "uploads/shell.php",
    "images/logo.php",
    "includes/db.php.bak",
]

# Web shell command patterns
WEBSHELL_COMMANDS = [
    "cmd=whoami",
    "cmd=id",
    "c=cat+/etc/passwd",
    "exec=ls+-la",
    "command=uname+-a",
    "action=execute&cmd=pwd",
    "do=shell&cmd=ifconfig",
    "a=Php&c=system&d=whoami",
    "act=cmd&cmd=netstat+-an",
    "p1=ls&p2=-la",
]

# Encoded web shell patterns
ENCODED_PATTERNS = [
    # Base64 encoded commands
    "eval(base64_decode('",
    "assert(base64_decode('",
    # Hex encoded
    "\\x73\\x79\\x73\\x74\\x65\\x6d",  # "system"
    # Rot13
    "riny($_CBFG",  # eval($_POST
    # Variable function
    "$_GET['f']($_GET['c']",
]


class WebShellsModule(TrafficModule):
    """Traffic module for web shell detection patterns.

    Generates HTTP requests that simulate web shell access attempts
    and upload patterns for security testing.
    """

    def __init__(self) -> None:
        """Initialize the web shells module."""
        self._access_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="web_shells",
            description="Web shell detection (shell filenames, command patterns, backdoor access)",
            category=TrafficCategory.WEB_FILTER,
            protocols=["TCP"],
            ports=[80, 443, 8080],
        )

    def _generate_shell_access(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate web shell access request."""
        filename = random.choice(WEBSHELL_FILENAMES)
        command = random.choice(WEBSHELL_COMMANDS)

        http_request = (
            f"GET /{filename}?{command} HTTP/1.1\r\n"
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

    def _generate_shell_post(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate web shell POST command execution."""
        filename = random.choice(WEBSHELL_FILENAMES)

        # POST body with command
        post_body = random.choice([
            "cmd=whoami&submit=Execute",
            "c=system('id');",
            "0=system&1=whoami",
            "action=shell&cmd=cat%20/etc/passwd",
        ])

        http_request = (
            f"POST /{filename} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(post_body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{post_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_shell_upload(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate web shell upload attempt."""
        # PHP web shell content (harmless indicator)
        shell_content = '<?php echo "test"; system($_GET["cmd"]); ?>'

        boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
        filename = random.choice(["shell.php", "image.php.jpg", "document.php.pdf"])

        multipart_body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/x-php\r\n\r\n"
            f"{shell_content}\r\n"
            f"--{boundary}--\r\n"
        )

        http_request = (
            f"POST /upload.php HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(multipart_body)}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
            f"{multipart_body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_encoded_shell(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate encoded/obfuscated shell access."""
        # Base64 encoded command
        cmd = base64.b64encode(b"whoami").decode()

        encoded_requests = [
            f"GET /shell.php?c={cmd}&e=base64 HTTP/1.1",
            "GET /index.php?page=php://filter/convert.base64-encode/resource=config HTTP/1.1",
            f"GET /index.php?file=data://text/plain;base64,{cmd} HTTP/1.1",
        ]

        http_request = (
            f"{random.choice(encoded_requests)}\r\n"
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

    def _generate_aspx_shell(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate ASPX web shell patterns."""
        aspx_shells = [
            "/aspxspy.aspx?cmd=whoami",
            "/cmd.aspx?c=dir",
            "/uploads/shell.aspx?exec=ipconfig",
            "/App_Data/shell.aspx",
        ]

        path = random.choice(aspx_shells)

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

    def _generate_jsp_shell(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate JSP web shell patterns."""
        jsp_shells = [
            "/shell.jsp?cmd=whoami",
            "/jspspy.jsp?o=shell&c=id",
            "/uploads/backdoor.jspx?exec=uname",
            "/admin/cmd.jsp?command=ls",
        ]

        path = random.choice(jsp_shells)

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

    def _generate_china_chopper(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate China Chopper web shell patterns."""
        # China Chopper uses single-char parameter
        china_chopper_patterns = [
            "z0=QGluaV9zZXQo",  # Base64 encoded PHP functions
            "z1=c3lzdGVt",  # "system"
            "z2=d2hvYW1p",  # "whoami"
        ]

        body = "&".join(random.sample(china_chopper_patterns, 2))

        http_request = (
            f"POST /images/logo.php HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
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
        """Generate web shell detection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with web shell patterns
        """
        port = dst_port or 80
        self._access_count += 1

        # Rotate through different shell patterns
        pattern = self._access_count % 7

        if pattern == 0:
            yield from self._generate_shell_access(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_shell_post(src_ip, dst_ip, port)
        elif pattern == 2:
            yield from self._generate_shell_upload(src_ip, dst_ip, port)
        elif pattern == 3:
            yield from self._generate_encoded_shell(src_ip, dst_ip, port)
        elif pattern == 4:
            yield from self._generate_aspx_shell(src_ip, dst_ip, port)
        elif pattern == 5:
            yield from self._generate_jsp_shell(src_ip, dst_ip, port)
        else:
            yield from self._generate_china_chopper(src_ip, dst_ip, port)

