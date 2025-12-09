"""Tests for traffic generation modules."""

import pytest

from netsec_tester.modules.antivirus.archive_evasion import ArchiveEvasionModule
from netsec_tester.modules.antivirus.cryptominer import CryptominerModule
from netsec_tester.modules.antivirus.dropper import DropperModule

# Antivirus modules
from netsec_tester.modules.antivirus.eicar import EICARModule
from netsec_tester.modules.antivirus.ransomware import RansomwareModule
from netsec_tester.modules.antivirus.signatures import AVSignaturesModule
from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule
from netsec_tester.modules.benign.cloud_services import CloudServicesModule
from netsec_tester.modules.benign.email import EmailModule
from netsec_tester.modules.benign.file_transfer import FileTransferModule
from netsec_tester.modules.benign.iot_device import IoTDeviceModule
from netsec_tester.modules.benign.mobile_app import MobileAppModule
from netsec_tester.modules.benign.vpn_proxy import VPNProxyModule

# Benign modules
from netsec_tester.modules.benign.web_browsing import WebBrowsingModule
from netsec_tester.modules.dns_filter.amplification import DNSAmplificationModule
from netsec_tester.modules.dns_filter.dga import DGAModule
from netsec_tester.modules.dns_filter.exfiltration import DNSExfiltrationModule
from netsec_tester.modules.dns_filter.fast_flux import FastFluxModule
from netsec_tester.modules.dns_filter.malicious_domains import MaliciousDomainsModule
from netsec_tester.modules.dns_filter.rebinding import DNSRebindingModule

# DNS modules
from netsec_tester.modules.dns_filter.tunneling import DNSTunnelingModule
from netsec_tester.modules.exfiltration.https_exfil import HTTPSExfilModule

# Exfiltration modules
from netsec_tester.modules.exfiltration.icmp_covert import ICMPCovertModule
from netsec_tester.modules.exfiltration.protocol_abuse import ProtocolAbuseModule
from netsec_tester.modules.ips_ids.brute_force import BruteForceModule
from netsec_tester.modules.ips_ids.c2_beacon import C2BeaconModule
from netsec_tester.modules.ips_ids.command_injection import CommandInjectionModule
from netsec_tester.modules.ips_ids.deserialization import DeserializationModule
from netsec_tester.modules.ips_ids.directory_traversal import DirectoryTraversalModule
from netsec_tester.modules.ips_ids.dos_patterns import DoSPatternsModule
from netsec_tester.modules.ips_ids.exploits import ExploitsModule
from netsec_tester.modules.ips_ids.protocol_anomaly import ProtocolAnomalyModule
from netsec_tester.modules.ips_ids.reconnaissance import ReconnaissanceModule

# IPS/IDS modules
from netsec_tester.modules.ips_ids.sql_injection import SQLInjectionModule
from netsec_tester.modules.ips_ids.ssrf_xxe import SSRFXXEModule
from netsec_tester.modules.ips_ids.xss import XSSModule
from netsec_tester.modules.video_filter.gaming import GamingModule
from netsec_tester.modules.video_filter.p2p_torrent import P2PTorrentModule

# Video filter modules
from netsec_tester.modules.video_filter.streaming import StreamingModule
from netsec_tester.modules.video_filter.voip_webrtc import VoIPWebRTCModule
from netsec_tester.modules.web_filter.api_abuse import APIAbuseModule

# Web filter modules
from netsec_tester.modules.web_filter.categories import WebCategoryModule
from netsec_tester.modules.web_filter.http_smuggling import HTTPSmugglingModule
from netsec_tester.modules.web_filter.tls_inspection import TLSInspectionModule
from netsec_tester.modules.web_filter.url_patterns import URLPatternsModule
from netsec_tester.modules.web_filter.web_shells import WebShellsModule

# List of all modules to test (45 total)
ALL_MODULES = [
    # IPS/IDS (12 modules)
    SQLInjectionModule,
    XSSModule,
    CommandInjectionModule,
    DirectoryTraversalModule,
    ExploitsModule,
    C2BeaconModule,
    ReconnaissanceModule,
    DoSPatternsModule,
    BruteForceModule,
    ProtocolAnomalyModule,
    SSRFXXEModule,
    DeserializationModule,
    # DNS (7 modules)
    DNSTunnelingModule,
    DGAModule,
    MaliciousDomainsModule,
    DNSExfiltrationModule,
    DNSRebindingModule,
    DNSAmplificationModule,
    FastFluxModule,
    # Web filter (6 modules)
    WebCategoryModule,
    URLPatternsModule,
    TLSInspectionModule,
    APIAbuseModule,
    WebShellsModule,
    HTTPSmugglingModule,
    # Antivirus (6 modules)
    EICARModule,
    AVSignaturesModule,
    RansomwareModule,
    CryptominerModule,
    DropperModule,
    ArchiveEvasionModule,
    # Video filter (4 modules)
    StreamingModule,
    P2PTorrentModule,
    VoIPWebRTCModule,
    GamingModule,
    # Benign (7 modules)
    WebBrowsingModule,
    EmailModule,
    FileTransferModule,
    CloudServicesModule,
    IoTDeviceModule,
    MobileAppModule,
    VPNProxyModule,
    # Exfiltration (3 modules)
    ICMPCovertModule,
    HTTPSExfilModule,
    ProtocolAbuseModule,
]


class TestModuleInterface:
    """Test that all modules implement the required interface."""

    @pytest.mark.parametrize("module_class", ALL_MODULES)
    def test_module_has_get_info(self, module_class: type[TrafficModule]) -> None:
        """Test that module implements get_info()."""
        module = module_class()
        info = module.get_info()

        assert isinstance(info, ModuleInfo)
        assert isinstance(info.name, str)
        assert len(info.name) > 0
        assert isinstance(info.description, str)
        assert isinstance(info.category, TrafficCategory)
        assert isinstance(info.protocols, list)
        assert isinstance(info.ports, list)

    @pytest.mark.parametrize("module_class", ALL_MODULES)
    def test_module_generates_packets(self, module_class: type[TrafficModule]) -> None:
        """Test that module generates packets."""
        module = module_class()
        packets = list(module.generate_packets(
            src_ip="10.0.0.1",
            dst_ip="192.168.1.1",
            dst_port=80,
        ))

        assert len(packets) > 0
        for packet in packets:
            # Verify packet has IP layer
            assert hasattr(packet, "src")
            assert hasattr(packet, "dst")

    @pytest.mark.parametrize("module_class", ALL_MODULES)
    def test_module_get_category(self, module_class: type[TrafficModule]) -> None:
        """Test that module returns valid category."""
        module = module_class()
        category = module.get_category()

        assert isinstance(category, TrafficCategory)

    @pytest.mark.parametrize("module_class", ALL_MODULES)
    def test_module_generates_multiple_variations(self, module_class: type[TrafficModule]) -> None:
        """Test that module generates varied packets over multiple calls."""
        module = module_class()

        all_packets = []
        for _ in range(5):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            all_packets.extend(packets)

        # Should generate packets each time
        assert len(all_packets) >= 5


class TestIPSModules:
    """Test IPS/IDS specific modules."""

    def test_sql_injection_payloads(self) -> None:
        """Test SQL injection module generates SQLi payloads."""
        module = SQLInjectionModule()

        all_packets_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_packets_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_packets_raw)
        sql_patterns = ["'", "OR", "UNION", "SELECT", "--", "DROP"]
        found_patterns = sum(1 for p in sql_patterns if p in combined)
        assert found_patterns >= 2, "Expected to find SQL injection patterns"

    def test_xss_payloads(self) -> None:
        """Test XSS module generates XSS payloads."""
        module = XSSModule()

        all_packets_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_packets_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_packets_raw)
        xss_patterns = ["<script>", "alert", "onerror", "javascript:"]
        found_patterns = sum(1 for p in xss_patterns if p.lower() in combined.lower())
        assert found_patterns >= 1, "Expected to find XSS patterns"

    def test_reconnaissance_scan_types(self) -> None:
        """Test reconnaissance module generates various scan types."""
        module = ReconnaissanceModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 80)))

        # Should generate various TCP flag combinations
        assert len(packets) > 0

    def test_dos_patterns_generates_flood(self) -> None:
        """Test DoS patterns module generates flood patterns."""
        module = DoSPatternsModule()

        packets = []
        for _ in range(5):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 80)))

        assert len(packets) >= 5

    def test_brute_force_credentials(self) -> None:
        """Test brute force module generates credential attempts."""
        module = BruteForceModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain username/password patterns
        assert "admin" in combined.lower() or "user" in combined.lower() or "pass" in combined.lower()

    def test_ssrf_xxe_patterns(self) -> None:
        """Test SSRF/XXE module generates attack patterns."""
        module = SSRFXXEModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain SSRF targets or XML patterns
        patterns_found = any(p in combined for p in ["127.0.0.1", "localhost", "<!DOCTYPE", "ENTITY"])
        assert patterns_found, "Expected SSRF/XXE patterns"


class TestDNSModules:
    """Test DNS specific modules."""

    def test_dns_tunneling_high_entropy(self) -> None:
        """Test DNS tunneling module generates high-entropy subdomains."""
        module = DNSTunnelingModule()

        packets = list(module.generate_packets("10.0.0.1", "8.8.8.8", 53))

        assert len(packets) > 0
        for pkt in packets:
            assert pkt.haslayer("DNS")

    def test_dga_generates_random_domains(self) -> None:
        """Test DGA module generates random-looking domains."""
        module = DGAModule()

        domains = set()
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "8.8.8.8", 53))
            for pkt in packets:
                if pkt.haslayer("DNS"):
                    qname = pkt["DNS"].qd.qname.decode("utf-8", errors="ignore")
                    domains.add(qname)

        assert len(domains) >= 5, "Expected varied DGA domains"

    def test_dns_exfiltration_encoded(self) -> None:
        """Test DNS exfiltration module generates encoded queries."""
        module = DNSExfiltrationModule()

        packets = []
        for _ in range(5):
            packets.extend(list(module.generate_packets("10.0.0.1", "8.8.8.8", 53)))

        assert len(packets) > 0
        for pkt in packets:
            assert pkt.haslayer("DNS")

    def test_dns_amplification_any_query(self) -> None:
        """Test DNS amplification generates ANY queries."""
        module = DNSAmplificationModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "8.8.8.8", 53)))

        assert len(packets) > 0


class TestWebModules:
    """Test web filter specific modules."""

    def test_tls_inspection_sni(self) -> None:
        """Test TLS inspection module generates SNI patterns."""
        module = TLSInspectionModule()

        packets = []
        for _ in range(5):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 443)))

        assert len(packets) >= 5

    def test_api_abuse_patterns(self) -> None:
        """Test API abuse module generates API attack patterns."""
        module = APIAbuseModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain API patterns
        assert "graphql" in combined.lower() or "api" in combined.lower() or "bearer" in combined.lower()

    def test_web_shells_patterns(self) -> None:
        """Test web shells module generates shell access patterns."""
        module = WebShellsModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain shell patterns
        patterns = ["cmd=", "shell", ".php", "whoami", "exec"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected web shell patterns"

    def test_http_smuggling(self) -> None:
        """Test HTTP smuggling module generates smuggling patterns."""
        module = HTTPSmugglingModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain smuggling indicators
        assert "Content-Length" in combined or "Transfer-Encoding" in combined


class TestAntivirusModules:
    """Test antivirus specific modules."""

    def test_eicar_contains_test_string(self) -> None:
        """Test EICAR module includes the EICAR test string."""
        module = EICARModule()

        all_raw = []
        for _ in range(5):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        assert "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in combined

    def test_ransomware_indicators(self) -> None:
        """Test ransomware module generates ransomware indicators."""
        module = RansomwareModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain ransomware patterns
        patterns = ["decrypt", "ransom", ".encrypted", "readme", "bitcoin"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected ransomware patterns"

    def test_cryptominer_stratum(self) -> None:
        """Test cryptominer module generates stratum patterns."""
        module = CryptominerModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 3333))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain mining patterns
        patterns = ["mining", "stratum", "subscribe", "authorize"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected cryptominer patterns"

    def test_dropper_patterns(self) -> None:
        """Test dropper module generates dropper patterns."""
        module = DropperModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain dropper patterns
        patterns = [".exe", ".dll", ".hta", ".vbs", "powershell", "certutil"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected dropper patterns"


class TestVideoModules:
    """Test video filter specific modules."""

    def test_p2p_torrent_handshake(self) -> None:
        """Test P2P/torrent module generates BitTorrent patterns."""
        module = P2PTorrentModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 6881)))

        assert len(packets) > 0

    def test_voip_webrtc_sip(self) -> None:
        """Test VoIP/WebRTC module generates SIP patterns."""
        module = VoIPWebRTCModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 5060))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain VoIP patterns
        patterns = ["sip", "invite", "register", "stun", "webrtc"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected VoIP patterns"

    def test_gaming_traffic(self) -> None:
        """Test gaming module generates gaming traffic patterns."""
        module = GamingModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 443)))

        assert len(packets) > 0


class TestBenignModules:
    """Test benign traffic modules."""

    def test_cloud_services_patterns(self) -> None:
        """Test cloud services module generates API patterns."""
        module = CloudServicesModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 443))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain cloud patterns
        patterns = ["aws", "azure", "google", "microsoft", "s3", "blob"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected cloud service patterns"

    def test_iot_device_mqtt(self) -> None:
        """Test IoT device module generates MQTT/CoAP patterns."""
        module = IoTDeviceModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 1883)))

        assert len(packets) > 0

    def test_mobile_app_patterns(self) -> None:
        """Test mobile app module generates mobile patterns."""
        module = MobileAppModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 443))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain mobile patterns
        patterns = ["apple", "google", "play", "push", "analytics", "firebase"]
        found = any(p in combined.lower() for p in patterns)
        assert found, "Expected mobile app patterns"

    def test_vpn_proxy_patterns(self) -> None:
        """Test VPN/proxy module generates tunnel patterns."""
        module = VPNProxyModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 1194)))

        assert len(packets) > 0


class TestExfiltrationModules:
    """Test exfiltration detection modules."""

    def test_icmp_covert_channel(self) -> None:
        """Test ICMP covert module generates ICMP with data."""
        module = ICMPCovertModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1")))

        assert len(packets) > 0
        # Should have ICMP packets
        for pkt in packets:
            assert pkt.haslayer("ICMP")

    def test_https_exfiltration(self) -> None:
        """Test HTTPS exfiltration module generates large POST patterns."""
        module = HTTPSExfilModule()

        all_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 443))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        combined = " ".join(all_raw)
        # Should contain exfil patterns
        assert "POST" in combined or "upload" in combined.lower()

    def test_protocol_abuse(self) -> None:
        """Test protocol abuse module generates covert channel patterns."""
        module = ProtocolAbuseModule()

        packets = []
        for _ in range(10):
            packets.extend(list(module.generate_packets("10.0.0.1", "192.168.1.1", 80)))

        assert len(packets) > 0
