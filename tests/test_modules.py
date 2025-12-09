"""Tests for traffic generation modules."""

import pytest

from netsec_tester.modules.base import TrafficCategory, TrafficModule, ModuleInfo
from netsec_tester.modules.ips_ids.sql_injection import SQLInjectionModule
from netsec_tester.modules.ips_ids.xss import XSSModule
from netsec_tester.modules.ips_ids.command_injection import CommandInjectionModule
from netsec_tester.modules.ips_ids.directory_traversal import DirectoryTraversalModule
from netsec_tester.modules.ips_ids.exploits import ExploitsModule
from netsec_tester.modules.ips_ids.c2_beacon import C2BeaconModule
from netsec_tester.modules.dns_filter.tunneling import DNSTunnelingModule
from netsec_tester.modules.dns_filter.dga import DGAModule
from netsec_tester.modules.dns_filter.malicious_domains import MaliciousDomainsModule
from netsec_tester.modules.web_filter.categories import WebCategoryModule
from netsec_tester.modules.web_filter.url_patterns import URLPatternsModule
from netsec_tester.modules.antivirus.eicar import EICARModule
from netsec_tester.modules.antivirus.signatures import AVSignaturesModule
from netsec_tester.modules.video_filter.streaming import StreamingModule
from netsec_tester.modules.benign.web_browsing import WebBrowsingModule
from netsec_tester.modules.benign.email import EmailModule
from netsec_tester.modules.benign.file_transfer import FileTransferModule


# List of all modules to test
ALL_MODULES = [
    SQLInjectionModule,
    XSSModule,
    CommandInjectionModule,
    DirectoryTraversalModule,
    ExploitsModule,
    C2BeaconModule,
    DNSTunnelingModule,
    DGAModule,
    MaliciousDomainsModule,
    WebCategoryModule,
    URLPatternsModule,
    EICARModule,
    AVSignaturesModule,
    StreamingModule,
    WebBrowsingModule,
    EmailModule,
    FileTransferModule,
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
    def test_module_get_default_ports(self, module_class: type[TrafficModule]) -> None:
        """Test that module returns default ports."""
        module = module_class()
        ports = module.get_default_ports()

        assert isinstance(ports, list)
        assert len(ports) > 0
        for port in ports:
            assert isinstance(port, int)
            assert 1 <= port <= 65535


class TestIPSModules:
    """Test IPS/IDS specific modules."""

    def test_sql_injection_payloads(self) -> None:
        """Test SQL injection module generates SQLi payloads."""
        module = SQLInjectionModule()

        # Generate multiple packets to get different payloads
        all_packets_raw = []
        for _ in range(10):
            packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
            for pkt in packets:
                if hasattr(pkt, "load"):
                    all_packets_raw.append(pkt.load.decode("utf-8", errors="ignore"))

        # Check for SQLi patterns in payloads
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


class TestDNSModules:
    """Test DNS specific modules."""

    def test_dns_tunneling_high_entropy(self) -> None:
        """Test DNS tunneling module generates high-entropy subdomains."""
        module = DNSTunnelingModule()

        packets = list(module.generate_packets("10.0.0.1", "8.8.8.8", 53))

        assert len(packets) > 0
        # DNS packets should have DNS layer
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

        # Should generate varied domains
        assert len(domains) >= 5, "Expected varied DGA domains"


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

