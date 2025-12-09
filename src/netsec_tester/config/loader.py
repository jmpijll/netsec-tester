"""Configuration loader for scenarios and settings."""

from pathlib import Path
from typing import Any

import yaml

from netsec_tester.scenarios.registry import ScenarioRegistry


class ConfigLoader:
    """Load and manage configuration from YAML files."""

    def __init__(self) -> None:
        """Initialize the config loader."""
        self.registry = ScenarioRegistry()
        self._config: dict[str, Any] = {}
        self._loaded = False

    def load(self, config_path: Path) -> None:
        """Load configuration from a YAML file.

        Args:
            config_path: Path to the YAML configuration file
        """
        if not config_path.exists():
            # Create default config if it doesn't exist
            self._create_default_config(config_path)

        with open(config_path) as f:
            self._config = yaml.safe_load(f) or {}

        # Register all available modules
        self._register_modules()

        # Load scenarios
        self.registry.load_scenarios_from_yaml(config_path)
        self._loaded = True

    def _register_modules(self) -> None:
        """Register all available traffic modules."""
        # Import and register IPS/IDS modules
        from netsec_tester.modules.ips_ids.sql_injection import SQLInjectionModule
        from netsec_tester.modules.ips_ids.xss import XSSModule
        from netsec_tester.modules.ips_ids.command_injection import CommandInjectionModule
        from netsec_tester.modules.ips_ids.directory_traversal import DirectoryTraversalModule
        from netsec_tester.modules.ips_ids.exploits import ExploitsModule
        from netsec_tester.modules.ips_ids.c2_beacon import C2BeaconModule
        from netsec_tester.modules.ips_ids.reconnaissance import ReconnaissanceModule
        from netsec_tester.modules.ips_ids.dos_patterns import DoSPatternsModule
        from netsec_tester.modules.ips_ids.brute_force import BruteForceModule
        from netsec_tester.modules.ips_ids.protocol_anomaly import ProtocolAnomalyModule
        from netsec_tester.modules.ips_ids.ssrf_xxe import SSRFXXEModule
        from netsec_tester.modules.ips_ids.deserialization import DeserializationModule

        self.registry.register_module("sql_injection", SQLInjectionModule)
        self.registry.register_module("xss", XSSModule)
        self.registry.register_module("command_injection", CommandInjectionModule)
        self.registry.register_module("directory_traversal", DirectoryTraversalModule)
        self.registry.register_module("exploits", ExploitsModule)
        self.registry.register_module("c2_beacon", C2BeaconModule)
        self.registry.register_module("reconnaissance", ReconnaissanceModule)
        self.registry.register_module("dos_patterns", DoSPatternsModule)
        self.registry.register_module("brute_force", BruteForceModule)
        self.registry.register_module("protocol_anomaly", ProtocolAnomalyModule)
        self.registry.register_module("ssrf_xxe", SSRFXXEModule)
        self.registry.register_module("deserialization", DeserializationModule)

        # Import and register DNS modules
        from netsec_tester.modules.dns_filter.tunneling import DNSTunnelingModule
        from netsec_tester.modules.dns_filter.dga import DGAModule
        from netsec_tester.modules.dns_filter.malicious_domains import MaliciousDomainsModule
        from netsec_tester.modules.dns_filter.exfiltration import DNSExfiltrationModule
        from netsec_tester.modules.dns_filter.rebinding import DNSRebindingModule
        from netsec_tester.modules.dns_filter.amplification import DNSAmplificationModule
        from netsec_tester.modules.dns_filter.fast_flux import FastFluxModule

        self.registry.register_module("dns_tunneling", DNSTunnelingModule)
        self.registry.register_module("dga", DGAModule)
        self.registry.register_module("malicious_domains", MaliciousDomainsModule)
        self.registry.register_module("dns_exfiltration", DNSExfiltrationModule)
        self.registry.register_module("dns_rebinding", DNSRebindingModule)
        self.registry.register_module("dns_amplification", DNSAmplificationModule)
        self.registry.register_module("fast_flux", FastFluxModule)

        # Import and register Web filtering modules
        from netsec_tester.modules.web_filter.categories import WebCategoryModule
        from netsec_tester.modules.web_filter.url_patterns import URLPatternsModule
        from netsec_tester.modules.web_filter.tls_inspection import TLSInspectionModule
        from netsec_tester.modules.web_filter.api_abuse import APIAbuseModule
        from netsec_tester.modules.web_filter.web_shells import WebShellsModule
        from netsec_tester.modules.web_filter.http_smuggling import HTTPSmugglingModule

        self.registry.register_module("web_categories", WebCategoryModule)
        self.registry.register_module("url_patterns", URLPatternsModule)
        self.registry.register_module("tls_inspection", TLSInspectionModule)
        self.registry.register_module("api_abuse", APIAbuseModule)
        self.registry.register_module("web_shells", WebShellsModule)
        self.registry.register_module("http_smuggling", HTTPSmugglingModule)

        # Import and register Antivirus modules
        from netsec_tester.modules.antivirus.eicar import EICARModule
        from netsec_tester.modules.antivirus.signatures import AVSignaturesModule
        from netsec_tester.modules.antivirus.ransomware import RansomwareModule
        from netsec_tester.modules.antivirus.cryptominer import CryptominerModule
        from netsec_tester.modules.antivirus.dropper import DropperModule
        from netsec_tester.modules.antivirus.archive_evasion import ArchiveEvasionModule

        self.registry.register_module("eicar", EICARModule)
        self.registry.register_module("av_signatures", AVSignaturesModule)
        self.registry.register_module("ransomware", RansomwareModule)
        self.registry.register_module("cryptominer", CryptominerModule)
        self.registry.register_module("dropper", DropperModule)
        self.registry.register_module("archive_evasion", ArchiveEvasionModule)

        # Import and register Video/Streaming modules
        from netsec_tester.modules.video_filter.streaming import StreamingModule
        from netsec_tester.modules.video_filter.p2p_torrent import P2PTorrentModule
        from netsec_tester.modules.video_filter.voip_webrtc import VoIPWebRTCModule
        from netsec_tester.modules.video_filter.gaming import GamingModule

        self.registry.register_module("streaming", StreamingModule)
        self.registry.register_module("p2p_torrent", P2PTorrentModule)
        self.registry.register_module("voip_webrtc", VoIPWebRTCModule)
        self.registry.register_module("gaming", GamingModule)

        # Import and register Benign traffic modules
        from netsec_tester.modules.benign.web_browsing import WebBrowsingModule
        from netsec_tester.modules.benign.email import EmailModule
        from netsec_tester.modules.benign.file_transfer import FileTransferModule
        from netsec_tester.modules.benign.cloud_services import CloudServicesModule
        from netsec_tester.modules.benign.iot_device import IoTDeviceModule
        from netsec_tester.modules.benign.mobile_app import MobileAppModule
        from netsec_tester.modules.benign.vpn_proxy import VPNProxyModule

        self.registry.register_module("web_browsing", WebBrowsingModule)
        self.registry.register_module("email", EmailModule)
        self.registry.register_module("file_transfer", FileTransferModule)
        self.registry.register_module("cloud_services", CloudServicesModule)
        self.registry.register_module("iot_device", IoTDeviceModule)
        self.registry.register_module("mobile_app", MobileAppModule)
        self.registry.register_module("vpn_proxy", VPNProxyModule)

        # Import and register Exfiltration modules
        from netsec_tester.modules.exfiltration.icmp_covert import ICMPCovertModule
        from netsec_tester.modules.exfiltration.https_exfil import HTTPSExfilModule
        from netsec_tester.modules.exfiltration.protocol_abuse import ProtocolAbuseModule

        self.registry.register_module("icmp_covert", ICMPCovertModule)
        self.registry.register_module("https_exfil", HTTPSExfilModule)
        self.registry.register_module("protocol_abuse", ProtocolAbuseModule)

    def _create_default_config(self, config_path: Path) -> None:
        """Create default configuration file.

        Args:
            config_path: Path where to create the config
        """
        config_path.parent.mkdir(parents=True, exist_ok=True)

        default_config = {
            "scenarios": {
                "quick-test": {
                    "description": "Brief test of all traffic categories",
                    "modules": [
                        "sql_injection",
                        "xss",
                        "dns_tunneling",
                        "dga",
                        "web_categories",
                        "eicar",
                        "web_browsing",
                    ],
                    "ip_pool_size": 5,
                    "packets_per_second": 50,
                    "duration_seconds": 60,
                    "ports": [80, 443, 8080],
                },
                "ips-deep": {
                    "description": "Comprehensive IPS/IDS signature testing",
                    "modules": [
                        "sql_injection",
                        "xss",
                        "command_injection",
                        "directory_traversal",
                        "exploits",
                        "c2_beacon",
                    ],
                    "ip_pool_size": 10,
                    "packets_per_second": 100,
                    "duration_seconds": 0,
                    "ports": [80, 443, 8080, 8443],
                },
                "dns-focus": {
                    "description": "DNS filtering and tunneling tests",
                    "modules": [
                        "dns_tunneling",
                        "dga",
                        "malicious_domains",
                    ],
                    "ip_pool_size": 5,
                    "packets_per_second": 50,
                    "duration_seconds": 0,
                    "ports": [53],
                },
                "web-focus": {
                    "description": "Web filtering category tests",
                    "modules": [
                        "web_categories",
                        "url_patterns",
                    ],
                    "ip_pool_size": 10,
                    "packets_per_second": 100,
                    "duration_seconds": 0,
                    "ports": [80, 443],
                },
                "av-focus": {
                    "description": "Antivirus detection tests",
                    "modules": [
                        "eicar",
                        "av_signatures",
                    ],
                    "ip_pool_size": 5,
                    "packets_per_second": 20,
                    "duration_seconds": 0,
                    "ports": [80, 443, 21],
                },
                "full-mix": {
                    "description": "All modules at maximum coverage",
                    "modules": [
                        "sql_injection",
                        "xss",
                        "command_injection",
                        "directory_traversal",
                        "exploits",
                        "c2_beacon",
                        "dns_tunneling",
                        "dga",
                        "malicious_domains",
                        "web_categories",
                        "url_patterns",
                        "eicar",
                        "av_signatures",
                        "streaming",
                        "web_browsing",
                        "email",
                        "file_transfer",
                    ],
                    "ip_pool_size": 20,
                    "packets_per_second": 200,
                    "duration_seconds": 0,
                    "ports": [21, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443],
                },
                "stealth": {
                    "description": "Low-rate, evasion-focused patterns",
                    "modules": [
                        "sql_injection",
                        "xss",
                        "c2_beacon",
                        "dns_tunneling",
                    ],
                    "ip_pool_size": 3,
                    "packets_per_second": 5,
                    "duration_seconds": 0,
                    "ports": [80, 443],
                    "burst_mode": False,
                },
            }
        }

        with open(config_path, "w") as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            key: Configuration key (dot-separated for nested)
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value
