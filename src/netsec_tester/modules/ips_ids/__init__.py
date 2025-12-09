"""IPS/IDS signature trigger modules."""

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

__all__ = [
    "SQLInjectionModule",
    "XSSModule",
    "CommandInjectionModule",
    "DirectoryTraversalModule",
    "ExploitsModule",
    "C2BeaconModule",
    "ReconnaissanceModule",
    "DoSPatternsModule",
    "BruteForceModule",
    "ProtocolAnomalyModule",
    "SSRFXXEModule",
    "DeserializationModule",
]
