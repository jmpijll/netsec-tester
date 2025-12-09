"""IPS/IDS signature trigger modules."""

from netsec_tester.modules.ips_ids.sql_injection import SQLInjectionModule
from netsec_tester.modules.ips_ids.xss import XSSModule
from netsec_tester.modules.ips_ids.command_injection import CommandInjectionModule
from netsec_tester.modules.ips_ids.directory_traversal import DirectoryTraversalModule
from netsec_tester.modules.ips_ids.exploits import ExploitsModule
from netsec_tester.modules.ips_ids.c2_beacon import C2BeaconModule

__all__ = [
    "SQLInjectionModule",
    "XSSModule",
    "CommandInjectionModule",
    "DirectoryTraversalModule",
    "ExploitsModule",
    "C2BeaconModule",
]


