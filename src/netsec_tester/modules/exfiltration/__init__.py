"""Data exfiltration detection modules."""

from netsec_tester.modules.exfiltration.https_exfil import HTTPSExfilModule
from netsec_tester.modules.exfiltration.icmp_covert import ICMPCovertModule
from netsec_tester.modules.exfiltration.protocol_abuse import ProtocolAbuseModule

__all__ = [
    "ICMPCovertModule",
    "HTTPSExfilModule",
    "ProtocolAbuseModule",
]
