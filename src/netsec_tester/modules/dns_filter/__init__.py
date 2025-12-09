"""DNS filtering test modules."""

from netsec_tester.modules.dns_filter.tunneling import DNSTunnelingModule
from netsec_tester.modules.dns_filter.dga import DGAModule
from netsec_tester.modules.dns_filter.malicious_domains import MaliciousDomainsModule

__all__ = [
    "DNSTunnelingModule",
    "DGAModule",
    "MaliciousDomainsModule",
]


