"""DNS filtering test modules."""

from netsec_tester.modules.dns_filter.amplification import DNSAmplificationModule
from netsec_tester.modules.dns_filter.dga import DGAModule
from netsec_tester.modules.dns_filter.exfiltration import DNSExfiltrationModule
from netsec_tester.modules.dns_filter.fast_flux import FastFluxModule
from netsec_tester.modules.dns_filter.malicious_domains import MaliciousDomainsModule
from netsec_tester.modules.dns_filter.rebinding import DNSRebindingModule
from netsec_tester.modules.dns_filter.tunneling import DNSTunnelingModule

__all__ = [
    "DNSTunnelingModule",
    "DGAModule",
    "MaliciousDomainsModule",
    "DNSExfiltrationModule",
    "DNSRebindingModule",
    "DNSAmplificationModule",
    "FastFluxModule",
]
