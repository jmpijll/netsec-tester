"""Antivirus detection test modules."""

from netsec_tester.modules.antivirus.eicar import EICARModule
from netsec_tester.modules.antivirus.signatures import AVSignaturesModule

__all__ = [
    "EICARModule",
    "AVSignaturesModule",
]


