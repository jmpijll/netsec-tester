"""Antivirus detection test modules."""

from netsec_tester.modules.antivirus.eicar import EICARModule
from netsec_tester.modules.antivirus.signatures import AVSignaturesModule
from netsec_tester.modules.antivirus.ransomware import RansomwareModule
from netsec_tester.modules.antivirus.cryptominer import CryptominerModule
from netsec_tester.modules.antivirus.dropper import DropperModule
from netsec_tester.modules.antivirus.archive_evasion import ArchiveEvasionModule

__all__ = [
    "EICARModule",
    "AVSignaturesModule",
    "RansomwareModule",
    "CryptominerModule",
    "DropperModule",
    "ArchiveEvasionModule",
]
