"""Benign traffic generation modules."""

from netsec_tester.modules.benign.web_browsing import WebBrowsingModule
from netsec_tester.modules.benign.email import EmailModule
from netsec_tester.modules.benign.file_transfer import FileTransferModule

__all__ = [
    "WebBrowsingModule",
    "EmailModule",
    "FileTransferModule",
]


