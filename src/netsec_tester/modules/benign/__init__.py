"""Benign traffic generation modules."""

from netsec_tester.modules.benign.web_browsing import WebBrowsingModule
from netsec_tester.modules.benign.email import EmailModule
from netsec_tester.modules.benign.file_transfer import FileTransferModule
from netsec_tester.modules.benign.cloud_services import CloudServicesModule
from netsec_tester.modules.benign.iot_device import IoTDeviceModule
from netsec_tester.modules.benign.mobile_app import MobileAppModule
from netsec_tester.modules.benign.vpn_proxy import VPNProxyModule

__all__ = [
    "WebBrowsingModule",
    "EmailModule",
    "FileTransferModule",
    "CloudServicesModule",
    "IoTDeviceModule",
    "MobileAppModule",
    "VPNProxyModule",
]
