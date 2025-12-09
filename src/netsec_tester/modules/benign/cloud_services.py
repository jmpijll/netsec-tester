"""Cloud services traffic module."""

import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Cloud provider endpoints
AWS_ENDPOINTS = [
    "s3.amazonaws.com",
    "ec2.amazonaws.com",
    "lambda.amazonaws.com",
    "dynamodb.amazonaws.com",
    "sqs.amazonaws.com",
    "sns.amazonaws.com",
]

AZURE_ENDPOINTS = [
    "blob.core.windows.net",
    "management.azure.com",
    "login.microsoftonline.com",
    "graph.microsoft.com",
    "vault.azure.net",
]

GCP_ENDPOINTS = [
    "storage.googleapis.com",
    "compute.googleapis.com",
    "container.googleapis.com",
    "bigquery.googleapis.com",
]

O365_ENDPOINTS = [
    "outlook.office365.com",
    "graph.microsoft.com",
    "login.microsoftonline.com",
    "sharepoint.com",
    "teams.microsoft.com",
]


class CloudServicesModule(TrafficModule):
    """Traffic module for cloud service traffic patterns.

    Generates HTTP traffic that simulates legitimate cloud service
    API calls and interactions.
    """

    def __init__(self) -> None:
        """Initialize the cloud services module."""
        self._cloud_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="cloud_services",
            description="Cloud services traffic (AWS, Azure, GCP, Office 365)",
            category=TrafficCategory.BENIGN,
            protocols=["TCP"],
            ports=[443, 80],
        )

    def _generate_aws_s3(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate AWS S3 API request."""
        bucket = f"my-bucket-{random.randint(1000, 9999)}"
        key = f"data/file-{random.randint(100, 999)}.json"

        http_request = (
            f"GET /{bucket}/{key} HTTP/1.1\r\n"
            f"Host: s3.amazonaws.com\r\n"
            f"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\r\n"
            f"x-amz-date: 20231215T120000Z\r\n"
            f"x-amz-content-sha256: UNSIGNED-PAYLOAD\r\n"
            f"User-Agent: aws-sdk-python/1.26.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_aws_ec2(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate AWS EC2 API request."""
        actions = [
            "DescribeInstances",
            "DescribeSecurityGroups",
            "DescribeVpcs",
            "DescribeSubnets",
        ]

        action = random.choice(actions)

        http_request = (
            f"POST / HTTP/1.1\r\n"
            f"Host: ec2.amazonaws.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE\r\n"
            f"X-Amz-Date: 20231215T120000Z\r\n"
            f"User-Agent: aws-sdk-python/1.26.0\r\n"
            f"\r\n"
            f"Action={action}&Version=2016-11-15"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_azure_blob(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Azure Blob Storage request."""
        account = f"storageaccount{random.randint(100, 999)}"
        container = "mycontainer"
        blob = f"data-{random.randint(1000, 9999)}.json"

        http_request = (
            f"GET /{container}/{blob} HTTP/1.1\r\n"
            f"Host: {account}.blob.core.windows.net\r\n"
            f"x-ms-version: 2021-08-06\r\n"
            f"x-ms-date: Thu, 15 Dec 2023 12:00:00 GMT\r\n"
            f"Authorization: SharedKey {account}:signature\r\n"
            f"User-Agent: Azure-SDK-Python/12.0.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_azure_management(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Azure Management API request."""
        subscription = f"sub-{random.randint(10000, 99999)}"

        http_request = (
            f"GET /subscriptions/{subscription}/resourceGroups HTTP/1.1\r\n"
            f"Host: management.azure.com\r\n"
            f"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjE...\r\n"
            f"api-version: 2021-04-01\r\n"
            f"User-Agent: Azure-SDK-Python/1.0.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_gcp_storage(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate GCP Cloud Storage request."""
        bucket = f"my-gcp-bucket-{random.randint(1000, 9999)}"
        obj = f"data/object-{random.randint(100, 999)}.json"

        http_request = (
            f"GET /storage/v1/b/{bucket}/o/{obj} HTTP/1.1\r\n"
            f"Host: storage.googleapis.com\r\n"
            f"Authorization: Bearer ya29.access_token\r\n"
            f"User-Agent: google-cloud-sdk gcloud/400.0.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_office365(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Office 365 API request."""
        endpoints = [
            "/v1.0/me/messages",
            "/v1.0/me/drive/root/children",
            "/v1.0/me/calendar/events",
            "/v1.0/users",
        ]

        endpoint = random.choice(endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: graph.microsoft.com\r\n"
            f"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IjE...\r\n"
            f"User-Agent: Microsoft Office/16.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_salesforce(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Salesforce API request."""
        endpoints = [
            "/services/data/v58.0/sobjects/Account",
            "/services/data/v58.0/query/?q=SELECT+Id+FROM+Contact",
            "/services/data/v58.0/chatter/feeds/news/me/feed-elements",
        ]

        endpoint = random.choice(endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: mycompany.salesforce.com\r\n"
            f"Authorization: Bearer 00D0x000000xxxxx!AQEAQE...\r\n"
            f"Content-Type: application/json\r\n"
            f"User-Agent: Salesforce/1.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_dropbox(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Dropbox API request."""
        http_request = (
            "POST /2/files/list_folder HTTP/1.1\r\n"
            "Host: api.dropboxapi.com\r\n"
            "Authorization: Bearer sl.access_token_here\r\n"
            "Content-Type: application/json\r\n"
            'Dropbox-API-Arg: {"path": ""}\r\n'
            "User-Agent: Dropbox-SDK-Python/11.0.0\r\n"
            "\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate cloud service packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with cloud service patterns
        """
        port = dst_port or 443
        self._cloud_count += 1

        # Rotate through different cloud services
        service = self._cloud_count % 8

        if service == 0:
            yield from self._generate_aws_s3(src_ip, dst_ip, port)
        elif service == 1:
            yield from self._generate_aws_ec2(src_ip, dst_ip, port)
        elif service == 2:
            yield from self._generate_azure_blob(src_ip, dst_ip, port)
        elif service == 3:
            yield from self._generate_azure_management(src_ip, dst_ip, port)
        elif service == 4:
            yield from self._generate_gcp_storage(src_ip, dst_ip, port)
        elif service == 5:
            yield from self._generate_office365(src_ip, dst_ip, port)
        elif service == 6:
            yield from self._generate_salesforce(src_ip, dst_ip, port)
        else:
            yield from self._generate_dropbox(src_ip, dst_ip, port)

