"""Mobile app traffic module."""

import json
import random
from typing import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Mobile app store endpoints
APP_STORES = {
    "apple": [
        "itunes.apple.com",
        "apps.apple.com",
        "api.apps.apple.com",
        "ppq.apple.com",
    ],
    "google": [
        "play.googleapis.com",
        "android.clients.google.com",
        "play.google.com",
    ],
}

# Push notification services
PUSH_SERVICES = {
    "apns": "api.push.apple.com",
    "fcm": "fcm.googleapis.com",
    "firebase": "firebaseinstallations.googleapis.com",
}


class MobileAppModule(TrafficModule):
    """Traffic module for mobile app traffic patterns.

    Generates HTTP traffic that simulates legitimate mobile application
    communication including app stores, push notifications, and analytics.
    """

    def __init__(self) -> None:
        """Initialize the mobile app module."""
        self._mobile_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="mobile_app",
            description="Mobile app traffic (app stores, push notifications, analytics)",
            category=TrafficCategory.BENIGN,
            protocols=["TCP"],
            ports=[443, 80],
        )

    def _generate_app_store_request(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate app store API request."""
        store = random.choice(["apple", "google"])
        host = random.choice(APP_STORES[store])

        if store == "apple":
            path = f"/WebObjects/MZStore.woa/wa/viewGrouping?id={random.randint(1000000, 9999999)}"
            user_agent = "AppStore/3.0 iOS/17.0"
        else:
            path = f"/fdfe/details?doc=com.app.example.{random.randint(1000, 9999)}"
            user_agent = "Android-Finsky/30.0.0-21"

        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {user_agent}\r\n"
            f"Accept: application/json\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_push_notification(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate push notification service request."""
        service = random.choice(list(PUSH_SERVICES.keys()))
        host = PUSH_SERVICES[service]

        if service == "apns":
            # APNs HTTP/2 style request
            device_token = "".join(random.choices("0123456789abcdef", k=64))
            path = f"/3/device/{device_token}"
            body = json.dumps({"aps": {"alert": "Test notification"}})
        else:
            # FCM request
            path = "/fcm/send"
            body = json.dumps({
                "to": f"device_token_{random.randint(1000, 9999)}",
                "notification": {"title": "Test", "body": "Message"}
            })

        http_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Authorization: key=AIzaSy...\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
            f"{body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_analytics(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate mobile analytics traffic."""
        analytics_endpoints = [
            ("www.google-analytics.com", "/collect"),
            ("app.adjust.com", "/session"),
            ("api2.branch.io", "/v1/open"),
            ("api.mixpanel.com", "/track"),
            ("api.segment.io", "/v1/track"),
        ]

        host, path = random.choice(analytics_endpoints)

        analytics_data = {
            "event": random.choice(["app_open", "screen_view", "purchase", "login"]),
            "app_version": "1.0.0",
            "device_id": f"device-{random.randint(100000, 999999)}",
            "timestamp": "2023-12-15T12:00:00Z"
        }

        body = json.dumps(analytics_data)

        http_request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"User-Agent: MyApp/1.0 iOS/17.0\r\n"
            f"\r\n"
            f"{body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_crash_report(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate crash reporting service traffic."""
        crash_services = [
            "firebase-crashlytics.googleapis.com",
            "api.bugsnag.com",
            "sentry.io",
            "api.crashlytics.com",
        ]

        host = random.choice(crash_services)

        crash_data = {
            "app_id": f"com.app.example.{random.randint(1000, 9999)}",
            "version": "1.0.0",
            "crash_id": f"crash-{random.randint(100000, 999999)}",
            "platform": random.choice(["iOS", "Android"])
        }

        body = json.dumps(crash_data)

        http_request = (
            f"POST /v1/crash HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"User-Agent: Crashlytics/1.0\r\n"
            f"\r\n"
            f"{body}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_app_update_check(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate app update check request."""
        http_request = (
            f"GET /api/v1/version/check?app_id=com.myapp&current_version=1.0.0 HTTP/1.1\r\n"
            f"Host: api.myapp.com\r\n"
            f"User-Agent: MyApp/1.0 Android/14\r\n"
            f"Accept: application/json\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_social_sdk(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate social SDK traffic (Facebook, Twitter, etc.)."""
        social_hosts = [
            "graph.facebook.com",
            "api.twitter.com",
            "api.instagram.com",
            "api.linkedin.com",
        ]

        host = random.choice(social_hosts)

        http_request = (
            f"GET /v17.0/me HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Authorization: Bearer access_token_here\r\n"
            f"User-Agent: FacebookSDK/17.0.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_in_app_purchase(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate in-app purchase verification request."""
        # Apple receipt verification style
        receipt_data = {
            "receipt-data": "MIITtQYJKoZIhvcNAQcCoII...",
            "password": "shared_secret"
        }

        body = json.dumps(receipt_data)

        http_request = (
            f"POST /verifyReceipt HTTP/1.1\r\n"
            f"Host: buy.itunes.apple.com\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"User-Agent: iPhone\r\n"
            f"\r\n"
            f"{body}"
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
        """Generate mobile app traffic packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with mobile app traffic patterns
        """
        port = dst_port or 443
        self._mobile_count += 1

        # Rotate through different mobile traffic patterns
        pattern = self._mobile_count % 7

        if pattern == 0:
            yield from self._generate_app_store_request(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_push_notification(src_ip, dst_ip, port)
        elif pattern == 2:
            yield from self._generate_analytics(src_ip, dst_ip, port)
        elif pattern == 3:
            yield from self._generate_crash_report(src_ip, dst_ip, port)
        elif pattern == 4:
            yield from self._generate_app_update_check(src_ip, dst_ip, port)
        elif pattern == 5:
            yield from self._generate_social_sdk(src_ip, dst_ip, port)
        else:
            yield from self._generate_in_app_purchase(src_ip, dst_ip, port)

