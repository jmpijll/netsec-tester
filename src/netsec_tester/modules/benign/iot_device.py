"""IoT device traffic module."""

import json
import random
import struct
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# MQTT message types
MQTT_CONNECT = 0x10
MQTT_PUBLISH = 0x30
MQTT_SUBSCRIBE = 0x82


class IoTDeviceModule(TrafficModule):
    """Traffic module for IoT device traffic patterns.

    Generates network traffic that simulates legitimate IoT device
    communication including MQTT, CoAP, and smart home protocols.
    """

    def __init__(self) -> None:
        """Initialize the IoT device module."""
        self._iot_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="iot_device",
            description="IoT device traffic (MQTT, CoAP, smart home protocols)",
            category=TrafficCategory.BENIGN,
            protocols=["TCP", "UDP"],
            ports=[1883, 8883, 5683],
        )

    def _generate_mqtt_connect(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate MQTT CONNECT packet."""
        client_id = f"device-{random.randint(1000, 9999)}"

        # MQTT CONNECT packet
        # Protocol name + level + flags + keepalive + client ID
        protocol = b"\x00\x04MQTT"
        level = b"\x04"  # MQTT 3.1.1
        flags = b"\x02"  # Clean session
        keepalive = struct.pack(">H", 60)
        client_id_len = struct.pack(">H", len(client_id))

        payload = protocol + level + flags + keepalive + client_id_len + client_id.encode()
        remaining_length = len(payload)

        mqtt_packet = bytes([MQTT_CONNECT, remaining_length]) + payload

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=1883, flags="PA")
            / Raw(load=mqtt_packet)
        )
        yield packet

    def _generate_mqtt_publish(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate MQTT PUBLISH packet."""
        topics = [
            "home/livingroom/temperature",
            "home/kitchen/humidity",
            "devices/sensor/1234/status",
            "home/garage/door",
        ]

        topic = random.choice(topics)
        message = json.dumps({
            "value": round(random.uniform(20.0, 30.0), 1),
            "unit": "celsius",
            "timestamp": "2023-12-15T12:00:00Z"
        })

        # MQTT PUBLISH packet
        topic_len = struct.pack(">H", len(topic))
        payload = topic_len + topic.encode() + message.encode()
        remaining_length = len(payload)

        mqtt_packet = bytes([MQTT_PUBLISH, remaining_length]) + payload

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=1883, flags="PA")
            / Raw(load=mqtt_packet)
        )
        yield packet

    def _generate_coap_request(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate CoAP GET request."""
        # CoAP header: Ver(2) + Type(2) + TKL(4) + Code(8) + Message ID(16)
        # Ver=1, Type=0 (CON), TKL=0
        version_type_tkl = 0x40
        code = 0x01  # GET
        message_id = random.randint(0, 65535)

        coap_header = bytes([version_type_tkl, code]) + struct.pack(">H", message_id)

        # URI-Path option (11) for /sensor/temperature
        option_delta = 11 << 4 | 6  # Delta=11, Length=6
        uri_path = b"sensor"

        coap_packet = coap_header + bytes([option_delta]) + uri_path

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=5683)
            / Raw(load=coap_packet)
        )
        yield packet

    def _generate_zigbee_gateway(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Zigbee gateway API request."""
        # Philips Hue style API
        endpoints = [
            "/api/newdeveloper/lights",
            "/api/newdeveloper/groups",
            "/api/newdeveloper/sensors",
            "/api/newdeveloper/config",
        ]

        endpoint = random.choice(endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: philips-hue.local\r\n"
            f"User-Agent: Hue/2.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_smart_plug(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate smart plug communication pattern."""
        # TP-Link Kasa style local API
        command = json.dumps({
            "system": {
                "get_sysinfo": {}
            }
        })

        # TP-Link uses a simple XOR encryption - this is plaintext pattern
        http_request = (
            f"POST /app HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(command)}\r\n"
            f"\r\n"
            f"{command}"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_thermostat(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate smart thermostat API request."""
        # Nest-style API pattern
        endpoints = [
            "/devices/thermostats",
            "/structures",
            "/devices/smoke_co_alarms",
        ]

        endpoint = random.choice(endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: developer-api.nest.com\r\n"
            f"Authorization: Bearer c.nest_token_here\r\n"
            f"Content-Type: application/json\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_camera_stream(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate IP camera RTSP-like pattern."""
        # RTSP DESCRIBE request
        rtsp_request = (
            f"DESCRIBE rtsp://{dst_ip}:554/stream1 RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"Accept: application/sdp\r\n"
            f"User-Agent: LIVE555 Streaming Media v2021.08.23\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=554, flags="PA")
            / Raw(load=rtsp_request.encode())
        )
        yield packet

    def _generate_home_assistant(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Home Assistant API request."""
        endpoints = [
            "/api/states",
            "/api/services",
            "/api/events",
            "/api/config",
        ]

        endpoint = random.choice(endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: homeassistant.local:8123\r\n"
            f"Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...\r\n"
            f"Content-Type: application/json\r\n"
            f"\r\n"
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
        """Generate IoT device packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with IoT device patterns
        """
        port = dst_port or 80
        self._iot_count += 1

        # Rotate through different IoT patterns
        pattern = self._iot_count % 8

        if pattern == 0:
            yield from self._generate_mqtt_connect(src_ip, dst_ip)
        elif pattern == 1:
            yield from self._generate_mqtt_publish(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_coap_request(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_zigbee_gateway(src_ip, dst_ip, port)
        elif pattern == 4:
            yield from self._generate_smart_plug(src_ip, dst_ip, port)
        elif pattern == 5:
            yield from self._generate_thermostat(src_ip, dst_ip, port)
        elif pattern == 6:
            yield from self._generate_camera_stream(src_ip, dst_ip, port)
        else:
            yield from self._generate_home_assistant(src_ip, dst_ip, port)

