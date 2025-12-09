"""VoIP and WebRTC traffic module."""

import random
import struct
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# SIP methods
SIP_METHODS = ["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS"]

# STUN message types
STUN_BINDING_REQUEST = 0x0001
STUN_MAGIC_COOKIE = 0x2112A442


class VoIPWebRTCModule(TrafficModule):
    """Traffic module for VoIP and WebRTC protocol patterns.

    Generates network traffic that simulates VoIP communication
    including SIP, RTP, and WebRTC signaling.
    """

    def __init__(self) -> None:
        """Initialize the VoIP/WebRTC module."""
        self._voip_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="voip_webrtc",
            description="VoIP/WebRTC detection (SIP, RTP, STUN/TURN)",
            category=TrafficCategory.VIDEO_FILTER,
            protocols=["TCP", "UDP"],
            ports=[5060, 5061, 3478, 19302],
        )

    def _generate_sip_invite(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate SIP INVITE request."""
        call_id = f"{random.randint(100000, 999999)}@{src_ip}"
        from_tag = f"{random.randint(1000, 9999)}"
        branch = f"z9hG4bK{random.randint(100000, 999999)}"

        sip_invite = (
            f"INVITE sip:user@{dst_ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {src_ip}:{port};branch={branch}\r\n"
            f"From: <sip:caller@{src_ip}>;tag={from_tag}\r\n"
            f"To: <sip:user@{dst_ip}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 INVITE\r\n"
            f"Contact: <sip:caller@{src_ip}:{port}>\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=port)
            / Raw(load=sip_invite.encode())
        )
        yield packet

    def _generate_sip_register(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate SIP REGISTER request."""
        call_id = f"{random.randint(100000, 999999)}@{src_ip}"
        branch = f"z9hG4bK{random.randint(100000, 999999)}"

        sip_register = (
            f"REGISTER sip:{dst_ip} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP {src_ip}:{port};branch={branch}\r\n"
            f"From: <sip:user@{dst_ip}>;tag={random.randint(1000, 9999)}\r\n"
            f"To: <sip:user@{dst_ip}>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: 1 REGISTER\r\n"
            f"Contact: <sip:user@{src_ip}:{port}>\r\n"
            f"Expires: 3600\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=port)
            / Raw(load=sip_register.encode())
        )
        yield packet

    def _generate_rtp_stream(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate RTP audio/video stream packet."""
        # RTP header
        # V=2, P=0, X=0, CC=0, M=0, PT=0 (PCMU), sequence, timestamp, SSRC
        version = 2 << 6
        payload_type = 0  # PCMU
        sequence = random.randint(0, 65535)
        timestamp = random.randint(0, 0xFFFFFFFF)
        ssrc = random.randint(0, 0xFFFFFFFF)

        rtp_header = struct.pack(
            ">BBHII",
            version,
            payload_type,
            sequence,
            timestamp,
            ssrc
        )

        # Add some fake audio payload
        payload = bytes(random.randint(0, 255) for _ in range(160))

        rtp_port = random.choice([16384, 16385, 16386, 10000, 10001])

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=rtp_port, dport=rtp_port)
            / Raw(load=rtp_header + payload)
        )
        yield packet

    def _generate_stun_binding(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate STUN Binding Request."""
        # STUN header: type (2) + length (2) + magic cookie (4) + transaction ID (12)
        message_type = STUN_BINDING_REQUEST
        message_length = 0  # No attributes
        magic_cookie = STUN_MAGIC_COOKIE
        transaction_id = bytes(random.randint(0, 255) for _ in range(12))

        stun_header = struct.pack(
            ">HHI",
            message_type,
            message_length,
            magic_cookie
        ) + transaction_id

        # Common STUN ports
        stun_port = random.choice([3478, 19302, 5349])

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=stun_port)
            / Raw(load=stun_header)
        )
        yield packet

    def _generate_turn_allocate(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate TURN Allocate Request."""
        # TURN Allocate (0x0003)
        message_type = 0x0003
        transaction_id = bytes(random.randint(0, 255) for _ in range(12))

        # REQUESTED-TRANSPORT attribute (UDP = 17)
        attr_type = 0x0019
        attr_length = 4
        transport = 17  # UDP
        attr = struct.pack(">HHI", attr_type, attr_length, transport << 24)

        stun_header = struct.pack(
            ">HHI",
            message_type,
            len(attr),
            STUN_MAGIC_COOKIE
        ) + transaction_id + attr

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=3478)
            / Raw(load=stun_header)
        )
        yield packet

    def _generate_webrtc_ice(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate WebRTC ICE candidate exchange (simulated via HTTP)."""
        # SDP offer with ICE candidates
        sdp_offer = {
            "type": "offer",
            "sdp": (
                f"v=0\r\n"
                f"o=- {random.randint(1000000, 9999999)} 2 IN IP4 {src_ip}\r\n"
                f"s=-\r\n"
                f"t=0 0\r\n"
                f"a=ice-ufrag:{random.randint(1000, 9999)}\r\n"
                f"a=ice-pwd:{random.randint(10000000, 99999999)}\r\n"
                f"m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
                f"c=IN IP4 0.0.0.0\r\n"
            )
        }

        import json
        body = json.dumps(sdp_offer)

        http_request = (
            f"POST /webrtc/offer HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
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

    def _generate_h323_setup(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate H.323 Setup message pattern."""
        # H.225.0 Q.931 Setup message (simplified)
        # Protocol discriminator + call reference + message type
        setup_msg = bytes([
            0x08,  # Protocol discriminator (Q.931)
            0x02,  # Call reference length
            0x00, 0x01,  # Call reference value
            0x05,  # Setup message type
        ]) + b"\x00" * 20  # Padding

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=1720, flags="PA")
            / Raw(load=setup_msg)
        )
        yield packet

    def _generate_teams_traffic(
        self, src_ip: str, dst_ip: str, port: int
    ) -> Iterator[Packet]:
        """Generate Microsoft Teams-like traffic pattern."""
        # Teams API call pattern
        teams_endpoints = [
            "/v1/users/me/conversations",
            "/v1/users/me/presence",
            "/api/chatsvc/emea/consumer",
            "/Calling/api/v1/call",
        ]

        endpoint = random.choice(teams_endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: teams.microsoft.com\r\n"
            f"User-Agent: Microsoft Teams\r\n"
            f"Authorization: Bearer token123\r\n"
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
        """Generate VoIP/WebRTC packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with VoIP/WebRTC patterns
        """
        port = dst_port or 5060
        self._voip_count += 1

        # Rotate through different VoIP patterns
        pattern = self._voip_count % 8

        if pattern == 0:
            yield from self._generate_sip_invite(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_sip_register(src_ip, dst_ip, port)
        elif pattern == 2:
            yield from self._generate_rtp_stream(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_stun_binding(src_ip, dst_ip)
        elif pattern == 4:
            yield from self._generate_turn_allocate(src_ip, dst_ip)
        elif pattern == 5:
            yield from self._generate_webrtc_ice(src_ip, dst_ip, 443)
        elif pattern == 6:
            yield from self._generate_h323_setup(src_ip, dst_ip)
        else:
            yield from self._generate_teams_traffic(src_ip, dst_ip, 443)

