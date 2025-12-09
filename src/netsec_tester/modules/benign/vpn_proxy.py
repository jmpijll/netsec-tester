"""VPN and proxy detection traffic module."""

import random
import struct
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


class VPNProxyModule(TrafficModule):
    """Traffic module for VPN and proxy protocol patterns.

    Generates network traffic that simulates VPN tunnel establishment
    and proxy communication patterns.
    """

    def __init__(self) -> None:
        """Initialize the VPN/proxy module."""
        self._vpn_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="vpn_proxy",
            description="VPN/proxy detection (OpenVPN, WireGuard, SOCKS, SSH tunnels)",
            category=TrafficCategory.BENIGN,
            protocols=["TCP", "UDP"],
            ports=[1194, 51820, 1080, 22],
        )

    def _generate_openvpn_handshake(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate OpenVPN handshake packet."""
        # OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2
        opcode = 0x38  # P_CONTROL_HARD_RESET_CLIENT_V2 (7 << 3)
        session_id = bytes(random.randint(0, 255) for _ in range(8))
        packet_id = struct.pack(">I", 0)

        # HMAC placeholder + packet_id_array_len + remote_session_id placeholder
        openvpn_packet = bytes([opcode]) + session_id + bytes(8) + packet_id + bytes([0])

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=1194)
            / Raw(load=openvpn_packet)
        )
        yield packet

    def _generate_wireguard_handshake(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate WireGuard handshake initiation packet."""
        # WireGuard handshake initiation
        message_type = struct.pack("<I", 1)  # Handshake initiation
        sender_index = struct.pack("<I", random.randint(0, 0xFFFFFFFF))
        # Ephemeral public key (32 bytes) + encrypted static + encrypted timestamp
        ephemeral = bytes(random.randint(0, 255) for _ in range(32))

        wireguard_packet = message_type + sender_index + ephemeral + bytes(48)  # Simplified

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=51820)
            / Raw(load=wireguard_packet)
        )
        yield packet

    def _generate_ipsec_ike(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate IPsec IKE initiation packet."""
        # IKE header
        initiator_spi = bytes(random.randint(0, 255) for _ in range(8))
        responder_spi = bytes(8)  # Zero for SA_INIT
        next_payload = 0x21  # Security Association
        version = 0x20  # IKEv2
        exchange_type = 0x22  # IKE_SA_INIT
        flags = 0x08  # Initiator
        message_id = struct.pack(">I", 0)
        length = struct.pack(">I", 28)  # Header only

        ike_header = (
            initiator_spi
            + responder_spi
            + bytes([next_payload, version, exchange_type, flags])
            + message_id
            + length
        )

        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike_header)
        yield packet

    def _generate_socks5_handshake(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate SOCKS5 handshake packet."""
        # SOCKS5 greeting
        # Version + Number of methods + Methods
        socks_greeting = bytes(
            [
                0x05,  # SOCKS version 5
                0x02,  # 2 authentication methods
                0x00,  # No authentication
                0x02,  # Username/password
            ]
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=socks_greeting)
        )
        yield packet

    def _generate_socks5_connect(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate SOCKS5 CONNECT request."""
        # SOCKS5 CONNECT request
        # Version + Command + Reserved + Address type + Address + Port
        target_host = "www.example.com"

        socks_connect = (
            bytes(
                [
                    0x05,  # Version
                    0x01,  # CONNECT
                    0x00,  # Reserved
                    0x03,  # Domain name
                    len(target_host),  # Domain length
                ]
            )
            + target_host.encode()
            + struct.pack(">H", 80)
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=socks_connect)
        )
        yield packet

    def _generate_ssh_tunnel(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate SSH tunnel establishment pattern."""
        # SSH version string
        ssh_banner = "SSH-2.0-OpenSSH_8.9\r\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=22, flags="PA")
            / Raw(load=ssh_banner.encode())
        )
        yield packet

    def _generate_http_proxy(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate HTTP CONNECT proxy request."""
        target = f"www.example.com:{random.choice([80, 443])}"

        http_connect = (
            f"CONNECT {target} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_connect.encode())
        )
        yield packet

    def _generate_ssl_vpn(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate SSL VPN pattern (Cisco AnyConnect style)."""
        # SSL VPN usually starts with HTTPS to specific paths
        vpn_paths = [
            "/+CSCOE+/logon.html",
            "/+webvpn+/index.html",
            "/dana-na/auth/url_default/welcome.cgi",
            "/remote/login",
        ]

        path = random.choice(vpn_paths)

        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: vpn.company.com\r\n"
            f"User-Agent: AnyConnect\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_tor_circuit(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Tor-like circuit establishment pattern."""
        # Tor cells are 512 bytes, starting with circuit ID and command
        circuit_id = struct.pack(">I", random.randint(1, 0xFFFFFFFF))
        command = bytes([0x01])  # CREATE cell
        # TAP handshake data (simplified)
        handshake_data = bytes(random.randint(0, 255) for _ in range(128))

        tor_cell = circuit_id + command + handshake_data

        # Usually over TLS on port 443 or 9001
        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=tor_cell)
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate VPN/proxy packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with VPN/proxy patterns
        """
        port = dst_port or 443
        self._vpn_count += 1

        # Rotate through different VPN/proxy patterns
        pattern = self._vpn_count % 9

        if pattern == 0:
            yield from self._generate_openvpn_handshake(src_ip, dst_ip)
        elif pattern == 1:
            yield from self._generate_wireguard_handshake(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_ipsec_ike(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_socks5_handshake(src_ip, dst_ip, 1080)
        elif pattern == 4:
            yield from self._generate_socks5_connect(src_ip, dst_ip, 1080)
        elif pattern == 5:
            yield from self._generate_ssh_tunnel(src_ip, dst_ip)
        elif pattern == 6:
            yield from self._generate_http_proxy(src_ip, dst_ip, 8080)
        elif pattern == 7:
            yield from self._generate_ssl_vpn(src_ip, dst_ip, port)
        else:
            yield from self._generate_tor_circuit(src_ip, dst_ip, port)
