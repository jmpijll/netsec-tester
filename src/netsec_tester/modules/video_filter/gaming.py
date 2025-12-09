"""Gaming traffic module."""

import random
import struct
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Game platform domains
GAMING_PLATFORMS = {
    "steam": [
        "steamcommunity.com",
        "store.steampowered.com",
        "api.steampowered.com",
        "steamcdn-a.akamaihd.net",
    ],
    "epic": [
        "epicgames.com",
        "launcher-public-service-prod06.ol.epicgames.com",
        "store-content.ak.epicgames.com",
    ],
    "xbox": [
        "xboxlive.com",
        "xbox.com",
        "login.live.com",
        "xnotify.xboxlive.com",
    ],
    "playstation": [
        "playstation.net",
        "playstation.com",
        "account.sonyentertainmentnetwork.com",
    ],
    "battlenet": [
        "battle.net",
        "blizzard.com",
        "us.battle.net",
    ],
}

# Common game server ports
GAME_PORTS = {
    "source": [27015, 27016, 27017],  # Source Engine games
    "minecraft": [25565],
    "unreal": [7777, 7778],
    "generic": [3074, 3478, 3479, 3480],  # Xbox Live, PSN
}


class GamingModule(TrafficModule):
    """Traffic module for gaming traffic patterns.

    Generates network traffic that simulates gaming platform
    communication and game server interactions.
    """

    def __init__(self) -> None:
        """Initialize the gaming module."""
        self._gaming_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="gaming",
            description="Gaming traffic detection (Steam, Xbox Live, PSN, game servers)",
            category=TrafficCategory.VIDEO_FILTER,
            protocols=["TCP", "UDP"],
            ports=[27015, 3074, 25565],
        )

    def _generate_steam_api(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Steam API request pattern."""
        steam_endpoints = [
            "/ISteamUser/GetPlayerSummaries/v2/",
            "/IPlayerService/GetOwnedGames/v1/",
            "/ISteamApps/GetAppList/v2/",
            "/ISteamUserStats/GetUserStatsForGame/v2/",
        ]

        endpoint = random.choice(steam_endpoints)
        api_key = "".join(random.choices("0123456789ABCDEF", k=32))

        http_request = (
            f"GET {endpoint}?key={api_key}&steamid=76561198000000000 HTTP/1.1\r\n"
            f"Host: api.steampowered.com\r\n"
            f"User-Agent: Valve/Steam HTTP Client 1.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_source_query(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate Source Engine server query."""
        # A2S_INFO query: 0xFF 0xFF 0xFF 0xFF 'T' "Source Engine Query\0"
        a2s_info = b"\xff\xff\xff\xffTSource Engine Query\x00"

        port = random.choice(GAME_PORTS["source"])

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(49152, 65535), dport=port)
            / Raw(load=a2s_info)
        )
        yield packet

    def _generate_xbox_live(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate Xbox Live traffic pattern."""
        # Xbox Live uses Teredo tunneling on port 3074
        # Generate UDP pattern
        xbox_data = (
            struct.pack(
                ">IIHH",
                random.randint(0, 0xFFFFFFFF),  # Session ID
                random.randint(0, 0xFFFFFFFF),  # Sequence
                0x0001,  # Message type
                0x0000,  # Flags
            )
            + b"\x00" * 20
        )

        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=3074, dport=3074) / Raw(load=xbox_data)
        yield packet

    def _generate_psn_traffic(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate PlayStation Network traffic pattern."""
        psn_endpoints = [
            "/trophy/v1/users/me/trophyTitles",
            "/userProfile/v1/users/me/profile",
            "/sessionInvitation/v1/users/me",
        ]

        endpoint = random.choice(psn_endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: m.np.playstation.net\r\n"
            f"User-Agent: PlayStation Network\r\n"
            f"Authorization: Bearer psn_token\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_minecraft_ping(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate Minecraft server list ping."""
        # Minecraft protocol: Handshake + Status Request
        # VarInt packet ID (0x00) + Protocol version + Server address + Port + Next state

        # Server List Ping packet (simplified)
        handshake = (
            bytes(
                [
                    0x10,  # Packet length
                    0x00,  # Packet ID (Handshake)
                    0xFD,
                    0x05,  # Protocol version (VarInt, 765 = 1.20.4)
                    0x09,  # Server address length
                ]
            )
            + b"localhost"
            + bytes(
                [
                    0x63,
                    0xDD,  # Port (25565)
                    0x01,  # Next state (1 = status)
                ]
            )
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=25565, flags="PA")
            / Raw(load=handshake)
        )
        yield packet

    def _generate_epic_launcher(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Epic Games Launcher traffic pattern."""
        epic_endpoints = [
            "/account/api/oauth/token",
            "/launcher/api/public/assets/v2/platform/Windows/catalogItem",
            "/friends/api/v1/public/friends/",
        ]

        endpoint = random.choice(epic_endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: launcher-public-service-prod06.ol.epicgames.com\r\n"
            f"User-Agent: EpicGamesLauncher/14.0.0\r\n"
            f"Authorization: bearer EG1~token\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_battlenet(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Battle.net traffic pattern."""
        bnet_endpoints = [
            "/wow/user/characters",
            "/d3/profile/",
            "/hearthstone/cards",
            "/account/api/oauth/token",
        ]

        endpoint = random.choice(bnet_endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: us.api.blizzard.com\r\n"
            f"User-Agent: Battle.net/1.0\r\n"
            f"Authorization: Bearer bnet_token\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_voice_chat(self, src_ip: str, dst_ip: str) -> Iterator[Packet]:
        """Generate in-game voice chat traffic pattern."""
        # Voice data over UDP (similar to RTP)
        voice_header = struct.pack(
            ">BBHI",
            0x80,  # Version + flags
            0x78,  # Payload type (Opus)
            random.randint(0, 65535),  # Sequence
            random.randint(0, 0xFFFFFFFF),  # Timestamp
        )

        # Simulated voice payload
        payload = bytes(random.randint(0, 255) for _ in range(50))

        # Common voice chat ports
        voice_port = random.choice([50000, 50001, 3478, 3479])

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=voice_port, dport=voice_port)
            / Raw(load=voice_header + payload)
        )
        yield packet

    def _generate_game_update(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate game update/patch download pattern."""
        # CDN requests for game updates
        cdns = [
            "steamcdn-a.akamaihd.net",
            "epicgames-download1.akamaized.net",
            "blzddist1-a.akamaihd.net",
        ]

        cdn = random.choice(cdns)

        http_request = (
            f"GET /depot/12345/chunk/abcdef1234567890 HTTP/1.1\r\n"
            f"Host: {cdn}\r\n"
            f"User-Agent: GameClient/1.0\r\n"
            f"Range: bytes=0-1048575\r\n"
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
        """Generate gaming traffic packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with gaming traffic patterns
        """
        port = dst_port or 443
        self._gaming_count += 1

        # Rotate through different gaming patterns
        pattern = self._gaming_count % 9

        if pattern == 0:
            yield from self._generate_steam_api(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_source_query(src_ip, dst_ip)
        elif pattern == 2:
            yield from self._generate_xbox_live(src_ip, dst_ip)
        elif pattern == 3:
            yield from self._generate_psn_traffic(src_ip, dst_ip, port)
        elif pattern == 4:
            yield from self._generate_minecraft_ping(src_ip, dst_ip)
        elif pattern == 5:
            yield from self._generate_epic_launcher(src_ip, dst_ip, port)
        elif pattern == 6:
            yield from self._generate_battlenet(src_ip, dst_ip, port)
        elif pattern == 7:
            yield from self._generate_voice_chat(src_ip, dst_ip)
        else:
            yield from self._generate_game_update(src_ip, dst_ip, port)
