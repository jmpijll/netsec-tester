"""Cryptominer detection traffic module."""

import json
import random
from collections.abc import Iterator

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

# Known mining pool domains
MINING_POOLS = [
    "pool.minexmr.com",
    "xmr.nanopool.org",
    "monerohash.com",
    "pool.supportxmr.com",
    "xmr.pool.minergate.com",
    "xmr-eu1.nanopool.org",
    "pool.hashvault.pro",
    "gulf.moneroocean.stream",
    "xmrpool.eu",
    "monero.crypto-pool.fr",
]

# Stratum protocol ports
STRATUM_PORTS = [3333, 4444, 5555, 7777, 8888, 9999, 14444, 45560]

# Coinhive/WebMiner patterns
WEB_MINER_SCRIPTS = [
    "coinhive.min.js",
    "cryptonight.wasm",
    "miner.min.js",
    "crypto-loot.js",
    "deepminer.js",
    "coinimp.js",
    "webmr.js",
]


class CryptominerModule(TrafficModule):
    """Traffic module for cryptominer detection patterns.

    Generates network traffic that simulates cryptocurrency mining
    activity including Stratum protocol and WebMiner patterns.
    """

    def __init__(self) -> None:
        """Initialize the cryptominer module."""
        self._mining_count = 0

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="cryptominer",
            description="Cryptominer detection (Stratum protocol, mining pools, WebMiner)",
            category=TrafficCategory.ANTIVIRUS,
            protocols=["TCP"],
            ports=[3333, 4444, 80, 443],
        )

    def _generate_stratum_subscribe(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Stratum mining.subscribe message."""
        # Stratum protocol subscribe request
        stratum_msg = {"id": 1, "method": "mining.subscribe", "params": ["xmrig/6.18.0", None]}

        payload = json.dumps(stratum_msg) + "\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=payload.encode())
        )
        yield packet

    def _generate_stratum_authorize(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Stratum mining.authorize message."""
        # Fake wallet address
        wallet = "4" + "".join(random.choices("0123456789ABCDEFabcdef", k=94))

        stratum_msg = {"id": 2, "method": "mining.authorize", "params": [wallet, "x"]}

        payload = json.dumps(stratum_msg) + "\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=payload.encode())
        )
        yield packet

    def _generate_stratum_submit(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate Stratum mining.submit message (share submission)."""
        stratum_msg = {
            "id": random.randint(100, 999),
            "method": "mining.submit",
            "params": [
                "worker1",
                f"job_{random.randint(1000, 9999)}",
                "".join(random.choices("0123456789abcdef", k=8)),
                "".join(random.choices("0123456789abcdef", k=64)),
                "".join(random.choices("0123456789abcdef", k=8)),
            ],
        }

        payload = json.dumps(stratum_msg) + "\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=payload.encode())
        )
        yield packet

    def _generate_pool_connection(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate connection to known mining pool."""
        pool = random.choice(MINING_POOLS)

        # HTTP keepalive to pool (some miners use HTTP)
        http_request = (
            f"GET /stats HTTP/1.1\r\n"
            f"Host: {pool}\r\n"
            f"User-Agent: XMRig/6.18.0\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_webminer_script(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate WebMiner script request."""
        script = random.choice(WEB_MINER_SCRIPTS)

        http_request = (
            f"GET /lib/{script} HTTP/1.1\r\n"
            f"Host: coinhive.com\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept: application/javascript\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_websocket_miner(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate WebSocket-based miner connection."""
        # WebSocket upgrade for browser mining
        ws_upgrade = (
            "GET /proxy HTTP/1.1\r\n"
            "Host: ws.coinhive.com\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Origin: https://example.com\r\n"
            "\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=ws_upgrade.encode())
        )
        yield packet

    def _generate_xmrig_api(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate XMRig API communication pattern."""
        # XMRig HTTP API access
        api_endpoints = [
            "/1/summary",
            "/1/backends",
            "/2/backends",
            "/api.json",
        ]

        endpoint = random.choice(api_endpoints)

        http_request = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {dst_ip}:{port}\r\n"
            f"Authorization: Bearer apikey\r\n"
            f"User-Agent: curl/7.68.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )
        yield packet

    def _generate_nicehash_pattern(self, src_ip: str, dst_ip: str, port: int) -> Iterator[Packet]:
        """Generate NiceHash stratum pattern."""
        # NiceHash stratum protocol subscription
        stratum_msg = {"id": 1, "method": "mining.subscribe", "params": ["nicehash/1.0.0"]}

        payload = json.dumps(stratum_msg) + "\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags="PA")
            / Raw(load=payload.encode())
        )
        yield packet

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate cryptominer detection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with cryptominer patterns
        """
        port = dst_port or random.choice(STRATUM_PORTS)
        self._mining_count += 1

        # Rotate through different mining patterns
        pattern = self._mining_count % 8

        if pattern == 0:
            yield from self._generate_stratum_subscribe(src_ip, dst_ip, port)
        elif pattern == 1:
            yield from self._generate_stratum_authorize(src_ip, dst_ip, port)
        elif pattern == 2:
            yield from self._generate_stratum_submit(src_ip, dst_ip, port)
        elif pattern == 3:
            yield from self._generate_pool_connection(src_ip, dst_ip, 80)
        elif pattern == 4:
            yield from self._generate_webminer_script(src_ip, dst_ip, 80)
        elif pattern == 5:
            yield from self._generate_websocket_miner(src_ip, dst_ip, 443)
        elif pattern == 6:
            yield from self._generate_xmrig_api(src_ip, dst_ip, port)
        else:
            yield from self._generate_nicehash_pattern(src_ip, dst_ip, port)
