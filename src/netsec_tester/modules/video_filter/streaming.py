"""Video and streaming protocol detection module."""

import random
from typing import Iterator

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet, Raw

from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule


# Streaming platform patterns for detection
STREAMING_PATTERNS = {
    "youtube": {
        "hosts": [
            "www.youtube.com",
            "youtube.com",
            "youtu.be",
            "googlevideo.com",
            "ytimg.com",
        ],
        "paths": [
            "/watch?v=dQw4w9WgXcQ",
            "/embed/video123",
            "/api/stats/playback",
            "/videoplayback",
        ],
    },
    "netflix": {
        "hosts": [
            "www.netflix.com",
            "netflix.com",
            "nflxvideo.net",
            "nflximg.net",
        ],
        "paths": [
            "/watch/80057281",
            "/api/shakti/mre",
            "/range/",
            "/playback/",
        ],
    },
    "twitch": {
        "hosts": [
            "www.twitch.tv",
            "twitch.tv",
            "usher.ttvnw.net",
            "video-weaver.jfk04.hls.ttvnw.net",
        ],
        "paths": [
            "/videos/123456",
            "/directory/game/",
            "/api/channel/hls/",
        ],
    },
    "tiktok": {
        "hosts": [
            "www.tiktok.com",
            "tiktok.com",
            "v16-webapp.tiktok.com",
            "v19.tiktokcdn.com",
        ],
        "paths": [
            "/@user/video/",
            "/api/video/",
            "/aweme/v1/play/",
        ],
    },
    "spotify": {
        "hosts": [
            "open.spotify.com",
            "api.spotify.com",
            "audio-ak.spotifycdn.com",
        ],
        "paths": [
            "/track/",
            "/playlist/",
            "/v1/me/player/",
        ],
    },
    "adult": {
        "hosts": [
            "adult-streaming-test.example.com",
            "video-adult-test.example.net",
        ],
        "paths": [
            "/video/",
            "/embed/",
            "/stream/",
        ],
    },
}

# Streaming protocol patterns
PROTOCOL_PATTERNS = {
    "hls": {
        "content_type": "application/vnd.apple.mpegurl",
        "extension": ".m3u8",
        "path": "/playlist.m3u8",
    },
    "dash": {
        "content_type": "application/dash+xml",
        "extension": ".mpd",
        "path": "/manifest.mpd",
    },
    "rtmp": {
        "port": 1935,
        "handshake": b"\x03" + b"\x00" * 1536,
    },
}


class StreamingModule(TrafficModule):
    """Traffic module for video/streaming detection.

    Generates traffic patterns that mimic streaming services
    to test video filtering policies.
    """

    def __init__(self) -> None:
        """Initialize the streaming module."""
        self._request_count = 0
        self._platforms = list(STREAMING_PATTERNS.keys())

    def get_info(self) -> ModuleInfo:
        """Return module information."""
        return ModuleInfo(
            name="streaming",
            description="Video streaming platform patterns for content filtering",
            category=TrafficCategory.VIDEO,
            protocols=["TCP", "HTTP", "RTMP"],
            ports=[80, 443, 1935, 8080],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate streaming detection packets.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port

        Yields:
            Scapy packets with streaming patterns
        """
        port = dst_port or 80
        self._request_count += 1

        # Select platform
        platform = self._platforms[self._request_count % len(self._platforms)]
        pattern = STREAMING_PATTERNS[platform]

        host = random.choice(pattern["hosts"])
        path = random.choice(pattern["paths"])

        # Generate HTTP request to streaming service
        http_request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            f"Accept: */*\r\n"
            f"Accept-Language: en-US,en;q=0.5\r\n"
            f"Origin: https://{host}\r\n"
            f"Referer: https://{host}/\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet

        # Generate HLS/DASH playlist request
        proto_type = self._request_count % 2
        if proto_type == 0:
            # HLS
            proto = PROTOCOL_PATTERNS["hls"]
            playlist_request = (
                f"GET /live/stream{proto['path']} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Accept: {proto['content_type']}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )
        else:
            # DASH
            proto = PROTOCOL_PATTERNS["dash"]
            playlist_request = (
                f"GET /video/stream{proto['path']} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Accept: {proto['content_type']}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=playlist_request.encode())
        )

        yield packet

        # Generate video segment request
        segment_request = (
            f"GET /video/segment_{random.randint(1, 100)}.ts HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Accept: video/MP2T\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Range: bytes=0-1048575\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._request_count % 25000), dport=port, flags="PA")
            / Raw(load=segment_request.encode())
        )

        yield packet

