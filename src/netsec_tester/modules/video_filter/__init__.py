"""Video and streaming detection test modules."""

from netsec_tester.modules.video_filter.streaming import StreamingModule
from netsec_tester.modules.video_filter.p2p_torrent import P2PTorrentModule
from netsec_tester.modules.video_filter.voip_webrtc import VoIPWebRTCModule
from netsec_tester.modules.video_filter.gaming import GamingModule

__all__ = [
    "StreamingModule",
    "P2PTorrentModule",
    "VoIPWebRTCModule",
    "GamingModule",
]
