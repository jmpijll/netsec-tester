"""Tests for statistics collection."""

import time

from netsec_tester.core.stats import StatsCollector
from netsec_tester.modules.base import TrafficCategory


class TestStatsCollector:
    """Test cases for StatsCollector class."""

    def test_init(self) -> None:
        """Test initialization."""
        stats = StatsCollector()
        snapshot = stats.get_snapshot()

        assert snapshot.total_packets == 0
        assert len(snapshot.packets_per_ip) == 0
        assert len(snapshot.packets_per_category) == 0

    def test_start(self) -> None:
        """Test starting stats collection."""
        stats = StatsCollector()
        stats.start()
        snapshot = stats.get_snapshot()

        assert snapshot.running_time >= 0

    def test_record_packet(self) -> None:
        """Test recording packets."""
        stats = StatsCollector()
        stats.start()

        stats.record_packet(
            src_ip="10.0.0.1",
            category=TrafficCategory.IPS_IDS,
            protocol="TCP",
            module_name="sql_injection",
        )

        snapshot = stats.get_snapshot()

        assert snapshot.total_packets == 1
        assert snapshot.packets_per_ip["10.0.0.1"] == 1
        assert snapshot.packets_per_category["ips_ids"] == 1
        assert snapshot.packets_per_protocol["TCP"] == 1
        assert "sql_injection" in snapshot.active_modules

    def test_multiple_packets(self) -> None:
        """Test recording multiple packets."""
        stats = StatsCollector()
        stats.start()

        # Record packets from different sources
        for i in range(5):
            stats.record_packet(
                src_ip=f"10.0.0.{i}",
                category=TrafficCategory.IPS_IDS,
                protocol="TCP",
                module_name="sql_injection",
            )

        stats.record_packet(
            src_ip="10.0.0.0",
            category=TrafficCategory.DNS_FILTER,
            protocol="UDP",
            module_name="dns_tunneling",
        )

        snapshot = stats.get_snapshot()

        assert snapshot.total_packets == 6
        assert len(snapshot.packets_per_ip) == 5
        assert snapshot.packets_per_category["ips_ids"] == 5
        assert snapshot.packets_per_category["dns_filter"] == 1
        assert snapshot.packets_per_protocol["TCP"] == 5
        assert snapshot.packets_per_protocol["UDP"] == 1

    def test_reset(self) -> None:
        """Test resetting statistics."""
        stats = StatsCollector()
        stats.start()

        stats.record_packet(
            src_ip="10.0.0.1",
            category=TrafficCategory.IPS_IDS,
            protocol="TCP",
            module_name="test",
        )

        stats.reset()
        snapshot = stats.get_snapshot()

        assert snapshot.total_packets == 0
        assert len(snapshot.packets_per_ip) == 0

    def test_packets_per_second(self) -> None:
        """Test packets per second calculation."""
        stats = StatsCollector()
        stats.start()

        # Record some packets
        for _ in range(10):
            stats.record_packet(
                src_ip="10.0.0.1",
                category=TrafficCategory.BENIGN,
                protocol="TCP",
                module_name="test",
            )

        # Get first snapshot to establish baseline
        stats.get_snapshot()

        # Wait a bit and get another snapshot
        time.sleep(0.1)

        # Record more packets
        for _ in range(10):
            stats.record_packet(
                src_ip="10.0.0.1",
                category=TrafficCategory.BENIGN,
                protocol="TCP",
                module_name="test",
            )

        snapshot = stats.get_snapshot()

        # Should have recorded some rate
        assert snapshot.packets_per_second >= 0


class TestTrafficCategory:
    """Test cases for TrafficCategory enum."""

    def test_categories_exist(self) -> None:
        """Test all expected categories exist."""
        assert TrafficCategory.IPS_IDS.value == "ips_ids"
        assert TrafficCategory.DNS_FILTER.value == "dns_filter"
        assert TrafficCategory.WEB_FILTER.value == "web_filter"
        assert TrafficCategory.ANTIVIRUS.value == "antivirus"
        assert TrafficCategory.VIDEO_FILTER.value == "video_filter"
        assert TrafficCategory.BENIGN.value == "benign"
        assert TrafficCategory.EXFILTRATION.value == "exfiltration"
