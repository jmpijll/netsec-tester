"""Tests for IP pool management."""

import pytest

from netsec_tester.core.ip_pool import IPPool


class TestIPPool:
    """Test cases for IPPool class."""

    def test_init_valid_cidr(self) -> None:
        """Test initialization with valid CIDR notation."""
        pool = IPPool("10.0.0.0/30")
        assert pool.size == 2  # /30 has 2 usable hosts

    def test_init_larger_network(self) -> None:
        """Test initialization with larger network."""
        pool = IPPool("192.168.1.0/24")
        assert pool.size == 254  # /24 has 254 usable hosts

    def test_init_single_ip(self) -> None:
        """Test initialization with single IP (/32)."""
        pool = IPPool("10.0.0.1/32")
        assert pool.size == 1

    def test_init_invalid_cidr(self) -> None:
        """Test initialization with invalid CIDR raises ValueError."""
        with pytest.raises(ValueError):
            IPPool("invalid")

        with pytest.raises(ValueError):
            IPPool("256.0.0.0/24")

    def test_get_next_round_robin(self) -> None:
        """Test round-robin IP selection."""
        pool = IPPool("10.0.0.0/30")  # 10.0.0.1, 10.0.0.2

        ip1 = pool.get_next_round_robin()
        ip2 = pool.get_next_round_robin()
        ip3 = pool.get_next_round_robin()  # Should wrap around

        assert ip1 == "10.0.0.1"
        assert ip2 == "10.0.0.2"
        assert ip3 == "10.0.0.1"  # Wrapped back

    def test_get_random(self) -> None:
        """Test random IP selection returns valid IP from pool."""
        pool = IPPool("10.0.0.0/28")  # 14 usable hosts

        for _ in range(100):
            ip = pool.get_random()
            assert ip in pool

    def test_get_all(self) -> None:
        """Test getting all IPs in pool."""
        pool = IPPool("10.0.0.0/30")
        all_ips = pool.get_all()

        assert len(all_ips) == 2
        assert "10.0.0.1" in all_ips
        assert "10.0.0.2" in all_ips

    def test_iterate(self) -> None:
        """Test iterating over pool."""
        pool = IPPool("10.0.0.0/30")
        ips = list(pool.iterate())

        assert len(ips) == 2
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_record_packet(self) -> None:
        """Test packet recording."""
        pool = IPPool("10.0.0.0/30")

        pool.record_packet("10.0.0.1")
        pool.record_packet("10.0.0.1")
        pool.record_packet("10.0.0.2")

        assert pool.get_packet_count("10.0.0.1") == 2
        assert pool.get_packet_count("10.0.0.2") == 1

    def test_get_total_packets(self) -> None:
        """Test total packet count."""
        pool = IPPool("10.0.0.0/30")

        pool.record_packet("10.0.0.1")
        pool.record_packet("10.0.0.1")
        pool.record_packet("10.0.0.2")

        assert pool.get_total_packets() == 3

    def test_reset_counts(self) -> None:
        """Test resetting packet counts."""
        pool = IPPool("10.0.0.0/30")

        pool.record_packet("10.0.0.1")
        pool.record_packet("10.0.0.2")
        pool.reset_counts()

        assert pool.get_total_packets() == 0
        assert pool.get_packet_count("10.0.0.1") == 0

    def test_contains(self) -> None:
        """Test IP membership check."""
        pool = IPPool("10.0.0.0/30")

        assert "10.0.0.1" in pool
        assert "10.0.0.2" in pool
        assert "10.0.0.5" not in pool
        assert "192.168.1.1" not in pool

    def test_len(self) -> None:
        """Test len() on pool."""
        pool = IPPool("10.0.0.0/30")
        assert len(pool) == 2

    def test_cidr_property(self) -> None:
        """Test CIDR property returns original network."""
        pool = IPPool("10.0.0.0/24")
        assert pool.cidr == "10.0.0.0/24"

