"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture(autouse=True)
def reset_scapy_conf() -> None:
    """Reset scapy configuration for each test."""
    from scapy.config import conf

    conf.verb = 0  # Suppress output
