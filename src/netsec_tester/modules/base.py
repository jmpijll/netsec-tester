"""Base class for all traffic generation modules."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum

from scapy.packet import Packet


class TrafficCategory(Enum):
    """Categories of traffic for grouping and reporting."""

    IPS_IDS = "ips_ids"
    DNS_FILTER = "dns_filter"
    WEB_FILTER = "web_filter"
    ANTIVIRUS = "antivirus"
    VIDEO_FILTER = "video_filter"
    BENIGN = "benign"
    EXFILTRATION = "exfiltration"


@dataclass
class ModuleInfo:
    """Information about a traffic module."""

    name: str
    description: str
    category: TrafficCategory
    protocols: list[str]
    ports: list[int]


class TrafficModule(ABC):
    """Abstract base class for traffic generation modules.

    All traffic modules must implement this interface to be usable
    by the traffic generation engine.
    """

    @abstractmethod
    def get_info(self) -> ModuleInfo:
        """Return information about this module.

        Returns:
            ModuleInfo containing name, description, category, etc.
        """
        pass

    @abstractmethod
    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        """Generate packets for this traffic type.

        Args:
            src_ip: Source IP address (spoofed)
            dst_ip: Destination IP address
            dst_port: Optional destination port override

        Yields:
            Scapy Packet objects ready to send
        """
        pass

    def get_default_ports(self) -> list[int]:
        """Return default destination ports for this module.

        Returns:
            List of port numbers
        """
        return self.get_info().ports

    def get_category(self) -> TrafficCategory:
        """Return the traffic category for this module.

        Returns:
            TrafficCategory enum value
        """
        return self.get_info().category


