"""Virtual IP pool management with CIDR support."""

import ipaddress
import random
from typing import Iterator


class IPPool:
    """Manages a pool of virtual IP addresses for traffic generation.

    Supports CIDR notation for defining IP ranges and provides
    various selection modes (round-robin, random).
    """

    def __init__(self, cidr: str) -> None:
        """Initialize IP pool from CIDR notation.

        Args:
            cidr: IP range in CIDR notation (e.g., "10.0.0.0/24")

        Raises:
            ValueError: If CIDR notation is invalid
        """
        try:
            self._network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR notation '{cidr}': {e}") from e

        # Generate list of usable host addresses (exclude network and broadcast)
        self._addresses = list(self._network.hosts())

        if not self._addresses:
            # For /32 or similar, use the network address itself
            self._addresses = [self._network.network_address]

        self._current_index = 0
        self._packet_counts: dict[str, int] = {}

        # Initialize packet counts
        for addr in self._addresses:
            self._packet_counts[str(addr)] = 0

    @property
    def size(self) -> int:
        """Return the number of addresses in the pool."""
        return len(self._addresses)

    @property
    def cidr(self) -> str:
        """Return the CIDR notation for this pool."""
        return str(self._network)

    def get_next_round_robin(self) -> str:
        """Get the next IP address using round-robin selection.

        Returns:
            IP address as string
        """
        addr = str(self._addresses[self._current_index])
        self._current_index = (self._current_index + 1) % len(self._addresses)
        return addr

    def get_random(self) -> str:
        """Get a random IP address from the pool.

        Returns:
            IP address as string
        """
        return str(random.choice(self._addresses))

    def get_all(self) -> list[str]:
        """Get all IP addresses in the pool.

        Returns:
            List of IP addresses as strings
        """
        return [str(addr) for addr in self._addresses]

    def iterate(self) -> Iterator[str]:
        """Iterate over all IP addresses in the pool.

        Yields:
            IP addresses as strings
        """
        for addr in self._addresses:
            yield str(addr)

    def record_packet(self, ip: str) -> None:
        """Record a packet sent from an IP address.

        Args:
            ip: Source IP address
        """
        if ip in self._packet_counts:
            self._packet_counts[ip] += 1

    def get_packet_count(self, ip: str) -> int:
        """Get packet count for an IP address.

        Args:
            ip: IP address to query

        Returns:
            Number of packets sent from this IP
        """
        return self._packet_counts.get(ip, 0)

    def get_all_packet_counts(self) -> dict[str, int]:
        """Get packet counts for all IP addresses.

        Returns:
            Dictionary mapping IP addresses to packet counts
        """
        return self._packet_counts.copy()

    def get_total_packets(self) -> int:
        """Get total packets sent from all IPs.

        Returns:
            Total packet count
        """
        return sum(self._packet_counts.values())

    def reset_counts(self) -> None:
        """Reset all packet counts to zero."""
        for ip in self._packet_counts:
            self._packet_counts[ip] = 0
        self._current_index = 0

    def __len__(self) -> int:
        """Return number of addresses in pool."""
        return self.size

    def __contains__(self, ip: str) -> bool:
        """Check if an IP is in the pool.

        Args:
            ip: IP address to check

        Returns:
            True if IP is in pool
        """
        try:
            addr = ipaddress.ip_address(ip)
            return addr in self._network
        except ValueError:
            return False


