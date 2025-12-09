"""Traffic generation engine."""

import random
import threading
import time
from typing import TYPE_CHECKING

from scapy.config import conf
from scapy.sendrecv import send

from netsec_tester.core.ip_pool import IPPool
from netsec_tester.core.stats import StatsCollector, StatsDisplay

if TYPE_CHECKING:
    from netsec_tester.scenarios.base import Scenario


class TrafficEngine:
    """Main engine for generating and sending traffic.

    Coordinates traffic generation from multiple modules,
    manages rate limiting, and handles packet sending.
    """

    def __init__(
        self,
        scenario: "Scenario",
        ip_pool: IPPool,
        target_ip: str,
        stats: StatsCollector,
        interface: str | None = None,
        dry_run: bool = False,
        verbose: bool = False,
    ) -> None:
        """Initialize the traffic engine.

        Args:
            scenario: Scenario to run
            ip_pool: Pool of source IP addresses
            target_ip: Target IP address for traffic
            stats: Statistics collector
            interface: Network interface to use (None for default)
            dry_run: If True, don't actually send packets
            verbose: Enable verbose output
        """
        self.scenario = scenario
        self.ip_pool = ip_pool
        self.target_ip = target_ip
        self.stats = stats
        self.interface = interface
        self.dry_run = dry_run
        self.verbose = verbose

        self._running = False
        self._stop_event = threading.Event()

        # Configure scapy
        conf.verb = 0  # Suppress scapy output
        if interface:
            conf.iface = interface

    def run(self, display: StatsDisplay) -> None:
        """Run the traffic generation.

        Args:
            display: StatsDisplay for live output
        """
        self._running = True
        self._stop_event.clear()
        self.stats.start()

        config = self.scenario.config
        modules = self.scenario.get_modules()

        if not modules:
            return

        # Calculate delay between packets
        if config.packets_per_second > 0:
            packet_delay = 1.0 / config.packets_per_second
        else:
            packet_delay = 0

        start_time = time.time()
        duration = config.duration_seconds

        # Start live display
        with display.start():
            try:
                while self._running and not self._stop_event.is_set():
                    # Check duration limit
                    if duration > 0:
                        elapsed = time.time() - start_time
                        if elapsed >= duration:
                            break

                    # Select a random module
                    module = random.choice(modules)
                    module_info = module.get_info()

                    # Get source IP
                    src_ip = self.ip_pool.get_next_round_robin()

                    # Select a port from scenario config or module defaults
                    ports = config.ports if config.ports else module_info.ports
                    dst_port = random.choice(ports) if ports else 80

                    # Generate and send packets
                    try:
                        for packet in module.generate_packets(
                            src_ip=src_ip,
                            dst_ip=self.target_ip,
                            dst_port=dst_port,
                        ):
                            if self._stop_event.is_set():
                                break

                            if not self.dry_run:
                                send(packet, verbose=0)

                            # Record statistics
                            self.stats.record_packet(
                                src_ip=src_ip,
                                category=module_info.category,
                                protocol=self._get_protocol(packet),
                                module_name=module_info.name,
                            )
                            self.ip_pool.record_packet(src_ip)

                            # Update display periodically
                            display.update()

                            # Rate limiting
                            if packet_delay > 0:
                                time.sleep(packet_delay)

                            # In burst mode, send multiple packets quickly
                            if config.burst_mode and config.burst_size > 1:
                                # Only delay after burst_size packets
                                pass

                    except Exception as e:
                        if self.verbose:
                            print(f"Error generating packet: {e}")
                        continue

            finally:
                self._running = False

    def _get_protocol(self, packet: object) -> str:
        """Extract protocol name from a packet.

        Args:
            packet: Scapy packet

        Returns:
            Protocol name string
        """
        # Check for common protocols
        if hasattr(packet, "haslayer"):
            # Import here to avoid circular imports
            from scapy.layers.dns import DNS
            from scapy.layers.inet import ICMP, TCP, UDP

            if packet.haslayer(TCP):
                return "TCP"
            elif packet.haslayer(UDP):
                if packet.haslayer(DNS):
                    return "DNS"
                return "UDP"
            elif packet.haslayer(ICMP):
                return "ICMP"

        return "OTHER"

    def stop(self) -> None:
        """Stop the traffic generation."""
        self._running = False
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        """Return whether the engine is currently running."""
        return self._running


