"""Statistics collection and live display."""

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout

if TYPE_CHECKING:
    from netsec_tester.modules.base import TrafficCategory


@dataclass
class StatsSnapshot:
    """A snapshot of statistics at a point in time."""

    timestamp: float
    total_packets: int
    packets_per_ip: dict[str, int]
    packets_per_category: dict[str, int]
    packets_per_protocol: dict[str, int]
    packets_per_second: float
    active_modules: list[str]
    running_time: float


class StatsCollector:
    """Thread-safe statistics collector for traffic generation."""

    def __init__(self) -> None:
        """Initialize the statistics collector."""
        self._lock = threading.Lock()
        self._total_packets = 0
        self._packets_per_ip: dict[str, int] = defaultdict(int)
        self._packets_per_category: dict[str, int] = defaultdict(int)
        self._packets_per_protocol: dict[str, int] = defaultdict(int)
        self._active_modules: set[str] = set()
        self._start_time: float | None = None
        self._last_snapshot_time: float = 0
        self._last_snapshot_packets: int = 0

    def start(self) -> None:
        """Mark the start of traffic generation."""
        with self._lock:
            self._start_time = time.time()
            self._last_snapshot_time = self._start_time
            self._last_snapshot_packets = 0

    def record_packet(
        self,
        src_ip: str,
        category: "TrafficCategory",
        protocol: str,
        module_name: str,
    ) -> None:
        """Record a sent packet.

        Args:
            src_ip: Source IP address
            category: Traffic category
            protocol: Protocol name (TCP, UDP, etc.)
            module_name: Name of the module that generated the packet
        """
        with self._lock:
            self._total_packets += 1
            self._packets_per_ip[src_ip] += 1
            self._packets_per_category[category.value] += 1
            self._packets_per_protocol[protocol] += 1
            self._active_modules.add(module_name)

    def get_snapshot(self) -> StatsSnapshot:
        """Get a snapshot of current statistics.

        Returns:
            StatsSnapshot with current statistics
        """
        with self._lock:
            now = time.time()
            running_time = now - (self._start_time or now)

            # Calculate packets per second
            time_delta = now - self._last_snapshot_time
            if time_delta > 0:
                packets_delta = self._total_packets - self._last_snapshot_packets
                pps = packets_delta / time_delta
            else:
                pps = 0.0

            # Update for next calculation
            self._last_snapshot_time = now
            self._last_snapshot_packets = self._total_packets

            return StatsSnapshot(
                timestamp=now,
                total_packets=self._total_packets,
                packets_per_ip=dict(self._packets_per_ip),
                packets_per_category=dict(self._packets_per_category),
                packets_per_protocol=dict(self._packets_per_protocol),
                packets_per_second=pps,
                active_modules=list(self._active_modules),
                running_time=running_time,
            )

    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self._total_packets = 0
            self._packets_per_ip.clear()
            self._packets_per_category.clear()
            self._packets_per_protocol.clear()
            self._active_modules.clear()
            self._start_time = None
            self._last_snapshot_time = 0
            self._last_snapshot_packets = 0


class StatsDisplay:
    """Live terminal display for statistics using Rich."""

    def __init__(self, stats: StatsCollector, console: Console) -> None:
        """Initialize the stats display.

        Args:
            stats: StatsCollector to display stats from
            console: Rich Console for output
        """
        self.stats = stats
        self.console = console
        self._live: Live | None = None

    def _format_time(self, seconds: float) -> str:
        """Format seconds into human-readable time.

        Args:
            seconds: Time in seconds

        Returns:
            Formatted time string
        """
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        if hours > 0:
            return f"{hours}h {minutes}m {secs}s"
        elif minutes > 0:
            return f"{minutes}m {secs}s"
        else:
            return f"{secs}s"

    def _create_display(self, snapshot: StatsSnapshot) -> Layout:
        """Create the display layout.

        Args:
            snapshot: Current statistics snapshot

        Returns:
            Rich Layout with stats tables
        """
        layout = Layout()

        # Header with summary stats
        header_text = (
            f"[bold green]Running Time:[/bold green] {self._format_time(snapshot.running_time)}  "
            f"[bold cyan]Total Packets:[/bold cyan] {snapshot.total_packets:,}  "
            f"[bold yellow]Rate:[/bold yellow] {snapshot.packets_per_second:.1f} pkt/s"
        )
        header = Panel(header_text, title="NetSec Tester Statistics", border_style="blue")

        # IP table (top 10 by packet count)
        ip_table = Table(title="Packets by Source IP", expand=True)
        ip_table.add_column("IP Address", style="cyan")
        ip_table.add_column("Packets", justify="right", style="green")

        sorted_ips = sorted(
            snapshot.packets_per_ip.items(), key=lambda x: x[1], reverse=True
        )[:10]
        for ip, count in sorted_ips:
            ip_table.add_row(ip, f"{count:,}")

        # Category table
        cat_table = Table(title="Packets by Category", expand=True)
        cat_table.add_column("Category", style="magenta")
        cat_table.add_column("Packets", justify="right", style="green")

        for cat, count in sorted(
            snapshot.packets_per_category.items(), key=lambda x: x[1], reverse=True
        ):
            cat_table.add_row(cat.upper(), f"{count:,}")

        # Protocol table
        proto_table = Table(title="Packets by Protocol", expand=True)
        proto_table.add_column("Protocol", style="yellow")
        proto_table.add_column("Packets", justify="right", style="green")

        for proto, count in sorted(
            snapshot.packets_per_protocol.items(), key=lambda x: x[1], reverse=True
        ):
            proto_table.add_row(proto, f"{count:,}")

        # Arrange layout
        layout.split_column(
            Layout(header, size=3),
            Layout(name="tables"),
        )
        layout["tables"].split_row(
            Layout(ip_table),
            Layout(cat_table),
            Layout(proto_table),
        )

        return layout

    def start(self) -> Live:
        """Start the live display.

        Returns:
            Rich Live context manager
        """
        self._live = Live(
            self._create_display(self.stats.get_snapshot()),
            console=self.console,
            refresh_per_second=2,
            transient=True,
        )
        return self._live

    def update(self) -> None:
        """Update the display with current statistics."""
        if self._live:
            snapshot = self.stats.get_snapshot()
            self._live.update(self._create_display(snapshot))

    def stop(self) -> None:
        """Stop the live display."""
        if self._live:
            self._live.stop()
            self._live = None

    def show_summary(self) -> None:
        """Display a final summary of the test run."""
        snapshot = self.stats.get_snapshot()

        self.console.print("\n[bold blue]===== Test Summary =====[/bold blue]\n")

        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="bold")
        summary_table.add_column("Value", style="green")

        summary_table.add_row("Total Running Time", self._format_time(snapshot.running_time))
        summary_table.add_row("Total Packets Sent", f"{snapshot.total_packets:,}")
        summary_table.add_row(
            "Average Rate", f"{snapshot.total_packets / max(snapshot.running_time, 1):.1f} pkt/s"
        )
        summary_table.add_row("Unique Source IPs", str(len(snapshot.packets_per_ip)))
        summary_table.add_row("Active Modules", str(len(snapshot.active_modules)))

        self.console.print(summary_table)

        if snapshot.packets_per_category:
            self.console.print("\n[bold]Packets by Category:[/bold]")
            for cat, count in sorted(
                snapshot.packets_per_category.items(), key=lambda x: x[1], reverse=True
            ):
                pct = (count / snapshot.total_packets * 100) if snapshot.total_packets > 0 else 0
                self.console.print(f"  {cat.upper()}: {count:,} ({pct:.1f}%)")

        self.console.print()


