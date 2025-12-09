"""Command-line interface for NetSec Tester."""

import signal
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from netsec_tester import __version__
from netsec_tester.config.loader import ConfigLoader
from netsec_tester.core.engine import TrafficEngine
from netsec_tester.core.ip_pool import IPPool
from netsec_tester.core.stats import StatsCollector, StatsDisplay

console = Console()


def get_default_config_path() -> Path:
    """Get the default configuration file path."""
    return Path(__file__).parent / "config" / "scenarios.yaml"


@click.group()
@click.version_option(version=__version__, prog_name="netsec-tester")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output",
)
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to custom configuration file",
)
@click.pass_context
def main(ctx: click.Context, verbose: bool, config: Optional[Path]) -> None:
    """NetSec Tester - Network security testing tool for NGFW validation.

    Generate diverse network traffic patterns to test firewall policies
    including IPS/IDS, web filtering, antivirus, DNS filtering, and more.

    Requires root/administrator privileges for raw packet operations.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config_path"] = config or get_default_config_path()

    # Initialize config loader and registry
    loader = ConfigLoader()
    loader.load(ctx.obj["config_path"])
    ctx.obj["loader"] = loader
    ctx.obj["registry"] = loader.registry


@main.command()
@click.pass_context
def list_scenarios(ctx: click.Context) -> None:
    """List all available test scenarios."""
    registry = ctx.obj["registry"]
    scenarios = registry.list_scenarios()

    if not scenarios:
        console.print("[yellow]No scenarios found.[/yellow]")
        return

    table = Table(title="Available Scenarios")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Description", style="white")

    for name, description in scenarios:
        table.add_row(name, description)

    console.print(table)


@main.command()
@click.argument("scenario_name")
@click.pass_context
def info(ctx: click.Context, scenario_name: str) -> None:
    """Show detailed information about a scenario.

    SCENARIO_NAME: Name of the scenario to display info for
    """
    registry = ctx.obj["registry"]
    scenario = registry.get_scenario(scenario_name)

    if scenario is None:
        console.print(f"[red]Scenario '{scenario_name}' not found.[/red]")
        console.print("Use 'netsec-tester list-scenarios' to see available scenarios.")
        sys.exit(1)

    console.print(f"\n[bold cyan]{scenario.name}[/bold cyan]")
    console.print(f"[white]{scenario.description}[/white]\n")

    config = scenario.config

    table = Table(title="Configuration")
    table.add_column("Parameter", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("IP Pool Size", str(config.ip_pool_size))
    table.add_row("Packets/Second", str(config.packets_per_second))
    table.add_row(
        "Duration",
        "Unlimited" if config.duration_seconds == 0 else f"{config.duration_seconds}s",
    )
    table.add_row("Ports", ", ".join(map(str, config.ports)))
    table.add_row("Burst Mode", "Yes" if config.burst_mode else "No")
    if config.burst_mode:
        table.add_row("Burst Size", str(config.burst_size))

    console.print(table)

    # Show modules
    console.print("\n[bold]Included Modules:[/bold]")
    for module_name in config.modules:
        console.print(f"  - {module_name}")


@main.command()
@click.argument("scenario_name")
@click.option(
    "--ip-range",
    "-i",
    default="10.99.0.0/24",
    help="IP range for virtual IPs (CIDR notation)",
)
@click.option(
    "--target",
    "-t",
    default="192.0.2.1",
    help="Target IP address for traffic",
)
@click.option(
    "--rate",
    "-r",
    type=int,
    default=None,
    help="Packets per second rate limit (overrides scenario config)",
)
@click.option(
    "--interface",
    "-I",
    default=None,
    help="Network interface to use",
)
@click.option(
    "--duration",
    "-d",
    type=int,
    default=None,
    help="Test duration in seconds (0 = unlimited, overrides scenario config)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Show what would be sent without actually sending packets",
)
@click.pass_context
def run(
    ctx: click.Context,
    scenario_name: str,
    ip_range: str,
    target: str,
    rate: Optional[int],
    interface: Optional[str],
    duration: Optional[int],
    dry_run: bool,
) -> None:
    """Run a test scenario.

    SCENARIO_NAME: Name of the scenario to run

    Examples:

        sudo netsec-tester run quick-test

        sudo netsec-tester run ips-deep --ip-range 10.0.0.0/24

        sudo netsec-tester run full-mix --rate 50 --duration 300
    """
    registry = ctx.obj["registry"]
    verbose = ctx.obj["verbose"]

    # Build scenario with modules
    scenario = registry.build_scenario(scenario_name)

    if scenario is None:
        console.print(f"[red]Scenario '{scenario_name}' not found.[/red]")
        console.print("Use 'netsec-tester list-scenarios' to see available scenarios.")
        sys.exit(1)

    # Override config with CLI options
    config = scenario.config
    if rate is not None:
        config.packets_per_second = rate
    if duration is not None:
        config.duration_seconds = duration

    # Create IP pool
    try:
        ip_pool = IPPool(ip_range)
    except ValueError as e:
        console.print(f"[red]Invalid IP range: {e}[/red]")
        sys.exit(1)

    # Create stats collector
    stats = StatsCollector()

    # Create traffic engine
    engine = TrafficEngine(
        scenario=scenario,
        ip_pool=ip_pool,
        target_ip=target,
        stats=stats,
        interface=interface,
        dry_run=dry_run,
        verbose=verbose,
    )

    # Setup signal handler for graceful shutdown
    def signal_handler(signum: int, frame: object) -> None:
        console.print("\n[yellow]Shutting down...[/yellow]")
        engine.stop()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Show startup info
    console.print(f"\n[bold green]Starting scenario: {scenario_name}[/bold green]")
    console.print(f"Target: {target}")
    console.print(f"IP Pool: {ip_range} ({ip_pool.size} addresses)")
    console.print(f"Rate: {config.packets_per_second} packets/sec")
    if config.duration_seconds > 0:
        console.print(f"Duration: {config.duration_seconds} seconds")
    else:
        console.print("Duration: Until cancelled (Ctrl+C)")

    if dry_run:
        console.print("[yellow]DRY RUN MODE - No packets will be sent[/yellow]")

    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")

    # Create and start display
    display = StatsDisplay(stats, console)

    try:
        # Run the engine with live display
        engine.run(display)
    finally:
        # Show final summary
        display.show_summary()


if __name__ == "__main__":
    main()


