"""Tests for CLI commands."""

import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from netsec_tester.cli import main


class TestCLI:
    """Test cases for CLI commands."""

    @pytest.fixture
    def runner(self) -> CliRunner:
        """Create CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def temp_config(self) -> Path:
        """Create temporary config file."""
        yaml_content = """
scenarios:
  test-scenario:
    description: "Test scenario"
    modules:
      - sql_injection
    ip_pool_size: 5
    packets_per_second: 50
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            return Path(f.name)

    def test_version(self, runner: CliRunner) -> None:
        """Test --version flag."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_help(self, runner: CliRunner) -> None:
        """Test --help flag."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "NetSec Tester" in result.output
        assert "list-scenarios" in result.output
        assert "run" in result.output
        assert "info" in result.output

    def test_list_scenarios(self, runner: CliRunner, temp_config: Path) -> None:
        """Test list-scenarios command."""
        result = runner.invoke(main, ["--config", str(temp_config), "list-scenarios"])
        assert result.exit_code == 0
        assert "test-scenario" in result.output
        temp_config.unlink()

    def test_info_existing_scenario(self, runner: CliRunner, temp_config: Path) -> None:
        """Test info command with existing scenario."""
        result = runner.invoke(main, ["--config", str(temp_config), "info", "test-scenario"])
        assert result.exit_code == 0
        assert "test-scenario" in result.output
        assert "Test scenario" in result.output
        temp_config.unlink()

    def test_info_nonexistent_scenario(self, runner: CliRunner, temp_config: Path) -> None:
        """Test info command with non-existent scenario."""
        result = runner.invoke(main, ["--config", str(temp_config), "info", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output
        temp_config.unlink()

    def test_run_dry_run(self, runner: CliRunner, temp_config: Path) -> None:
        """Test run command in dry-run mode."""
        result = runner.invoke(
            main,
            [
                "--config",
                str(temp_config),
                "run",
                "test-scenario",
                "--dry-run",
                "--duration",
                "1",  # Very short duration
            ],
        )
        # Should start without errors
        assert "DRY RUN" in result.output or result.exit_code == 0
        temp_config.unlink()

    def test_run_nonexistent_scenario(self, runner: CliRunner, temp_config: Path) -> None:
        """Test run command with non-existent scenario."""
        result = runner.invoke(
            main,
            ["--config", str(temp_config), "run", "nonexistent", "--dry-run"],
        )
        assert result.exit_code == 1
        assert "not found" in result.output
        temp_config.unlink()

    def test_run_invalid_ip_range(self, runner: CliRunner, temp_config: Path) -> None:
        """Test run command with invalid IP range."""
        result = runner.invoke(
            main,
            [
                "--config",
                str(temp_config),
                "run",
                "test-scenario",
                "--ip-range",
                "invalid",
                "--dry-run",
            ],
        )
        assert result.exit_code == 1
        assert "Invalid IP range" in result.output
        temp_config.unlink()
