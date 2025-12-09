"""Tests for scenario management."""

import tempfile
from pathlib import Path

from netsec_tester.scenarios.base import Scenario, ScenarioConfig
from netsec_tester.scenarios.registry import ScenarioRegistry


class TestScenarioConfig:
    """Test cases for ScenarioConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = ScenarioConfig(
            name="test",
            description="Test scenario",
            modules=["module1"],
        )

        assert config.ip_pool_size == 10
        assert config.packets_per_second == 100
        assert config.duration_seconds == 0
        assert config.burst_mode is False

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = ScenarioConfig(
            name="test",
            description="Test scenario",
            modules=["module1", "module2"],
            ip_pool_size=20,
            packets_per_second=200,
            duration_seconds=300,
            ports=[80, 443],
            burst_mode=True,
            burst_size=50,
        )

        assert config.ip_pool_size == 20
        assert config.packets_per_second == 200
        assert config.duration_seconds == 300
        assert config.ports == [80, 443]
        assert config.burst_mode is True
        assert config.burst_size == 50


class TestScenario:
    """Test cases for Scenario class."""

    def test_init(self) -> None:
        """Test scenario initialization."""
        config = ScenarioConfig(
            name="test-scenario",
            description="A test scenario",
            modules=["sql_injection", "xss"],
        )
        scenario = Scenario(config)

        assert scenario.name == "test-scenario"
        assert scenario.description == "A test scenario"

    def test_get_module_names(self) -> None:
        """Test getting module names."""
        config = ScenarioConfig(
            name="test",
            description="Test",
            modules=["module1", "module2"],
        )
        scenario = Scenario(config)

        names = scenario.get_module_names()
        assert names == ["module1", "module2"]
        # Ensure it returns a copy
        names.append("module3")
        assert "module3" not in scenario.get_module_names()


class TestScenarioRegistry:
    """Test cases for ScenarioRegistry."""

    def test_init(self) -> None:
        """Test registry initialization."""
        registry = ScenarioRegistry()
        scenarios = registry.list_scenarios()
        assert scenarios == []

    def test_load_scenarios_from_yaml(self) -> None:
        """Test loading scenarios from YAML file."""
        yaml_content = """
scenarios:
  test-scenario:
    description: "Test scenario description"
    modules:
      - sql_injection
      - xss
    ip_pool_size: 5
    packets_per_second: 50
    duration_seconds: 60
    ports:
      - 80
      - 443
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = Path(f.name)

        try:
            registry = ScenarioRegistry()
            registry.load_scenarios_from_yaml(yaml_path)

            scenarios = registry.list_scenarios()
            assert len(scenarios) == 1
            assert scenarios[0][0] == "test-scenario"
            assert scenarios[0][1] == "Test scenario description"

            scenario = registry.get_scenario("test-scenario")
            assert scenario is not None
            assert scenario.config.ip_pool_size == 5
            assert scenario.config.packets_per_second == 50
            assert scenario.config.duration_seconds == 60
        finally:
            yaml_path.unlink()

    def test_get_nonexistent_scenario(self) -> None:
        """Test getting a scenario that doesn't exist."""
        registry = ScenarioRegistry()
        scenario = registry.get_scenario("nonexistent")
        assert scenario is None

    def test_register_module(self) -> None:
        """Test registering a module class."""
        from netsec_tester.modules.ips_ids.sql_injection import SQLInjectionModule

        registry = ScenarioRegistry()
        registry.register_module("sql_injection", SQLInjectionModule)

        module_class = registry.get_module_class("sql_injection")
        assert module_class is SQLInjectionModule

    def test_build_scenario(self) -> None:
        """Test building a scenario with modules."""
        from netsec_tester.modules.ips_ids.sql_injection import SQLInjectionModule

        yaml_content = """
scenarios:
  test:
    description: "Test"
    modules:
      - sql_injection
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            yaml_path = Path(f.name)

        try:
            registry = ScenarioRegistry()
            registry.register_module("sql_injection", SQLInjectionModule)
            registry.load_scenarios_from_yaml(yaml_path)

            scenario = registry.build_scenario("test")
            assert scenario is not None

            modules = scenario.get_modules()
            assert len(modules) == 1
            assert isinstance(modules[0], SQLInjectionModule)
        finally:
            yaml_path.unlink()
