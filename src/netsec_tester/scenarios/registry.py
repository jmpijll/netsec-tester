"""Scenario registry for discovering and managing scenarios."""

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from netsec_tester.scenarios.base import Scenario, ScenarioConfig

if TYPE_CHECKING:
    from netsec_tester.modules.base import TrafficModule


class ScenarioRegistry:
    """Registry for discovering and loading test scenarios."""

    def __init__(self) -> None:
        """Initialize the scenario registry."""
        self._scenarios: dict[str, Scenario] = {}
        self._modules: dict[str, type[TrafficModule]] = {}

    def register_module(self, name: str, module_class: type["TrafficModule"]) -> None:
        """Register a traffic module class.

        Args:
            name: Name to register the module under
            module_class: TrafficModule subclass
        """
        self._modules[name] = module_class

    def get_module_class(self, name: str) -> type["TrafficModule"] | None:
        """Get a registered module class by name.

        Args:
            name: Module name

        Returns:
            TrafficModule subclass or None if not found
        """
        return self._modules.get(name)

    def load_scenarios_from_yaml(self, yaml_path: Path) -> None:
        """Load scenario definitions from a YAML file.

        Args:
            yaml_path: Path to scenarios YAML file
        """
        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        scenarios_data = data.get("scenarios", {})
        for name, config_data in scenarios_data.items():
            config = ScenarioConfig(
                name=name,
                description=config_data.get("description", ""),
                modules=config_data.get("modules", []),
                ip_pool_size=config_data.get("ip_pool_size", 10),
                packets_per_second=config_data.get("packets_per_second", 100),
                duration_seconds=config_data.get("duration_seconds", 0),
                ports=config_data.get("ports", [80, 443, 8080]),
                burst_mode=config_data.get("burst_mode", False),
                burst_size=config_data.get("burst_size", 10),
            )
            scenario = Scenario(config)
            self._scenarios[name] = scenario

    def get_scenario(self, name: str) -> Scenario | None:
        """Get a scenario by name.

        Args:
            name: Scenario name

        Returns:
            Scenario instance or None if not found
        """
        return self._scenarios.get(name)

    def list_scenarios(self) -> list[tuple[str, str]]:
        """List all registered scenarios.

        Returns:
            List of (name, description) tuples
        """
        return [(s.name, s.description) for s in self._scenarios.values()]

    def build_scenario(self, name: str) -> Scenario | None:
        """Build a scenario with instantiated modules.

        Args:
            name: Scenario name

        Returns:
            Scenario with modules loaded, or None if not found
        """
        scenario = self.get_scenario(name)
        if scenario is None:
            return None

        # Instantiate and add modules
        for module_name in scenario.get_module_names():
            module_class = self.get_module_class(module_name)
            if module_class is not None:
                module = module_class()
                scenario.add_module(module)

        return scenario
