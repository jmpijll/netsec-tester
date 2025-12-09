"""Base class for test scenarios."""

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from netsec_tester.modules.base import TrafficModule


@dataclass
class ScenarioConfig:
    """Configuration for a test scenario."""

    name: str
    description: str
    modules: list[str]  # Module names to include
    ip_pool_size: int = 10
    packets_per_second: int = 100
    duration_seconds: int = 0  # 0 = unlimited
    ports: list[int] = field(default_factory=lambda: [80, 443, 8080])
    burst_mode: bool = False
    burst_size: int = 10


class Scenario:
    """A test scenario that combines multiple traffic modules."""

    def __init__(self, config: ScenarioConfig) -> None:
        """Initialize the scenario with configuration.

        Args:
            config: ScenarioConfig with scenario parameters
        """
        self.config = config
        self._modules: list["TrafficModule"] = []

    @property
    def name(self) -> str:
        """Return scenario name."""
        return self.config.name

    @property
    def description(self) -> str:
        """Return scenario description."""
        return self.config.description

    def add_module(self, module: "TrafficModule") -> None:
        """Add a traffic module to this scenario.

        Args:
            module: TrafficModule instance to add
        """
        self._modules.append(module)

    def get_modules(self) -> list["TrafficModule"]:
        """Return all modules in this scenario.

        Returns:
            List of TrafficModule instances
        """
        return self._modules.copy()

    def get_module_names(self) -> list[str]:
        """Return names of modules to be loaded.

        Returns:
            List of module names from config
        """
        return self.config.modules.copy()


