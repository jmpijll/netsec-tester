# NetSec Tester Development Guide

## Development Setup

### Prerequisites

- Python 3.10+
- Git
- Virtual environment tool (venv, conda, etc.)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/netsec-tester/netsec-tester.git
cd netsec-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install in development mode with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=netsec_tester

# Run specific test file
pytest tests/test_ip_pool.py

# Run with verbose output
pytest -v
```

### Code Quality

```bash
# Lint code
ruff check src tests

# Format code
ruff format src tests

# Type checking
mypy src
```

## Architecture Overview

### Core Components

```
src/netsec_tester/
    __init__.py
    cli.py              # Click-based CLI entry point
    core/
        engine.py       # Traffic generation engine
        stats.py        # Statistics collection and display
        ip_pool.py      # Virtual IP pool management
    modules/            # Traffic generation modules
        base.py         # Abstract base class
        ips_ids/        # IPS/IDS attack patterns
        dns_filter/     # DNS filtering tests
        web_filter/     # Web filtering tests
        antivirus/      # AV detection tests
        video_filter/   # Streaming detection
        benign/         # Normal traffic patterns
    scenarios/
        base.py         # Scenario class
        registry.py     # Scenario discovery and registration
    config/
        loader.py       # Configuration loading
        scenarios.yaml  # Built-in scenario definitions
```

### Key Classes

#### TrafficModule (Abstract Base Class)

All traffic modules must inherit from `TrafficModule` and implement:

```python
from abc import ABC, abstractmethod
from netsec_tester.modules.base import TrafficModule, ModuleInfo, TrafficCategory

class MyModule(TrafficModule):
    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            name="my_module",
            description="Description of what this module does",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        # Generate and yield Scapy packets
        yield IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port or 80)
```

#### TrafficEngine

The engine coordinates packet generation:
- Selects modules from the scenario
- Manages IP pool rotation
- Handles rate limiting
- Records statistics
- Manages graceful shutdown

#### StatsCollector

Thread-safe statistics collection:
- Per-IP packet counts
- Per-category distribution
- Per-protocol distribution
- Packets per second calculation

### Adding a New Module

1. Create a new file in the appropriate category directory:

```python
# src/netsec_tester/modules/ips_ids/my_attack.py

from typing import Iterator
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

class MyAttackModule(TrafficModule):
    def __init__(self) -> None:
        self._counter = 0

    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            name="my_attack",
            description="My custom attack pattern",
            category=TrafficCategory.IPS_IDS,
            protocols=["TCP", "HTTP"],
            ports=[80, 443],
        )

    def generate_packets(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None = None,
    ) -> Iterator[Packet]:
        port = dst_port or 80
        self._counter += 1

        # Your attack pattern here
        payload = f"GET /attack?payload={self._counter} HTTP/1.1\r\nHost: {dst_ip}\r\n\r\n"

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + self._counter, dport=port, flags="PA")
            / Raw(load=payload.encode())
        )

        yield packet
```

2. Register the module in `config/loader.py`:

```python
from netsec_tester.modules.ips_ids.my_attack import MyAttackModule
self.registry.register_module("my_attack", MyAttackModule)
```

3. Add to `__init__.py` if desired for easier imports:

```python
# modules/ips_ids/__init__.py
from netsec_tester.modules.ips_ids.my_attack import MyAttackModule
__all__ = [..., "MyAttackModule"]
```

4. Add to scenario definitions:

```yaml
# config/scenarios.yaml
my-scenario:
  description: "Test with my new attack"
  modules:
    - my_attack
    - sql_injection
```

5. Add tests:

```python
# tests/test_modules.py
def test_my_attack_module():
    module = MyAttackModule()
    info = module.get_info()
    assert info.name == "my_attack"

    packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
    assert len(packets) > 0
```

### Traffic Categories

Available categories in `TrafficCategory` enum:
- `IPS_IDS`: Intrusion prevention/detection patterns
- `DNS`: DNS filtering tests
- `WEB`: Web filtering tests
- `ANTIVIRUS`: AV detection tests
- `VIDEO`: Video/streaming content
- `BENIGN`: Normal/legitimate traffic

### Configuration System

Scenarios are defined in YAML format:

```yaml
scenarios:
  scenario-name:
    description: "Scenario description"
    modules:
      - module_name_1
      - module_name_2
    ip_pool_size: 10          # Number of virtual IPs
    packets_per_second: 100   # Rate limit
    duration_seconds: 0       # 0 = unlimited
    ports:                    # Target ports
      - 80
      - 443
    burst_mode: false         # Enable burst mode
    burst_size: 10            # Packets per burst
```

## Scapy Packet Crafting Tips

### Basic HTTP Request

```python
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

packet = (
    IP(src="10.0.0.1", dst="192.168.1.1")
    / TCP(sport=40000, dport=80, flags="PA")
    / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
)
```

### DNS Query

```python
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR

packet = (
    IP(src="10.0.0.1", dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
)
```

### Sending Packets

```python
from scapy.sendrecv import send

# Layer 3 send (IP and above)
send(packet, verbose=0)

# Layer 2 send (Ethernet and above)
from scapy.sendrecv import sendp
sendp(Ether() / packet, verbose=0)
```

## Best Practices

1. **Keep modules focused**: Each module should test one category of patterns
2. **Rotate payloads**: Use counters to cycle through different payloads
3. **Use realistic headers**: Include proper HTTP headers, User-Agents, etc.
4. **Document payloads**: Comment why each payload triggers detection
5. **Test patterns**: Ensure patterns actually trigger detections on test firewalls
6. **Thread safety**: Use locks if module maintains shared state
7. **Error handling**: Handle packet generation errors gracefully

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for new functionality
4. Ensure all tests pass: `pytest`
5. Run linting: `ruff check src tests`
6. Commit changes: `git commit -am 'Add new feature'`
7. Push to branch: `git push origin feature/my-feature`
8. Create a Pull Request

## Release Process

1. Update version in `pyproject.toml` and `src/netsec_tester/__init__.py`
2. Update CHANGELOG.md
3. Create git tag: `git tag v1.0.0`
4. Push tag: `git push origin v1.0.0`
5. GitHub Actions will build and publish to PyPI

