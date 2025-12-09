# NetSec Tester Development Guide

## Development Setup

### Prerequisites

- Python 3.10+
- Git
- Virtual environment tool (venv, conda, etc.)

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/jmpijll/netsec-tester.git
cd netsec-tester

# Create virtual environment
python3 -m venv venv
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
pytest --cov=netsec_tester --cov-report=term-missing

# Run specific test file
pytest tests/test_ip_pool.py

# Run with verbose output
pytest -v

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"
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
    modules/            # 45 traffic generation modules
        base.py         # Abstract base class + TrafficCategory enum
        ips_ids/        # 12 IPS/IDS attack patterns
        dns_filter/     # 7 DNS filtering tests
        web_filter/     # 6 Web filtering tests
        antivirus/      # 6 AV detection tests
        video_filter/   # 4 Streaming detection
        benign/         # 7 Normal traffic patterns
        exfiltration/   # 3 Data exfiltration patterns
    scenarios/
        base.py         # Scenario class
        registry.py     # Scenario discovery and registration
    config/
        loader.py       # Configuration loading
        scenarios.yaml  # 15 built-in scenario definitions
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

### Traffic Categories (7)

Available categories in `TrafficCategory` enum:

| Category | Value | Description |
|----------|-------|-------------|
| `IPS_IDS` | `ips_ids` | Intrusion prevention/detection patterns |
| `DNS` | `dns` | DNS filtering tests |
| `WEB` | `web` | Web filtering tests |
| `ANTIVIRUS` | `antivirus` | AV detection tests |
| `VIDEO` | `video` | Video/streaming content |
| `BENIGN` | `benign` | Normal/legitimate traffic |
| `EXFILTRATION` | `exfiltration` | Data exfiltration patterns |

## Adding a New Module

### 1. Create the Module File

Create a new file in the appropriate category directory:

```python
# src/netsec_tester/modules/ips_ids/my_attack.py

from typing import Iterator
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet, Raw
from netsec_tester.modules.base import ModuleInfo, TrafficCategory, TrafficModule

class MyAttackModule(TrafficModule):
    """Generates traffic patterns for my custom attack."""

    def __init__(self) -> None:
        self._counter = 0
        self._payloads = [
            "attack_payload_1",
            "attack_payload_2",
            "attack_payload_3",
        ]

    def get_info(self) -> ModuleInfo:
        return ModuleInfo(
            name="my_attack",
            description="My custom attack pattern for testing specific signatures",
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

        # Rotate through payloads
        payload = self._payloads[self._counter % len(self._payloads)]
        
        http_request = (
            f"GET /attack?payload={payload} HTTP/1.1\r\n"
            f"Host: {dst_ip}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"\r\n"
        )

        packet = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=40000 + (self._counter % 1000), dport=port, flags="PA")
            / Raw(load=http_request.encode())
        )

        yield packet
```

### 2. Register the Module

Add imports and registration in `config/loader.py`:

```python
from netsec_tester.modules.ips_ids.my_attack import MyAttackModule
self.registry.register_module("my_attack", MyAttackModule)
```

### 3. Update Package Exports

Add to `modules/ips_ids/__init__.py`:

```python
from netsec_tester.modules.ips_ids.my_attack import MyAttackModule
__all__ = [..., "MyAttackModule"]
```

### 4. Add to Scenario Definitions

Update `config/scenarios.yaml`:

```yaml
my-scenario:
  description: "Test with my new attack"
  modules:
    - my_attack
    - sql_injection
  ip_pool_size: 5
  packets_per_second: 50
```

### 5. Write Tests

Add to `tests/test_modules.py`:

```python
def test_my_attack_module():
    """Test MyAttackModule generates valid packets."""
    module = MyAttackModule()
    info = module.get_info()
    
    assert info.name == "my_attack"
    assert info.category == TrafficCategory.IPS_IDS
    assert 80 in info.ports

    packets = list(module.generate_packets("10.0.0.1", "192.168.1.1", 80))
    assert len(packets) > 0
    
    # Verify packet structure
    packet = packets[0]
    assert packet.haslayer(IP)
    assert packet.haslayer(TCP)
    assert packet.haslayer(Raw)
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

### DNS with Numeric Query Type

For compatibility with newer Scapy versions, use numeric query types:

```python
# Use numeric value instead of string for query types
# A=1, AAAA=28, MX=15, TXT=16, ANY=255
packet = (
    IP(src="10.0.0.1", dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))  # ANY query
)
```

### ICMP Packet

```python
from scapy.layers.inet import IP, ICMP

packet = (
    IP(src="10.0.0.1", dst="192.168.1.1")
    / ICMP(type=8, code=0)  # Echo request
    / Raw(load=b"AAAA" * 64)  # Payload
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

### Module Development

1. **Keep modules focused**: Each module should test one category of patterns
2. **Rotate payloads**: Use counters to cycle through different payloads
3. **Use realistic headers**: Include proper HTTP headers, User-Agents, etc.
4. **Document payloads**: Comment why each payload triggers detection
5. **Test patterns**: Ensure patterns actually trigger detections on test firewalls
6. **Thread safety**: Use locks if module maintains shared state
7. **Error handling**: Handle packet generation errors gracefully

### Code Quality

1. **Type hints**: Use type hints for all function signatures
2. **Docstrings**: Document all classes and public methods
3. **Tests**: Write tests for all new modules
4. **Linting**: Pass `ruff check` before committing
5. **Type checking**: Pass `mypy` before committing

## Configuration System

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

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for new functionality
4. Ensure all tests pass: `pytest`
5. Run linting: `ruff check src tests`
6. Run type checking: `mypy src`
7. Commit changes: `git commit -am 'Add new feature'`
8. Push to branch: `git push origin feature/my-feature`
9. Create a Pull Request

## Release Process

1. Update version in `pyproject.toml` and `src/netsec_tester/__init__.py`
2. Update CHANGELOG.md
3. Create git tag: `git tag v1.x.x`
4. Push tag: `git push origin v1.x.x`
5. GitHub Actions will build and run tests
