# NetSec Tester

A cross-platform command-line network security testing tool that generates diverse traffic patterns to comprehensively test Next-Generation Firewall (NGFW) policies.

## Overview

NetSec Tester generates both benign and simulated malicious network traffic using spoofed source IPs to test NGFW features including:

- **Web Filtering** - Category-based URL blocking
- **IPS/IDS** - Intrusion Prevention/Detection signatures
- **Antivirus** - Malware detection (using safe test patterns like EICAR)
- **DNS Filtering** - Malicious domain and DNS tunneling detection
- **Video Filtering** - Streaming protocol detection

The tool runs continuously, displaying live statistics until cancelled, making it ideal for validating firewall policies in lab environments.

## Features

- Cross-platform support (Linux, macOS, Windows with Npcap)
- Configurable virtual IP pool with spoofed source addresses
- Multiple pre-built testing scenarios
- Modular architecture for easy extension
- Live terminal statistics display
- YAML-based scenario configuration
- Safe test patterns that trigger detections without actual harm

## Requirements

- Python 3.10+
- Root/Administrator privileges (required for raw packet crafting)
- **Linux/macOS**: No additional requirements
- **Windows**: [Npcap](https://npcap.com/) must be installed

## Installation

```bash
# Clone the repository
git clone https://github.com/netsec-tester/netsec-tester.git
cd netsec-tester

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install the package
pip install -e .

# For development
pip install -e ".[dev]"
```

## Quick Start

```bash
# List available scenarios
sudo netsec-tester list-scenarios

# Run a quick test of all categories
sudo netsec-tester run quick-test

# Run comprehensive IPS/IDS testing
sudo netsec-tester run ips-deep

# Run with custom IP pool
sudo netsec-tester run full-mix --ip-range 10.0.0.0/24

# Show detailed information about a scenario
netsec-tester info ips-deep
```

## Available Scenarios

| Scenario | Description |
|----------|-------------|
| `quick-test` | Brief test of all traffic categories |
| `ips-deep` | Comprehensive IPS/IDS signature testing |
| `dns-focus` | DNS filtering and tunneling tests |
| `web-focus` | Web filtering category tests |
| `av-focus` | Antivirus detection tests |
| `full-mix` | All modules at maximum coverage |
| `stealth` | Low-rate, evasion-focused patterns |

## Usage

### Basic Commands

```bash
# Run a scenario
sudo netsec-tester run <scenario-name> [options]

# List all available scenarios
netsec-tester list-scenarios

# Get detailed info about a scenario
netsec-tester info <scenario-name>
```

### Options

```
--ip-range TEXT      IP range for virtual IPs (CIDR notation)
--rate INTEGER       Packets per second rate limit
--interface TEXT     Network interface to use
--duration INTEGER   Test duration in seconds (0 = unlimited)
--verbose           Enable verbose output
--config PATH       Path to custom configuration file
```

## Architecture

```
src/netsec_tester/
    cli.py              # Command-line interface
    core/
        engine.py       # Traffic generation engine
        stats.py        # Statistics collection
        ip_pool.py      # Virtual IP management
    modules/
        ips_ids/        # IPS/IDS attack patterns
        dns_filter/     # DNS filtering tests
        web_filter/     # Web filtering tests
        antivirus/      # AV detection tests
        video_filter/   # Streaming detection
        benign/         # Normal traffic patterns
    scenarios/
        base.py         # Scenario base class
        registry.py     # Scenario discovery
    config/
        scenarios.yaml  # Built-in scenarios
        signatures.yaml # Attack signatures
```

## Traffic Types

### IPS/IDS Patterns
- SQL Injection payloads
- XSS (Cross-Site Scripting) patterns
- Command injection sequences
- Directory traversal attempts
- Buffer overflow signatures
- C2 (Command & Control) beaconing
- Known exploit patterns (Shellshock, Log4Shell, etc.)

### DNS Patterns
- DNS tunneling simulation
- DGA (Domain Generation Algorithm) domains
- Known malicious domain patterns
- DNS exfiltration patterns

### Web Filtering
- Category-specific URL requests
- Suspicious URL patterns
- HTTPS/SNI-based detection

### Antivirus
- EICAR test file transfers
- Known malware signature triggers
- Archive evasion tests

## Safety Notice

This tool is designed for **testing purposes only** in controlled lab environments. All malicious traffic patterns are simulated and use industry-standard test signatures (like EICAR) that trigger security detections without causing actual harm.

**Do not use this tool on production networks without authorization.**

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=netsec_tester

# Lint code
ruff check src tests

# Type checking
mypy src
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to the main repository.

## License

MIT License - see LICENSE file for details.

## Acknowledgments

Inspired by:
- [AlphaSOC FlightSim](https://github.com/alphasoc/flightsim)
- [Scapy](https://scapy.net/)
- Snort/Suricata IPS signatures


