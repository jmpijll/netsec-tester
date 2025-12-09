# NetSec Tester Usage Guide

## Prerequisites

- Python 3.10 or higher
- Root/Administrator privileges (required for raw packet operations)
- **Windows only**: [Npcap](https://npcap.com/) must be installed

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/netsec-tester/netsec-tester.git
cd netsec-tester

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install the package
pip install -e .
```

### For Development

```bash
pip install -e ".[dev]"
```

## Quick Start

### List Available Scenarios

```bash
netsec-tester list-scenarios
```

### Get Scenario Information

```bash
netsec-tester info ips-deep
```

### Run a Test Scenario

```bash
# Run with root privileges
sudo netsec-tester run quick-test

# Or on Windows (run terminal as Administrator)
netsec-tester run quick-test
```

## Command Reference

### Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--verbose, -v` | Enable verbose output |
| `--config, -c PATH` | Path to custom configuration file |
| `--help` | Show help message |

### `run` Command

Run a test scenario to generate traffic.

```bash
netsec-tester run SCENARIO_NAME [OPTIONS]
```

#### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--ip-range, -i TEXT` | `10.99.0.0/24` | IP range for virtual IPs (CIDR notation) |
| `--target, -t TEXT` | `192.0.2.1` | Target IP address for traffic |
| `--rate, -r INT` | From scenario | Packets per second rate limit |
| `--interface, -I TEXT` | System default | Network interface to use |
| `--duration, -d INT` | From scenario | Test duration in seconds (0 = unlimited) |
| `--dry-run` | False | Show what would be sent without sending packets |

#### Examples

```bash
# Basic test run
sudo netsec-tester run quick-test

# Custom IP range
sudo netsec-tester run ips-deep --ip-range 10.0.0.0/24

# Limit rate and duration
sudo netsec-tester run full-mix --rate 50 --duration 300

# Specify target
sudo netsec-tester run dns-focus --target 192.168.1.1

# Dry run mode (no packets sent)
netsec-tester run full-mix --dry-run
```

### `list-scenarios` Command

Display all available test scenarios.

```bash
netsec-tester list-scenarios
```

### `info` Command

Show detailed information about a specific scenario.

```bash
netsec-tester info SCENARIO_NAME
```

## Available Scenarios

### quick-test
- **Duration**: 60 seconds
- **Purpose**: Brief validation of all traffic categories
- **Modules**: SQL injection, XSS, DNS tunneling, DGA, web categories, EICAR, web browsing

### ips-deep
- **Duration**: Until cancelled
- **Purpose**: Comprehensive IPS/IDS signature testing
- **Modules**: SQL injection, XSS, command injection, directory traversal, exploits, C2 beacon

### dns-focus
- **Duration**: Until cancelled
- **Purpose**: DNS filtering and tunneling detection
- **Modules**: DNS tunneling, DGA, malicious domains

### web-focus
- **Duration**: Until cancelled
- **Purpose**: Web filtering category tests
- **Modules**: Web categories, URL patterns

### av-focus
- **Duration**: Until cancelled
- **Purpose**: Antivirus detection tests
- **Modules**: EICAR, AV signatures

### video-focus
- **Duration**: Until cancelled
- **Purpose**: Video streaming content filtering
- **Modules**: Streaming, web categories

### full-mix
- **Duration**: Until cancelled
- **Purpose**: Comprehensive NGFW testing with all modules
- **Modules**: All available modules

### stealth
- **Duration**: Until cancelled
- **Purpose**: Low-rate evasion testing
- **Rate**: 5 packets/second
- **Modules**: SQL injection, XSS, C2 beacon, DNS tunneling

### benign-only
- **Duration**: Until cancelled
- **Purpose**: Baseline testing with legitimate traffic only
- **Modules**: Web browsing, email, file transfer

## Understanding the Statistics Display

During test execution, a live statistics display shows:

### Summary Panel
- **Running Time**: How long the test has been running
- **Total Packets**: Total packets generated
- **Rate**: Current packets per second

### Packets by Source IP
Shows the top 10 source IPs by packet count, demonstrating traffic distribution across virtual IPs.

### Packets by Category
Shows traffic distribution across categories:
- `ips_ids`: IPS/IDS signature testing traffic
- `dns`: DNS filtering test traffic
- `web`: Web filtering test traffic
- `antivirus`: Antivirus detection test traffic
- `video`: Video streaming test traffic
- `benign`: Normal/legitimate traffic

### Packets by Protocol
Shows protocol distribution (TCP, UDP, DNS, etc.)

## Custom Configuration

Create a custom YAML configuration file:

```yaml
scenarios:
  my-custom-test:
    description: "My custom test scenario"
    modules:
      - sql_injection
      - dns_tunneling
      - eicar
    ip_pool_size: 10
    packets_per_second: 75
    duration_seconds: 120
    ports:
      - 80
      - 443
      - 53
    burst_mode: false
```

Run with custom config:

```bash
sudo netsec-tester --config my_config.yaml run my-custom-test
```

## Stopping Tests

Press `Ctrl+C` to gracefully stop a running test. A summary will be displayed showing:
- Total running time
- Total packets sent
- Average packet rate
- Packets by category

## Troubleshooting

### "Permission denied" or "Operation not permitted"
- Run with root/administrator privileges: `sudo netsec-tester run ...`
- On Windows, run Command Prompt or PowerShell as Administrator

### "No such device" or interface errors
- Specify a valid network interface with `--interface`
- List interfaces: `ip link show` (Linux) or `ipconfig` (Windows)

### Windows: "Unable to open BPF device"
- Install Npcap from https://npcap.com/
- During installation, select "Install Npcap in WinPcap API-compatible Mode"

### Low packet rates
- Check network interface speed and configuration
- Reduce the `--rate` parameter if system is overloaded
- Check for firewall rules blocking outbound traffic from the test machine

## Security Considerations

- **Use only in lab environments**: This tool generates traffic that may be flagged as malicious
- **Get authorization**: Ensure you have permission to test the network
- **Isolated testing**: Use isolated network segments to prevent unintended impact
- **Traffic is simulated**: All "malicious" patterns use industry-standard test signatures (like EICAR) that trigger detections without causing actual harm

