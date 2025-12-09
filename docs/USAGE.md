# NetSec Tester Usage Guide

## Prerequisites

- Python 3.10 or higher
- Root/Administrator privileges (required for raw packet operations)
- **Windows only**: [Npcap](https://npcap.com/) must be installed

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/jmpijll/netsec-tester.git
cd netsec-tester

# Create and activate virtual environment
python3 -m venv venv
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

## Available Scenarios (15)

### General Testing

| Scenario | Description | Modules |
|----------|-------------|---------|
| `quick-test` | Brief validation of all traffic categories | 7 core modules |
| `full-mix` | Comprehensive NGFW testing with all modules | All 45 modules |
| `stealth` | Low-rate, evasion-focused patterns | 4 evasion modules |
| `benign-only` | Baseline testing with legitimate traffic only | 7 benign modules |

### Category-Focused Testing

| Scenario | Description | Modules |
|----------|-------------|---------|
| `ips-deep` | Comprehensive IPS/IDS signature testing | 12 IPS/IDS modules |
| `dns-focus` | DNS filtering and tunneling detection | 7 DNS modules |
| `web-focus` | Web filtering category tests | 6 web modules |
| `av-focus` | Antivirus detection tests | 6 AV modules |
| `video-focus` | Video streaming content filtering | 4 video modules |

### Specialized Testing

| Scenario | Description | Modules |
|----------|-------------|---------|
| `recon-test` | Network reconnaissance and scanning detection | Reconnaissance, protocol anomaly |
| `dos-test` | DoS/DDoS attack pattern testing | DoS patterns, protocol anomaly |
| `exfil-test` | Data exfiltration detection testing | DNS exfil, ICMP covert, HTTPS exfil, protocol abuse |
| `ransomware-test` | Ransomware indicator detection | Ransomware, cryptominer, dropper, archive evasion |
| `iot-test` | IoT device and protocol testing | IoT device, cloud services |
| `api-test` | API security and abuse testing | API abuse, HTTP smuggling, web shells |

## Available Modules (45)

### IPS/IDS Modules (12)

| Module | Description |
|--------|-------------|
| `sql_injection` | SQL injection attack patterns (UNION, blind, error-based) |
| `xss` | Cross-site scripting payloads (reflected, stored, DOM-based) |
| `command_injection` | OS command injection patterns (bash, cmd, PowerShell) |
| `directory_traversal` | Path traversal and local file inclusion |
| `exploits` | Known CVE patterns (Log4Shell, Shellshock, ProxyLogon) |
| `c2_beacon` | Command & Control beaconing patterns |
| `reconnaissance` | Port scanning, OS fingerprinting, vulnerability scanner patterns |
| `dos_patterns` | SYN flood, Slowloris, DNS/NTP/SSDP amplification |
| `brute_force` | SSH, FTP, HTTP auth, SMTP, RDP, MySQL brute force |
| `protocol_anomaly` | Malformed headers, invalid TCP flags, fragmentation attacks |
| `ssrf_xxe` | Server-side request forgery, XML external entity injection |
| `deserialization` | Java, PHP, .NET, Python pickle deserialization attacks |

### DNS Filter Modules (7)

| Module | Description |
|--------|-------------|
| `dns_tunneling` | Data exfiltration via DNS queries |
| `dga` | Domain Generation Algorithm patterns |
| `malicious_domains` | Known malicious domain categories |
| `dns_exfiltration` | Base64/hex encoded data in DNS queries |
| `dns_rebinding` | Short TTL, IP switching attacks |
| `dns_amplification` | ANY queries, DNSSEC abuse, open resolver attacks |
| `fast_flux` | Botnet domain patterns, rapid IP rotation |

### Web Filter Modules (6)

| Module | Description |
|--------|-------------|
| `web_categories` | Category-based URL filtering (gambling, adult, malware) |
| `url_patterns` | Suspicious URL pattern detection |
| `tls_inspection` | SNI filtering, JA3 fingerprints, certificate anomalies |
| `api_abuse` | GraphQL injection, JWT attacks, rate limit bypass |
| `web_shells` | Shell access patterns, upload attempts, China Chopper |
| `http_smuggling` | CL.TE, TE.CL, TE.TE request smuggling |

### Antivirus Modules (6)

| Module | Description |
|--------|-------------|
| `eicar` | EICAR test file transfers (HTTP, FTP, SMTP) |
| `av_signatures` | Known malware signature triggers |
| `ransomware` | File extensions, ransom notes, key exchange patterns |
| `cryptominer` | Stratum protocol, mining pools, WebMiner |
| `dropper` | PowerShell cradles, LOLBins, macro document patterns |
| `archive_evasion` | Nested archives, polyglots, zip bomb patterns |

### Video/Streaming Modules (4)

| Module | Description |
|--------|-------------|
| `streaming` | RTMP, HLS, DASH streaming protocols |
| `p2p_torrent` | BitTorrent handshakes, DHT, tracker requests |
| `voip_webrtc` | SIP, RTP, STUN/TURN, Microsoft Teams patterns |
| `gaming` | Steam, Xbox Live, PSN, game server queries |

### Benign Traffic Modules (7)

| Module | Description |
|--------|-------------|
| `web_browsing` | Normal HTTP/HTTPS browsing patterns |
| `email` | SMTP, IMAP, POP3 traffic |
| `file_transfer` | FTP, SFTP file transfer patterns |
| `cloud_services` | AWS, Azure, GCP, Office 365 API patterns |
| `iot_device` | MQTT, CoAP, smart home, IP camera protocols |
| `mobile_app` | App stores, push notifications, analytics |
| `vpn_proxy` | OpenVPN, WireGuard, IPsec, SOCKS, Tor detection |

### Exfiltration Modules (3)

| Module | Description |
|--------|-------------|
| `icmp_covert` | Data in ICMP payload, oversized pings, tunneling |
| `https_exfil` | Large POSTs to cloud storage, webhooks |
| `protocol_abuse` | NTP covert channels, HTTP headers, TCP timestamps |

## Understanding the Statistics Display

During test execution, a live statistics display shows:

### Summary Panel
- **Running Time**: How long the test has been running
- **Total Packets**: Total packets generated
- **Rate**: Current packets per second

### Packets by Source IP
Shows the top 10 source IPs by packet count, demonstrating traffic distribution across virtual IPs.

### Packets by Category
Shows traffic distribution across all 7 categories:
- `ips_ids`: IPS/IDS signature testing traffic
- `dns`: DNS filtering test traffic
- `web`: Web filtering test traffic
- `antivirus`: Antivirus detection test traffic
- `video`: Video streaming test traffic
- `benign`: Normal/legitimate traffic
- `exfiltration`: Data exfiltration test traffic

### Packets by Protocol
Shows protocol distribution (TCP, UDP, DNS, ICMP, etc.)

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
      - icmp_covert
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

### Import errors or missing modules
- Ensure you've installed the package: `pip install -e .`
- Check that all dependencies are installed: `pip install -e ".[dev]"`

## Security Considerations

- **Use only in lab environments**: This tool generates traffic that may be flagged as malicious
- **Get authorization**: Ensure you have permission to test the network
- **Isolated testing**: Use isolated network segments to prevent unintended impact
- **Traffic is simulated**: All "malicious" patterns use industry-standard test signatures (like EICAR) that trigger detections without causing actual harm
