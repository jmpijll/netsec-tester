<p align="center">
  <img src="https://img.shields.io/badge/🔒-NetSec_Tester-1a1a2e?style=for-the-badge&labelColor=16213e" alt="NetSec Tester"/>
</p>

<h1 align="center">
  <br>
  <sub>Next-Generation Firewall Testing Suite</sub>
</h1>

<p align="center">
  <a href="#-features"><strong>Features</strong></a> ·
  <a href="#-quick-start"><strong>Quick Start</strong></a> ·
  <a href="#-scenarios"><strong>Scenarios</strong></a> ·
  <a href="#-modules"><strong>Modules</strong></a> ·
  <a href="#-documentation"><strong>Docs</strong></a>
</p>

<p align="center">
  <a href="https://github.com/jmpijll/netsec-tester/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/jmpijll/netsec-tester/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI Status"/></a>
  <a href="https://codecov.io/gh/jmpijll/netsec-tester"><img src="https://img.shields.io/codecov/c/github/jmpijll/netsec-tester?style=flat-square&logo=codecov" alt="Coverage"/></a>
  <img src="https://img.shields.io/badge/python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="MIT License"/></a>
  <img src="https://img.shields.io/badge/platform-linux%20|%20macos%20|%20windows-lightgrey?style=flat-square" alt="Platform"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/modules-45-blue?style=flat-square" alt="45 Modules"/>
  <img src="https://img.shields.io/badge/scenarios-15-purple?style=flat-square" alt="15 Scenarios"/>
  <img src="https://img.shields.io/badge/tests-246-success?style=flat-square" alt="246 Tests"/>
  <a href="https://github.com/jmpijll/netsec-tester/releases"><img src="https://img.shields.io/github/v/release/jmpijll/netsec-tester?style=flat-square" alt="Release"/></a>
</p>

<br>

<p align="center">
  <strong>A cross-platform CLI tool that generates diverse network traffic patterns to comprehensively test NGFW policies including IPS/IDS, web filtering, antivirus, DNS filtering, and more.</strong>
</p>

---

## ⚡ Overview

NetSec Tester generates both **benign** and **simulated malicious** network traffic using spoofed source IPs to validate Next-Generation Firewall (NGFW) capabilities. Perfect for:

- 🔬 **Security Lab Testing** — Validate firewall rules before production deployment
- 📊 **Policy Verification** — Ensure UTP policies correctly detect and block threats
- 🎯 **Penetration Testing** — Generate realistic attack traffic for security assessments
- 📈 **Performance Benchmarking** — Test firewall throughput under various traffic loads

All malicious traffic patterns use **industry-standard test signatures** (like EICAR) that trigger security detections **without causing actual harm**.

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🌐 Comprehensive Coverage
- **45 traffic modules** across 7 categories
- **15 pre-built scenarios** for common test cases
- Tests IPS/IDS, web filtering, AV, DNS, video filtering, and more

### 🔄 Cross-Platform
- Native support for Linux, macOS, and Windows
- Windows requires [Npcap](https://npcap.com/)

### 📊 Live Statistics
- Real-time packet generation metrics
- Per-IP traffic distribution
- Category and protocol breakdowns

</td>
<td width="50%">

### 🎛️ Flexible Configuration
- YAML-based scenario definitions
- Custom IP pools (CIDR notation)
- Adjustable packet rates and durations
- Burst mode for high-volume testing

### 🧩 Modular Architecture
- Easily extend with custom modules
- Clean, well-documented codebase
- Full test coverage

### 🛡️ Safe by Design
- Simulated attacks trigger detections only
- No actual malware or exploitation
- Industry-standard test patterns

</td>
</tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- Root/Administrator privileges
- **Windows only:** [Npcap](https://npcap.com/)

### Installation

```bash
# Clone the repository
git clone https://github.com/jmpijll/netsec-tester.git
cd netsec-tester

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install the package
pip install -e .
```

### Basic Usage

```bash
# List all available scenarios
netsec-tester list-scenarios

# Run a quick test of all categories
sudo netsec-tester run quick-test

# Run comprehensive IPS/IDS testing
sudo netsec-tester run ips-deep

# Run with custom IP pool and rate limit
sudo netsec-tester run full-mix --ip-range 10.0.0.0/24 --rate 100

# Get detailed scenario information
netsec-tester info full-mix
```

---

## 📋 Scenarios

NetSec Tester includes **15 pre-built scenarios** for common testing needs:

| Scenario | Description | Focus Area |
|----------|-------------|------------|
| `quick-test` | Brief validation of all traffic categories | All |
| `full-mix` | Comprehensive testing with all 45 modules | All |
| `ips-deep` | Comprehensive IPS/IDS signature testing | IPS/IDS |
| `dns-focus` | DNS filtering and tunneling detection | DNS |
| `web-focus` | Web filtering category tests | Web |
| `av-focus` | Antivirus detection tests | Antivirus |
| `video-focus` | Video/streaming content detection | Video |
| `benign-only` | Baseline with legitimate traffic only | Benign |
| `stealth` | Low-rate, evasion-focused patterns | Evasion |
| **`recon-test`** | Network reconnaissance and scanning detection | IPS/IDS |
| **`dos-test`** | DoS/DDoS attack pattern testing | IPS/IDS |
| **`exfil-test`** | Data exfiltration detection testing | Exfiltration |
| **`ransomware-test`** | Ransomware indicator detection | Antivirus |
| **`iot-test`** | IoT device and protocol testing | Benign |
| **`api-test`** | API security and abuse testing | Web |

---

## 🧩 Modules

### Overview by Category

| Category | Modules | Description |
|----------|---------|-------------|
| **IPS/IDS** | 12 | Attack signatures, exploits, reconnaissance |
| **DNS Filter** | 7 | Tunneling, DGA, exfiltration, amplification |
| **Web Filter** | 6 | TLS inspection, API abuse, web shells |
| **Antivirus** | 6 | EICAR, ransomware, cryptominer, dropper |
| **Video/Streaming** | 4 | P2P, VoIP, gaming traffic |
| **Benign** | 7 | Normal traffic for baseline testing |
| **Exfiltration** | 3 | Covert channels, data theft patterns |

### IPS/IDS Modules (12)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `sql_injection` | SQL injection attack patterns (UNION, blind, error-based) |
| `xss` | Cross-site scripting payloads (reflected, stored, DOM) |
| `command_injection` | OS command injection patterns |
| `directory_traversal` | Path traversal and LFI attempts |
| `exploits` | Known CVE patterns (Log4Shell, Shellshock, etc.) |
| `c2_beacon` | Command & Control communication patterns |
| `reconnaissance` | Port scanning, OS fingerprinting, vulnerability scanner patterns |
| `dos_patterns` | SYN flood, Slowloris, amplification attacks |
| `brute_force` | SSH, FTP, HTTP auth, RDP brute force patterns |
| `protocol_anomaly` | Malformed headers, invalid flags, fragmentation |
| `ssrf_xxe` | Server-side request forgery, XML injection |
| `deserialization` | Java, PHP, .NET, Python pickle attacks |

</details>

### DNS Filter Modules (7)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `dns_tunneling` | Data exfiltration via DNS queries |
| `dga` | Domain Generation Algorithm patterns |
| `malicious_domains` | Known malicious domain categories |
| `dns_exfiltration` | Base64/hex encoded DNS exfiltration |
| `dns_rebinding` | Short TTL, IP switching attacks |
| `dns_amplification` | ANY queries, DNSSEC abuse |
| `fast_flux` | Botnet domain patterns, rapid IP rotation |

</details>

### Web Filter Modules (6)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `web_categories` | Category-based URL filtering tests |
| `url_patterns` | Suspicious URL pattern detection |
| `tls_inspection` | SNI filtering, JA3 fingerprints, cert anomalies |
| `api_abuse` | GraphQL injection, JWT attacks, rate limit bypass |
| `web_shells` | Shell access patterns, China Chopper, etc. |
| `http_smuggling` | CL.TE, TE.CL, TE.TE obfuscation |

</details>

### Antivirus Modules (6)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `eicar` | EICAR test file transfers |
| `av_signatures` | Known malware signature triggers |
| `ransomware` | File extensions, ransom notes, key exchange |
| `cryptominer` | Stratum protocol, mining pools, WebMiner |
| `dropper` | PowerShell cradles, LOLBins, macro documents |
| `archive_evasion` | Nested archives, polyglots, zip bombs |

</details>

### Video/Streaming Modules (4)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `streaming` | RTMP, HLS, DASH streaming protocols |
| `p2p_torrent` | BitTorrent handshakes, DHT, tracker requests |
| `voip_webrtc` | SIP, RTP, STUN/TURN, Teams patterns |
| `gaming` | Steam, Xbox Live, PSN, game server queries |

</details>

### Benign Traffic Modules (7)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `web_browsing` | Normal HTTP/HTTPS browsing patterns |
| `email` | SMTP, IMAP, POP3 traffic |
| `file_transfer` | FTP, SFTP patterns |
| `cloud_services` | AWS, Azure, GCP, Office 365 API patterns |
| `iot_device` | MQTT, CoAP, smart home, IP camera protocols |
| `mobile_app` | App stores, push notifications, analytics |
| `vpn_proxy` | OpenVPN, WireGuard, IPsec, SOCKS, Tor |

</details>

### Exfiltration Modules (3)

<details>
<summary>Click to expand</summary>

| Module | Description |
|--------|-------------|
| `icmp_covert` | Data in ICMP payload, oversized pings, tunneling |
| `https_exfil` | Large POSTs, cloud storage abuse, webhooks |
| `protocol_abuse` | NTP covert, HTTP headers, TCP timestamps |

</details>

---

## 📁 Project Structure

```
netsec-tester/
├── src/netsec_tester/
│   ├── cli.py              # Click-based CLI entry point
│   ├── core/
│   │   ├── engine.py       # Traffic generation engine
│   │   ├── stats.py        # Live statistics display
│   │   └── ip_pool.py      # Virtual IP pool management
│   ├── modules/
│   │   ├── base.py         # Abstract base class
│   │   ├── ips_ids/        # 12 IPS/IDS modules
│   │   ├── dns_filter/     # 7 DNS modules
│   │   ├── web_filter/     # 6 Web modules
│   │   ├── antivirus/      # 6 AV modules
│   │   ├── video_filter/   # 4 Video modules
│   │   ├── benign/         # 7 Benign modules
│   │   └── exfiltration/   # 3 Exfiltration modules
│   ├── scenarios/
│   │   ├── base.py         # Scenario class
│   │   └── registry.py     # Module/scenario discovery
│   └── config/
│       ├── loader.py       # Configuration loading
│       └── scenarios.yaml  # 15 built-in scenarios
├── tests/                  # 246 unit tests
├── docs/
│   ├── USAGE.md           # User guide
│   └── DEVELOPMENT.md     # Developer guide
└── pyproject.toml         # Project configuration
```

---

## 🖥️ CLI Reference

### Commands

```bash
netsec-tester [OPTIONS] COMMAND [ARGS]
```

| Command | Description |
|---------|-------------|
| `run SCENARIO` | Run a test scenario |
| `list-scenarios` | List all available scenarios |
| `info SCENARIO` | Show detailed scenario information |

### Run Options

| Option | Default | Description |
|--------|---------|-------------|
| `--ip-range, -i` | `10.99.0.0/24` | Source IP range (CIDR) |
| `--target, -t` | `192.0.2.1` | Target IP address |
| `--rate, -r` | From scenario | Packets per second |
| `--interface, -I` | System default | Network interface |
| `--duration, -d` | From scenario | Duration (0 = unlimited) |
| `--dry-run` | False | Preview without sending |

---

## 📖 Documentation

| Document | Description |
|----------|-------------|
| [Usage Guide](docs/USAGE.md) | Complete user documentation |
| [Development Guide](docs/DEVELOPMENT.md) | Contributing and extending |
| [Contributing](CONTRIBUTING.md) | How to contribute |
| [Changelog](CHANGELOG.md) | Version history |

---

## 🧪 Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=netsec_tester --cov-report=term-missing

# Lint code
ruff check src tests

# Type checking
mypy src
```

---

## ⚠️ Important Safety Notice

> **This tool is for authorized security testing only.**

- ✅ Use in isolated lab environments
- ✅ Obtain proper authorization before testing
- ✅ All "malicious" traffic uses safe test patterns
- ❌ Do not use on production networks without permission
- ❌ Do not use for actual malicious purposes

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built with:
- [Scapy](https://scapy.net/) — Packet manipulation library
- [Click](https://click.palletsprojects.com/) — CLI framework
- [Rich](https://rich.readthedocs.io/) — Terminal formatting

Inspired by:
- [AlphaSOC FlightSim](https://github.com/alphasoc/flightsim)
- [Snort/Suricata](https://www.snort.org/) IPS signatures

---

<p align="center">
  <sub>Made with 🔐 for the security community</sub>
</p>
