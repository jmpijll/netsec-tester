# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2024-12-09

### Added

#### Core Features
- Command-line interface with `run`, `list-scenarios`, and `info` commands
- Virtual IP pool management with CIDR notation support
- Real-time statistics display using Rich library
- Rate limiting and burst mode support
- Graceful shutdown with `Ctrl+C`

#### Traffic Modules (45 total)

**IPS/IDS Detection (12 modules)**
- `sql_injection` - SQL injection patterns (UNION, blind, error-based)
- `xss` - Cross-site scripting payloads (reflected, stored, DOM)
- `command_injection` - OS command injection patterns
- `directory_traversal` - Path traversal and LFI attempts
- `exploits` - Known CVE patterns (Log4Shell, Shellshock, etc.)
- `c2_beacon` - Command & Control communication patterns
- `reconnaissance` - Port scanning, OS fingerprinting, vulnerability scanner patterns
- `dos_patterns` - SYN flood, Slowloris, DNS/NTP/SSDP amplification
- `brute_force` - SSH, FTP, HTTP auth, SMTP, RDP, MySQL attacks
- `protocol_anomaly` - Malformed headers, invalid flags, fragmentation
- `ssrf_xxe` - Server-side request forgery, XML injection
- `deserialization` - Java, PHP, .NET, Python pickle attacks

**DNS Filtering (7 modules)**
- `dns_tunneling` - Data exfiltration via DNS queries
- `dga` - Domain Generation Algorithm patterns
- `malicious_domains` - Known malicious domain categories
- `dns_exfiltration` - Base64/hex encoded DNS exfiltration
- `dns_rebinding` - Short TTL, IP switching attacks
- `dns_amplification` - ANY queries, DNSSEC abuse
- `fast_flux` - Botnet domain patterns, rapid IP rotation

**Web Filtering (6 modules)**
- `web_categories` - Category-based URL filtering
- `url_patterns` - Suspicious URL pattern detection
- `tls_inspection` - SNI filtering, JA3 fingerprints, cert anomalies
- `api_abuse` - GraphQL injection, JWT attacks, rate limit bypass
- `web_shells` - Shell access patterns, China Chopper
- `http_smuggling` - CL.TE, TE.CL, TE.TE obfuscation

**Antivirus Detection (6 modules)**
- `eicar` - EICAR test file transfers
- `av_signatures` - Known malware signature triggers
- `ransomware` - File extensions, ransom notes, key exchange
- `cryptominer` - Stratum protocol, mining pools, WebMiner
- `dropper` - PowerShell cradles, LOLBins, macro documents
- `archive_evasion` - Nested archives, polyglots, zip bombs

**Video/Streaming (4 modules)**
- `streaming` - RTMP, HLS, DASH protocols
- `p2p_torrent` - BitTorrent handshakes, DHT, trackers
- `voip_webrtc` - SIP, RTP, STUN/TURN, Teams patterns
- `gaming` - Steam, Xbox Live, PSN, game server queries

**Benign Traffic (7 modules)**
- `web_browsing` - Normal HTTP/HTTPS patterns
- `email` - SMTP, IMAP, POP3 traffic
- `file_transfer` - FTP, SFTP patterns
- `cloud_services` - AWS, Azure, GCP, O365 API patterns
- `iot_device` - MQTT, CoAP, smart home, IP cameras
- `mobile_app` - App stores, push notifications, analytics
- `vpn_proxy` - OpenVPN, WireGuard, IPsec, SOCKS, Tor

**Data Exfiltration (3 modules)**
- `icmp_covert` - Data in ICMP payload, oversized pings
- `https_exfil` - Large POSTs, cloud storage abuse, webhooks
- `protocol_abuse` - NTP covert, HTTP headers, TCP timestamps

#### Scenarios (15 total)
- `quick-test` - Brief validation of all categories
- `full-mix` - Comprehensive testing with all 45 modules
- `ips-deep` - Complete IPS/IDS testing
- `dns-focus` - DNS filtering validation
- `web-focus` - Web filtering tests
- `av-focus` - Antivirus detection tests
- `video-focus` - Video streaming detection
- `benign-only` - Baseline legitimate traffic
- `stealth` - Low-rate evasion patterns
- `recon-test` - Reconnaissance detection
- `dos-test` - DoS/DDoS pattern testing
- `exfil-test` - Data exfiltration detection
- `ransomware-test` - Ransomware indicators
- `iot-test` - IoT protocol testing
- `api-test` - API security testing

#### Documentation
- Comprehensive README with badges and module tables
- User guide (docs/USAGE.md)
- Developer guide (docs/DEVELOPMENT.md)
- Contributing guidelines (CONTRIBUTING.md)
- Security policy (SECURITY.md)
- Code of Conduct (CODE_OF_CONDUCT.md)

#### Testing & CI
- 246 unit tests with pytest
- GitHub Actions CI workflow
- Cross-platform testing (Linux, macOS, Windows)
- Code quality checks with Ruff and mypy

### Security

- All malicious patterns use safe test signatures (EICAR, etc.)
- No actual exploitation code included
- Traffic is clearly identifiable as test traffic

[Unreleased]: https://github.com/jmpijll/netsec-tester/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jmpijll/netsec-tester/releases/tag/v1.0.0

