# Security Policy

## About This Tool

NetSec Tester is a **security testing tool** designed to generate simulated network traffic for testing Next-Generation Firewall (NGFW) policies. All "malicious" traffic patterns use industry-standard test signatures (like EICAR) that trigger security detections **without causing actual harm**.

## ⚠️ Responsible Use

This tool is intended for:
- ✅ Authorized security testing in lab environments
- ✅ NGFW policy validation and verification
- ✅ Security research and education
- ✅ Penetration testing with proper authorization

**DO NOT** use this tool:
- ❌ On networks without proper authorization
- ❌ Against production systems without approval
- ❌ For any malicious or illegal purposes

Unauthorized use of this tool may violate laws in your jurisdiction.

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities in NetSec Tester seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **DO NOT** create a public GitHub issue for security vulnerabilities
2. Email your findings to: **security@netsec-tester.dev**
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Initial Assessment**: Within 7 days, we will provide an initial assessment
- **Resolution Timeline**: 
  - Critical vulnerabilities: 7-14 days
  - High severity: 14-30 days
  - Medium/Low severity: 30-90 days
- **Disclosure**: We will coordinate disclosure timing with you

### Recognition

We believe in recognizing security researchers who help improve our project:

- Contributors who report valid vulnerabilities will be credited in our CHANGELOG (unless they prefer to remain anonymous)
- Significant contributions may be recognized in our README

## Security Best Practices for Users

When using NetSec Tester:

### Network Isolation

```bash
# Run tests in an isolated network segment
# Use a dedicated testing VLAN
# Never test against production firewalls without authorization
```

### Privilege Management

```bash
# Use the minimum required privileges
# On Linux/macOS: use sudo only when necessary
# On Windows: run as Administrator only when required
```

### Configuration Security

```yaml
# Do not commit custom configs with sensitive target IPs
# Use environment variables for sensitive values
# Review scenario configs before running
```

### Monitoring

- Monitor your test traffic to ensure it stays within scope
- Have a way to quickly stop tests if needed (`Ctrl+C`)
- Log all testing activities for compliance

## Dependencies

We regularly update dependencies to address security vulnerabilities. If you discover a vulnerability in one of our dependencies:

1. Check if it's already reported in our issues
2. If not, open an issue with the dependency name and CVE (if available)
3. For critical dependency vulnerabilities, email us directly

## Security-Related Configuration

### Safe Defaults

NetSec Tester uses safe defaults:
- Test patterns use EICAR and other industry-standard safe signatures
- No actual exploitation code is included
- Traffic is clearly identifiable as test traffic

### Custom Modules

If you create custom modules:
- Do not include actual malicious payloads
- Use clearly identifiable test patterns
- Document any security considerations
- Submit for review before contributing

## Audit Log

For compliance and security auditing, NetSec Tester outputs can be logged:

```bash
# Log output to file for auditing
sudo netsec-tester run full-mix 2>&1 | tee test-log-$(date +%Y%m%d).log
```

## Contact

- Security Issues: security@netsec-tester.dev
- General Questions: [GitHub Discussions](https://github.com/jmpijll/netsec-tester/discussions)
- Bug Reports: [GitHub Issues](https://github.com/jmpijll/netsec-tester/issues)

