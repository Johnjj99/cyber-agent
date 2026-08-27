# Cyber-Agent – Self‑Evolving Security Auditing

A deterministic, self‑improving, continuous cybersecurity auditing agent that detects vulnerabilities across web, network, DNS, cloud, APIs, and VPNs – without root or credentials.

## Features

- **Web Security**: Headers (HSTS, CSP, XFO), SSL/TLS, XSS, SQLi, directory enumeration.
- **Network**: RDP, VPN (OpenVPN, IPsec, WireGuard, SSL VPN).
- **DNS**: SPF, DKIM, DMARC, DNSSEC, CAA.
- **Cloud**: S3 public bucket detection.
- **API**: GraphQL introspection, CORS, admin endpoints, rate limiting, JWT weaknesses.
- **Fuzzing**: 20+ payloads with statistical anomaly detection.
- **CVE Scanning**: Local database for known CVEs (Apache, nginx, OpenSSH, GoAnywhere, ScreenConnect, BeyondTrust).
- **Self‑Healing**: Repairs its own code when normalizers crash.
- **Meta‑Evolution**: Tunes population size, generations, and mutation rate.
- **Continuous Operation**: Runs every 30 seconds, adapts to new targets.

## Quick Start

```bash
git clone https://github.com/yourname/cyber-agent.git
cd cyber-agent
pip install -r requirements.txt
python cyber_runner.py
