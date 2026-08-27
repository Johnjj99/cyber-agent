# Cyber-Agent – Self‑Evolving Security Auditing System

**A deterministic, self‑improving, continuous cybersecurity auditing agent that detects vulnerabilities across web, network, DNS, cloud, APIs, and VPNs – without root, credentials, or machine learning.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/security-auditing-red.svg)](https://github.com/yourname/cyber-agent)

---

## 🌟 Overview

Cyber-Agent is a **living security system** that:
- **Audits** targets continuously (every 30 seconds).
- **Evolves** its own remediation strategies using a genetic algorithm.
- **Learns** from past failures via a persistent learning store.
- **Heals** its own code when normalizers crash.
- **Invents** new normalizers when it detects repeated error patterns.
- **Tunes** its own hyperparameters (population size, generations, mutation rate).

It is **completely deterministic** – no neural networks, no LLMs, no black boxes. Every action is traceable and explainable.

---

## 🚀 Key Features

### Web Security
| Check | Detection Method |
|-------|------------------|
| Security Headers | HSTS, CSP, X‑Frame‑Options, X‑Content‑Type‑Options, Referrer‑Policy |
| SSL/TLS | Certificate validity, connection errors |
| XSS | Reflected XSS via payload injection |
| SQL Injection | Parameter‑based SQLi via error detection |
| Directory Enumeration | Wordlist‑based discovery (admin, login, wp‑admin, etc.) |

### Network Security
| Check | Detection Method |
|-------|------------------|
| RDP | Open port 3389, missing Network Level Authentication (NLA) |
| VPN | OpenVPN (UDP/1194), IPsec (UDP/500, 4500), WireGuard (UDP/51820), SSL VPN endpoints (/vpn, /sra, /sslvpn) |

### DNS Security
| Check | Detection Method |
|-------|------------------|
| SPF | Missing record, missing `~all` or `-all` |
| DKIM | Missing record |
| DMARC | Missing record, weak policy (none) |
| DNSSEC | Not enabled |
| CAA | Missing record |

### Cloud Security
| Check | Detection Method |
|-------|------------------|
| S3 | Publicly accessible buckets (HEAD request) |

### API Security
| Check | Detection Method |
|-------|------------------|
| GraphQL | Introspection enabled |
| CORS | `Access-Control-Allow-Origin: *` |
| Admin Endpoints | Exposed `/admin`, `/dashboard`, `/panel` |
| Rate Limiting | Missing or weak rate limiting |
| JWT Weakness | Acceptance of `none` algorithm, empty tokens |

### Fuzzing & Anomaly Detection
- **20+ payloads** – SQLi, path traversal, NoSQL, LDAP, XSS, SSTI, command injection, format strings.
- **Statistical anomaly detection** – flags deviations in status code, response length, and response time (> 3 standard deviations from baseline).
- **Error detection** – identifies SQL errors, stack traces, and fatal errors.

### CVE Scanning
- **Local database** (`cve_db.json`) for known CVEs.
- **Fingerprinting** – extracts versions from:
  - HTTP `Server` header
  - `X-Powered-By` header
  - Response body (keyword matching)
- **Currently supported products**:
  - Apache (CVE-2021-41773, CVE-2021-42013)
  - nginx (CVE-2021-23017)
  - OpenSSH (CVE-2021-36368)
  - Fortra GoAnywhere MFT (CVE-2023-48788, CVE-2025-10035)
  - ConnectWise ScreenConnect (CVE-2024-1709)
  - BeyondTrust (CVE-2026-1731)

### Self‑Healing Intelligence
| Feature | Description |
|---------|-------------|
| **Normaliser Crash Detection** | Catches exceptions, records traceback, operation, and field. |
| **Traceback‑Based Repair** | Parses tracebacks, repairs `KeyError`, `AttributeError`, `IndexError`, `TypeError`. |
| **Advanced Pattern‑Based Repair** | Analyses repeated failures to generate targeted patches (e.g., adds `.get()` for `KeyError`). |
| **Event‑Driven Triggers** | Self‑healing activates only when fitness stagnates for 3 cycles. |
| **Code Rewriter** | Appends new normalizers, modifies existing code with backup, rollback, syntax validation. |

### Evolutionary Intelligence
| Component | Description |
|-----------|-------------|
| **Chromosome** | `(normalizers, meta)` – normalizers are a set of actions; meta contains hyperparameters. |
| **Population** | Evolves over generations using selection, crossover, mutation, elitism. |
| **Meta‑Evolution** | Evolves population size (10–50), generations (3–15), mutation rate (0.1–0.6). |
| **Learning Store** | Records all failures; seeds future populations with successful fixes. |
| **Normalizer Invention** | Detects repeated errors and generates new Python functions to fix them. |
| **Dynamic Validator Checks** | Adds new security rules to `validator_config.json`. |

### Reporting
- **Structured JSON report** (`output/report.json`) with:
  - Timestamp, targets, fitness score.
  - Vulnerability list with field, type, description, severity (High/Medium/Info).
- **Severity Mapping**:
  - **High**: Open ports, SQLi, XSS, S3 public, path traversal, fuzzing anomalies, VPN detection.
  - **Medium**: Missing headers, weak DNS, API misconfigurations, rate limiting, JWT weaknesses.
  - **Info**: Missing DNSSEC, CAA.

### Continuous Operation
- Runs **indefinitely** in a loop (default interval: 30 seconds).
- Scans all targets in `targets.txt` in **parallel** (ThreadPoolExecutor).
- Updates `output/report.json` after every cycle.
- Records all failures in `output/learning_store.json`.

---

## 🏗️ Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                     Cyber-Runner.py                         │
│               (Continuous Evolution Loop)                   │
│  - Initialises population                                   │
│  - Evaluates fitness                                       │
│  - Applies best chromosome                                 │
│  - Evolves next generation                                 │
│  - Triggers self‑healing on stagnation                     │
└─────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│                  Cyber-Validator.py                         │
│              (Runs all scanners in parallel)               │
│  - Web Scanner (headers, SSL, directories)                │
│  - XSS Scanner                                            │
│  - DNS Scanner                                            │
│  - RDP Scanner                                            │
│  - VPN Scanner                                            │
│  - API Scanner (REST, advanced)                           │
│  - Cloud Scanner (S3)                                     │
│  - Container Scanner (Docker)                             │
│  - CVE Scanner                                            │
│  - Fuzzer                                                 │
└─────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│                    Cyber-Rules.py                          │
│                  (Normalizers & Repair)                    │
│  - enable_hsts, add_csp, block_rdp_port, enable_nla      │
│  - fix_xss, make_s3_private, fix_api_config              │
│  - patch_cve, report_anomaly                             │
│  - fix_normalizer (self‑healing)                         │
│  - create_custom_fix (normalizer invention)              │
└─────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────┐
│                   Learning Store                           │
│          (Persistent memory – output/learning_store.json)  │
│  - Records all failures                                   │
│  - Seeds future populations                               │
│  - Supports advanced pattern‑based repair                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Requirements
- Python 3.8+
- Termux, Linux, macOS, or Windows (with WSL)

### Clone & Install
```bash
git clone https://github.com/Johnjj99/cyber-agent.git
cd cyber-agent
pip install -r requirements.txt
