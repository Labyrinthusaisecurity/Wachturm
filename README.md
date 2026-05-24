# Wachturm
SSL/TLS Security Suite
A collection of offensive & defensive scripts for auditing, monitoring, and hardening TLS configurations.

<img width="1756" height="660" alt="wachturm_logo_cropped_v2" src="https://github.com/user-attachments/assets/82fa7113-a1df-4538-bc55-bcbf86e08a3f" />



**The watchtower that never sleeps.**

*Wachturm (German: watchtower) — a suite of SSL/TLS security tools*
*built to watch your certificates, cipher suites, and protocol posture*
*so your infrastructure never goes dark without warning.*

---

![Python](https://img.shields.io/badge/Python-3.8%2B-3572A5?style=flat-square&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-00ff88?style=flat-square)
![Dependencies](https://img.shields.io/badge/Dependencies-zero-00d4ff?style=flat-square)
![Tests](https://img.shields.io/badge/Tests-passing-00ff88?style=flat-square)
![Coverage](https://img.shields.io/badge/Coverage-80%25%2B-00ff88?style=flat-square)
![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20macOS%20%7C%20Docker-888?style=flat-square)

</div>

---

## What is Wachturm?

Wachturm is a collection of purpose-built Python scripts for SSL/TLS security operations. It covers the full lifecycle of certificate and protocol security — from continuous expiry monitoring and multi-channel alerting, to vulnerability scanning, cipher grading, and audit reporting.

Every tool is a single Python file. No pip install. No virtual environment required. Drop it on any server with Python 3.8+ and it runs.

> **The name.** *Wachturm* is the German word for watchtower — a structure built to observe, to warn, and to never miss what approaches in the dark. That is exactly what these tools do.

---

## The Suite

```
wachturm/
│
├── cert-canary/          Continuous certificate expiry monitor
├── vuln-sweep/           CVE vulnerability scanner (6 CVEs)
├── cipher-judge/         Cipher suite grader and auditor
├── tls-timeline/         Certificate rotation history tracker
├── hsts-probe/           HSTS header and preload eligibility checker
└── audit-report/         HTML audit report generator
```

---

## Tools

### 🔐 cert-canary
> *The canary in the coal mine — except this one monitors your TLS stack.*

Continuously scans SSL/TLS certificates across any number of hosts in parallel. Grades each cert `OK / INFO / WARNING / CRITICAL` and fires alerts the moment something needs attention — before your users see a browser warning.

```
🟢  api.example.com:443        OK          87d left
🟡  staging.example.com:443    WARNING     24d left
🔴  legacy.example.com:8443    CRITICAL    4d left
💀  old.example.com:443        CRITICAL    EXPIRED 2d ago
⚫  internal.corp:443          ERROR       Connection refused
```

**Alert channels:**

| Channel | How |
|---|---|
| Slack | Block Kit formatted message with per-host fields and grade colours |
| Discord | Rich embeds, one per alerting host, colour-coded by severity |
| PagerDuty | Events API v2 — triggers and auto-resolves with stable `dedup_key` |
| Email | HTML + plaintext multipart via SMTP, supports STARTTLS and SSL |
| Webhook | Generic JSON POST with optional HMAC-SHA256 request signing |

```bash
# Single scan
python3 main.py --host example.com --once

# Daemon mode — sweeps every hour
python3 main.py --hosts hosts.txt --interval 3600

# All alert channels from env vars
export CANARY_SLACK_WEBHOOK="https://hooks.slack.com/..."
export CANARY_PAGERDUTY_KEY="your-routing-key"
python3 main.py --hosts hosts.txt --once --verbose
```

---

### 🔬 vuln-sweep
> *Six CVEs. One pass. No mercy.*

Probes hosts for six major SSL/TLS vulnerabilities using raw socket probes and `openssl` subprocess calls. Every check uses the actual exploit technique — not a version string lookup, not a banner grab.

```bash
python3 vuln-sweep.py --target example.com --all --verbose
python3 vuln-sweep.py --target example.com --heartbleed --robot
python3 vuln-sweep.py --file targets.txt --json-out results.json
```

**CVEs covered:**

```
┌─────────────────┬──────────────┬────────────────────────────────────────────┐
│ CVE             │ Name         │ Detection method                           │
├─────────────────┼──────────────┼────────────────────────────────────────────┤
│ CVE-2014-0160   │ Heartbleed   │ Raw HeartbeatRequest with padded length    │
│ CVE-2014-3566   │ POODLE       │ SSLv3 handshake probe + CBC cipher check   │
│ CVE-2011-3389   │ BEAST        │ TLS 1.0 + CBC cipher negotiation           │
│ CVE-2017-17382  │ ROBOT        │ ServerHello RSA key exchange detection     │
│ CVE-2016-0800   │ DROWN        │ Raw SSLv2 CLIENT-HELLO + EXPORT check      │
│ CVE-2013-0169   │ LUCKY13      │ CBC cipher structural exposure on TLS≤1.2  │
└─────────────────┴──────────────┴────────────────────────────────────────────┘
```

**Exit codes:** `0` clean · `1` vulnerabilities found · `2` errors

---

### ⚖️ cipher-judge
> *Every cipher suite on trial. Weak ones don't walk free.*

Enumerates accepted cipher suites, flags RC4, NULL, EXPORT, 3DES, and AECDH, and produces a per-suite verdict with an overall server grade.

```bash
python3 cipher-judge.py --target example.com
python3 cipher-judge.py --target example.com --json-out ciphers.json
```

```
VERDICT  example.com:443
──────────────────────────────────────────────
✓ PASS    TLS_AES_256_GCM_SHA384          TLS 1.3   AEAD, forward secret
✓ PASS    ECDHE-RSA-AES256-GCM-SHA384    TLS 1.2   AEAD, forward secret
~ WARN    ECDHE-RSA-AES128-SHA           TLS 1.2   CBC — prefer GCM
✗ FAIL    RC4-SHA                        TLS 1.0   Statistical bias attacks
✗ FAIL    DES-CBC3-SHA                   TLS 1.1   SWEET32 CVE-2016-2183
──────────────────────────────────────────────
Grade: B  (2 weak ciphers accepted)
```

---

### 📜 tls-timeline
> *Every certificate your host ever wore, catalogued.*

Stores a SQLite history of certificate fingerprints per host. Detects surprise replacements, mis-issuances, and rotation gaps. Alerts when a cert changes unexpectedly.

```bash
python3 tls-timeline.py --host example.com   # snapshot + diff
python3 tls-timeline.py --report example.com # full history
python3 tls-timeline.py --watch hosts.txt    # continuous tracking
```

```
example.com  cert history
────────────────────────────────────────────────────────
2026-01-15   aabbccdd11223344   Let's Encrypt   90d ✓ expected rotation
2025-10-12   ee99ff0011223344   Let's Encrypt   90d ✓ expected rotation
2025-07-08   deadbeef12345678   Unknown CA      ⚡ SURPRISE — issuer changed
2025-04-01   aaccddeeff001122   Let's Encrypt   90d ✓ expected rotation
────────────────────────────────────────────────────────
```

---

### 🛡️ hsts-probe
> *HSTS without preload is a seatbelt you only buckle after the crash.*

Checks `Strict-Transport-Security` headers, validates `max-age`, `includeSubDomains`, and `preload` eligibility, and walks the full redirect chain to detect HTTP→HTTPS leaks.

```bash
python3 hsts-probe.py --host example.com
python3 hsts-probe.py --file hosts.txt --json-out hsts.json
```

```
example.com
  HSTS header:      present
  max-age:          31536000  (365 days)
  includeSubDomains: yes
  preload:          yes
  preload eligible: ✓ YES
  redirect chain:   http://example.com → https://example.com
  mixed content:    none detected
```

---

### 📊 audit-report
> *From raw scan JSON to boardroom-ready PDF in one command.*

Consumes JSON output from any Wachturm tool and generates a self-contained HTML audit report with an executive summary, per-host cert details, cipher scorecard, CVE exposure matrix, and a prioritised remediation checklist.

```bash
python3 audit-report.py --input scan.json --out report.html
python3 audit-report.py --input scan.json --out report.html --logo company.png
```

---

## Quick Start

```bash
# Clone the suite
git clone https://github.com/yourname/wachturm.git
cd wachturm

# No pip install needed — stdlib only
python3 --version   # 3.8+ required
openssl version     # needed for vuln-sweep cipher checks

# Run your first cert scan
python3 cert-canary/main.py --host example.com --once

# Run your first vulnerability sweep
python3 vuln-sweep/vuln-sweep.py --target example.com --all
```

---

## Requirements

```
Python    3.8+       stdlib only — no pip install for any tool
openssl   any        binary in $PATH (for vuln-sweep and cipher-judge)
pytest    any        pip install pytest pytest-cov  (tests only)
```

No virtual environment required. No requirements.txt. No setup.py.
Every tool imports only from the Python standard library.

---

## Configuration

### Environment variables (recommended)

```bash
# cert-canary alert channels
export CANARY_SLACK_WEBHOOK="https://hooks.slack.com/services/T.../B.../..."
export CANARY_DISCORD_WEBHOOK="https://discord.com/api/webhooks/..."
export CANARY_PAGERDUTY_KEY="your-32-char-routing-key"
export CANARY_WEBHOOK_URL="https://your-endpoint.com/hooks"
export CANARY_WEBHOOK_SECRET="hmac-signing-secret"
```

### JSON config file

```json
{
  "hosts":   ["example.com", "api.example.com:8443"],
  "threads":  10,
  "interval": 3600,
  "thresholds": {
    "critical": 7,
    "warning":  30,
    "info":     60
  },
  "slack_webhook":   "https://hooks.slack.com/...",
  "pagerduty_key":   "your-routing-key",
  "smtp": {
    "host": "smtp.gmail.com", "port": 587,
    "user": "you@gmail.com",  "password": "app-password",
    "to":   ["ops@example.com"]
  }
}
```

```bash
python3 cert-canary/main.py --config canary.json
```

---

## Deployment

### Cron — run every 6 hours

```cron
0 */6 * * * canary /usr/bin/python3 /opt/wachturm/cert-canary/main.py \
    --hosts /opt/wachturm/hosts.txt --once \
    --json-out /var/log/wachturm/audit.jsonl >> /var/log/wachturm/canary.log 2>&1
```

### systemd — persistent daemon

```bash
sudo cp cert-canary/deploy/cert-canary.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cert-canary
sudo journalctl -u cert-canary -f
```

### Docker

```bash
cd cert-canary
docker compose up -d
docker compose logs -f
```

### GitHub Actions — daily scheduled scan

```yaml
on:
  schedule:
    - cron: "0 8 * * *"
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python3 cert-canary/main.py --hosts hosts.txt --once --verbose
        env:
          CANARY_SLACK_WEBHOOK: ${{ secrets.CANARY_SLACK_WEBHOOK }}
          CANARY_PAGERDUTY_KEY: ${{ secrets.CANARY_PAGERDUTY_KEY }}
```

---

## Testing

```bash
# Install test dependencies (the only pip install in the whole suite)
pip install pytest pytest-cov

# Run all tests
pytest tests/ --verbose --tb=short

# Run with coverage
pytest tests/ --cov=cert_canary --cov-report=term-missing --cov-fail-under=80

# Run a single test class
pytest tests/test_scanner.py::TestScanCertSuccess -v

# Run linting and type checking
pip install ruff mypy
ruff check cert_canary/ main.py
mypy  cert_canary/ main.py --ignore-missing-imports

# Run security analysis
pip install bandit
bandit -r cert_canary/ main.py --severity-level medium
```

**Test coverage targets:**

```
cert_canary/scanner.py   — 24 success tests · 12 exception tests · 10 sweep tests
cert_canary/config.py    — 8 defaults · 14 load · 10 env · 18 build · 22 parse
cert_canary/alerts/      — 7 base · 11 slack · 10 discord · 16 pagerduty
                           14 email · 13 webhook · 4 dispatcher
```

---

## Security Hardening

Every deployment method ships with hardening enabled by default.

### systemd

```ini
# Unit file includes full service isolation
NoNewPrivileges=true
CapabilityBoundingSet=           # all capabilities dropped
ProtectSystem=strict             # / and /usr read-only
MemoryDenyWriteExecute=true      # no writable+executable pages
SystemCallFilter=@system-service # syscall allowlist
PrivateTmp=true
```

### Docker

```yaml
# docker-compose.yml ships with
cap_drop: [ALL]
read_only: true
security_opt: [no-new-privileges:true]
```

---

## Design Principles

**Zero dependencies.**
Every tool uses only the Python standard library. No supply chain. No `pip install`. No `requirements.txt` to audit. Drop it on a server and it runs.

**Never raises.**
`scan_cert()` catches every exception and returns a structured `CertInfo` with `error` set. Callers never need try/except. A broken host never crashes a sweep of 200 healthy ones.

**One file per concern.**
Alert channels are one file each. Adding Microsoft Teams support means creating `alerts/teams.py` and adding two lines to `alerts/__init__.py`. Nothing else changes.

**Exit codes mean something.**
`0` = clean. `1` = attention needed. `2` = errors. Every tool plays nicely with cron, Nagios, PagerDuty, and CI pipelines without extra wrapper scripts.

**Credentials never in source.**
All secrets load from environment variables or a gitignored config file. The `.gitignore` in every tool directory blocks `.env` and `canary.json` by default.

---

## Repo Structure

```
wachturm/
│
├── cert-canary/
│   ├── cert_canary/
│   │   ├── __init__.py
│   │   ├── scanner.py
│   │   ├── config.py
│   │   ├── output.py
│   │   └── alerts/
│   │       ├── __init__.py
│   │       ├── base.py
│   │       ├── slack.py
│   │       ├── discord.py
│   │       ├── pagerduty.py
│   │       ├── email.py
│   │       └── webhook.py
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   ├── test_scanner.py
│   │   ├── test_config.py
│   │   └── test_alerts.py
│   ├── deploy/
│   │   ├── Dockerfile
│   │   ├── docker-compose.yml
│   │   ├── cert-canary.service
│   │   └── cert-canary-cron
│   ├── .github/
│   │   └── workflows/
│   │       ├── cert-check.yml
│   │       └── test.yml
│   ├── main.py
│   ├── hosts.txt
│   ├── canary.json.example
│   ├── .env.example
│   ├── .gitignore
│   └── README.md
│
├── vuln-sweep/
│   └── vuln-sweep.py
│
├── cipher-judge/
│   └── cipher-judge.py
│
├── tls-timeline/
│   └── tls-timeline.py
│
├── hsts-probe/
│   └── hsts-probe.py
│
├── audit-report/
│   └── audit-report.py
│
└── README.md                 ← you are here
```

---

## Roadmap

- [ ] `cert-canary` — Prometheus `/metrics` endpoint for Grafana dashboards
- [ ] `cert-canary` — Certificate chain validation (root / intermediate trust)
- [ ] `cert-canary` — Microsoft Teams and OpsGenie alert channels
- [ ] `cert-canary` — mTLS / client certificate support
- [ ] `vuln-sweep`  — Full Bleichenbacher oracle test for ROBOT (adaptive queries)
- [ ] `vuln-sweep`  — TLS 1.3 downgrade attack detection
- [ ] `cipher-judge`— Mozilla Observatory scoring integration
- [ ] `tls-timeline`— Cert Transparency log cross-reference
- [ ] `audit-report` — PDF export via WeasyPrint (optional dependency)
- [ ] `wachturm`    — Unified CLI: `wachturm scan example.com --all`

---

## Contributing

Contributions welcome. The bar is:

- New alert channel → one file in `cert_canary/alerts/`, two lines in `__init__.py`, tests in `test_alerts.py`
- New CVE check → one function in `vuln-sweep.py`, entry in `ALL_CHECKS`, tests
- All PRs must pass `pytest --cov-fail-under=80`, `ruff check`, `mypy`, and `bandit`
- No new runtime dependencies — stdlib only

---

## Legal

> Wachturm is built for authorized security testing of systems you own
> or have explicit written permission to scan.
>
> Unauthorized scanning may violate laws including the
> Computer Fraud and Abuse Act (CFAA) and equivalents in other jurisdictions.
> The authors accept no liability for misuse.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

*Built to watch. Built to warn. Built to last.*

**Wachturm** · MIT License · Pure Python · Zero dependencies

</div>

⚠️ Warning
These tools are intended for authorized security testing, research, and defensive use only.
Do not use this software against systems, networks, or infrastructure that you do not own or do not have explicit permission to test. Unauthorized use may violate laws and regulations.
The authors assume no liability for misuse or damage caused by this toolkit.
