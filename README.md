# SSRF & OWASP Scanner Toolkit

A collection of Python-based security scanning tools for SSRF discovery, escalation, and OWASP Top 10 testing. Built for authorized security assessments and bug bounty hunting.

## ⚠️ WARNING

**Only use these tools against systems you own or have explicit written authorization to test.** Unauthorized scanning may violate laws and bug bounty program policies. The author accepts no liability for misuse.

---

## 📁 Project Structure

```
ssrf-toolkit/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── ssrf_hunter.py            # SSRF detection & recon scanner
├── ssrf_escalate.py          # SSRF escalation (metadata, RCE, file read)
├── indeed_owasp_scanner.py   # OWASP Top 10 scanner for recon data
├── run_ssrf_hunter.sh        # Shell wrapper for ssrf_hunter.py
├── run_escalation.sh         # Shell wrapper for ssrf_escalate.py
└── run_owasp_scan.sh         # Shell wrapper for indeed_owasp_scanner.py
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- `pip` package manager

### Installation

```bash
# Clone or download this repository
git clone https://github.com/YOUR_USERNAME/ssrf-toolkit.git
cd ssrf-toolkit

# Install dependencies
pip install -r requirements.txt
```

### Required Dependency

```
requests>=2.31.0
urllib3>=2.0.0
```

---

## 🔧 Tools Overview

| Tool | Purpose |
|------|---------|
| `ssrf_hunter.py` | SSRF detection from recon data (OOB, in-band, WAF bypasses, cloud metadata) |
| `ssrf_escalate.py` | SSRF escalation to Cloud Metadata theft, Local File Read, Internal Port access, RCE |
| `indeed_owasp_scanner.py` | OWASP Top 10 + Infrastructure scanner using recon data (subs, endpoints, ports) |

---

## 🛠️ ssrf_hunter.py — SSRF Detection

### Description
Reads an `endpoints.txt` recon file, identifies SSRF-susceptible parameters, and tests them using OOB blind detection, in-band confirmation, WAF/filter bypasses, header injection, alternative URI schemes, and cloud metadata probes.

### Usage

```bash
python3 ssrf_hunter.py -f endpoints.txt --mode all --confirm-authorized
```

### Required Flag

| Flag | Description |
|------|-------------|
| `--confirm-authorized` | **REQUIRED.** Confirms you have written authorization to test the target. |

### Optional Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-f, --file` | Path to `endpoints.txt` recon file | (required if `--dir` not used) |
| `-d, --dir` | Target folder containing `endpoints.txt` | (required if `--file` not used) |
| `-m, --mode` | Scan mode: `detect`, `confirm`, `bypass`, `escalate`, `headers`, `all` | `all` |
| `-t, --threads` | Concurrent threads | `10` |
| `--timeout` | Request timeout in seconds | `10` |
| `--oob-callback` | Full callback URL for OOB blind SSRF payloads (e.g. `https://webhook.site/UUID`) | `http://YOUR_OOB_DOMAIN.oast.fun` |
| `--webhook-url` | Webhook.site / Requestrepo URL to poll for OOB callbacks | (optional) |
| `--listener-url` | In-band confirmation listener URL | `http://YOUR_LISTENER:8080/test` |
| `--listen-port` | Local port for in-band confirmation listener | `8080` |
| `--redirector-url` | Open redirector chain destination (for whitelist bypass testing) | `https://YOUR_SERVER.com/ssrf_redirect.php` |
| `-o, --output` | Report output directory | `ssrf_report` |

### Examples

**Basic detection mode:**
```bash
python3 ssrf_hunter.py -f target/endpoints.txt --mode detect \
  --oob-callback "https://webhook.site/YOUR_ID" \
  --confirm-authorized
```

**Full scan with custom threads and timeout:**
```bash
python3 ssrf_hunter.py -d target/ --mode all \
  --oob-callback "https://webhook.site/YOUR_ID" \
  --webhook-url "https://webhook.site/YOUR_ID" \
  --threads 20 --timeout 15 \
  --confirm-authorized
```

**Using shell wrapper:**
```bash
chmod +x run_ssrf_hunter.sh
./run_ssrf_hunter.sh
```

---

## 🚀 ssrf_escalate.py — SSRF Escalation

### Description
Takes confirmed/vulnerable endpoints from a previous scan report and escalates them to Cloud Metadata theft, Local File Read, Internal Port scanning, WAF bypass testing, and RCE via Gopher (Redis webshell, MongoDB admin injection).

### Usage

```bash
python3 ssrf_escalate.py --from-report ssrf_report/ssrf_findings.json \
  --output ssrf_escalation_report \
  --confirm-authorized
```

### Required Flag

| Flag | Description |
|------|-------------|
| `--confirm-authorized` | **REQUIRED.** Confirms you have written authorization to test the target. |

### Optional Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--from-report` | Previous scan JSON report to load targets from | (required if `--endpoint` not used) |
| `-e, --endpoint` | Single endpoint to escalate | (required if `--from-report` not used) |
| `-p, --parameter` | Parameter to test (required with `--endpoint`) | — |
| `-t, --threads` | Concurrent threads | `5` |
| `--timeout` | Request timeout in seconds | `10` |
| `-o, --output` | Report output directory | `ssrf_escalation_report` |

### Examples

**Escalate from previous report:**
```bash
python3 ssrf_escalate.py --from-report ssrf_report/ssrf_findings.json \
  --confirm-authorized
```

**Escalate a single endpoint:**
```bash
python3 ssrf_escalate.py -e "https://target.com/proxy?url=" -p url \
  --confirm-authorized
```

**Using shell wrapper:**
```bash
chmod +x run_escalation.sh
./run_escalation.sh
```

---

## 🎯 indeed_owasp_scanner.py — OWASP Top 10 Scanner

### Description
Targeted OWASP Top 10 (2021) + Infrastructure scanner that uses recon data (`subs.txt`, `endpoints.txt`, `open_ports.txt`) to test high-value hosts for access control, crypto failures, injection, misconfiguration, outdated components, auth failures, integrity failures, logging failures, SSRF, CORS issues, and subdomain takeover indicators.

### Usage

```bash
python3 indeed_owasp_scanner.py --threads 15 --timeout 8 --confirm-authorized
```

### Required Flag

| Flag | Description |
|------|-------------|
| `--confirm-authorized` | **REQUIRED.** Confirms you have written authorization to test the target. |

### Optional Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --threads` | Concurrent threads | `20` |
| `--timeout` | Request timeout in seconds | `8` |

### Examples

**Run with default settings:**
```bash
python3 indeed_owasp_scanner.py --confirm-authorized
```

**Using shell wrapper:**
```bash
chmod +x run_owasp_scan.sh
./run_owasp_scan.sh
```

**Note:** The scanner reads recon data from `/mnt/c/Users/mansu/bb/indeed.com/20261010-123858/` by default. Edit `RECON_DIR` in the script to point to your recon folder.

---

## 📋 Output Reports

All tools generate reports in the specified output directory:

| File | Format | Description |
|------|--------|-------------|
| `ssrf_findings.json` | JSON | Machine-readable scan results |
| `ssrf_report.md` | Markdown | Human-readable report sorted by severity |
| `ssrf_escalation.json` | JSON | Escalation findings |
| `ssrf_escalation.md` | Markdown | Escalation report sorted by severity |
| `owasp_findings.json` | JSON | OWASP scan results |
| `owasp_report.md` | Markdown | OWASP scan report |

---

## 🔒 Authorization Requirement

All tools require the `--confirm-authorized` flag. This is a safety measure to ensure you only scan systems you own or have explicit written authorization to test. The tool will exit with an error if this flag is not provided.

```
AUTHORIZATION REQUIRED
======================================================================
SSRF testing can impact internal infrastructure and cloud metadata.
Only run against systems you own or have explicit written
authorization to test. Re-run with --confirm-authorized to proceed.
======================================================================
```

---

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Do not use against systems without explicit permission. The author is not responsible for any misuse or damage caused by this tool.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📬 Contact

For questions or issues, open a GitHub Issue in this repository.
