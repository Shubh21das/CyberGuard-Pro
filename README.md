# CyberGuard Pro

### An Integrated Cyber Incident Response & Security Analysis Toolkit

CyberGuard Pro is a full-stack, web-based cybersecurity incident response toolkit that consolidates 8 security disciplines into a single, unified Flask dashboard. Built entirely on free and open-source technologies, it enables security analysts and students to perform OSINT reconnaissance, network scanning, threat intelligence, web security auditing, digital forensics, phishing detection, and password analysis — all from one browser tab — with automated PDF report generation.

> **Ethical Use Disclaimer:** This tool is designed strictly for authorized and educational use. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## Table of Contents

- [Features](#features)
- [Modules](#modules)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [API Keys Setup](#api-keys-setup)
- [Running the Application](#running-the-application)
- [Module Usage Guide](#module-usage-guide)
- [Safe Test Targets](#safe-test-targets)
- [Project Structure](#project-structure)
- [Course Practicals Coverage](#course-practicals-coverage)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- 8 integrated security modules accessible from a single web dashboard
- Real-time scan results rendered in a clean, responsive Bootstrap 5 interface
- Interactive IP geolocation maps powered by Folium
- Automated PDF audit report generation consolidating all scan results
- Session-based scan tracking — run multiple modules and compile one final report
- Cross-platform — runs on Windows, macOS, and Linux
- 100% free APIs and open-source tools — no paid subscriptions required
- Ethical by design — authorization disclaimers and consent checks built in

---

## Modules

| # | Module | Description | APIs / Tools Used |
|---|--------|-------------|-------------------|
| 1 | OSINT Reconnaissance | IP/domain profiling — ports, CVEs, WHOIS, DNS, geolocation, map | Shodan InternetDB, python-whois, dnspython, ip-api.com, Folium |
| 2 | Network Scanner | Socket-based TCP port reachability check with risk rating | Python socket library |
| 3 | Threat Intelligence | URL, file hash, and IP reputation analysis | VirusTotal API v3, AbuseIPDB API |
| 4 | Web Security Auditor | HTTP headers, SSL/TLS, cookies, SQLi, XSS detection | Python requests, ssl library |
| 5 | Digital Forensics | File metadata, hashes, strings extraction, disk image analysis | ExifTool, hashlib, Sleuth Kit |
| 6 | Phishing Detector | Email header analysis, spoofing detection, SPF/DMARC verification | dnspython, VirusTotal API |
| 7 | Password Analyzer | Strength estimation and breach database checking | zxcvbn, PwnedPasswords API |
| 8 | PDF Report Generator | Consolidated professional audit report from all session scans | FPDF2 |

---

## Tech Stack

**Backend:** Python 3.x, Flask, python-dotenv

**Frontend:** HTML5, Bootstrap 5, Font Awesome, Chart.js, Jinja2

**Security APIs:** Shodan InternetDB, VirusTotal v3, AbuseIPDB, PwnedPasswords, ip-api.com

**Security Tools:** ExifTool, Sleuth Kit, python-whois, dnspython, zxcvbn

**Reporting:** FPDF2, Folium

---

## Prerequisites

Make sure the following are installed on your system before running the project:

**Python 3.8 or higher**
```
python --version
```

**Nmap** (optional — used for reference)
- Windows: Download from https://nmap.org/download
- Linux/Kali: `sudo apt install nmap`
- Mac: `brew install nmap`

**ExifTool**
- Windows: Download from https://exiftool.org, rename to `exiftool.exe`, place in `C:/Windows/`
- Linux: `sudo apt install libimage-exiftool-perl`
- Mac: `brew install exiftool`

**Sleuth Kit** (optional — for disk image forensics)
- Kali Linux: Pre-installed. Verify with `ils --version`
- Others: Download from https://sleuthkit.org/sleuthkit/download.php
- Alternative GUI: Autopsy from https://www.autopsy.com

---

## Installation

**1. Clone the repository**
```bash
git clone https://github.com/Shubh21das/CyberGuard-Pro.git
cd CyberGuard-Pro
```

**2. Create and activate virtual environment**
```bash
# Create
python -m venv venv

# Activate — Windows
venv\Scripts\activate

# Activate — Mac/Linux
source venv/bin/activate
```

**3. Install Python dependencies**
```bash
pip install -r requirements.txt
```

---

## API Keys Setup

CyberGuard Pro uses 3 external APIs that require free API keys. Sign up at the links below — no credit card required for any of them.

| API | Sign Up Link | Free Tier Limits |
|-----|-------------|-----------------|
| VirusTotal | https://virustotal.com/gui/join-us | 4 requests/min, 500/day |
| AbuseIPDB | https://abuseipdb.com (Pricing → Free) | 1000 requests/day |
| Shodan (optional) | https://shodan.io (Register) | 100 queries/month |

> **Note:** Shodan InternetDB (used by default) and PwnedPasswords API require no API key at all.

**Create your `.env` file** by copying the example:
```bash
cp .env.example .env
```

**Edit `.env` and fill in your keys:**
```
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
SECRET_KEY=your_random_secret_key_here
```

> **Security Note:** Never commit your `.env` file. It is already listed in `.gitignore` to prevent accidental exposure.

---

## Running the Application

```bash
# Make sure venv is activated
python app.py
```

Open your browser and navigate to:
```
http://localhost:5000
```

You will see the CyberGuard Pro dashboard with all 8 modules ready to use.

---

## Module Usage Guide

**OSINT Reconnaissance**
Enter an IP address or domain name. The module queries Shodan InternetDB, performs WHOIS and DNS lookups, fetches geolocation data, and renders an interactive map. Best used with domain names like `scanme.nmap.org`.

**Network Scanner**
Enter a target IP address or hostname. Check the authorization confirmation checkbox. The module checks 14 common TCP ports for reachability and assigns a risk rating based on open port count.

**Threat Intelligence**
Choose between URL scanning, file hash lookup, or IP reputation check. Enter the target value and the module queries VirusTotal and/or AbuseIPDB and returns a CLEAN / SUSPICIOUS / MALICIOUS verdict.

**Web Security Auditor**
Enter a full URL including `http://` or `https://`. The module checks HTTP security headers, SSL certificate validity, cookie security flags, and performs basic SQLi and XSS reflection tests.

**Digital Forensics**
Upload any file (image, document, PDF). The module extracts all available metadata using ExifTool, computes MD5/SHA1/SHA256 hashes, checks the hash on VirusTotal, and extracts embedded strings. For disk images, Sleuth Kit analysis is also performed.

**Phishing Detector**
Paste raw email headers into the text area. To get raw headers: in Gmail → open email → three dots menu → Show Original. The module analyzes for spoofing, checks SPF/DMARC records, and assigns a phishing risk rating.

**Password Analyzer**
Enter any password for analysis. The module estimates strength using zxcvbn, checks if the password appears in known data breaches using the PwnedPasswords k-anonymity API, and suggests improvements. Your password is never transmitted to any server.

**PDF Report Generator**
After running any combination of modules, navigate to PDF Reports. All session scan results are automatically consolidated into a professional PDF audit report saved to the `/reports/` folder.

---

## Safe Test Targets

Always use authorized targets. The following are publicly sanctioned for testing:

| Target | Provider | Suitable For |
|--------|----------|-------------|
| `scanme.nmap.org` | Nmap Project | OSINT, Network Scanner |
| `http://testphp.vulnweb.com` | Acunetix | Web Security Auditor |
| `http://demo.testfire.net` | IBM | Web Security Auditor |
| `127.0.0.1` | Localhost | Network Scanner |
| Your own IP address | Self | All modules |
| Your own files | Self | Digital Forensics |
| Your own email headers | Self | Phishing Detector |

---

## Project Structure

```
CyberGuard-Pro/
│
├── app.py                      # Main Flask application
├── requirements.txt            # Python dependencies
├── .env.example                # API key template
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── recon.py                # OSINT Reconnaissance
│   ├── network.py              # Network Scanner
│   ├── threat_intel.py         # Threat Intelligence
│   ├── web_security.py         # Web Security Auditor
│   ├── forensics.py            # Digital Forensics
│   ├── phishing.py             # Phishing Detector
│   ├── passwords.py            # Password Analyzer
│   └── report.py               # PDF Report Generator
│
├── templates/
│   ├── base.html               # Base layout with navbar
│   ├── index.html              # Home dashboard
│   ├── recon.html              # OSINT module page
│   ├── network.html            # Network scanner page
│   ├── threat.html             # Threat intel page
│   ├── websec.html             # Web security page
│   ├── forensics.html          # Forensics page
│   ├── phishing.html           # Phishing detector page
│   ├── passwords.html          # Password analyzer page
│   └── report.html             # Report compiler page
│
├── static/                     # CSS, JS, assets (CDN-based)
├── reports/                    # Generated PDF reports (gitignored)
└── uploads/                    # Temporary file uploads (gitignored)
```

---

## Course Practicals Coverage

This project was built as a mini project for the Cybersecurity and Forensics course at MIT Academy of Engineering, Pune. It covers the following practicals:

| Practical | Topic | CyberGuard Module |
|-----------|-------|------------------|
| Practical 01 | NSA Features, Firewall, Browser Security, Web Vulnerabilities | Web Security Auditor, Phishing Detector |
| Practical 02 | SQL Injection Penetration Testing | Web Security Auditor |
| Practical 03 | Kali Linux Security Tools | Network Scanner, Password Analyzer |
| Practical 04 | Web Application Security Framework | Web Security Auditor |
| Practical 05 | wfuzz Fuzzing Tool | Web Security Auditor |
| Practical 06 | OSINT with Shodan/Censys | OSINT Reconnaissance, Threat Intelligence |
| Practical 08 | Wireless Security & Traffic Analysis | Network Scanner |
| Practical 09 | Sleuth Kit — Digital Forensics | Digital Forensics |

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/NewModule`
3. Commit your changes: `git commit -m "Add new module"`
4. Push to the branch: `git push origin feature/NewModule`
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

## Author

**Shubh Das**
- GitHub: [@Shubh21das](https://github.com/Shubh21das)
- LinkedIn: [in/shubh-das-66330a31a](https://linkedin.com/in/shubh-das-66330a31a)
- Email: shubhdas.17.w@gmail.com

---

*Built with purpose for the Cybersecurity and Forensics course — MIT Academy of Engineering, Pune — 2025–2026*
