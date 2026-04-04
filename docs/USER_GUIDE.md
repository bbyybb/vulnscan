# VulnScan User Guide

**Version 1.0.0**

An integrated vulnerability scanning tool combining Web DAST, Code SAST, and SCA capabilities into a single unified interface.

---

## Table of Contents

- [1. System Requirements](#1-system-requirements)
- [2. Installation](#2-installation)
- [3. CLI Usage](#3-cli-usage)
- [4. GUI Usage](#4-gui-usage)
- [5. HTTP Options](#5-http-options)
- [6. Scanners](#6-scanners)
- [7. Custom Tool Paths](#7-custom-tool-paths)
- [8. Reports](#8-reports)
- [9. Themes](#9-themes)
- [10. Language Configuration](#10-language-configuration)
- [11. Vulnerability Severity Levels](#11-vulnerability-severity-levels)
- [12. Troubleshooting](#12-troubleshooting)
- [13. Legal Notice](#13-legal-notice)

---

## 1. System Requirements

| Requirement | Details |
|---|---|
| Python | 3.10 or higher |
| Operating System | Windows, macOS, Linux |
| tkinter | Required for the GUI (included with most Python installations) |
| Dependencies | `requests`, `jinja2`, `rich`, `Pillow` (installed via `pip`) |

**Pre-built executables**: Standalone `.exe` / binary releases are available on the GitHub Releases page. These do not require a Python installation -- simply download and run.

---

## 2. Installation

### From Source

```bash
git clone https://github.com/bbyybb/vulnscan.git
cd vulnscan
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install .
```

### Pre-built Executables

Download the latest release for your platform from the GitHub Releases page. No Python installation is needed. On Linux, make the binary executable after downloading:

```bash
chmod +x vulnscan
```

### Verify Installation

```bash
# Check version
vulnscan --version

# Check scanner availability
vulnscan status
```

When running from source (without `pip install`), use `python main.py` instead of `vulnscan`:

```bash
python main.py --version
python main.py status
```

---

## 3. CLI Usage

### Synopsis

```
vulnscan [-V | --version] [--lang en|zh] [--log-file PATH] <command> [options]
```

### Subcommands

| Command  | Description |
|----------|---|
| `web`    | Run a web vulnerability scan (DAST + Infrastructure) |
| `code`   | Run a code vulnerability scan (SAST + SCA) |
| `status` | Show scanner availability status |
| `gui`    | Launch the graphical interface |

### Global Flags

| Flag | Description |
|---|---|
| `-V`, `--version` | Print the version number and exit |
| `--lang en\|zh` | Set the interface language (English or Chinese) |
| `--log-file PATH` | Write debug log output to a file |

### `web` Subcommand

Scan a target URL for web vulnerabilities.

```
vulnscan web <url> [options]
```

| Flag | Default | Description |
|---|---|---|
| `url` (positional) | -- | Target URL (e.g. `https://example.com`) |
| `-o`, `--output DIR` | `.` (current directory) | Report output directory |
| `--scanners NAME [NAME ...]` | all available | Specific scanners to use |
| `--format json\|html\|both` | `both` | Report output format |
| `--workers N` | `6` | Number of concurrent worker threads |
| `-H`, `--header 'Key: Value'` | -- | Custom HTTP header (repeatable) |
| `--cookie 'k1=v1; k2=v2'` | -- | HTTP cookies |
| `--data 'body'` | -- | HTTP POST body data |
| `--method GET\|POST\|PUT\|DELETE\|HEAD` | `GET` | HTTP request method |

### `code` Subcommand

Scan a file or directory for source code vulnerabilities.

```
vulnscan code <path> [options]
```

| Flag | Default | Description |
|---|---|---|
| `path` (positional) | -- | Target file or directory |
| `-o`, `--output DIR` | `.` (current directory) | Report output directory |
| `--scanners NAME [NAME ...]` | all available | Specific scanners to use |
| `--format json\|html\|both` | `both` | Report output format |

### `status` Subcommand

Display a table of all scanners with their availability status, type, and installation hints.

```
vulnscan status
```

### `gui` Subcommand

Launch the graphical user interface.

```
vulnscan gui
```

### Examples

```bash
# Basic web scan (all available scanners, both report formats)
vulnscan web https://example.com

# Web scan with specific scanners only
vulnscan web https://example.com --scanners HeaderScanner SSLScanner

# Web scan with HTML report only, saved to ./reports
vulnscan web https://example.com -o ./reports --format html

# Web scan with 8 concurrent workers
vulnscan web https://example.com --workers 8

# Authenticated web scan with custom headers and cookies
vulnscan web https://example.com \
  -H "Authorization: Bearer eyJhbG..." \
  -H "Content-Type: application/json" \
  --cookie "session=abc123; csrf=xyz"

# Web scan with POST data
vulnscan web https://example.com/api --method POST --data '{"key":"value"}'

# Code scan on a project directory
vulnscan code ./my-project

# Code scan with JSON report only
vulnscan code ./my-project --format json -o ./reports

# Code scan with specific scanners
vulnscan code ./my-project --scanners FileAnalyzer DependencyScanner

# Check scanner status in Chinese
vulnscan --lang zh status

# Write debug log while scanning
vulnscan --log-file scan.log web https://example.com

# Launch GUI
vulnscan gui
```

---

## 4. GUI Usage

### Launching the GUI

There are three ways to start the graphical interface:

```bash
# From source
python main.py gui
# or simply (defaults to GUI when no command is given):
python main.py

# If installed via pip
vulnscan gui

# Pre-built executable
# Double-click the vulnscan executable file
```

### Left Panel Walkthrough

The left panel contains all scan configuration controls, arranged from top to bottom:

1. **Language Selector** -- Two buttons (`English` / `中文`) to switch the UI language. The currently active language button appears sunken.

2. **Theme Switcher** -- A button on the right side of the language row that cycles through three themes: Light, Cyber, and Matrix.

3. **Scan Mode** -- Radio buttons to choose between:
   - **Web Scan** -- targets a URL (DAST + Infrastructure scanners)
   - **Code Scan** -- targets a file or directory (SAST + SCA scanners)

4. **Target Input** -- A text field for the target URL or path. In Code mode, a **Browse** button is enabled to select a file or directory via a dialog.

5. **HTTP Options** (Web mode only) -- A collapsible section containing:
   - **Method** dropdown (GET, POST, PUT, DELETE, HEAD)
   - **Parse curl** button to import a curl command
   - **Headers** text area (one `Key: Value` per line)
   - **Cookies** input field
   - **Data** text area for POST body

6. **Scanner List** -- A scrollable list of checkboxes for each scanner. Quick-select buttons:
   - **Select All** -- checks all available scanners
   - **Built-in Only** -- checks only the 7 built-in scanners
   - Each external scanner shows a **Browse** button (to set a custom executable path) and an **Install** link (opens the download page in a browser).
   - Unavailable external scanners are marked `(N/A)` and disabled.

7. **Progress** -- A progress bar and status label showing the current scan state. During a scan, individual scanner statuses are displayed below the progress bar.

8. **Start/Stop Buttons** -- Start Scan and Stop Scan buttons at the bottom.

### Right Panel Walkthrough

The right panel has two tabs and an export bar:

1. **Results Tab**
   - **Treeview Table** (upper) -- Displays found vulnerabilities with columns: Severity, Name, Scanner, Location, Confidence. Rows are color-coded by severity level. Click any row to view details.
   - **Detail Pane** (lower, resizable) -- Shows full vulnerability information: description, evidence, remediation advice, references, CVE/CWE IDs.

2. **Log Tab** -- A read-only text area that displays real-time log messages from the scan engine.

3. **Export Buttons** (bottom bar) -- Three buttons to export the scan results:
   - **Export JSON** -- saves a JSON report
   - **Export HTML** -- saves an HTML report
   - **Export Both** -- saves both formats

### Step-by-Step: Running a Web Scan

1. Set the scan mode to **Web Scan**.
2. Enter the target URL in the target field (e.g. `https://example.com`).
3. Optionally configure HTTP options (headers, cookies, method, data).
4. Select which scanners to use from the scanner list (or leave all checked).
5. Click **Start Scan**.
6. Monitor progress in the progress section and scanner status indicators.
7. When complete, review results in the Results tab. Click any vulnerability row to see details.
8. Click **Export HTML** or **Export JSON** to save the report.

### Step-by-Step: Running a Code Scan

1. Set the scan mode to **Code Scan**.
2. Click **Browse** and choose a directory or file, or type the path manually.
3. Select which scanners to use (built-in FileAnalyzer and DependencyScanner are always available; external tools like Bandit, Semgrep, Trivy, Grype require installation).
4. Click **Start Scan**.
5. Review results and export reports as needed.

### Step-by-Step: Importing a curl Command

1. In Web scan mode, click the **Parse curl** button in the HTTP Options section.
2. A dialog appears. Paste a curl command copied from your browser DevTools or another source.
3. Click **Parse & Fill**. The tool extracts:
   - The target URL (fills the target field)
   - HTTP method
   - Headers
   - Cookies
   - POST data
4. Review the populated fields, adjust if needed, then start the scan.

### Step-by-Step: Exporting Reports

1. Complete a scan.
2. Click one of the export buttons at the bottom of the right panel:
   - **Export JSON** -- opens a save dialog for the JSON report
   - **Export HTML** -- opens a save dialog for the HTML report
   - **Export Both** -- opens a directory chooser and saves both formats
3. Reports are saved with a timestamped filename: `vulnscan_report_YYYYMMDD_HHMMSS.json|html`.

---

## 5. HTTP Options

HTTP options allow you to scan authenticated or customized web endpoints.

### Custom Headers

**CLI:**

```bash
vulnscan web https://example.com \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value"
```

The `-H` / `--header` flag can be repeated multiple times. Format: `"Key: Value"`.

**GUI:** Enter headers in the Headers text area, one per line:

```
Authorization: Bearer token123
X-Custom-Header: value
```

### Cookies

**CLI:**

```bash
vulnscan web https://example.com --cookie "session=abc123; csrf=token456"
```

**GUI:** Enter the cookie string in the Cookies input field.

### POST Data

**CLI:**

```bash
vulnscan web https://example.com --method POST --data '{"username":"admin","password":"test"}'
```

**GUI:** Select `POST` from the Method dropdown and enter the body in the Data text area.

### HTTP Method Selection

Supported methods: `GET`, `POST`, `PUT`, `DELETE`, `HEAD`.

**CLI:** Use the `--method` flag.

**GUI:** Select from the Method dropdown.

### Importing from curl Command (GUI)

The **Parse curl** dialog accepts a standard curl command and automatically extracts all HTTP options. This is especially useful for copying requests from browser Developer Tools:

1. Open your browser DevTools (F12), go to the Network tab.
2. Right-click a request and select "Copy as cURL".
3. In VulnScan GUI, click **Parse curl**, paste the command, and click **Parse & Fill**.

---

## 6. Scanners

### Built-in Scanners (Always Available)

These scanners require no external tools and are included with every VulnScan installation.

#### HeaderScanner

- **Type:** DAST
- **Target:** URL
- **Description:** Checks HTTP security headers including Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy, and Permissions-Policy. Also checks for misconfigured CORS headers, missing cookie security flags (HttpOnly, Secure), cache control issues, and deprecated X-XSS-Protection headers.
- **Severity Levels:** Medium (missing headers, misconfigurations), Low (deprecated headers), Info (informational notes)

#### SSLScanner

- **Type:** Infrastructure
- **Target:** URL
- **Description:** Validates SSL/TLS certificates and protocols. Checks for expired certificates, self-signed certificates, certificates expiring soon (within 30 days), insecure protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1), and hostname mismatches between the certificate subject/SAN and the actual hostname.
- **Severity Levels:** Critical (expired certificate), High (self-signed, insecure protocol), Medium (expiring soon, hostname mismatch)

#### DirectoryScanner

- **Type:** DAST
- **Target:** URL
- **Description:** Probes for approximately 130 sensitive paths and files commonly exposed on web servers, such as `.git/`, `.env`, `wp-admin/`, backup files, configuration files, and admin panels. Differentiates between accessible paths (200 OK) and forbidden paths (403), which may still indicate the existence of resources.
- **Severity Levels:** High (sensitive files exposed), Medium (paths returning 403 Forbidden), Low (less sensitive discoveries)

#### InfoLeakScanner

- **Type:** DAST
- **Target:** URL
- **Description:** Detects server information leakage including: Server version headers, X-Powered-By headers, ASP.NET version headers, detailed error pages (debug 404), sensitive paths in robots.txt, sensitive content in HTML comments, internal IP address leakage, and email address exposure.
- **Severity Levels:** Medium (version leaks, debug pages, internal IPs), Low (robots.txt sensitive paths, email leaks, HTML comments)

#### PortScanner

- **Type:** Infrastructure
- **Target:** URL
- **Description:** Performs TCP port scanning on 61 common ports with banner grabbing. Identifies open services such as HTTP, HTTPS, SSH, FTP, databases, and more. Reports open ports with their associated service names.
- **Severity Levels:** Info (open port detected), Low (potentially risky services)

#### FileAnalyzer

- **Type:** SAST
- **Target:** File/Directory
- **Description:** Pattern-based source code vulnerability analysis covering 10 vulnerability categories including: SQL injection, cross-site scripting (XSS), command injection, path traversal, hardcoded secrets/passwords, insecure cryptography, insecure deserialization, debug/test code left in production, and more.
- **Severity Levels:** Critical (hardcoded secrets), High (SQL injection, command injection), Medium (XSS, path traversal), Low (debug code)

#### DependencyScanner

- **Type:** SCA
- **Target:** File/Directory
- **Description:** Checks project dependencies for known vulnerabilities using the OSV (Open Source Vulnerabilities) API. Supports 10 dependency file formats including: `package.json`, `package-lock.json`, `requirements.txt`, `Pipfile.lock`, `go.mod`, `go.sum`, `pom.xml`, `build.gradle`, `Cargo.toml`, and `Gemfile.lock`.
- **Severity Levels:** Critical, High, Medium, Low (based on CVE severity from the OSV database)

### External Tool Scanners (Require Installation)

These scanners wrap popular open-source security tools. Install them separately to enable their capabilities.

#### Nuclei

- **Type:** DAST
- **Target:** URL
- **Description:** Template-based vulnerability scanner by ProjectDiscovery. Runs thousands of community and custom templates to detect CVEs, misconfigurations, exposed panels, default credentials, and more.
- **Install:**
  ```bash
  # Go install
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

  # Or download binary from GitHub Releases
  # https://github.com/projectdiscovery/nuclei/releases
  ```
- **Severity Levels:** Critical, High, Medium, Low, Info (determined by template metadata)
- **Platform Notes:** Cross-platform. Available as a single binary for Windows, macOS, and Linux.

#### Nmap

- **Type:** Infrastructure
- **Target:** URL
- **Description:** Comprehensive network port and service scanner. Runs with script scanning (`-sC`), version detection (`-sV`), and vulnerability detection scripts (`--script vuln`). Parses XML output for detailed results including open ports, services, and known vulnerabilities.
- **Install:**
  ```bash
  # Windows / macOS: Download installer from https://nmap.org/download.html
  # Linux (Debian/Ubuntu):
  sudo apt install nmap
  # Linux (RHEL/CentOS):
  sudo yum install nmap
  # macOS (Homebrew):
  brew install nmap
  ```
- **Severity Levels:** High (known vulnerabilities), Medium (script findings), Info (open ports)
- **Platform Notes:** May require root/administrator privileges for certain scan types.

#### SQLMap

- **Type:** DAST
- **Target:** URL
- **Description:** Automatic SQL injection detection and exploitation tool. VulnScan runs it with thorough settings (level=5, risk=3) and WAF bypass capabilities. Detects SQL injection vulnerabilities in URL parameters.
- **Install:**
  ```bash
  pip install sqlmap
  ```
- **Severity Levels:** Critical (SQL injection confirmed)
- **Platform Notes:** Cross-platform. Requires Python.

#### Nikto

- **Type:** DAST
- **Target:** URL
- **Description:** Web server vulnerability scanner that checks for dangerous files, outdated server versions, and server configuration issues across all 13 vulnerability categories.
- **Install:**
  ```bash
  # Linux (Debian/Ubuntu):
  sudo apt install nikto
  # macOS:
  brew install nikto
  # Windows: Download from https://github.com/sullo/nikto/releases
  # or use the Perl script directly
  ```
- **Severity Levels:** High, Medium, Low (based on finding type)
- **Platform Notes:** Requires Perl on Windows if not using a pre-built binary.

#### ffuf

- **Type:** DAST
- **Target:** URL
- **Description:** Fast web fuzzer for path discovery. Uses built-in wordlists with path and extension combinations, supports recursive scanning, and automatically filters common false positives.
- **Install:**
  ```bash
  # Go install
  go install github.com/ffuf/ffuf/v2@latest

  # Or download binary from GitHub Releases
  # https://github.com/ffuf/ffuf/releases
  ```
- **Severity Levels:** Medium (restricted paths), Low (discovered paths, redirects)
- **Platform Notes:** Cross-platform. Available as a single binary.

#### Bandit

- **Type:** SAST
- **Target:** File/Directory
- **Description:** Python-specific security linter. Analyzes Python source code for common security issues such as hardcoded passwords, use of `eval()`, insecure SSL settings, SQL injection risks, and more.
- **Install:**
  ```bash
  pip install bandit
  ```
- **Severity Levels:** High, Medium, Low (based on Bandit's confidence and severity scores)
- **Platform Notes:** Cross-platform. Python projects only.

#### Semgrep

- **Type:** SAST
- **Target:** File/Directory
- **Description:** Multi-language static analysis engine. VulnScan runs it with four rule sets for broad coverage across Python, JavaScript, Go, Java, Ruby, and other languages. Detects security anti-patterns, injection flaws, and coding mistakes.
- **Install:**
  ```bash
  pip install semgrep
  ```
- **Severity Levels:** Critical, High, Medium, Low (based on rule metadata)
- **Platform Notes:** Cross-platform. Supports 30+ programming languages.

#### Trivy

- **Type:** SCA
- **Target:** File/Directory
- **Description:** Comprehensive filesystem vulnerability scanner. Scans for three categories: dependency vulnerabilities, leaked secrets (API keys, passwords), and infrastructure misconfigurations (Dockerfiles, Kubernetes manifests, Terraform).
- **Install:**
  ```bash
  # macOS:
  brew install trivy
  # Linux / Windows: Download from GitHub Releases
  # https://github.com/aquasecurity/trivy/releases
  ```
- **Severity Levels:** Critical, High, Medium, Low (based on CVE severity and finding type)
- **Platform Notes:** Cross-platform. Available as a single binary.

#### Grype

- **Type:** SCA
- **Target:** File/Directory
- **Description:** Dependency vulnerability scanner by Anchore. Scans filesystem for known vulnerabilities in packages and dependencies, with support for many package formats and ecosystems.
- **Install:**
  ```bash
  # macOS:
  brew install grype
  # Linux / Windows: Download from GitHub Releases
  # https://github.com/anchore/grype/releases
  ```
- **Severity Levels:** Critical, High, Medium, Low, Negligible (based on CVE severity)
- **Platform Notes:** Cross-platform. Available as a single binary.

---

## 7. Custom Tool Paths

### Default Behavior

By default, VulnScan looks for external tools in your system `PATH`. If a tool is found in `PATH`, it is automatically available.

### Custom Paths File

You can configure custom executable paths for external tools via a JSON configuration file:

```
~/.vulnscan/tool_paths.json
```

On Windows, this expands to `C:\Users\<username>\.vulnscan\tool_paths.json`.

### JSON Format

```json
{
  "Nuclei": "/opt/nuclei/nuclei",
  "Nmap": "/usr/local/bin/nmap",
  "Bandit": "C:\\Python310\\Scripts\\bandit.exe",
  "SQLMap": "/home/user/.local/bin/sqlmap"
}
```

Keys are scanner names (as shown in the scanner list). Values are absolute file paths to the executable.

### GUI: Browse Button

Each external scanner in the GUI scanner list has a **Browse** button. Clicking it opens a file picker to select the tool's executable. The path is automatically saved to `~/.vulnscan/tool_paths.json` and the scanner list refreshes.

### Security Rules

- Paths **must be absolute**. Relative paths are rejected.
- Directory traversal (`..`) in paths is rejected.
- Supported file types for custom paths: native executables plus script formats `.py`, `.pl`, `.rb`, `.sh`, `.bat`, `.cmd`, `.jar`, `.ps1`. Script files are automatically invoked with the appropriate interpreter.

---

## 8. Reports

### JSON Format

JSON reports contain the full structured scan data. Example structure:

```json
{
  "target": "https://example.com",
  "scan_mode": "web",
  "start_time": 1700000000.00,
  "end_time": 1700000060.00,
  "duration_seconds": 60.00,
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3,
    "info": 1,
    "total": 11
  },
  "results": [
    {
      "scanner_name": "HeaderScanner",
      "scan_type": "dast",
      "target": "https://example.com",
      "success": true,
      "error_message": "",
      "duration_seconds": 1.23,
      "vulnerability_count": 3,
      "vulnerabilities": [
        {
          "name": "Missing Content-Security-Policy Header",
          "severity": "medium",
          "description": "The Content-Security-Policy header is not set...",
          "scanner": "HeaderScanner",
          "scan_type": "dast",
          "evidence": "Response headers: ...",
          "remediation": "Add a Content-Security-Policy header...",
          "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
          "target": "https://example.com",
          "location": "https://example.com",
          "cve_id": "",
          "cwe_id": "CWE-693",
          "confidence": "high",
          "timestamp": 1700000001.50
        }
      ]
    }
  ]
}
```

### HTML Format

HTML reports are self-contained, visually formatted documents rendered from Jinja2 templates. They include:

- A severity summary chart (Critical, High, Medium, Low, Info counts)
- Scan metadata (target, mode, start/end time, duration)
- A detailed vulnerability list with severity badges, descriptions, evidence, remediation, and references
- A scanner summary table showing each scanner's execution status and finding counts

### Output Directory

- **CLI default:** The current working directory (`.`), changeable with `-o ./reports`.
- **GUI:** A save dialog prompts you to choose the output location.

Reports are named with a timestamp: `vulnscan_report_YYYYMMDD_HHMMSS.json` and `vulnscan_report_YYYYMMDD_HHMMSS.html`.

### CLI Export Options

```bash
# Both JSON and HTML (default)
vulnscan web https://example.com --format both

# JSON only
vulnscan web https://example.com --format json

# HTML only
vulnscan web https://example.com --format html

# Save to a specific directory
vulnscan web https://example.com -o ./reports
```

---

## 9. Themes

VulnScan GUI offers three visual themes. Cycle through them by clicking the theme button in the language row.

### Light Theme (Default)

- Clean, high-contrast design with a white/light-gray background.
- Standard appearance suitable for well-lit environments.
- Severity colors: Critical (dark red `#d32f2f`), High (dark orange `#e65100`), Medium (dark yellow `#bf8f00`), Low (blue `#1565c0`), Info (gray `#616161`).

### Cyber Theme

- GitHub Dark-inspired design with a dark background (`#0d1117`).
- Optimized for extended use and low-light environments.
- Severity colors: Critical (soft red `#ff6b6b`), High (orange `#ffa94d`), Medium (yellow `#ffd43b`), Low (light blue `#74c0fc`), Info (gray `#adb5bd`).

### Matrix Theme

- Terminal-style green-on-black aesthetic.
- Severity colors: Critical (bright red `#ff1744`), High (orange `#ff9100`), Medium (bright yellow `#ffea00`), Low (cyan `#00e5ff`), Info (green `#69f0ae`).

### How to Switch

Click the theme button (top-right of the language row in the left panel). It cycles: **Light** -> **Cyber** -> **Matrix** -> **Light**. The button label shows the name of the next theme.

---

## 10. Language Configuration

### Detection Priority

VulnScan determines the UI language using this priority order:

1. **`--lang` CLI flag** -- highest priority
2. **`VULNSCAN_LANG` environment variable** -- set to `en` or `zh`
3. **System locale** -- if the locale starts with `zh`, Chinese is selected
4. **English** -- default fallback

### Supported Languages

| Code | Language |
|---|---|
| `en` | English |
| `zh` | Simplified Chinese |

### Setting the Language

**CLI:**

```bash
vulnscan --lang en web https://example.com
vulnscan --lang zh status
```

**Environment variable:**

```bash
export VULNSCAN_LANG=zh
vulnscan status
```

On Windows:

```cmd
set VULNSCAN_LANG=zh
vulnscan status
```

**GUI:** Click the `English` or `中文` button at the top of the left panel. The entire interface updates instantly.

### What Is Translated

- All UI labels, buttons, and status messages
- Scanner output descriptions and vulnerability names
- Report content (HTML and JSON reports)
- CLI output (progress messages, summary panel)

---

## 11. Vulnerability Severity Levels

VulnScan classifies all findings into five severity levels, sorted from most to least severe:

| Level | Description | Examples |
|---|---|---|
| **Critical** | Immediate risk. Exploitable vulnerabilities that can lead to full system compromise. | Expired SSL certificate, confirmed SQL injection, hardcoded secrets, critical CVEs in dependencies |
| **High** | Serious vulnerabilities that should be fixed promptly. | Self-signed certificates, insecure protocols (SSLv3, TLS 1.0), exposed sensitive files, command injection patterns |
| **Medium** | Moderate-risk issues that should be addressed in the normal development cycle. | Missing security headers (CSP, HSTS), server version leakage, XSS patterns, certificates expiring soon |
| **Low** | Low-risk findings or best-practice recommendations. | Deprecated headers, email addresses in source, informational discoveries, robots.txt sensitive paths |
| **Info** | Informational findings with no direct security impact. | Open ports, scan metadata, configuration notes |

Vulnerabilities found by multiple scanners are automatically deduplicated. When the same issue is reported by different scanners, they are merged into a single entry with the highest severity level and a combined scanner name.

---

## 12. Troubleshooting

### "Scanner not found"

External tool scanners require separate installation. Run `vulnscan status` to see which tools are missing and their install hints. You can also set a custom path to the tool via `~/.vulnscan/tool_paths.json` or the Browse button in the GUI.

### "SSL certificate verify failed"

This is expected behavior. VulnScan intentionally uses `verify=False` for SSL connections when scanning, since it needs to inspect targets that may have self-signed or invalid certificates. This warning can be safely ignored during scanning operations.

### GUI Does Not Launch

Ensure tkinter is installed with your Python distribution:

```bash
# Test tkinter availability
python -c "import tkinter; print('OK')"

# Install on Debian/Ubuntu if missing
sudo apt install python3-tk

# Install on Fedora/RHEL
sudo dnf install python3-tkinter
```

On macOS, tkinter is included with the official Python installer from python.org. If using Homebrew Python, install `python-tk`:

```bash
brew install python-tk@3.10
```

### Chinese Characters Garbled

If Chinese characters display incorrectly in the terminal:

- Check your terminal encoding (should be UTF-8).
- Use `--lang en` to switch to English output.
- On Windows, run `chcp 65001` before using VulnScan to set the console to UTF-8.

### Scan Takes Too Long

- Reduce the number of concurrent workers: `--workers 3`.
- Select fewer scanners (disable slower external tools like Nmap or Nikto).
- Check network connectivity to the target.
- Some external tools (SQLMap, Nikto) perform thorough testing that is inherently slow.

### Empty Scan Results

- Verify the target is reachable (try opening the URL in a browser or `curl`-ing it).
- Check that the selected scanners are appropriate for the target (e.g., code scanners do not work on URLs).
- Run `vulnscan status` to confirm scanners are available.
- Use `--log-file debug.log` to capture detailed diagnostic output.

---

## 13. Legal Notice

**VulnScan is intended for authorized security testing only.**

- Only scan systems that you own or have explicit written permission to test.
- Unauthorized vulnerability scanning may violate computer crime laws in your jurisdiction, including but not limited to the Computer Fraud and Abuse Act (CFAA), the Computer Misuse Act, and equivalent legislation worldwide.
- The authors of VulnScan accept no liability for misuse of this tool.
- This tool is designed for **defensive security testing** -- helping developers and security professionals identify and fix vulnerabilities in their own systems.

Always obtain proper authorization before performing any security testing.
