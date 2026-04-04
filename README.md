# VulnScan - Integrated Vulnerability Scanner

<!-- badges -->

> An integrated vulnerability scanning tool that combines Web DAST, Code SAST, and SCA capabilities into a single unified interface.

**[中文文档](README_zh.md)**

## Features

- **7 built-in scanners** -- security headers (CSP/Cookie checks), SSL/TLS (certificate + SAN hostname match), sensitive paths (~130), info leak (internal IP/email detection), port scan (61 ports + banner), source code analysis (10 vuln patterns), dependency CVE check (10 formats)
- **9 external tool integrations** -- Nuclei (all templates), Nmap (TCP+UDP), SQLMap (level=5/risk=3 + WAF bypass), Nikto (all 13 categories), ffuf (paths x extensions x recursive), Bandit, Semgrep (4 rule sets), Trivy (vuln+secret+misconfig), Grype
- **Custom HTTP options** -- headers, cookies, POST data, method; paste curl commands from browser DevTools
- **Both CLI and GUI interfaces** -- use from terminal or graphical window
- **HTML + JSON report generation** -- rich HTML reports and machine-readable JSON
- **Vulnerability deduplication** -- same findings from multiple scanners are automatically merged
- **Debug logging** -- `--log-file` option to write detailed scan logs for troubleshooting
- **Cyber / Light theme** -- switch between Cyber (GitHub Dark-inspired) and Light themes in GUI
- **One-click tool install** -- GUI shows download links and browse button for unavailable tools; supports .exe/.py/.pl/.jar/.ps1 scripts; custom paths saved to `~/.vulnscan/tool_paths.json`
- **Cross-platform** -- Windows / macOS / Linux
- **Bilingual** -- English / Chinese (auto-detect or manual switch)

### Screenshots

| English Interface | Chinese Interface |
|:-:|:-:|
| ![English UI](docs/screenshots/gui_en.png) | ![Chinese UI](docs/screenshots/gui_zh.png) |

## Quick Start

```bash
git clone https://github.com/bbyybb/vulnscan.git && cd vulnscan
pip install -r requirements.txt

# Check scanner availability
python main.py status

# Web scan (DAST)
python main.py web https://example.com

# Code scan (SAST + SCA)
python main.py code ./your-project

# Launch GUI
python main.py gui
```

## CLI Usage

```
vulnscan [-V | --version] [--lang en|zh] [--log-file PATH] <command> [options]
```

### Subcommands

| Command  | Description                          |
|----------|--------------------------------------|
| `web`    | Run web vulnerability scan (DAST)    |
| `code`   | Run code vulnerability scan (SAST/SCA) |
| `status` | Show scanner availability status     |
| `gui`    | Launch the graphical interface       |

### Examples

```bash
# Web scan with default settings (all available scanners, both report formats)
python main.py web https://example.com

# Web scan with specific scanners
python main.py web https://example.com --scanners HeaderScanner SSLScanner

# Web scan with custom output directory and format
python main.py web https://example.com -o ./reports --format html

# Web scan with custom worker threads
python main.py web https://example.com --workers 8

# Web scan with custom HTTP headers and cookies (for authenticated scanning)
python main.py web https://example.com -H "Authorization: Bearer token" -H "Content-Type: application/json" --cookie "session=abc123"

# Web scan with POST data
python main.py web https://example.com --method POST --data '{"key":"value"}'

# Show version
python main.py --version

# Write debug log to file
python main.py --log-file scan.log web https://example.com

# Code scan
python main.py code ./your-project

# Code scan with specific scanners
python main.py code ./your-project --scanners FileAnalyzer DependencyScanner

# Code scan with JSON report only
python main.py code ./your-project --format json -o ./reports

# Check scanner status
python main.py status

# Switch language
python main.py --lang zh status
python main.py --lang en web https://example.com

# Launch GUI
python main.py gui
```

## GUI

Launch the graphical interface with:

```bash
python main.py gui
# or simply
python main.py
```

The GUI provides:

- Target URL/path input
- Scanner selection (toggle individual scanners)
- Real-time scan progress display
- Vulnerability results table with severity filtering
- One-click HTML/JSON report generation
- Scanner status overview
- Language switching (English / Chinese)

## Built-in Scanners

| Scanner             | Type  | Target | Description                                      |
|---------------------|-------|--------|--------------------------------------------------|
| HeaderScanner       | DAST  | URL    | HTTP security headers check                      |
| SSLScanner          | Infra | URL    | SSL/TLS certificate and protocol check           |
| DirectoryScanner    | DAST  | URL    | Sensitive path and file exposure detection        |
| InfoLeakScanner     | DAST  | URL    | Server information leakage detection             |
| PortScanner         | Infra | URL    | TCP port scanner with banner grabbing            |
| FileAnalyzer        | SAST  | File   | Source code vulnerability pattern matching        |
| DependencyScanner   | SCA   | File   | Dependency vulnerability check via OSV API       |

## External Tool Scanners

These scanners require external tools to be installed separately.

| Scanner  | Type  | Target | Description                            | Install Command                                |
|----------|-------|--------|----------------------------------------|------------------------------------------------|
| Nuclei   | DAST  | URL    | Template-based vulnerability scanner   | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| Nmap     | Infra | URL    | Network port and service scanner       | Download from https://nmap.org/download.html   |
| SQLMap   | DAST  | URL    | SQL injection detection tool           | `pip install sqlmap`                           |
| Nikto    | DAST  | URL    | Web server vulnerability scanner       | `sudo apt install nikto` (Linux), `brew install nikto` (macOS) |
| ffuf     | DAST  | URL    | Web fuzzing and path discovery         | Download from https://github.com/ffuf/ffuf/releases |
| Bandit   | SAST  | File   | Python security linter                 | `pip install bandit`                           |
| Semgrep  | SAST  | File   | Multi-language static analysis         | `pip install semgrep`                          |
| Trivy    | SCA   | File   | Filesystem vulnerability scanner       | Download from https://github.com/aquasecurity/trivy/releases |
| Grype    | SCA   | File   | Dependency vulnerability scanner       | `brew install grype` (macOS), Download from https://github.com/anchore/grype/releases |

Use `python main.py status` to check which external tools are installed and available.

## Configuration

### Language

VulnScan supports English and Chinese. The language is auto-detected from your system locale, but can be overridden:

- **Environment variable**: `VULNSCAN_LANG=en` or `VULNSCAN_LANG=zh`
- **CLI parameter**: `python main.py --lang en` or `python main.py --lang zh`
- **GUI**: Use the language switch button in the interface

Priority: `--lang` parameter > `VULNSCAN_LANG` environment variable > system locale detection.

## Project Structure

```
vulnscan/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md            # Bug report template
│   │   └── feature_request.md       # Feature request template
│   ├── workflows/
│   │   ├── build.yml                # Build and release workflow
│   │   └── test.yml                 # CI test workflow
│   ├── dependabot.yml               # Dependabot configuration
│   └── PULL_REQUEST_TEMPLATE.md     # PR template
├── docs/
│   └── screenshots/                 # GUI screenshots
├── scripts/
│   ├── build.py                     # PyInstaller build script
│   └── update_hashes.py             # Integrity hash update script
├── vulnscan/
│   ├── __init__.py                  # Package info (__version__, __author__)
│   ├── cli.py                       # CLI interface (argparse + rich)
│   ├── gui.py                       # GUI interface (tkinter)
│   ├── engine.py                    # Core scan engine (concurrent execution)
│   ├── models.py                    # Data models (ScanResult, Vulnerability, etc.)
│   ├── registry.py                  # Scanner registry and availability check
│   ├── report.py                    # Report generator (HTML + JSON)
│   ├── utils.py                     # Utility functions
│   ├── i18n.py                      # Internationalization framework
│   ├── integrity.py                 # Integrity verification module
│   ├── locale/
│   │   ├── __init__.py
│   │   └── messages.py              # English / Chinese message definitions
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base.py                  # Scanner / ExternalScanner base classes
│   │   ├── builtin/
│   │   │   ├── __init__.py
│   │   │   ├── header_scanner.py    # HTTP security headers
│   │   │   ├── ssl_scanner.py       # SSL/TLS check
│   │   │   ├── directory_scanner.py # Sensitive path detection
│   │   │   ├── info_leak_scanner.py # Information leakage
│   │   │   ├── port_scanner.py      # TCP port scan
│   │   │   ├── file_analyzer.py     # Source code analysis (SAST)
│   │   │   └── dependency_scanner.py# Dependency check (SCA)
│   │   └── external/
│   │       ├── __init__.py
│   │       ├── nuclei_scanner.py    # Nuclei integration
│   │       ├── nmap_scanner.py      # Nmap integration
│   │       ├── sqlmap_scanner.py    # SQLMap integration
│   │       ├── nikto_scanner.py     # Nikto integration
│   │       ├── ffuf_scanner.py      # ffuf integration
│   │       ├── bandit_scanner.py    # Bandit integration
│   │       ├── semgrep_scanner.py   # Semgrep integration
│   │       ├── trivy_scanner.py     # Trivy integration
│   │       └── grype_scanner.py     # Grype integration
│   ├── assets/                      # QR codes and icons
│   └── data/                        # Scan data files (ports, paths, patterns)
├── tests/
│   ├── __init__.py
│   ├── conftest.py
│   ├── test_models.py
│   ├── test_utils.py
│   ├── test_scanners.py
│   ├── test_builtin_scanners.py
│   ├── test_external_scanners.py    # External scanner integration tests
│   ├── test_report.py
│   ├── test_engine.py
│   ├── test_cli.py                  # CLI interface tests
│   ├── test_gui.py                  # GUI interface tests
│   ├── test_i18n.py                 # Internationalization tests
│   ├── test_integrity.py            # Integrity verification tests
│   └── test_integration.py
├── main.py                          # Unified entry point (CLI / GUI)
├── pyproject.toml                   # Project metadata and dependencies
├── requirements.txt                 # pip dependencies
└── reports/                         # Generated reports output directory
```

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install pytest pytest-cov

# Run tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ -v --cov=vulnscan --cov-report=term-missing

# Run only unit tests (exclude integration tests)
python -m pytest tests/ -v -m "not integration"
```

## Building Executables

See [BUILDING.md](BUILDING.md) for instructions on building standalone executables with PyInstaller.

## Author

**白白LOVE尹尹** ([@bbyybb](https://github.com/bbyybb))

## Support / Donate

If you find this tool useful, consider supporting the author:

- **WeChat Pay / Alipay**: Launch the GUI and click the "Donate" button to scan QR codes
- **Buy Me A Coffee**: [![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-ffdd00?style=flat&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/bbyybb)

| WeChat Pay | Alipay | Buy Me A Coffee |
|:-:|:-:|:-:|
| <img src="vulnscan/assets/wechat_pay.jpg" width="200"> | <img src="vulnscan/assets/alipay.jpg" width="200"> | <img src="vulnscan/assets/bmc_qr.png" width="200"> |

## License

MIT License - see [LICENSE](LICENSE) for details
