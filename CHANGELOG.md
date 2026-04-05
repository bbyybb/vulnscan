# Changelog / 更新日志

All notable changes to this project will be documented in this file.
本文件记录项目的所有重要变更。

## [1.0.1] - 2026-04-06

### Changed / 变更

- Theme system redesigned with Apple Human Interface Guidelines color palette / 主题系统采用 Apple 人机界面指南配色方案重新设计
  - 2 themes: Light (浅色) and Aqua (深色) / 两套主题：Light 浅色 + Aqua 深色
  - Auto-detects system dark/light mode on macOS and Windows at startup / 启动时自动检测 macOS 和 Windows 的系统深色/浅色模式
  - Theme-aware severity colors, start/stop buttons, links, and dialogs / 严重程度颜色、按钮、链接和对话框均跟随主题

## [1.0.0] - 2026-04-02

### Added / 新增

- Core scanning engine with concurrent execution / 核心扫描引擎，支持并发执行
- 7 built-in scanners with comprehensive checks / 7 个内置扫描器，全面检查:
  - HeaderScanner -- 14 checks (9 security headers + CSP unsafe-inline/unsafe-eval validation + CORS + X-XSS-Protection + Cache-Control + Set-Cookie HttpOnly/Secure) / 14 项检查（含 CSP 值深度检查、Cookie 安全属性）
  - SSLScanner -- certificate expiry, self-signed, legacy protocols (TLSv1.0/1.1), hostname/SAN mismatch with wildcard support / 证书过期、自签名、旧协议、域名匹配（含 SAN 通配符）
  - DirectoryScanner -- ~130 sensitive paths with content verification (.git/HEAD, .env) / ~130 条敏感路径探测
  - InfoLeakScanner -- 8 checks (Server version, X-Powered-By, ASP.NET, 404 debug info, robots.txt, HTML comments, internal IP leak, email leak) / 8 类信息泄露检查（含内部 IP 和 Email 泄露）
  - PortScanner -- 61 common ports with banner grabbing / 61 端口 TCP 扫描 + Banner 抓取
  - FileAnalyzer -- 10 vulnerability pattern categories (38 regex patterns incl. SSRF) / 10 类漏洞模式匹配
  - DependencyScanner -- 10 dependency file formats via OSV API / 10 种依赖格式 + OSV API
- 9 external tool integrations with maximum coverage parameters / 9 个外部工具集成，参数配置为最大覆盖面:
  - Nuclei -- all template types, info~critical severity / 全模板类型，info~critical 全级别
  - Nmap -- TCP top-1000 (-sV -sC -A --script vuln,default) + UDP top-100 / TCP+UDP 双扫描
  - SQLMap -- level=5 risk=3 with WAF bypass tamper scripts / 最高级别 + WAF 绕过
  - Nikto -- all 13 check categories (-Tuning 123456789abcd -C all) / 全部 13 类检查
  - ffuf -- 194 paths x 18 file extensions, recursive 2 levels / 路径×扩展名×递归
  - Bandit -- all severity levels, recursive / 全级别递归扫描
  - Semgrep -- 4 rule sets (auto + security-audit + secrets + OWASP Top 10) / 4 个规则集
  - Trivy -- 3 scanner types (vuln + secret + misconfig), all severity / 3 种扫描器
  - Grype -- CPE auto-fill, CVE aggregation / CPE 补全 + CVE 聚合
- GUI install links and browse button for unavailable external tools — click "Install" to download, or "Browse" to manually select executable path (saved to ~/.vulnscan/tool_paths.json) / GUI 中不可用工具旁显示"安装"链接和"浏览"按钮——点击安装跳转下载，或点击浏览手动指定可执行文件路径（保存到 ~/.vulnscan/tool_paths.json）
- Cyber / Light theme switching in GUI / GUI Cyber 深邃/明亮主题切换
- SSLScanner auto-skips HTTP targets (non-HTTPS) / SSLScanner 自动跳过 HTTP 目标
- Script tool support (.py/.pl/.rb/.jar/.ps1) — auto-detects interpreter (python/perl/ruby/java/powershell) / 支持脚本工具（.py/.pl/.rb/.jar/.ps1）——自动检测解释器
- Tool path validation on browse — rejects non-executable files with warning / 浏览选择工具时验证可执行性——非可执行文件弹窗警告
- Tooltip on hover for external tools showing current executable path / 鼠标悬浮外部工具显示当前可执行文件路径
- Custom HTTP options support (headers, cookies, POST data, method) for all web scanners / 所有 Web 扫描器支持自定义 HTTP 选项（请求头、Cookies、POST 数据、请求方法）
- Curl command parser in GUI — paste curl from browser DevTools to auto-fill scan options / GUI 中的 curl 命令解析器——从浏览器开发工具粘贴 curl 自动填充扫描选项
- CLI `--header`, `--cookie`, `--data`, `--method` flags for web scans / CLI 新增 Web 扫描的 HTTP 选项参数
- CLI interface with rich progress display / CLI 界面，rich 进度条显示
- GUI interface (tkinter) with language switching / GUI 图形界面，支持语言切换
- HTML + JSON report generation (fully self-contained, no CDN dependencies) / HTML + JSON 报告生成（完全自包含，无 CDN 依赖）
- Bilingual support (English/Chinese) / 中英文双语支持
- Cross-platform support (Windows/macOS Intel+M/Linux) / 跨平台支持
- GUI scanner real-time status display — each scanner shows Pending/Running/Done/Failed with color coding / GUI 扫描器实时状态显示——每个扫描器显示等待中/运行中/完成/失败状态（带颜色）
- CLI `--log-file` parameter to write debug logs to file / CLI 新增 `--log-file` 参数，将调试日志写入文件
- Vulnerability deduplication and aggregation — same CVE or port found by multiple scanners is merged into one entry / 漏洞去重与聚合——多个扫描器发现的同一 CVE 或端口自动合并为一条
- Engine `on_scanner_start` callback for real-time scanner status tracking / 引擎新增 `on_scanner_start` 回调用于实时状态追踪
- DependencyScanner reports clear error when OSV API is unreachable (offline-friendly) / DependencyScanner 在 OSV API 不可达时明确报错（离线友好）
- External command output encoding adapts to system locale on Windows (CJK support) / 外部命令输出编码在 Windows 上自适应系统区域（中文支持）
- External command stderr logged at DEBUG level for diagnostics / 外部命令 stderr 记录到 DEBUG 日志
- Data file loading handles missing files gracefully / 数据文件加载优雅处理文件缺失
- Integrity protection for author info and donation assets / 作者信息和打赏资源防篡改保护
- Donate dialog with WeChat/Alipay/BuyMeACoffee QR codes / 打赏对话框
- 238+ unit and integration tests (builtin scanners, external scanners, CLI, engine, models, GUI, i18n, integrity, utils, report) / 238+ 个单元测试和集成测试
- GitHub Actions CI for testing (3 OS x 3 Python, with coverage) and building (4 platforms) / CI 自动测试（含覆盖率）和多平台构建
- Build scripts for local development / 本地开发构建脚本
