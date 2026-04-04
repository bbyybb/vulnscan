# VulnScan 用户指南

> VulnScan v1.0.0 -- 整合型漏洞扫描工具，将 Web DAST、代码 SAST 和 SCA 能力集成于统一界面中。

---

## 目录

- [1. 系统要求](#1-系统要求)
- [2. 安装](#2-安装)
- [3. 命令行使用](#3-命令行使用)
- [4. 图形界面使用](#4-图形界面使用)
- [5. HTTP 选项](#5-http-选项)
- [6. 扫描器](#6-扫描器)
- [7. 自定义工具路径](#7-自定义工具路径)
- [8. 报告](#8-报告)
- [9. 主题](#9-主题)
- [10. 语言配置](#10-语言配置)
- [11. 漏洞严重程度说明](#11-漏洞严重程度说明)
- [12. 故障排除](#12-故障排除)
- [13. 法律声明](#13-法律声明)

---

## 1. 系统要求

| 条目 | 要求 |
|------|------|
| Python 版本 | 3.10 或更高 |
| 操作系统 | Windows 10+、macOS 10.15+、Linux（主流发行版） |
| GUI 依赖 | tkinter（Python 标准库，部分 Linux 发行版需单独安装） |
| 预编译可执行文件 | 无需 Python 环境，下载即用 |

**Linux 用户注意**: 如果你的系统没有预装 tkinter，需手动安装：

```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter

# Arch Linux
sudo pacman -S tk
```

**其他依赖**: VulnScan 依赖 `rich`、`jinja2` 等 Python 包，通过 `requirements.txt` 一键安装。

---

## 2. 安装

### 2.1 从源码安装

```bash
# 克隆仓库
git clone https://github.com/bbyybb/vulnscan.git
cd vulnscan

# 安装依赖
pip install -r requirements.txt
```

安装完成后即可通过 `python main.py` 运行。

### 2.2 使用预编译可执行文件

从 [GitHub Releases](https://github.com/bbyybb/vulnscan/releases) 页面下载对应平台的可执行文件：

- **Windows**: `vulnscan.exe`
- **macOS**: `vulnscan`（可能需要在"系统偏好设置 > 安全性与隐私"中允许运行）
- **Linux**: `vulnscan`（需添加执行权限）

```bash
# Linux / macOS 添加执行权限
chmod +x vulnscan
```

双击可执行文件即可启动 GUI；也可在终端中以命令行模式运行。

### 2.3 验证安装

```bash
# 查看版本
python main.py --version
# 或使用可执行文件
vulnscan --version
```

预期输出：`vulnscan 1.0.0`

```bash
# 检查扫描器可用状态
python main.py status
```

此命令会列出所有扫描器的名称、类型、可用状态以及缺失工具的安装提示。

---

## 3. 命令行使用

### 3.1 命令格式

```
vulnscan [-V | --version] [--lang en|zh] [--log-file PATH] <command> [options]
```

或使用源码方式运行：

```
python main.py [-V | --version] [--lang en|zh] [--log-file PATH] <command> [options]
```

### 3.2 全局参数

| 参数 | 说明 |
|------|------|
| `-V`, `--version` | 显示版本号并退出 |
| `--lang en\|zh` | 设置界面语言（en=英文，zh=中文） |
| `--log-file PATH` | 将调试日志写入指定文件 |

### 3.3 子命令

| 子命令 | 说明 |
|--------|------|
| `web` | 执行 Web 漏洞扫描（DAST） |
| `code` | 执行代码漏洞扫描（SAST/SCA） |
| `status` | 显示所有扫描器的可用状态 |
| `gui` | 启动图形界面 |

### 3.4 web 子命令

对目标 URL 执行 Web 漏洞扫描。

```
vulnscan web <url> [options]
```

**参数说明：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `url` | 目标 URL（必填），如 `https://example.com` | -- |
| `-o`, `--output` | 报告输出目录 | `.`（当前目录） |
| `--scanners NAME [NAME ...]` | 指定使用的扫描器名称（空格分隔） | 全部可用扫描器 |
| `--format json\|html\|both` | 报告格式 | `both` |
| `--workers N` | 并发工作线程数 | `6` |
| `-H`, `--header 'Key: Value'` | 自定义 HTTP 请求头（可多次使用） | 无 |
| `--cookie 'k1=v1; k2=v2'` | HTTP Cookies | 无 |
| `--data 'key=value'` | HTTP POST 请求体 | 无 |
| `--method GET\|POST\|PUT\|DELETE\|HEAD` | HTTP 方法 | `GET` |

**示例：**

```bash
# 基本 Web 扫描（使用所有可用扫描器，生成 JSON + HTML 报告）
python main.py web https://example.com

# 指定扫描器
python main.py web https://example.com --scanners HeaderScanner SSLScanner

# 自定义输出目录和报告格式
python main.py web https://example.com -o ./reports --format html

# 调整并发线程数
python main.py web https://example.com --workers 8

# 使用自定义请求头和 Cookies（适用于需要认证的站点）
python main.py web https://example.com \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  --cookie "session=abc123; lang=zh"

# 使用 POST 方法
python main.py web https://example.com --method POST --data '{"key":"value"}'

# 将调试日志写入文件
python main.py --log-file scan.log web https://example.com
```

### 3.5 code 子命令

对目标文件或目录执行代码漏洞扫描。

```
vulnscan code <path> [options]
```

**参数说明：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `path` | 目标文件或目录路径（必填） | -- |
| `-o`, `--output` | 报告输出目录 | `.`（当前目录） |
| `--scanners NAME [NAME ...]` | 指定使用的扫描器名称 | 全部可用扫描器 |
| `--format json\|html\|both` | 报告格式 | `both` |

**示例：**

```bash
# 扫描整个项目目录
python main.py code ./your-project

# 指定扫描器
python main.py code ./your-project --scanners FileAnalyzer DependencyScanner

# 仅生成 JSON 报告
python main.py code ./your-project --format json -o ./reports
```

### 3.6 status 子命令

显示所有扫描器的可用状态，包括名称、类型、是否内置、是否可用等信息。

```bash
python main.py status
```

该命令会以表格形式输出信息，方便快速查看哪些外部工具已安装、哪些缺失。

### 3.7 gui 子命令

启动图形界面。

```bash
python main.py gui
```

如果不带任何子命令运行 `python main.py`，默认也会显示帮助信息。

---

## 4. 图形界面使用

### 4.1 启动方式

```bash
# 方式一：通过子命令
python main.py gui

# 方式二：使用安装后的命令
vulnscan gui

# 方式三：双击预编译可执行文件
# Windows: 双击 vulnscan.exe
# macOS/Linux: 双击 vulnscan
```

启动后会打开一个 1100x700 的窗口（最小尺寸 750x500），界面分为左右两个面板。

### 4.2 左侧面板

左侧面板包含所有控制选项，从上到下依次为：

#### 语言选择

提供 **English** 和 **中文** 两个按钮，点击后界面文本实时切换。当前激活的语言按钮处于禁用状态。

#### 主题切换

一个循环切换按钮，在三个主题之间切换：Light（明亮） -> Cyber（深邃） -> Matrix（黑客）。按钮上显示下一个主题的名称。

#### 扫描模式

两个单选按钮：
- **Web 扫描**: 对目标 URL 执行 DAST 扫描
- **代码扫描**: 对目标文件/目录执行 SAST/SCA 扫描

切换模式时，扫描器列表会自动过滤显示对应模式的扫描器。

#### 目标输入

一个文本输入框：
- Web 模式下：输入目标 URL（如 `https://example.com`）
- 代码模式下：输入文件/目录路径，右侧出现"浏览"按钮用于选择目录

#### HTTP 选项

仅在 Web 扫描模式下显示，包含：
- **Method**: 下拉框选择 HTTP 方法（GET/POST/PUT/DELETE/HEAD）
- **Parse curl**: 按钮，打开 curl 命令解析对话框
- **Headers**: 多行文本框，每行一个请求头，格式为 `Key: Value`
- **Cookies**: 单行输入框，格式为 `k1=v1; k2=v2`
- **Data**: 多行文本框，输入 POST 请求体

#### 扫描器列表

可滚动的复选框列表，显示当前模式下的所有扫描器。每个扫描器旁有复选框用于启用/禁用。顶部有两个快捷按钮：
- **全选**: 选中所有扫描器
- **仅内置**: 只选中内置扫描器（取消外部工具）

对于不可用的外部工具扫描器，旁边会显示"安装"和"浏览"按钮：
- **安装**: 打开该工具的下载页面
- **浏览**: 打开文件选择对话框，手动指定工具可执行文件路径

#### 进度

显示扫描进度条和状态文字。扫描时会实时更新当前进度，并在下方列出每个扫描器的执行状态（成功/失败）。

#### 开始/停止按钮

- **开始扫描**: 启动扫描任务（扫描期间禁用）
- **停止扫描**: 中止正在进行的扫描（仅扫描期间可用）

### 4.3 右侧面板

右侧面板包含结果展示区域，分为两个标签页和底部导出按钮。

#### 结果标签页

分为上下两部分（可拖拽调整比例）：

**上部 -- 漏洞列表（Treeview 表格）**：

| 列名 | 说明 |
|------|------|
| 严重程度 | 显示为带颜色的文字（Critical/High/Medium/Low/Info） |
| 名称 | 漏洞名称 |
| 扫描器 | 发现该漏洞的扫描器名称 |
| 位置 | 漏洞位置（URL 路径或文件:行号） |
| 置信度 | 置信程度（high/medium/low） |

点击任意一行，下方详情区域会显示该漏洞的完整信息。

**下部 -- 漏洞详情**：

显示选中漏洞的详细信息，包括：描述、证据、修复建议、参考链接、CVE/CWE 编号等。

#### 日志标签页

实时显示扫描过程中的日志信息，便于排查问题。

#### 导出按钮（底部）

三个导出按钮：
- **导出 JSON**: 将扫描结果导出为 JSON 文件
- **导出 HTML**: 将扫描结果导出为 HTML 可视化报告
- **导出全部**: 同时导出 JSON 和 HTML 两种格式

点击导出按钮会弹出文件保存对话框，选择保存位置。

### 4.4 操作流程：执行 Web 扫描

1. 选择扫描模式为 **Web 扫描**
2. 在目标输入框中输入目标 URL（如 `https://example.com`）
3. （可选）配置 HTTP 选项：请求头、Cookies、POST 数据等
4. （可选）在扫描器列表中选择需要的扫描器
5. 点击 **开始扫描**
6. 等待扫描完成，查看右侧结果标签页中的漏洞列表
7. 点击漏洞查看详情
8. 点击底部导出按钮生成报告

### 4.5 操作流程：执行代码扫描

1. 选择扫描模式为 **代码扫描**
2. 点击"浏览"按钮选择目标目录，或手动输入路径
3. （可选）在扫描器列表中选择需要的扫描器
4. 点击 **开始扫描**
5. 等待扫描完成，查看结果

### 4.6 操作流程：导入 curl 命令

如果你在浏览器开发者工具中复制了 curl 命令，可以直接导入：

1. 确保处于 **Web 扫描** 模式
2. 点击 HTTP 选项区域的 **Parse curl** 按钮
3. 在弹出的对话框中粘贴完整的 curl 命令
4. 点击确认，VulnScan 会自动解析并填充以下字段：
   - 目标 URL
   - HTTP 方法
   - 请求头（Headers）
   - Cookies
   - POST 数据（Data）

### 4.7 操作流程：导出报告

1. 完成扫描后，点击右侧底部的导出按钮
2. 选择导出格式：JSON、HTML 或全部
3. 在文件对话框中选择保存位置
4. 导出完成后会显示成功提示

---

## 5. HTTP 选项

VulnScan 支持自定义 HTTP 请求选项，这对于扫描需要认证的站点尤为重要。

### 5.1 自定义请求头

**CLI 方式：**

使用 `-H` 或 `--header` 参数，可多次使用：

```bash
python main.py web https://example.com \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "X-Custom-Header: my-value"
```

**GUI 方式：**

在 HTTP 选项区域的 Headers 文本框中输入，每行一个：

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
X-Custom-Header: my-value
Content-Type: application/json
```

### 5.2 Cookies

**CLI 方式：**

```bash
python main.py web https://example.com --cookie "session=abc123; lang=zh; token=xyz"
```

**GUI 方式：**

在 HTTP 选项区域的 Cookies 输入框中输入，格式为 `key=value`，多个 Cookie 用分号和空格分隔。

### 5.3 POST 数据

**CLI 方式：**

```bash
# JSON 格式
python main.py web https://example.com --method POST --data '{"username":"admin","password":"test"}'

# 表单格式
python main.py web https://example.com --method POST --data "username=admin&password=test"
```

**GUI 方式：**

1. 将 Method 下拉框切换为 `POST`
2. 在 Data 文本框中输入请求体内容

### 5.4 HTTP 方法选择

支持的 HTTP 方法：`GET`、`POST`、`PUT`、`DELETE`、`HEAD`。

**CLI 方式：**

```bash
python main.py web https://example.com/api/resource --method DELETE
```

**GUI 方式：**

通过 Method 下拉框选择。

### 5.5 从 curl 命令导入（GUI）

GUI 提供了 **Parse curl** 按钮，可以直接粘贴从浏览器开发者工具中复制的 curl 命令。VulnScan 会自动解析以下内容：

- 目标 URL
- `-H` / `--header` 中的请求头
- `-b` / `--cookie` 中的 Cookies
- `-d` / `--data` 中的请求体
- `-X` / `--request` 中的 HTTP 方法

**示例 curl 命令：**

```bash
curl 'https://example.com/api/login' \
  -X POST \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer token123' \
  -b 'session=abc123' \
  -d '{"username":"admin","password":"test"}'
```

粘贴后，所有字段会自动填入对应位置。

---

## 6. 扫描器

VulnScan 集成了 16 个扫描器，分为内置扫描器和外部工具扫描器两类。

### 6.1 内置扫描器（始终可用）

内置扫描器无需安装额外工具，开箱即用。

| 扫描器 | 类型 | 目标 | 检查内容 | 报告严重程度 | 注意事项 |
|--------|------|------|----------|-------------|----------|
| **HeaderScanner** | DAST | URL | HTTP 安全响应头检查：CSP、X-Frame-Options、X-Content-Type-Options、HSTS、CORS 配置、Cookie 安全属性（HttpOnly/Secure）、Cache-Control 等 | 中危~信息 | 部分网站可能使用自定义安全机制替代标准头 |
| **SSLScanner** | 基础设施 | URL | SSL/TLS 证书有效性、过期检查、SAN 域名匹配、证书链验证 | 高危~信息 | 仅对 HTTPS 站点有效；非 HTTPS 目标会报告缺少 SSL |
| **DirectoryScanner** | DAST | URL | 敏感路径和文件探测（约 130 条常见路径），如 `.git/`、`.env`、`backup/`、管理后台等 | 高危~低危 | 大量请求可能触发 WAF/IDS 告警 |
| **InfoLeakScanner** | DAST | URL | 服务器信息泄露检测：Server 头版本泄露、X-Powered-By 泄露、ASP.NET 版本、调试页面、robots.txt 敏感路径、HTML 注释中的敏感信息、内部 IP 泄露、Email 泄露 | 中危~信息 | 信息泄露级别通常为低危或信息级 |
| **PortScanner** | 基础设施 | URL | TCP 端口扫描（61 个常用端口），含 Banner 抓取 | 低危~信息 | 扫描速度受网络延迟和防火墙影响 |
| **FileAnalyzer** | SAST | 文件 | 源代码漏洞模式匹配（10 类模式），包括 SQL 注入、XSS、命令注入、路径遍历、硬编码密码等 | 高危~低危 | 基于正则匹配，可能存在误报 |
| **DependencyScanner** | SCA | 文件 | 依赖组件 CVE 漏洞检查（通过 OSV API），支持 10 种依赖文件格式：package.json、requirements.txt、go.mod、pom.xml 等 | 严重~低危 | 需要网络连接以查询 OSV API |

### 6.2 外部工具扫描器（需安装）

外部工具扫描器需要先安装对应的命令行工具。

| 扫描器 | 类型 | 目标 | 功能说明 | 安装命令 | 平台说明 |
|--------|------|------|----------|----------|----------|
| **Nuclei** | DAST | URL | 基于模板的漏洞扫描器（ProjectDiscovery），支持全模板类型扫描 | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | 全平台；需要 Go 环境，或从 [Releases](https://github.com/projectdiscovery/nuclei/releases) 下载预编译版本 |
| **Nmap** | 基础设施 | URL | 网络端口和服务扫描器，支持 TCP+UDP 双扫描、NSE 脚本 | 从 [nmap.org](https://nmap.org/download.html) 下载 | Windows 需安装 Npcap；macOS: `brew install nmap`；Linux: `sudo apt install nmap` |
| **SQLMap** | DAST | URL | SQL 注入自动检测工具，使用 level=5/risk=3 深度扫描，含 WAF 绕过 | `pip install sqlmap` | 全平台 |
| **Nikto** | DAST | URL | Web 服务器漏洞扫描器，执行全部 13 类安全检查 | Linux: `sudo apt install nikto`；macOS: `brew install nikto` | Windows 需要 Perl 环境和 nikto.pl 脚本 |
| **ffuf** | DAST | URL | Web 模糊测试与路径发现工具（路径 x 扩展名 x 递归） | 从 [GitHub Releases](https://github.com/ffuf/ffuf/releases) 下载 | 全平台预编译版本；macOS: `brew install ffuf`；Go: `go install github.com/ffuf/ffuf/v2@latest` |
| **Bandit** | SAST | 文件 | Python 安全代码检查工具 | `pip install bandit` | 全平台 |
| **Semgrep** | SAST | 文件 | 多语言静态代码分析，使用 4 个规则集 | `pip install semgrep`；macOS: `brew install semgrep` | 全平台；Windows 支持可能有限 |
| **Trivy** | SCA | 文件 | 文件系统漏洞扫描器，检测漏洞 + 密钥泄露 + 配置错误 | 从 [GitHub Releases](https://github.com/aquasecurity/trivy/releases) 下载 | 全平台；macOS: `brew install trivy`；Linux 可使用安装脚本 |
| **Grype** | SCA | 文件 | 依赖组件漏洞扫描器 | macOS: `brew install grype`；其他平台从 [GitHub Releases](https://github.com/anchore/grype/releases) 下载 | 全平台 |

**提示**: 运行 `python main.py status` 可以快速查看哪些外部工具已安装且可用。

---

## 7. 自定义工具路径

### 7.1 默认查找方式

VulnScan 默认通过系统 `PATH` 环境变量查找外部工具的可执行文件。如果工具已正确安装并添加到 PATH 中，VulnScan 会自动检测到。

### 7.2 自定义路径配置文件

如果外部工具没有添加到 PATH，或者你希望使用特定版本的工具，可以通过配置文件指定自定义路径。

**配置文件位置：**

```
~/.vulnscan/tool_paths.json
```

- Windows: `C:\Users\<用户名>\.vulnscan\tool_paths.json`
- macOS/Linux: `/home/<用户名>/.vulnscan/tool_paths.json`

### 7.3 JSON 格式示例

```json
{
  "Nuclei": "C:/Tools/nuclei/nuclei.exe",
  "Nmap": "C:/Program Files (x86)/Nmap/nmap.exe",
  "SQLMap": "/usr/local/bin/sqlmap",
  "Bandit": "/home/user/.local/bin/bandit",
  "Trivy": "/opt/trivy/trivy",
  "Nikto": "C:/Tools/nikto/program/nikto.pl"
}
```

**键（key）** 为扫描器名称（与 `status` 命令中显示的名称一致），**值（value）** 为工具的绝对路径。

### 7.4 GUI 中设置自定义路径

在 GUI 的扫描器列表中，不可用的外部工具旁会显示 **浏览** 按钮：

1. 点击 **浏览** 按钮
2. 在文件选择对话框中定位到工具的可执行文件
3. 选择后路径会自动保存到 `~/.vulnscan/tool_paths.json`
4. 扫描器状态立即更新为可用

### 7.5 安全性

- **路径必须为绝对路径**：相对路径或包含 `..` 的路径会被拒绝
- 路径会通过 `Path.resolve()` 解析后进行安全校验
- 支持的脚本类型：`.py`、`.pl`、`.rb`、`.sh`、`.bat`、`.cmd`、`.jar`、`.ps1`
- 脚本文件会自动使用对应的解释器运行（如 `.py` 用 Python，`.pl` 用 Perl，`.jar` 用 Java）

---

## 8. 报告

VulnScan 支持 JSON 和 HTML 两种报告格式。

### 8.1 JSON 格式

JSON 报告是机器可读的结构化数据，适合与其他工具集成或自动化处理。

**报告结构：**

```json
{
  "target": "https://example.com",
  "scan_mode": "web",
  "start_time": 1700000000.0,
  "end_time": 1700000120.5,
  "duration_seconds": 120.5,
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3,
    "info": 8,
    "total": 18
  },
  "results": [
    {
      "scanner_name": "HeaderScanner",
      "scan_type": "dast",
      "target": "https://example.com",
      "success": true,
      "error_message": "",
      "duration_seconds": 1.25,
      "vulnerability_count": 3,
      "vulnerabilities": [
        {
          "name": "Missing X-Frame-Options Header",
          "severity": "medium",
          "description": "...",
          "scanner": "HeaderScanner",
          "scan_type": "dast",
          "evidence": "...",
          "remediation": "...",
          "reference": "...",
          "target": "https://example.com",
          "location": "https://example.com",
          "cve_id": "",
          "cwe_id": "",
          "confidence": "high",
          "timestamp": 1700000001.5
        }
      ]
    }
  ]
}
```

**主要字段说明：**

| 字段 | 说明 |
|------|------|
| `target` | 扫描目标 |
| `scan_mode` | 扫描模式（web/code） |
| `duration_seconds` | 扫描总耗时（秒） |
| `summary` | 各严重程度的漏洞计数 |
| `results` | 每个扫描器的详细结果列表 |
| `vulnerabilities[].severity` | 严重程度：critical/high/medium/low/info |
| `vulnerabilities[].confidence` | 置信度：high/medium/low |
| `vulnerabilities[].cve_id` | CVE 编号（如有） |
| `vulnerabilities[].cwe_id` | CWE 编号（如有） |

### 8.2 HTML 格式

HTML 报告是可视化的交互式报告，可直接在浏览器中打开查看。包含：

- 扫描概览：目标、模式、开始/结束时间、耗时
- 漏洞统计摘要：各严重级别的数量
- 漏洞详细列表：名称、严重程度、描述、证据、修复建议、参考链接
- 扫描器执行摘要：每个扫描器的成功/失败状态和发现数量

HTML 报告基于 Jinja2 模板引擎渲染，支持中英文双语。

### 8.3 输出目录

- **CLI 默认输出目录**: 当前工作目录（`.`），通过 `-o` 参数修改
- **文件命名规则**: `vulnscan_report_YYYYMMDD_HHMMSS.json` 和 `vulnscan_report_YYYYMMDD_HHMMSS.html`

```bash
# 指定输出到 reports 目录
python main.py web https://example.com -o ./reports

# 仅生成 JSON
python main.py web https://example.com --format json

# 仅生成 HTML
python main.py web https://example.com --format html
```

### 8.4 GUI 导出 vs CLI 导出

| 方式 | 操作 | 输出位置 |
|------|------|----------|
| CLI | 扫描完成后自动生成 | `-o` 参数指定的目录 |
| GUI | 扫描完成后手动点击导出按钮 | 文件对话框选择的位置 |

GUI 导出更灵活，可以在扫描完成后反复导出到不同位置。

---

## 9. 主题

VulnScan GUI 提供三种视觉主题。

### 9.1 Light 明亮主题（默认）

- 背景：浅灰色 (`#f5f5f5`)
- 文字：深色 (`#1a1a1a`)
- 特点：适合白天或明亮环境使用，对比度高，阅读舒适

### 9.2 Cyber 深邃主题

- 背景：深蓝黑色 (`#0d1117`)，采用 GitHub Dark 风格配色
- 文字：浅灰色 (`#c9d1d9`)
- 特点：低亮度暗色主题，长时间使用不易疲劳，适合夜间或暗光环境

### 9.3 Matrix 黑客主题

- 背景：纯黑色 (`#0a0a0a`)
- 文字：终端绿色 (`#00ff41`)
- 特点：经典黑客终端风格，极致暗色体验

### 9.4 切换方式

在 GUI 左上角的语言选择区域旁，有一个主题切换按钮。点击按钮在三个主题间循环切换：

```
Light -> Cyber -> Matrix -> Light -> ...
```

按钮上会显示下一个主题的名称作为提示。

### 9.5 各主题严重程度颜色

| 严重程度 | Light 主题 | Cyber 主题 | Matrix 主题 |
|---------|-----------|-----------|------------|
| 严重 (Critical) | `#d32f2f` 深红 | `#ff6b6b` 亮红 | `#ff1744` 荧光红 |
| 高危 (High) | `#e65100` 深橙 | `#ffa94d` 亮橙 | `#ff9100` 荧光橙 |
| 中危 (Medium) | `#bf8f00` 深黄 | `#ffd43b` 亮黄 | `#ffea00` 荧光黄 |
| 低危 (Low) | `#1565c0` 深蓝 | `#74c0fc` 亮蓝 | `#00e5ff` 荧光青 |
| 信息 (Info) | `#616161` 灰色 | `#adb5bd` 浅灰 | `#69f0ae` 荧光绿 |

---

## 10. 语言配置

VulnScan 支持中文（zh）和英文（en）两种语言。

### 10.1 优先级

语言选择遵循以下优先级（从高到低）：

1. **`--lang` 命令行参数** -- 最高优先级
2. **`VULNSCAN_LANG` 环境变量** -- 适合设为系统默认
3. **系统 locale** -- 自动检测，`zh` 开头的 locale 使用中文
4. **默认英文** -- 以上都不匹配时使用英文

### 10.2 设置方式

**CLI 参数：**

```bash
python main.py --lang zh web https://example.com
python main.py --lang en status
```

**环境变量：**

```bash
# Linux / macOS
export VULNSCAN_LANG=zh

# Windows (CMD)
set VULNSCAN_LANG=zh

# Windows (PowerShell)
$env:VULNSCAN_LANG="zh"
```

**GUI 语言切换器：**

点击左侧面板顶部的 **English** 或 **中文** 按钮即可实时切换语言。切换后，界面中所有文本、按钮、标签都会立即更新。

### 10.3 支持语言

| 代码 | 语言 |
|------|------|
| `en` | English（英文） |
| `zh` | 简体中文 |

### 10.4 翻译范围

- **用户界面**: 所有按钮、标签、提示、对话框文本
- **扫描器输出**: 漏洞名称、描述、修复建议
- **报告内容**: HTML/JSON 报告中的标题和标签
- **CLI 输出**: 进度信息、摘要面板、错误提示

---

## 11. 漏洞严重程度说明

VulnScan 使用五级严重程度分类系统：

### 严重 (Critical)

表示可以被立即利用且影响重大的漏洞，可能导致系统完全被入侵。

**示例**：
- 已知的高危 CVE 漏洞（如远程代码执行）
- 未修复的严重依赖组件漏洞

### 高危 (High)

表示可能导致重要数据泄露或系统功能受损的漏洞。

**示例**：
- SQL 注入
- SSL 证书过期
- 敏感文件暴露（`.env`、`.git/` 等）
- 硬编码密码/密钥

### 中危 (Medium)

表示需要特定条件才能利用，或影响范围有限的漏洞。

**示例**：
- 缺少安全响应头（CSP、X-Frame-Options 等）
- CORS 配置过于宽松
- 源码中的潜在注入点

### 低危 (Low)

表示影响较小或利用难度较高的安全问题。

**示例**：
- 开放的非关键端口
- Cookie 缺少 Secure 标志
- 缺少 Cache-Control 头

### 信息 (Info)

非漏洞，但可能对安全评估有参考价值的信息。

**示例**：
- 服务器版本信息泄露
- 开放端口的 Banner 信息
- X-Powered-By 头泄露技术栈

---

## 12. 故障排除

### "扫描器未找到"

**症状**: `status` 显示某个外部扫描器不可用，提示 `not found in PATH`。

**解决方案**:
1. 安装对应的外部工具（参见第 6 节安装命令）
2. 确认工具已添加到系统 PATH 环境变量
3. 或者使用自定义路径配置（参见第 7 节）
4. GUI 中可直接点击"浏览"按钮指定工具路径

### "SSL 证书验证失败"

**症状**: 扫描某些站点时出现 SSL 相关错误。

**说明**: 这通常是正常现象。VulnScan 在扫描时使用 `verify=False` 来跳过 SSL 验证，以便检测 SSL 相关问题。SSLScanner 会主动检查目标的证书状态并报告问题。

### GUI 无法启动

**症状**: 运行 `python main.py gui` 时提示 `ModuleNotFoundError: No module named 'tkinter'`。

**解决方案**:

```bash
# Debian / Ubuntu
sudo apt install python3-tk

# Fedora
sudo dnf install python3-tkinter

# macOS (使用 Homebrew Python)
brew install python-tk

# Windows: 重新安装 Python 时勾选 "tcl/tk and IDLE" 选项
```

### 中文乱码

**症状**: CLI 输出或报告中出现乱码字符。

**解决方案**:
1. 确认终端编码为 UTF-8
2. Windows CMD 中执行 `chcp 65001` 切换到 UTF-8
3. Windows 建议使用 Windows Terminal 或 PowerShell
4. 临时切换到英文输出：`python main.py --lang en web https://example.com`

### 扫描耗时过长

**症状**: 扫描长时间未完成。

**解决方案**:
1. 减少并发线程数：`--workers 2`
2. 只使用部分扫描器：`--scanners HeaderScanner SSLScanner`
3. 检查网络连接是否正常
4. 某些外部工具（如 SQLMap、Nmap）本身扫描时间较长，属于正常现象
5. GUI 中可点击"停止扫描"中止任务

### 扫描结果为空

**症状**: 扫描完成但未发现任何漏洞。

**解决方案**:
1. 确认目标 URL 或文件路径可达/可访问
2. 检查是否选择了正确模式的扫描器（Web 扫描器无法扫描文件，反之亦然）
3. 对于需要认证的站点，配置 HTTP 选项（请求头、Cookies）
4. 运行 `status` 命令确认所选扫描器状态为可用
5. 使用 `--log-file` 参数输出调试日志查看详细信息

```bash
python main.py --log-file debug.log web https://example.com
```

---

## 13. 法律声明

**重要提示**：

1. **仅扫描你自己拥有或已获得书面授权的目标**。在扫描任何系统之前，确保你有明确的许可。
2. **未经授权的扫描可能违反法律**。在许多国家和地区，未经授权对计算机系统进行安全扫描属于违法行为，可能导致刑事或民事责任。
3. **本工具仅用于防御性安全测试**。VulnScan 的设计目的是帮助安全专业人员和开发者发现并修复自有系统中的安全问题。
4. **使用者对其行为承担全部责任**。VulnScan 的开发者不对因不当使用本工具所导致的任何后果负责。

请在合法、合规的范围内使用本工具。
