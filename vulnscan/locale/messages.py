"""所有翻译条目，按模块分组。

调用 register_all() 将全部条目注册到 i18n 模块。
"""

from __future__ import annotations

from vulnscan.i18n import register_translations

# ------------------------------------------------------------------
# CLI 相关
# ------------------------------------------------------------------
CLI_MESSAGES: dict[str, dict[str, str]] = {
    "cli.desc": {
        "en": "VulnScan - Integrated Vulnerability Scanner",
        "zh": "VulnScan - 漏洞扫描整合工具",
    },
    "cli.web_help": {
        "en": "Scan a URL for web vulnerabilities (DAST)",
        "zh": "扫描URL的Web漏洞 (DAST)",
    },
    "cli.code_help": {
        "en": "Scan files/directory for code vulnerabilities",
        "zh": "扫描文件/目录的代码漏洞",
    },
    "cli.status_help": {
        "en": "Show available scanners and tool status",
        "zh": "显示所有扫描器和工具状态",
    },
    "cli.gui_help": {
        "en": "Launch GUI interface",
        "zh": "启动图形界面",
    },
    "cli.starting_scan": {
        "en": "Starting {mode} scan: {target}",
        "zh": "开始{mode}扫描: {target}",
    },
    "cli.scan_complete": {
        "en": "Scan Complete",
        "zh": "扫描完成",
    },
    "cli.duration": {
        "en": "Duration",
        "zh": "耗时",
    },
    "cli.total": {
        "en": "Total",
        "zh": "总计",
    },
    "cli.report_saved_json": {
        "en": "JSON report saved",
        "zh": "JSON 报告已保存",
    },
    "cli.report_saved_html": {
        "en": "HTML report saved",
        "zh": "HTML 报告已保存",
    },
    "cli.scanner_status_title": {
        "en": "Scanner Status",
        "zh": "扫描器状态",
    },
    "cli.scan_summary": {
        "en": "Scan Summary",
        "zh": "扫描摘要",
    },
    "cli.initializing": {
        "en": "Initializing scan...",
        "zh": "正在初始化扫描...",
    },
}

# ------------------------------------------------------------------
# GUI 相关
# ------------------------------------------------------------------
GUI_MESSAGES: dict[str, dict[str, str]] = {
    "gui.title": {
        "en": "VulnScan - Vulnerability Scanner",
        "zh": "VulnScan - 漏洞扫描器",
    },
    "gui.scan_config": {
        "en": "Scan Configuration",
        "zh": "扫描配置",
    },
    "gui.scan_mode": {
        "en": "Scan Mode",
        "zh": "扫描模式",
    },
    "gui.web_scan": {
        "en": "Web Scan (URL)",
        "zh": "Web 扫描 (URL)",
    },
    "gui.code_scan": {
        "en": "Code Scan (File/Dir)",
        "zh": "代码扫描 (文件/目录)",
    },
    "gui.target": {
        "en": "Target",
        "zh": "目标",
    },
    "gui.browse": {
        "en": "Browse...",
        "zh": "浏览...",
    },
    "gui.scanners": {
        "en": "Scanners",
        "zh": "扫描器",
    },
    "gui.select_all": {
        "en": "Select All",
        "zh": "全选",
    },
    "gui.builtin_only": {
        "en": "Built-in Only",
        "zh": "仅内置",
    },
    "gui.start_scan": {
        "en": "Start Scan",
        "zh": "开始扫描",
    },
    "gui.stop_scan": {
        "en": "Stop",
        "zh": "停止",
    },
    "gui.results": {
        "en": "Results",
        "zh": "结果",
    },
    "gui.log": {
        "en": "Log",
        "zh": "日志",
    },
    "gui.vuln_detail": {
        "en": "Vulnerability Detail",
        "zh": "漏洞详情",
    },
    "gui.export_json": {
        "en": "Export JSON",
        "zh": "导出 JSON",
    },
    "gui.export_html": {
        "en": "Export HTML",
        "zh": "导出 HTML",
    },
    "gui.export_both": {
        "en": "Export Both",
        "zh": "全部导出",
    },
    "gui.ready": {
        "en": "Ready",
        "zh": "就绪",
    },
    "gui.scanning": {
        "en": "Scanning...",
        "zh": "扫描中...",
    },
    "gui.idle": {
        "en": "Idle",
        "zh": "空闲",
    },
    "gui.no_target": {
        "en": "Please enter a target.",
        "zh": "请输入扫描目标",
    },
    "gui.no_scanner": {
        "en": "Please select at least one scanner.",
        "zh": "请至少选择一个扫描器",
    },
    "gui.scan_done": {
        "en": "Scan complete",
        "zh": "扫描完成",
    },
    "gui.language": {
        "en": "Language",
        "zh": "语言",
    },
    "gui.progress": {
        "en": "Progress",
        "zh": "进度",
    },
    "gui.starting": {
        "en": "Starting...",
        "zh": "启动中...",
    },
    "gui.input_required": {
        "en": "Input required",
        "zh": "需要输入",
    },
    "gui.scan_cancelled": {
        "en": "Scan cancelled",
        "zh": "扫描已取消",
    },
    "gui.scan_cancelled_by_user": {
        "en": "Scan cancelled by user.",
        "zh": "用户取消了扫描。",
    },
    "gui.scan_error": {
        "en": "Scan Error",
        "zh": "扫描错误",
    },
    "gui.no_data": {
        "en": "No data",
        "zh": "无数据",
    },
    "gui.run_scan_first": {
        "en": "Run a scan first before exporting.",
        "zh": "请先运行扫描再导出。",
    },
    "gui.export_complete": {
        "en": "Export complete",
        "zh": "导出完成",
    },
    "gui.saved": {
        "en": "Saved:",
        "zh": "已保存:",
    },
    "gui.save_json_report": {
        "en": "Save JSON Report",
        "zh": "保存 JSON 报告",
    },
    "gui.save_html_report": {
        "en": "Save HTML Report",
        "zh": "保存 HTML 报告",
    },
    "gui.select_code_dir": {
        "en": "Select code directory to scan",
        "zh": "选择要扫描的代码目录",
    },
    "gui.scan_finished_in": {
        "en": "Scan finished in {duration}s.",
        "zh": "扫描完成，耗时 {duration}s。",
    },
    "gui.details": {
        "en": "Details",
        "zh": "详情",
    },
    "gui.author": {
        "en": "Author",
        "zh": "作者",
    },
    "gui.donate": {
        "en": "Donate",
        "zh": "打赏",
    },
    "gui.donate_title": {
        "en": "Support VulnScan",
        "zh": "支持 VulnScan",
    },
    "gui.donate_desc": {
        "en": "If you find this tool helpful, consider buying me a coffee!",
        "zh": "如果这个工具对你有帮助，请考虑请作者喝杯咖啡！",
    },
    "gui.wechat_pay": {
        "en": "WeChat Pay",
        "zh": "微信支付",
    },
    "gui.alipay": {
        "en": "Alipay",
        "zh": "支付宝",
    },
    "gui.buymeacoffee": {
        "en": "Buy Me a Coffee",
        "zh": "Buy Me a Coffee",
    },
    "gui.http_options": {
        "en": "HTTP Options",
        "zh": "HTTP 选项",
    },
    "gui.parse_curl": {
        "en": "Parse curl",
        "zh": "解析 curl",
    },
    "gui.paste_curl_hint": {
        "en": "Paste a curl command below to auto-fill URL, headers, cookies and data:",
        "zh": "在下方粘贴 curl 命令，自动填充 URL、请求头、Cookies 和数据：",
    },
    "gui.parse_and_fill": {
        "en": "Parse & Fill",
        "zh": "解析并填充",
    },
    "gui.close": {
        "en": "Close",
        "zh": "关闭",
    },
    "gui.qr_load_failed": {
        "en": "Failed to load QR code image",
        "zh": "加载收款码图片失败",
    },
    "gui.qr_not_found": {
        "en": "QR code image not found",
        "zh": "收款码图片未找到",
    },
    "gui.install_pillow": {
        "en": "Install Pillow (pip install Pillow) to display JPG images",
        "zh": "请安装 Pillow (pip install Pillow) 以显示 JPG 图片",
    },
    "gui.install": {
        "en": "Install",
        "zh": "安装",
    },
    "gui.browse_exe": {
        "en": "Browse",
        "zh": "浏览",
    },
    "gui.select_exe": {
        "en": "Select executable file",
        "zh": "选择可执行文件",
    },
    "gui.path_saved": {
        "en": "Path Saved",
        "zh": "路径已保存",
    },
    "gui.path_saved_msg": {
        "en": "{tool} path saved: {path}\nIt will be used on next scan.",
        "zh": "{tool} 路径已保存: {path}\n下次扫描时将自动使用。",
    },
    "gui.invalid_exe": {
        "en": "Invalid Executable",
        "zh": "无效的可执行文件",
    },
    "gui.select_code_file": {
        "en": "Select source file to scan",
        "zh": "选择要扫描的源码文件",
    },
    "gui.browse_choose": {
        "en": "What do you want to scan?",
        "zh": "请选择扫描对象：",
    },
    "gui.select_dir": {
        "en": "Directory",
        "zh": "选择目录",
    },
    "gui.select_file": {
        "en": "File",
        "zh": "选择文件",
    },
    "gui.dark_theme": {
        "en": "Aqua",
        "zh": "深色",
    },
    "gui.light_theme": {
        "en": "Light",
        "zh": "浅色",
    },
    "gui.invalid_exe_msg": {
        "en": "The selected file is not a valid executable:\n{path}\n\nPlease select the correct program file.",
        "zh": "所选文件不是有效的可执行文件:\n{path}\n\n请选择正确的程序文件。",
    },
}

# ------------------------------------------------------------------
# 扫描器描述
# ------------------------------------------------------------------
SCANNER_MESSAGES: dict[str, dict[str, str]] = {
    "scanner.header": {
        "en": "HTTP security headers check",
        "zh": "HTTP 安全头检查",
    },
    "scanner.ssl": {
        "en": "SSL/TLS certificate and protocol check",
        "zh": "SSL/TLS 证书与协议检查",
    },
    "scanner.directory": {
        "en": "Sensitive path and file exposure detection",
        "zh": "敏感路径与文件暴露检测",
    },
    "scanner.info_leak": {
        "en": "Server information leakage detection",
        "zh": "服务器信息泄露检测",
    },
    "scanner.port": {
        "en": "TCP port scanner with banner grabbing",
        "zh": "TCP 端口扫描与 Banner 抓取",
    },
    "scanner.file_analyzer": {
        "en": "Source code vulnerability pattern matching",
        "zh": "源码漏洞模式匹配",
    },
    "scanner.dependency": {
        "en": "Dependency vulnerability check via OSV API",
        "zh": "依赖漏洞检查 (OSV API)",
    },
    "scanner.nuclei": {
        "en": "Template-based vulnerability scanner",
        "zh": "基于模板的漏洞扫描器",
    },
    "scanner.nmap": {
        "en": "Network port and service scanner",
        "zh": "网络端口与服务扫描器",
    },
    "scanner.bandit": {
        "en": "Python security linter",
        "zh": "Python 安全扫描器",
    },
    "scanner.trivy": {
        "en": "Filesystem vulnerability scanner",
        "zh": "文件系统漏洞扫描器",
    },
    "scanner.sqlmap": {
        "en": "SQL injection detection tool",
        "zh": "SQL 注入检测工具",
    },
}

# ------------------------------------------------------------------
# 报告相关
# ------------------------------------------------------------------
REPORT_MESSAGES: dict[str, dict[str, str]] = {
    "report.title": {
        "en": "VulnScan Report",
        "zh": "VulnScan 扫描报告",
    },
    "report.target": {
        "en": "Target",
        "zh": "扫描目标",
    },
    "report.mode": {
        "en": "Scan Mode",
        "zh": "扫描模式",
    },
    "report.start_time": {
        "en": "Start Time",
        "zh": "开始时间",
    },
    "report.end_time": {
        "en": "End Time",
        "zh": "结束时间",
    },
    "report.duration": {
        "en": "Duration",
        "zh": "耗时",
    },
    "report.summary": {
        "en": "Summary",
        "zh": "摘要",
    },
    "report.vuln_list": {
        "en": "Vulnerability List",
        "zh": "漏洞列表",
    },
    "report.severity": {
        "en": "Severity",
        "zh": "严重程度",
    },
    "report.name": {
        "en": "Name",
        "zh": "名称",
    },
    "report.scanner": {
        "en": "Scanner",
        "zh": "扫描器",
    },
    "report.location": {
        "en": "Location",
        "zh": "位置",
    },
    "report.confidence": {
        "en": "Confidence",
        "zh": "置信度",
    },
    "report.description": {
        "en": "Description",
        "zh": "描述",
    },
    "report.evidence": {
        "en": "Evidence",
        "zh": "证据",
    },
    "report.remediation": {
        "en": "Remediation",
        "zh": "修复建议",
    },
    "report.reference": {
        "en": "Reference",
        "zh": "参考链接",
    },
    "report.scanner_summary": {
        "en": "Scanner Execution Summary",
        "zh": "扫描器执行摘要",
    },
    "report.status": {
        "en": "Status",
        "zh": "状态",
    },
    "report.success": {
        "en": "Success",
        "zh": "成功",
    },
    "report.failed": {
        "en": "Failed",
        "zh": "失败",
    },
    "report.found": {
        "en": "Found",
        "zh": "发现",
    },
    "report.generated_by": {
        "en": "Generated by VulnScan v{version}",
        "zh": "由 VulnScan v{version} 生成",
    },
    "report.no_vulns": {
        "en": "No vulnerabilities found",
        "zh": "未发现漏洞",
    },
    "report.type": {
        "en": "Type",
        "zh": "类型",
    },
    "report.findings": {
        "en": "Findings",
        "zh": "发现数",
    },
    "report.details": {
        "en": "Details",
        "zh": "详情",
    },
}

# ------------------------------------------------------------------
# 通用
# ------------------------------------------------------------------
COMMON_MESSAGES: dict[str, dict[str, str]] = {
    "common.critical": {
        "en": "Critical",
        "zh": "严重",
    },
    "common.high": {
        "en": "High",
        "zh": "高危",
    },
    "common.medium": {
        "en": "Medium",
        "zh": "中危",
    },
    "common.low": {
        "en": "Low",
        "zh": "低危",
    },
    "common.info": {
        "en": "Info",
        "zh": "信息",
    },
    "common.yes": {
        "en": "Yes",
        "zh": "是",
    },
    "common.no": {
        "en": "No",
        "zh": "否",
    },
    "common.web": {
        "en": "web",
        "zh": "Web",
    },
    "common.code": {
        "en": "code",
        "zh": "代码",
    },
}


# ------------------------------------------------------------------
# 引擎相关
# ------------------------------------------------------------------
ENGINE_MESSAGES: dict[str, dict[str, str]] = {
    "engine.skip_unavailable": {
        "en": "Skipping unavailable scanner %s: %s",
        "zh": "跳过不可用的扫描器 %s: %s",
    },
    "engine.preparing": {
        "en": "Preparing to run {total} scanners",
        "zh": "准备执行 {total} 个扫描器",
    },
    "engine.starting_scan": {
        "en": "Starting scan target=%s mode=%s scanners=[%s]",
        "zh": "开始扫描 target=%s mode=%s scanners=[%s]",
    },
    "engine.callback_error_start": {
        "en": "on_scanner_start callback error",
        "zh": "on_scanner_start 回调异常",
    },
    "engine.cancelled": {
        "en": "Scan cancelled",
        "zh": "扫描已取消",
    },
    "engine.scanner_exception": {
        "en": "Scanner %s execution error",
        "zh": "扫描器 %s 执行异常",
    },
    "engine.unexpected_error": {
        "en": "Unexpected error: {exc}",
        "zh": "未预期异常: {exc}",
    },
    "engine.scanner_done": {
        "en": "Scanner %s done (%.1fs, %d vulns, %s)",
        "zh": "扫描器 %s 完成 (%.1fs, %d 漏洞, %s)",
    },
    "engine.scanner_done_success": {
        "en": "success",
        "zh": "成功",
    },
    "engine.scanner_done_failed": {
        "en": "failed: {error}",
        "zh": "失败: {error}",
    },
    "engine.callback_error_done": {
        "en": "on_scanner_done callback error",
        "zh": "on_scanner_done 回调异常",
    },
    "engine.progress_status_success": {
        "en": "done",
        "zh": "完成",
    },
    "engine.progress_status_failed": {
        "en": "failed",
        "zh": "失败",
    },
    "engine.callback_error_progress": {
        "en": "on_progress callback error",
        "zh": "on_progress 回调异常",
    },
    "engine.scan_complete": {
        "en": "Scan complete total_time=%.1fs total_vulns=%d scanners=%d",
        "zh": "扫描完成 总耗时=%.1fs 总漏洞=%d 扫描器=%d",
    },
}

# ------------------------------------------------------------------
# 扫描器漏洞相关
# ------------------------------------------------------------------
SCANNER_VULN_MESSAGES: dict[str, dict[str, str]] = {
    # ── HeaderScanner ──────────────────────────────────────
    "scanner.header.requesting": {
        "en": "Requesting {target} ...",
        "zh": "正在请求 {target} ...",
    },
    "scanner.header.complete": {
        "en": "Header check complete, found {count} issues",
        "zh": "安全头检查完成，发现 {count} 个问题",
    },
    "scanner.header.request_failed": {
        "en": "Request failed: {exc}",
        "zh": "请求失败: {exc}",
    },
    # _CHECKS: missing headers
    "scanner.header.missing_xframe": {
        "en": "Missing X-Frame-Options header, site may be vulnerable to clickjacking",
        "zh": "缺少 X-Frame-Options 头，站点可能遭受点击劫持攻击",
    },
    "scanner.header.remediation_xframe": {
        "en": "Set X-Frame-Options to DENY or SAMEORIGIN",
        "zh": "设置 X-Frame-Options 为 DENY 或 SAMEORIGIN",
    },
    "scanner.header.bad_xframe": {
        "en": "X-Frame-Options should be DENY or SAMEORIGIN",
        "zh": "X-Frame-Options 值应为 DENY 或 SAMEORIGIN",
    },
    "scanner.header.missing_csp": {
        "en": "Missing Content-Security-Policy header, XSS attacks may not be effectively prevented",
        "zh": "缺少 Content-Security-Policy 头，可能无法有效防御 XSS 攻击",
    },
    "scanner.header.remediation_csp": {
        "en": "Configure an appropriate Content-Security-Policy",
        "zh": "配置合适的 Content-Security-Policy 策略",
    },
    "scanner.header.csp_unsafe_inline": {
        "en": "Content-Security-Policy contains 'unsafe-inline', weakening XSS protection",
        "zh": "Content-Security-Policy 包含 'unsafe-inline'，削弱了 XSS 防护",
    },
    "scanner.header.csp_unsafe_eval": {
        "en": "Content-Security-Policy contains 'unsafe-eval', allowing dynamic code execution",
        "zh": "Content-Security-Policy 包含 'unsafe-eval'，允许动态代码执行",
    },
    "scanner.header.missing_hsts": {
        "en": "Missing Strict-Transport-Security header, may be vulnerable to protocol downgrade attacks",
        "zh": "缺少 Strict-Transport-Security 头，可能遭受协议降级攻击",
    },
    "scanner.header.remediation_hsts": {
        "en": "Set Strict-Transport-Security header with max-age directive",
        "zh": "设置 Strict-Transport-Security 头并包含 max-age 指令",
    },
    "scanner.header.hsts_no_maxage": {
        "en": "Strict-Transport-Security should include max-age directive",
        "zh": "Strict-Transport-Security 应包含 max-age 指令",
    },
    "scanner.header.missing_xcto": {
        "en": "Missing X-Content-Type-Options header, browser may perform MIME sniffing",
        "zh": "缺少 X-Content-Type-Options 头，浏览器可能进行 MIME 嗅探",
    },
    "scanner.header.remediation_xcto": {
        "en": "Set X-Content-Type-Options to nosniff",
        "zh": "设置 X-Content-Type-Options 为 nosniff",
    },
    "scanner.header.bad_xcto": {
        "en": "X-Content-Type-Options should be nosniff",
        "zh": "X-Content-Type-Options 值应为 nosniff",
    },
    "scanner.header.missing_referrer": {
        "en": "Missing Referrer-Policy header, sensitive URL information may be leaked",
        "zh": "缺少 Referrer-Policy 头，可能泄露敏感 URL 信息",
    },
    "scanner.header.remediation_referrer": {
        "en": "Set an appropriate Referrer-Policy",
        "zh": "设置合适的 Referrer-Policy 策略",
    },
    "scanner.header.missing_permissions": {
        "en": "Missing Permissions-Policy header, browser feature permissions not restricted",
        "zh": "缺少 Permissions-Policy 头，未限制浏览器功能权限",
    },
    "scanner.header.remediation_permissions": {
        "en": "Configure Permissions-Policy to restrict unnecessary browser features",
        "zh": "配置 Permissions-Policy 限制不必要的浏览器功能",
    },
    "scanner.header.missing_coep": {
        "en": "Missing Cross-Origin-Embedder-Policy (COEP) header, may affect cross-origin isolation",
        "zh": "缺少 Cross-Origin-Embedder-Policy (COEP) 头，可能影响跨域隔离",
    },
    "scanner.header.remediation_coep": {
        "en": "Set Cross-Origin-Embedder-Policy to require-corp or credentialless",
        "zh": "设置 Cross-Origin-Embedder-Policy 为 require-corp 或 credentialless",
    },
    "scanner.header.missing_coop": {
        "en": "Missing Cross-Origin-Opener-Policy (COOP) header, may affect cross-origin isolation",
        "zh": "缺少 Cross-Origin-Opener-Policy (COOP) 头，可能影响跨域隔离",
    },
    "scanner.header.remediation_coop": {
        "en": "Set Cross-Origin-Opener-Policy to same-origin",
        "zh": "设置 Cross-Origin-Opener-Policy 为 same-origin",
    },
    "scanner.header.missing_corp": {
        "en": "Missing Cross-Origin-Resource-Policy (CORP) header, resources may be loaded cross-origin",
        "zh": "缺少 Cross-Origin-Resource-Policy (CORP) 头，资源可能被跨域加载",
    },
    "scanner.header.remediation_corp": {
        "en": "Set Cross-Origin-Resource-Policy to same-origin or same-site",
        "zh": "设置 Cross-Origin-Resource-Policy 为 same-origin 或 same-site",
    },
    # header missing / misconfigured names & evidence
    "scanner.header.missing_header_name": {
        "en": "Missing {header} header",
        "zh": "缺少 {header} 头",
    },
    "scanner.header.misconfigured_name": {
        "en": "{header} misconfigured",
        "zh": "{header} 配置不当",
    },
    "scanner.header.evidence_missing": {
        "en": "Response does not contain {header} header",
        "zh": "响应中未包含 {header} 头",
    },
    # CORS
    "scanner.header.cors_too_permissive": {
        "en": "Overly permissive CORS policy",
        "zh": "过于宽松的 CORS 策略",
    },
    "scanner.header.cors_desc": {
        "en": "Access-Control-Allow-Origin is set to *, allowing cross-origin access from any domain",
        "zh": "Access-Control-Allow-Origin 设置为 *，允许任意域跨域访问",
    },
    "scanner.header.cors_remediation": {
        "en": "Restrict Access-Control-Allow-Origin to trusted domains",
        "zh": "将 Access-Control-Allow-Origin 限制为可信域名",
    },
    # X-XSS-Protection
    "scanner.header.missing_xxss": {
        "en": "Missing X-XSS-Protection header",
        "zh": "缺少 X-XSS-Protection 头",
    },
    "scanner.header.missing_xxss_desc": {
        "en": "Missing X-XSS-Protection header (deprecated, modern browsers rely on CSP)",
        "zh": "缺少 X-XSS-Protection 头（该头已废弃，现代浏览器依赖 CSP）",
    },
    "scanner.header.missing_xxss_evidence": {
        "en": "Response does not contain X-XSS-Protection header",
        "zh": "响应中未包含 X-XSS-Protection 头",
    },
    "scanner.header.missing_xxss_remediation": {
        "en": "This header is deprecated, use Content-Security-Policy to defend against XSS",
        "zh": "该头已废弃，建议通过 Content-Security-Policy 防御 XSS",
    },
    "scanner.header.xxss_deprecated_ok": {
        "en": "X-XSS-Protection deprecated but configured correctly",
        "zh": "X-XSS-Protection 已废弃但配置正确",
    },
    "scanner.header.xxss_deprecated_ok_desc": {
        "en": "X-XSS-Protection is set to 0, correctly disabling this deprecated feature",
        "zh": "X-XSS-Protection 设置为 0，已正确禁用该废弃功能",
    },
    "scanner.header.xxss_deprecated_ok_remediation": {
        "en": "This header is deprecated, current configuration is correct, rely on CSP for XSS defense",
        "zh": "该头已废弃，当前配置正确，建议依赖 CSP 防御 XSS",
    },
    # Cache-Control
    "scanner.header.cache_control_missing": {
        "en": "HTML page missing Cache-Control security directive",
        "zh": "HTML 页面缺少 Cache-Control 安全指令",
    },
    "scanner.header.cache_control_desc": {
        "en": "HTML page Cache-Control does not contain no-store or no-cache, sensitive pages may be cached by browser or proxy",
        "zh": "HTML 页面的 Cache-Control 未包含 no-store 或 no-cache，敏感页面可能被浏览器或代理缓存",
    },
    "scanner.header.cache_control_evidence_value": {
        "en": "Cache-Control: {value}",
        "zh": "Cache-Control: {value}",
    },
    "scanner.header.cache_control_evidence_missing": {
        "en": "Response does not contain Cache-Control header",
        "zh": "响应中未包含 Cache-Control 头",
    },
    "scanner.header.cache_control_remediation": {
        "en": "Set Cache-Control: no-store or no-cache for HTML pages",
        "zh": "为 HTML 页面设置 Cache-Control: no-store 或 no-cache",
    },
    # Cookie
    "scanner.header.cookie_no_httponly": {
        "en": "Cookie missing HttpOnly attribute",
        "zh": "Cookie 缺少 HttpOnly 属性",
    },
    "scanner.header.cookie_no_httponly_desc": {
        "en": "Set-Cookie does not have HttpOnly flag, cookie may be accessed by JavaScript",
        "zh": "Set-Cookie 未设置 HttpOnly 标志，Cookie 可能被 JavaScript 访问",
    },
    "scanner.header.cookie_no_httponly_remediation": {
        "en": "Add HttpOnly attribute to sensitive cookies",
        "zh": "为敏感 Cookie 添加 HttpOnly 属性",
    },
    "scanner.header.cookie_no_secure": {
        "en": "Cookie missing Secure attribute",
        "zh": "Cookie 缺少 Secure 属性",
    },
    "scanner.header.cookie_no_secure_desc": {
        "en": "Set-Cookie does not have Secure flag, cookie may be transmitted over plaintext HTTP",
        "zh": "Set-Cookie 未设置 Secure 标志，Cookie 可能通过 HTTP 明文传输",
    },
    "scanner.header.cookie_no_secure_remediation": {
        "en": "Add Secure attribute to sensitive cookies",
        "zh": "为敏感 Cookie 添加 Secure 属性",
    },

    # ── DirectoryScanner ───────────────────────────────────
    "scanner.dir.loading_paths": {
        "en": "Loading sensitive path dictionary ...",
        "zh": "正在加载敏感路径字典 ...",
    },
    "scanner.dir.loaded_paths": {
        "en": "Loaded {total} sensitive paths, starting concurrent probing ...",
        "zh": "已加载 {total} 条敏感路径，开始并发探测 ...",
    },
    "scanner.dir.load_error": {
        "en": "Failed to load sensitive path dictionary: %s",
        "zh": "无法加载敏感路径字典: %s",
    },
    "scanner.dir.progress": {
        "en": "Probing progress: {completed}/{total}",
        "zh": "探测进度: {completed}/{total}",
    },
    "scanner.dir.complete": {
        "en": "Sensitive path scan complete, found {count} issues",
        "zh": "敏感路径扫描完成，发现 {count} 个问题",
    },
    "scanner.dir.path_forbidden": {
        "en": "Path exists but access forbidden: {path}",
        "zh": "路径存在但被禁止访问: {path}",
    },
    "scanner.dir.path_forbidden_desc": {
        "en": "Path {path} returned 403 Forbidden, indicating the path exists but access is denied",
        "zh": "路径 {path} 返回 403 Forbidden，表明该路径存在但访问被拒绝",
    },
    "scanner.dir.sensitive_path_exposed": {
        "en": "Sensitive path exposed: {path}",
        "zh": "敏感路径暴露: {path}",
    },
    "scanner.dir.git_confirmed": {
        "en": "GET {url} -> Confirmed Git repository (content: {body})",
        "zh": "GET {url} -> 确认为 Git 仓库 (内容: {body})",
    },
    "scanner.dir.git_not_confirmed": {
        "en": "GET {url} -> 200 but content does not start with ref:, possible false positive",
        "zh": "GET {url} -> 200 但内容非 ref: 开头，可能为误报",
    },
    "scanner.dir.env_confirmed": {
        "en": "GET {url} -> Confirmed environment config file (contains key=value format content)",
        "zh": "GET {url} -> 确认为环境配置文件 (包含 key=value 格式内容)",
    },
    "scanner.dir.env_not_confirmed": {
        "en": "GET {url} -> 200 but content does not match .env file characteristics, may not be a real .env file",
        "zh": "GET {url} -> 200 但内容不符合 .env 文件特征，可能非真实 .env 文件",
    },
    "scanner.dir.remediation": {
        "en": "Restrict public access to this path, or remove the file from the server",
        "zh": "限制对该路径的公开访问，或从服务器中移除该文件",
    },

    # ── InfoLeakScanner ────────────────────────────────────
    "scanner.info.requesting": {
        "en": "Requesting {target} ...",
        "zh": "正在请求 {target} ...",
    },
    "scanner.info.request_failed": {
        "en": "Main page request failed: {exc}",
        "zh": "主页请求失败: {exc}",
    },
    "scanner.info.checking_404": {
        "en": "Checking if 404 page leaks debug information ...",
        "zh": "正在检查 404 页面是否泄露调试信息 ...",
    },
    "scanner.info.checking_robots": {
        "en": "Checking robots.txt ...",
        "zh": "正在检查 robots.txt ...",
    },
    "scanner.info.complete": {
        "en": "Information leak check complete, found {count} issues",
        "zh": "信息泄露检查完成，发现 {count} 个问题",
    },
    "scanner.info.server_version_leak": {
        "en": "Server header leaks version information",
        "zh": "Server 头泄露版本信息",
    },
    "scanner.info.server_version_leak_desc": {
        "en": "Server response header contains specific version number, attacker can look up known vulnerabilities",
        "zh": "Server 响应头中包含具体版本号，攻击者可据此查找已知漏洞",
    },
    "scanner.info.server_version_leak_remediation": {
        "en": "Hide or remove version information in web server configuration",
        "zh": "在 Web 服务器配置中隐藏或移除版本信息",
    },
    "scanner.info.powered_by_leak": {
        "en": "X-Powered-By header leaks technology stack",
        "zh": "X-Powered-By 头泄露技术栈",
    },
    "scanner.info.powered_by_leak_desc": {
        "en": "X-Powered-By header exposes backend technology stack information",
        "zh": "X-Powered-By 头暴露了后端技术栈信息",
    },
    "scanner.info.powered_by_leak_remediation": {
        "en": "Remove X-Powered-By response header",
        "zh": "移除 X-Powered-By 响应头",
    },
    "scanner.info.aspnet_version_leak": {
        "en": "{header} header leaks version information",
        "zh": "{header} 头泄露版本信息",
    },
    "scanner.info.aspnet_version_leak_desc": {
        "en": "{header} header exposes ASP.NET version information",
        "zh": "{header} 头暴露了 ASP.NET 版本信息",
    },
    "scanner.info.aspnet_version_leak_remediation": {
        "en": "Remove {header} header in Web.config",
        "zh": "在 Web.config 中移除 {header} 头",
    },
    "scanner.info.debug_404_leak": {
        "en": "404 page leaks debug/stack trace information",
        "zh": "404 页面泄露调试/栈追踪信息",
    },
    "scanner.info.debug_404_leak_desc": {
        "en": "Error page contains debug information or stack trace, may leak code structure and internal paths",
        "zh": "错误页面中包含调试信息或栈追踪，可能泄露代码结构和内部路径",
    },
    "scanner.info.debug_404_leak_remediation": {
        "en": "Disable debug mode in production environment, configure custom error pages",
        "zh": "在生产环境中关闭调试模式，配置自定义错误页面",
    },
    "scanner.info.robots_sensitive_paths": {
        "en": "robots.txt leaks sensitive paths",
        "zh": "robots.txt 泄露敏感路径",
    },
    "scanner.info.robots_sensitive_paths_desc": {
        "en": "robots.txt contains sensitive directory paths, attacker can directly access these paths",
        "zh": "robots.txt 中包含敏感目录路径，攻击者可直接访问这些路径",
    },
    "scanner.info.robots_sensitive_paths_evidence": {
        "en": "Sensitive paths: {paths}",
        "zh": "敏感路径: {paths}",
    },
    "scanner.info.robots_sensitive_paths_remediation": {
        "en": "Remove sensitive paths from robots.txt and restrict access through permission controls",
        "zh": "移除 robots.txt 中的敏感路径，并通过权限控制限制访问",
    },
    "scanner.info.html_comments_sensitive": {
        "en": "HTML comments contain sensitive information",
        "zh": "HTML 注释中包含敏感信息",
    },
    "scanner.info.html_comments_sensitive_desc": {
        "en": "Page HTML comments contain sensitive keywords such as TODO/FIXME/password/key",
        "zh": "页面 HTML 注释中包含 TODO/FIXME/密码/密钥等敏感关键词",
    },
    "scanner.info.html_comments_sensitive_remediation": {
        "en": "Remove debug comments and sensitive information from HTML source before deployment",
        "zh": "在部署前移除 HTML 源码中的调试注释和敏感信息",
    },
    "scanner.info.internal_ip_leak": {
        "en": "Response leaks internal IP addresses",
        "zh": "响应中泄露内部 IP 地址",
    },
    "scanner.info.internal_ip_leak_desc": {
        "en": "Response content or headers contain internal IP addresses, may leak internal network architecture",
        "zh": "响应内容或头中包含内部 IP 地址，可能泄露内网架构",
    },
    "scanner.info.internal_ip_leak_evidence": {
        "en": "Internal IP: {ips}",
        "zh": "内部 IP: {ips}",
    },
    "scanner.info.internal_ip_leak_remediation": {
        "en": "Remove internal IP address information from responses",
        "zh": "移除响应中的内部 IP 地址信息",
    },
    "scanner.info.email_leak": {
        "en": "Page leaks email addresses",
        "zh": "页面中泄露 Email 地址",
    },
    "scanner.info.email_leak_desc": {
        "en": "Page content contains email addresses, may be used for social engineering attacks",
        "zh": "页面内容中包含 Email 地址，可能被用于社会工程攻击",
    },
    "scanner.info.email_leak_evidence": {
        "en": "Emails found: {emails}",
        "zh": "发现 Email: {emails}",
    },
    "scanner.info.email_leak_remediation": {
        "en": "Avoid directly exposing email addresses in HTML",
        "zh": "避免在 HTML 中直接暴露 Email 地址",
    },

    # ── SSLScanner ─────────────────────────────────────────
    "scanner.ssl.http_skip": {
        "en": "Target uses HTTP protocol (not HTTPS), skipping SSL check",
        "zh": "目标使用 HTTP 协议（非 HTTPS），跳过 SSL 检查",
    },
    "scanner.ssl.no_host": {
        "en": "Unable to parse hostname from target",
        "zh": "无法从目标中解析出主机名",
    },
    "scanner.ssl.fetching_cert": {
        "en": "Fetching SSL certificate for {host}:{port} ...",
        "zh": "正在获取 {host}:{port} 的 SSL 证书 ...",
    },
    "scanner.ssl.connect_failed": {
        "en": "SSL connection failed ({host}:{port}): {exc}",
        "zh": "SSL 连接失败 ({host}:{port}): {exc}",
    },
    "scanner.ssl.cert_expired": {
        "en": "SSL certificate has expired",
        "zh": "SSL 证书已过期",
    },
    "scanner.ssl.cert_expired_desc": {
        "en": "Certificate expired on {date}",
        "zh": "证书已于 {date} 过期",
    },
    "scanner.ssl.cert_expired_remediation": {
        "en": "Immediately renew or replace the SSL certificate",
        "zh": "立即续签或更换 SSL 证书",
    },
    "scanner.ssl.self_signed": {
        "en": "Self-signed SSL certificate",
        "zh": "使用自签名 SSL 证书",
    },
    "scanner.ssl.self_signed_desc": {
        "en": "Certificate issuer and subject are the same, indicating a self-signed certificate",
        "zh": "证书的签发者与使用者相同，属于自签名证书",
    },
    "scanner.ssl.self_signed_remediation": {
        "en": "Use a certificate issued by a trusted CA",
        "zh": "使用受信任 CA 签发的证书",
    },
    "scanner.ssl.cert_expiring": {
        "en": "SSL certificate expiring soon",
        "zh": "SSL 证书即将过期",
    },
    "scanner.ssl.cert_expiring_desc": {
        "en": "Certificate will expire in {days} days ({date})",
        "zh": "证书将在 {days} 天后过期 ({date})",
    },
    "scanner.ssl.cert_expiring_remediation": {
        "en": "Renew the SSL certificate as soon as possible",
        "zh": "尽快续签 SSL 证书",
    },
    "scanner.ssl.checking_protocols": {
        "en": "Checking for insecure TLS protocol versions ...",
        "zh": "正在检测不安全的 TLS 协议版本 ...",
    },
    "scanner.ssl.insecure_protocol": {
        "en": "Supports insecure {proto} protocol",
        "zh": "支持不安全的 {proto} 协议",
    },
    "scanner.ssl.insecure_protocol_desc": {
        "en": "Server still accepts {proto} connections, this protocol has known security vulnerabilities",
        "zh": "服务器仍然接受 {proto} 连接，该协议存在已知安全漏洞",
    },
    "scanner.ssl.insecure_protocol_remediation": {
        "en": "Disable {proto} in server configuration",
        "zh": "在服务器配置中禁用 {proto}",
    },
    "scanner.ssl.hostname_mismatch": {
        "en": "SSL certificate hostname mismatch",
        "zh": "SSL 证书域名不匹配",
    },
    "scanner.ssl.hostname_mismatch_desc": {
        "en": "Certificate subject '{subject}' does not match target hostname '{host}'",
        "zh": "证书主题 '{subject}' 与目标主机名 '{host}' 不匹配",
    },
    "scanner.ssl.hostname_mismatch_remediation": {
        "en": "Use an SSL certificate that matches the domain name",
        "zh": "使用与域名匹配的 SSL 证书",
    },
    "scanner.ssl.complete": {
        "en": "SSL/TLS check complete, found {count} issues",
        "zh": "SSL/TLS 检查完成，发现 {count} 个问题",
    },

    # ── PortScanner ────────────────────────────────────────
    "scanner.port.no_host": {
        "en": "Unable to parse hostname from target",
        "zh": "无法从目标中解析出主机名",
    },
    "scanner.port.loading": {
        "en": "Loading port dictionary and preparing to scan {host} ...",
        "zh": "正在加载端口字典并准备扫描 {host} ...",
    },
    "scanner.port.load_error": {
        "en": "Failed to load port dictionary: %s",
        "zh": "无法加载端口字典: %s",
    },
    "scanner.port.starting": {
        "en": "Starting scan of {total} common ports on {host} ...",
        "zh": "开始扫描 {host} 的 {total} 个常见端口 ...",
    },
    "scanner.port.progress": {
        "en": "Port scan progress: {completed}/{total}",
        "zh": "端口扫描进度: {completed}/{total}",
    },
    "scanner.port.complete": {
        "en": "Port scan complete, found {count} open ports",
        "zh": "端口扫描完成，发现 {count} 个开放端口",
    },
    "scanner.port.open_port": {
        "en": "Open port: {port}/{service}",
        "zh": "开放端口: {port}/{service}",
    },
    "scanner.port.open_port_desc": {
        "en": "Detected port {port} ({service}) is open on host {host}",
        "zh": "检测到主机 {host} 的 {port} 端口 ({service}) 处于开放状态",
    },
    "scanner.port.evidence_open": {
        "en": "{host}:{port} open ({service})",
        "zh": "{host}:{port} 开放 ({service})",
    },
    "scanner.port.evidence_note": {
        "en": "Note: {note}",
        "zh": "说明: {note}",
    },
    "scanner.port.remediation": {
        "en": "Close this port or restrict access sources if not needed",
        "zh": "如非必要，关闭该端口或限制访问来源",
    },

    # ── FileAnalyzer ───────────────────────────────────────
    "scanner.file.load_error": {
        "en": "Failed to load vulnerability pattern file: %s",
        "zh": "无法加载漏洞模式文件: %s",
    },
    "scanner.file.load_failed": {
        "en": "Failed to load vulnerability pattern file",
        "zh": "无法加载漏洞模式文件",
    },
    "scanner.file.skip_invalid_regex": {
        "en": "Skipping invalid regex [%s]: %s",
        "zh": "跳过无效正则 [%s]: %s",
    },
    "scanner.file.read_error": {
        "en": "Unable to read file %s: %s",
        "zh": "无法读取文件 %s: %s",
    },
    "scanner.file.complete": {
        "en": "Source code scan complete, found {count} issues",
        "zh": "源码扫描完成，发现 {count} 个问题",
    },

    # ── DependencyScanner ──────────────────────────────────
    "scanner.dep.no_dep_files": {
        "en": "No dependency files found",
        "zh": "未找到任何依赖文件",
    },
    "scanner.dep.found_deps": {
        "en": "Found {count} dependencies, starting OSV API query...",
        "zh": "发现 {count} 个依赖，开始查询 OSV API...",
    },
    "scanner.dep.osv_query_failed": {
        "en": "OSV API query failed (%s==%s, %s): %s",
        "zh": "OSV API 查询失败 (%s==%s, %s): %s",
    },
    "scanner.dep.all_queries_failed": {
        "en": "All {count} OSV API queries failed, please check network connectivity",
        "zh": "所有 {count} 个 OSV API 查询均失败，请检查网络连接",
    },
    "scanner.dep.complete": {
        "en": "Dependency scan complete, found {count} vulnerabilities",
        "zh": "依赖扫描完成，发现 {count} 个漏洞",
    },
    "scanner.dep.parse_warning": {
        "en": "Unable to read %s: %s",
        "zh": "无法读取 %s: %s",
    },
    "scanner.dep.parse_error": {
        "en": "Unable to parse %s: %s",
        "zh": "无法解析 %s: %s",
    },
}


def register_all() -> None:
    """注册所有翻译条目到 i18n 模块。"""
    register_translations(CLI_MESSAGES)
    register_translations(GUI_MESSAGES)
    register_translations(SCANNER_MESSAGES)
    register_translations(REPORT_MESSAGES)
    register_translations(COMMON_MESSAGES)
    register_translations(ENGINE_MESSAGES)
    register_translations(SCANNER_VULN_MESSAGES)
