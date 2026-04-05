"""服务器信息泄露检查扫描器"""

from __future__ import annotations

import re
import time
from typing import Callable, Optional

import requests

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner

# 常见的版本号模式 (Server 头中)
_VERSION_RE = re.compile(
    r"(?:Apache|Nginx|IIS|LiteSpeed|OpenResty|Caddy|Tomcat|Jetty|Gunicorn)"
    r"[/\s][\d]+\.[\d]+[.\d]*",
    re.IGNORECASE,
)

# HTML 注释中的敏感关键词
_SENSITIVE_COMMENT_RE = re.compile(
    r"<!--[\s\S]*?"
    r"(?:TODO|FIXME|HACK|XXX|password|passwd|secret|token|api[_-]?key|credential)"
    r"[\s\S]*?-->",
    re.IGNORECASE,
)

# robots.txt 中的敏感路径关键词
_SENSITIVE_PATHS = (
    "/admin", "/backup", "/config", "/database", "/db",
    "/debug", "/dump", "/env", "/internal", "/log",
    "/manage", "/migrate", "/monitor", "/private", "/secret",
    "/setup", "/staging", "/test", "/tmp", "/upload",
)

# 内部 IP 地址模式
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)

# Email 地址模式
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# 404 页面中常见的调试/栈追踪特征
_DEBUG_PATTERNS = re.compile(
    r"(?:Traceback \(most recent call last\)"
    r"|Exception in thread"
    r"|Stack Trace:"
    r"|at [\w.$]+\([\w.]+:\d+\)"
    r"|<pre class=\"exception_value\">"
    r"|Debug mode is enabled"
    r"|SQLSTATE\["
    r"|Fatal error:"
    r"|Parse error:"
    r"|Warning:.*on line \d+)",
    re.IGNORECASE,
)


class InfoLeakScanner(Scanner):
    """检测服务器信息泄露"""

    name = "InfoLeakScanner"
    description = "Server information leakage detection"
    target_mode = "url"
    scan_type = ScanType.DAST

    _REQUEST_TIMEOUT = 10

    def run(
        self,
        target: str,
        callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "VulnScan/1.0"})

        # 合并用户自定义 HTTP 选项
        if http_options:
            if http_options.headers:
                session.headers.update(http_options.headers)
            if http_options.cookies:
                for item in http_options.cookies.split(";"):
                    if "=" in item:
                        k, v = item.strip().split("=", 1)
                        session.cookies.set(k.strip(), v.strip())

        try:
            # ── 主请求 ──────────────────────────────────────
            if callback:
                callback(t("scanner.info.requesting", target=target))
            resp = session.get(
                target, timeout=self._REQUEST_TIMEOUT, allow_redirects=True
            )

            # 1. Server 头版本信息
            self._check_server_header(resp, target, vulns)

            # 2. X-Powered-By
            self._check_powered_by(resp, target, vulns)

            # 3. ASP.NET 版本头
            self._check_aspnet_headers(resp, target, vulns)

            # 6. HTML 注释中的敏感信息 (先检查首页)
            self._check_html_comments(resp.text, target, target, vulns)

            # 7. 响应中的内部 IP 地址
            self._check_internal_ip(resp, target, vulns)

            # 8. 页面中的 Email 地址泄露
            self._check_email_leak(resp.text, target, vulns)

        except requests.RequestException as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=t("scanner.info.request_failed", exc=exc),
                duration_seconds=time.time() - start,
            )

        # ── 4. 404 页面调试信息 ─────────────────────────────
        if callback:
            callback(t("scanner.info.checking_404"))
        self._check_404_debug(session, target, vulns)

        # ── 5. robots.txt 敏感路径 ─────────────────────────
        if callback:
            callback(t("scanner.info.checking_robots"))
        self._check_robots_txt(session, target, vulns)

        if callback:
            callback(t("scanner.info.complete", count=len(vulns)))

        session.close()

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
        )

    # ── 各项检查 ──────────────────────────────────────────────

    def _check_server_header(
        self,
        resp: requests.Response,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        server = resp.headers.get("Server", "")
        if server and _VERSION_RE.search(server):
            vulns.append(
                Vulnerability(
                    name=t("scanner.info.server_version_leak"),
                    severity=Severity.MEDIUM,
                    description=t("scanner.info.server_version_leak_desc"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=f"Server: {server}",
                    remediation=t("scanner.info.server_version_leak_remediation"),
                    target=target,
                    location=target,
                )
            )

    def _check_powered_by(
        self,
        resp: requests.Response,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        powered_by = resp.headers.get("X-Powered-By")
        if powered_by:
            vulns.append(
                Vulnerability(
                    name=t("scanner.info.powered_by_leak"),
                    severity=Severity.LOW,
                    description=t("scanner.info.powered_by_leak_desc"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=f"X-Powered-By: {powered_by}",
                    remediation=t("scanner.info.powered_by_leak_remediation"),
                    target=target,
                    location=target,
                )
            )

    def _check_aspnet_headers(
        self,
        resp: requests.Response,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        for header in ("X-AspNet-Version", "X-AspNetMvc-Version"):
            value = resp.headers.get(header)
            if value:
                vulns.append(
                    Vulnerability(
                        name=t("scanner.info.aspnet_version_leak", header=header),
                        severity=Severity.LOW,
                        description=t("scanner.info.aspnet_version_leak_desc", header=header),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=f"{header}: {value}",
                        remediation=t("scanner.info.aspnet_version_leak_remediation", header=header),
                        target=target,
                        location=target,
                    )
                )

    def _check_404_debug(
        self,
        session: requests.Session,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        not_found_url = target.rstrip("/") + "/vulnscan_nonexistent_test_page_404"
        try:
            resp = session.get(
                not_found_url, timeout=self._REQUEST_TIMEOUT, allow_redirects=True
            )
            if _DEBUG_PATTERNS.search(resp.text):
                vulns.append(
                    Vulnerability(
                        name=t("scanner.info.debug_404_leak"),
                        severity=Severity.MEDIUM,
                        description=t("scanner.info.debug_404_leak_desc"),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=self._truncate(
                            _DEBUG_PATTERNS.search(resp.text).group(), 300  # type: ignore[union-attr]
                        ),
                        remediation=t("scanner.info.debug_404_leak_remediation"),
                        target=target,
                        location=not_found_url,
                    )
                )
        except requests.RequestException:
            pass  # 无法访问则跳过

    def _check_robots_txt(
        self,
        session: requests.Session,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        robots_url = target.rstrip("/") + "/robots.txt"
        try:
            resp = session.get(
                robots_url, timeout=self._REQUEST_TIMEOUT, allow_redirects=True
            )
            if resp.status_code != 200:
                return
            content = resp.text.lower()
            leaked = [p for p in _SENSITIVE_PATHS if p in content]
            if leaked:
                vulns.append(
                    Vulnerability(
                        name=t("scanner.info.robots_sensitive_paths"),
                        severity=Severity.LOW,
                        description=t("scanner.info.robots_sensitive_paths_desc"),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=t("scanner.info.robots_sensitive_paths_evidence", paths=", ".join(leaked)),
                        remediation=t("scanner.info.robots_sensitive_paths_remediation"),
                        target=target,
                        location=robots_url,
                    )
                )
        except requests.RequestException:
            pass

    def _check_html_comments(
        self,
        html: str,
        target: str,
        location: str,
        vulns: list[Vulnerability],
    ) -> None:
        matches = _SENSITIVE_COMMENT_RE.findall(html)
        if matches:
            evidence_list = [self._truncate(m.strip(), 120) for m in matches[:5]]
            vulns.append(
                Vulnerability(
                    name=t("scanner.info.html_comments_sensitive"),
                    severity=Severity.LOW,
                    description=t("scanner.info.html_comments_sensitive_desc"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence="\n".join(evidence_list),
                    remediation=t("scanner.info.html_comments_sensitive_remediation"),
                    target=target,
                    location=location,
                )
            )

    def _check_internal_ip(
        self,
        resp: requests.Response,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        """检查响应体和响应头中是否泄露内部 IP 地址。"""
        ips_found: set[str] = set(_INTERNAL_IP_RE.findall(resp.text[:50000]))
        for header_val in resp.headers.values():
            ips_found.update(_INTERNAL_IP_RE.findall(header_val))
        if ips_found:
            vulns.append(
                Vulnerability(
                    name=t("scanner.info.internal_ip_leak"),
                    severity=Severity.LOW,
                    description=t("scanner.info.internal_ip_leak_desc"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=t("scanner.info.internal_ip_leak_evidence", ips=", ".join(sorted(ips_found)[:5])),
                    remediation=t("scanner.info.internal_ip_leak_remediation"),
                    target=target,
                    location=target,
                )
            )

    def _check_email_leak(
        self,
        resp_text: str,
        target: str,
        vulns: list[Vulnerability],
    ) -> None:
        """检查页面内容中是否泄露 Email 地址。"""
        emails = set(_EMAIL_RE.findall(resp_text[:50000]))
        # 排除常见的无关 email（如以资源文件扩展名结尾的）
        emails = {e for e in emails if not e.endswith((".png", ".jpg", ".gif", ".css", ".js"))}
        if emails:
            vulns.append(
                Vulnerability(
                    name=t("scanner.info.email_leak"),
                    severity=Severity.INFO,
                    description=t("scanner.info.email_leak_desc"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=t("scanner.info.email_leak_evidence", emails=", ".join(sorted(emails)[:5])),
                    remediation=t("scanner.info.email_leak_remediation"),
                    target=target,
                    location=target,
                )
            )

    @staticmethod
    def _truncate(text: str, max_len: int) -> str:
        """截断文本到指定长度。"""
        if len(text) <= max_len:
            return text
        return text[: max_len - 3] + "..."
