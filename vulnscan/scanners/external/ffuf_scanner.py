"""ffuf Web 路径模糊测试扫描器"""

from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner, _PLATFORM

# 内置常见路径字典 (~200 条)
COMMON_PATHS = [
    # 管理后台
    "admin", "admin/login", "administrator", "admin.php", "admin.html",
    "login", "login.php", "signin", "auth", "authentication",
    "dashboard", "panel", "cpanel", "manager", "manage",
    "console", "terminal", "shell", "webshell",
    # API 端点
    "api", "api/v1", "api/v2", "api/v3", "api/docs",
    "api/swagger", "api/graphql", "api/health", "api/status",
    "api/config", "api/admin", "api/users", "api/tokens",
    "graphql", "graphiql", "playground",
    # 调试与监控
    "debug", "debug/vars", "debug/pprof", "trace",
    "health", "healthz", "health/check", "healthcheck",
    "status", "server-status", "server-info", "nginx_status",
    "metrics", "prometheus", "monitor", "monitoring",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "actuator/configprops", "actuator/mappings", "actuator/info",
    # 配置与环境
    "config", "configuration", "settings", "setup",
    "env", "environment", "info", "version",
    "phpinfo.php", "info.php", "test.php",
    # 文档
    "docs", "documentation", "doc", "help",
    "swagger", "swagger-ui", "swagger-ui.html", "swagger.json",
    "openapi", "openapi.json", "redoc",
    # 敏感文件
    ".env", ".env.local", ".env.production", ".env.backup",
    ".git", ".git/config", ".git/HEAD", ".gitignore",
    ".svn", ".svn/entries", ".hg",
    ".htaccess", ".htpasswd", ".DS_Store",
    "Thumbs.db", "web.config", "crossdomain.xml",
    "robots.txt", "sitemap.xml", "security.txt",
    ".well-known/security.txt",
    # WordPress
    "wp-admin", "wp-login.php", "wp-content", "wp-includes",
    "wp-config.php", "wp-config.php.bak", "wp-json",
    "xmlrpc.php", "wp-cron.php",
    # 数据库管理
    "phpmyadmin", "pma", "adminer", "adminer.php",
    "dbadmin", "mysql", "pgadmin",
    # 备份与临时文件
    "backup", "backups", "bak", "old", "archive",
    "temp", "tmp", "test", "dev", "staging",
    "dump", "dump.sql", "database.sql", "db.sql",
    "backup.zip", "backup.tar.gz", "site.zip",
    # 日志
    "log", "logs", "error.log", "access.log",
    "debug.log", "application.log",
    # 上传
    "upload", "uploads", "files", "media",
    "images", "img", "assets", "static",
    "attachments", "documents",
    # 脚本与包含
    "cgi-bin", "bin", "scripts", "includes",
    "inc", "lib", "vendor", "node_modules",
    # 源码与版本控制
    "src", "source", "app", "application",
    ".svn/wc.db", "WEB-INF/web.xml",
    "META-INF/MANIFEST.MF",
    # 安全相关
    "secret", "secrets", "private", "hidden",
    "internal", "restricted", "confidential",
    "token", "tokens", "keys", "credentials",
    # 常见框架路由
    "index.php", "index.html", "default.aspx",
    "elmah.axd", "trace.axd",
    "jmx-console", "web-console", "invoker",
    "solr", "jenkins", "gitlab", "nexus",
    ".aws/credentials", "config.json", "config.yml",
    "config.yaml", "config.xml", "config.ini",
    "package.json", "composer.json", "Gemfile",
    "requirements.txt", "Dockerfile", "docker-compose.yml",
    # 其他
    "readme", "README.md", "CHANGELOG", "LICENSE",
    "install", "installer", "setup.php",
    "register", "signup", "forgot-password",
    "reset-password", "profile", "account",
    "user", "users", "members",
]

# 敏感路径关键词 (用于判断是否为 MEDIUM 级别)
_SENSITIVE_KEYWORDS = frozenset([
    "admin", "config", "debug", "env", "backup", "secret",
    "private", "console", "internal", "hidden", "credential",
    "token", "key", "password", "database", "dump", "log",
    "actuator", "phpinfo", "htpasswd", "htaccess", "git",
    "svn", "wp-config", "shell", "manage", "monitor",
])


class FfufScanner(ExternalScanner):
    """ffuf - Web fuzzing and path discovery"""

    name = "ffuf"
    description = "Web fuzzing and path discovery"
    executable = "ffuf"
    target_mode = "url"
    scan_type = ScanType.DAST

    def get_install_hint(self) -> str:
        if _PLATFORM == "Windows":
            return "Download from https://github.com/ffuf/ffuf/releases"
        elif _PLATFORM == "Darwin":
            return "brew install ffuf"
        else:
            return "Download from https://github.com/ffuf/ffuf/releases"

    def get_install_url(self) -> str:
        return "https://github.com/ffuf/ffuf/releases"

    # ---- 扫描 ----

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()

        if callback:
            callback(f"[ffuf] 正在扫描 {target} ...")

        # 确保 target 以 / 结尾
        base_url = target.rstrip("/")

        # 写入临时字典文件
        wordlist_fd, wordlist_path = tempfile.mkstemp(
            prefix="ffuf_wordlist_", suffix=".txt"
        )
        output_fd, output_path = tempfile.mkstemp(
            prefix="ffuf_output_", suffix=".json"
        )
        # 关闭 output fd，ffuf 会自己写入
        os.close(output_fd)

        try:
            with os.fdopen(wordlist_fd, "w", encoding="utf-8") as f:
                for path in COMMON_PATHS:
                    f.write(path + "\n")
        except Exception as exc:
            self._cleanup_files(wordlist_path, output_path)
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=f"创建字典文件失败: {exc}",
                duration_seconds=time.time() - start,
            )

        try:
            return self._do_ffuf_scan(
                target, base_url, wordlist_path, output_path,
                callback, http_options, start,
            )
        finally:
            self._cleanup_files(wordlist_path, output_path)

    def _do_ffuf_scan(
        self,
        target: str,
        base_url: str,
        wordlist_path: str,
        output_path: str,
        callback: Optional[Callable[[str], None]],
        http_options: Optional[HttpOptions],
        start: float,
    ) -> ScanResult:
        vulns: list[Vulnerability] = []

        cmd = [
            self.executable,
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist_path,
            "-o", output_path,
            "-of", "json",
            "-mc", "200,204,301,302,307,401,403,405",
            "-fc", "404",
            "-ac",
            "-t", "50",
            "-rate", "100",
            "-timeout", "10",
            "-e", ".php,.asp,.aspx,.jsp,.html,.js,.bak,.old,.txt,.xml,.json,.yml,.env,.config,.sql,.log,.zip,.tar.gz",
            "-recursion", "-recursion-depth", "2",
            "-s",
        ]

        if http_options:
            for key, value in http_options.headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
            if http_options.cookies:
                cmd.extend(["-b", http_options.cookies])
            if http_options.data:
                cmd.extend(["-d", http_options.data])
            if http_options.method and http_options.method.upper() != "GET":
                cmd.extend(["-X", http_options.method.upper()])

        try:
            self._run_command(cmd, timeout=300)
        except Exception as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=f"命令执行失败: {exc}",
                duration_seconds=time.time() - start,
            )

        if callback:
            callback("[ffuf] 命令执行完成，正在解析结果 ...")

        raw_output = ""
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                raw_output = f.read()
            vulns = self._parse_output(raw_output, target)
        except json.JSONDecodeError as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=f"JSON 解析失败: {exc}",
                duration_seconds=time.time() - start,
                raw_output=raw_output,
            )
        except Exception as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=f"输出解析失败: {exc}",
                duration_seconds=time.time() - start,
                raw_output=raw_output,
            )

        if callback:
            callback(f"[ffuf] 扫描完成，发现 {len(vulns)} 个路径")

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
            raw_output=raw_output,
        )

    # ---- 解析 ----

    def _parse_output(self, output: str, target: str) -> list[Vulnerability]:
        """解析 ffuf JSON 输出。"""
        vulns: list[Vulnerability] = []

        data = json.loads(output) if output.strip() else {}
        results_list = data.get("results", [])

        for item in results_list:
            url = item.get("url", "")
            status = item.get("status", 0)
            length = item.get("length", 0)
            words = item.get("words", 0)

            # 判断严重程度
            severity = self._classify_severity(url, status)

            # 描述
            description = (
                f"发现路径: {url} "
                f"(状态码: {status}, 响应长度: {length}, 字数: {words})"
            )

            # 名称
            if status in (401, 403):
                name = f"Restricted Path: {url}"
            elif status in (301, 302, 307):
                name = f"Redirect: {url}"
            else:
                name = f"Discovered Path: {url}"

            evidence = f"HTTP {status} | Length: {length} | Words: {words}"

            vulns.append(
                Vulnerability(
                    name=name,
                    severity=severity,
                    description=description,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=evidence,
                    target=target,
                    location=url,
                )
            )

        return vulns

    @staticmethod
    def _classify_severity(url: str, status: int) -> Severity:
        """根据状态码和路径敏感度判断严重程度。"""
        # 401/403: 需要认证/被禁止 -> INFO
        if status in (401, 403):
            return Severity.INFO
        # 301/302/307: 重定向 -> INFO
        if status in (301, 302, 307):
            return Severity.INFO
        # 200/204/405: 路径存在
        url_lower = url.lower()
        for keyword in _SENSITIVE_KEYWORDS:
            if keyword in url_lower:
                return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _cleanup_files(*paths: str) -> None:
        """安全删除临时文件。"""
        for path in paths:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except Exception:
                pass
