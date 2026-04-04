# -*- coding: utf-8 -*-
"""内置扫描器单元测试。

使用 unittest.mock 模拟网络请求，确保测试不依赖网络连接。
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from vulnscan.models import Severity


@pytest.fixture(autouse=True)
def _init_i18n():
    """确保每个测试运行前 i18n 已初始化。"""
    from vulnscan.locale.messages import register_all
    from vulnscan.i18n import set_language

    register_all()
    set_language("zh")


class TestHeaderScanner:
    """HeaderScanner 安全头检查测试。"""

    def test_header_scanner_missing_headers(self):
        """缺少安全头时应检测到漏洞。"""
        from vulnscan.scanners.builtin.header_scanner import HeaderScanner

        mock_resp = MagicMock()
        mock_resp.headers = {}  # 所有安全头缺失

        with patch("vulnscan.scanners.builtin.header_scanner.requests.get", return_value=mock_resp):
            scanner = HeaderScanner()
            result = scanner.run("https://example.com")

        assert result.success is True
        assert len(result.vulnerabilities) > 0

        vuln_names = [v.name for v in result.vulnerabilities]
        # 至少应检测到 X-Frame-Options 和 Content-Security-Policy 缺失
        assert any("X-Frame-Options" in name for name in vuln_names)
        assert any("Content-Security-Policy" in name for name in vuln_names)

    def test_header_scanner_all_present(self):
        """所有安全头都存在且配置正确时不应报告漏洞。"""
        from vulnscan.scanners.builtin.header_scanner import HeaderScanner

        mock_resp = MagicMock()
        mock_resp.headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-XSS-Protection": "0",
            "Cache-Control": "no-store",
            "Content-Type": "text/html",
        }

        with patch("vulnscan.scanners.builtin.header_scanner.requests.get", return_value=mock_resp):
            scanner = HeaderScanner()
            result = scanner.run("https://example.com")

        assert result.success is True
        # X-XSS-Protection="0" 会产生 INFO 提示(已废弃但配置正确)，不算严重问题
        serious = [v for v in result.vulnerabilities if v.severity.value not in ("info",)]
        assert len(serious) == 0

    def test_header_scanner_cors_wildcard(self):
        """Access-Control-Allow-Origin 为 * 时应报告过于宽松的 CORS。"""
        from vulnscan.scanners.builtin.header_scanner import HeaderScanner

        mock_resp = MagicMock()
        mock_resp.headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Access-Control-Allow-Origin": "*",
        }

        with patch("vulnscan.scanners.builtin.header_scanner.requests.get", return_value=mock_resp):
            scanner = HeaderScanner()
            result = scanner.run("https://example.com")

        assert result.success is True
        cors_vulns = [v for v in result.vulnerabilities if "CORS" in v.name]
        assert len(cors_vulns) == 1

    def test_header_scanner_request_error(self):
        """请求异常时应返回 success=False。"""
        import requests as req_lib
        from vulnscan.scanners.builtin.header_scanner import HeaderScanner

        with patch(
            "vulnscan.scanners.builtin.header_scanner.requests.get",
            side_effect=req_lib.ConnectionError("Connection refused"),
        ):
            scanner = HeaderScanner()
            result = scanner.run("https://example.com")

        assert result.success is False
        assert "请求失败" in result.error_message


class TestSSLScanner:
    """SSLScanner 证书检查测试。"""

    def test_ssl_scanner_expired_cert(self):
        """过期证书应被检测到。"""
        from vulnscan.scanners.builtin.ssl_scanner import SSLScanner

        expired_cert = {
            "subject": "CN=example.com",
            "issuer": "CN=Let's Encrypt Authority",
            "not_after": datetime(2020, 1, 1, tzinfo=timezone.utc),
        }

        scanner = SSLScanner()
        with patch.object(scanner, "_get_certificate", return_value=expired_cert):
            with patch.object(scanner, "_legacy_protocols", return_value=[]):
                result = scanner.run("https://example.com")

        assert result.success is True
        expired_vulns = [v for v in result.vulnerabilities if "过期" in v.name]
        assert len(expired_vulns) >= 1
        assert expired_vulns[0].severity == Severity.HIGH

    def test_ssl_scanner_self_signed(self):
        """自签名证书应被检测到。"""
        from vulnscan.scanners.builtin.ssl_scanner import SSLScanner

        # 设置一个未来的日期，避免触发过期检测
        from datetime import timedelta

        future = datetime.now(timezone.utc) + timedelta(days=365)

        self_signed_cert = {
            "subject": "CN=example.com",
            "issuer": "CN=example.com",  # issuer == subject -> 自签名
            "not_after": future,
        }

        scanner = SSLScanner()
        with patch.object(scanner, "_get_certificate", return_value=self_signed_cert):
            with patch.object(scanner, "_legacy_protocols", return_value=[]):
                result = scanner.run("https://example.com")

        assert result.success is True
        self_signed_vulns = [v for v in result.vulnerabilities if "自签名" in v.name]
        assert len(self_signed_vulns) == 1
        assert self_signed_vulns[0].severity == Severity.MEDIUM

    def test_ssl_scanner_connection_failure(self):
        """SSL 连接失败时应返回 success=False。"""
        from vulnscan.scanners.builtin.ssl_scanner import SSLScanner

        scanner = SSLScanner()
        with patch.object(
            scanner, "_get_certificate", side_effect=ConnectionError("timeout")
        ):
            result = scanner.run("https://example.com")

        assert result.success is False
        assert "SSL 连接失败" in result.error_message


class TestInfoLeakScanner:
    """InfoLeakScanner 信息泄露检查测试。"""

    def test_info_leak_scanner_server_header(self):
        """Server 头包含版本号时应检测到。"""
        from vulnscan.scanners.builtin.info_leak_scanner import InfoLeakScanner

        mock_resp = MagicMock()
        mock_resp.headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        mock_resp.text = "<html></html>"
        mock_resp.status_code = 200

        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp

        with patch("vulnscan.scanners.builtin.info_leak_scanner.requests.Session", return_value=mock_session):
            scanner = InfoLeakScanner()
            result = scanner.run("https://example.com")

        assert result.success is True
        server_vulns = [v for v in result.vulnerabilities if "Server" in v.name and "版本" in v.name]
        assert len(server_vulns) >= 1

    def test_info_leak_scanner_no_leaks(self):
        """无信息泄露时不应报告漏洞（Server 头无版本号，无敏感注释等）。"""
        from vulnscan.scanners.builtin.info_leak_scanner import InfoLeakScanner

        # 主请求响应
        mock_main_resp = MagicMock()
        mock_main_resp.headers = {"Server": "CustomServer"}
        mock_main_resp.text = "<html><body>Clean page</body></html>"
        mock_main_resp.status_code = 200

        # 404 响应
        mock_404_resp = MagicMock()
        mock_404_resp.text = "<html>Not Found</html>"
        mock_404_resp.status_code = 404

        # robots.txt 响应
        mock_robots_resp = MagicMock()
        mock_robots_resp.text = "User-agent: *\nDisallow: /"
        mock_robots_resp.status_code = 200

        mock_session = MagicMock()

        def session_get(url, **kwargs):
            if "nonexistent" in url:
                return mock_404_resp
            if "robots.txt" in url:
                return mock_robots_resp
            return mock_main_resp

        mock_session.get.side_effect = session_get

        with patch("vulnscan.scanners.builtin.info_leak_scanner.requests.Session", return_value=mock_session):
            scanner = InfoLeakScanner()
            result = scanner.run("https://example.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 0


class TestDirectoryScanner:
    """DirectoryScanner 敏感路径检测测试。"""

    def test_directory_scanner_exposed_git(self):
        """/.git/HEAD 返回 200 时应检测到 Git 仓库暴露。"""
        from vulnscan.scanners.builtin.directory_scanner import DirectoryScanner

        # mock _load_sensitive_paths 返回仅包含 /.git/HEAD 的列表
        mock_paths = [("/.git/HEAD", Severity.HIGH, "Git repository exposed")]

        mock_head_resp = MagicMock()
        mock_head_resp.status_code = 200

        mock_get_resp = MagicMock()
        mock_get_resp.text = "ref: refs/heads/main"

        with patch(
            "vulnscan.scanners.builtin.directory_scanner._load_sensitive_paths",
            return_value=mock_paths,
        ):
            with patch(
                "vulnscan.scanners.builtin.directory_scanner.requests.head",
                return_value=mock_head_resp,
            ):
                with patch(
                    "vulnscan.scanners.builtin.directory_scanner.requests.get",
                    return_value=mock_get_resp,
                ):
                    scanner = DirectoryScanner()
                    result = scanner.run("https://example.com")

        assert result.success is True
        git_vulns = [v for v in result.vulnerabilities if ".git" in v.name.lower() or "git" in v.evidence.lower()]
        assert len(git_vulns) >= 1

    def test_directory_scanner_no_exposure(self):
        """所有敏感路径返回 404 时不应报告漏洞。"""
        from vulnscan.scanners.builtin.directory_scanner import DirectoryScanner

        mock_paths = [
            ("/.git/HEAD", Severity.HIGH, "Git repository exposed"),
            ("/.env", Severity.CRITICAL, "Environment file exposed"),
        ]

        mock_head_resp = MagicMock()
        mock_head_resp.status_code = 404

        with patch(
            "vulnscan.scanners.builtin.directory_scanner._load_sensitive_paths",
            return_value=mock_paths,
        ):
            with patch(
                "vulnscan.scanners.builtin.directory_scanner.requests.head",
                return_value=mock_head_resp,
            ):
                scanner = DirectoryScanner()
                result = scanner.run("https://example.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 0


class TestPortScanner:
    """PortScanner 端口扫描测试。"""

    def test_port_scanner_open_port(self):
        """connect_ex 返回 0 表示端口开放。"""
        from vulnscan.scanners.builtin.port_scanner import PortScanner

        mock_ports = {80: {"service": "HTTP", "risk": "medium", "note": "Web server"}}

        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 0
        mock_socket.recv.return_value = b"HTTP/1.1 200 OK"

        with patch(
            "vulnscan.scanners.builtin.port_scanner._load_common_ports",
            return_value=mock_ports,
        ):
            with patch(
                "vulnscan.scanners.builtin.port_scanner.socket.socket",
                return_value=mock_socket,
            ):
                scanner = PortScanner()
                result = scanner.run("http://example.com")

        assert result.success is True
        assert len(result.vulnerabilities) >= 1
        assert any("80" in v.name for v in result.vulnerabilities)

    def test_port_scanner_closed_port(self):
        """connect_ex 返回非 0 表示端口关闭。"""
        from vulnscan.scanners.builtin.port_scanner import PortScanner

        mock_ports = {80: {"service": "HTTP", "risk": "medium", "note": ""}}

        mock_socket = MagicMock()
        mock_socket.connect_ex.return_value = 1  # 端口关闭

        with patch(
            "vulnscan.scanners.builtin.port_scanner._load_common_ports",
            return_value=mock_ports,
        ):
            with patch(
                "vulnscan.scanners.builtin.port_scanner.socket.socket",
                return_value=mock_socket,
            ):
                scanner = PortScanner()
                result = scanner.run("http://example.com")

        assert result.success is True
        assert len(result.vulnerabilities) == 0


class TestFileAnalyzer:
    """FileAnalyzer 源码扫描测试。"""

    def test_file_analyzer_hardcoded_secret(self, tmp_path):
        """包含硬编码密码的文件应被检测到。"""
        from vulnscan.scanners.builtin.file_analyzer import FileAnalyzer

        vuln_file = tmp_path / "config.py"
        vuln_file.write_text(
            'password = "mysecret123"\ndb_host = "localhost"\n',
            encoding="utf-8",
        )

        scanner = FileAnalyzer()
        result = scanner.run(str(tmp_path))

        assert result.success is True
        assert len(result.vulnerabilities) >= 1

        secret_vulns = [
            v for v in result.vulnerabilities
            if "secret" in v.name.lower() or "hardcoded" in v.description.lower()
        ]
        assert len(secret_vulns) >= 1

    def test_file_analyzer_clean_code(self, tmp_path):
        """无漏洞模式的代码不应触发报告。"""
        from vulnscan.scanners.builtin.file_analyzer import FileAnalyzer

        clean_file = tmp_path / "clean.py"
        clean_file.write_text(
            "import os\n\ndef hello():\n    return 'world'\n",
            encoding="utf-8",
        )

        scanner = FileAnalyzer()
        result = scanner.run(str(tmp_path))

        assert result.success is True
        assert len(result.vulnerabilities) == 0

    def test_file_analyzer_empty_directory(self, tmp_path):
        """空目录扫描不应崩溃。"""
        from vulnscan.scanners.builtin.file_analyzer import FileAnalyzer

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        scanner = FileAnalyzer()
        result = scanner.run(str(empty_dir))

        assert result.success is True
        assert len(result.vulnerabilities) == 0


class TestDependencyScanner:
    """DependencyScanner 依赖扫描测试。"""

    def test_dependency_scanner_no_deps(self, tmp_path):
        """空目录（无依赖文件）应返回 success=True, vulnerabilities=[]。"""
        from vulnscan.scanners.builtin.dependency_scanner import DependencyScanner

        scanner = DependencyScanner()
        result = scanner.run(str(tmp_path))

        assert result.success is True
        assert result.vulnerabilities == []

    def test_dependency_scanner_with_requirements(self, tmp_path):
        """有 requirements.txt 时应查询 OSV API (mock)。"""
        from vulnscan.scanners.builtin.dependency_scanner import DependencyScanner

        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.0.0\nrequests==2.25.0\n", encoding="utf-8")

        # mock OSV API 返回空结果
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulns": []}
        mock_resp.raise_for_status = MagicMock()

        with patch(
            "vulnscan.scanners.builtin.dependency_scanner.requests.post",
            return_value=mock_resp,
        ):
            scanner = DependencyScanner()
            result = scanner.run(str(tmp_path))

        assert result.success is True
        # OSV 返回空，所以无漏洞
        assert len(result.vulnerabilities) == 0
