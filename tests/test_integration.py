# -*- coding: utf-8 -*-
"""集成测试。

使用 pytest.mark.integration 标记，可通过以下方式选择性运行:
    pytest -m integration          # 只运行集成测试
    pytest -m "not integration"    # 跳过集成测试
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from vulnscan.engine import ScanEngine
from vulnscan.models import (
    ScanReport,
    ScanResult,
    ScanType,
    Severity,
    Vulnerability,
)
from vulnscan.report import ReportGenerator

# 标记所有本模块的测试为 integration
pytestmark = pytest.mark.integration


class TestFullWebScanMock:
    """模拟完整 Web 扫描流程集成测试。"""

    def test_full_web_scan_mock(self, tmp_path):
        """mock 所有 HTTP 请求，从 engine.scan 到 report 生成的完整流程。"""
        from vulnscan.scanners.base import Scanner

        # 创建一个简易的 mock 扫描器类
        class MockWebScanner(Scanner):
            name = "MockWebScanner"
            is_builtin = True
            target_mode = "url"
            scan_type = ScanType.DAST

            def run(self, target, callback=None, http_options=None):
                return ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    target=target,
                    success=True,
                    vulnerabilities=[
                        Vulnerability(
                            name="Mock Vuln",
                            severity=Severity.MEDIUM,
                            description="A mock vulnerability",
                            scanner=self.name,
                            scan_type=self.scan_type,
                            target=target,
                        )
                    ],
                    duration_seconds=0.1,
                )

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[MockWebScanner],
        ):
            engine = ScanEngine(max_workers=2)
            report = engine.scan("https://example.com", mode="web")

        # 验证报告
        assert isinstance(report, ScanReport)
        assert report.target == "https://example.com"
        assert len(report.results) == 1
        assert report.results[0].success is True
        assert report.summary["total"] >= 1

        # 生成 JSON 报告
        gen = ReportGenerator(output_dir=str(tmp_path))
        json_path = gen.generate_json(report, filename="integration_test.json")
        assert os.path.exists(json_path)

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["target"] == "https://example.com"
        assert data["summary"]["total"] >= 1

        # 生成 HTML 报告
        html_path = gen.generate_html(report, filename="integration_test.html")
        assert os.path.exists(html_path)

        with open(html_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        assert "<html" in html_content.lower()


class TestFullCodeScan:
    """代码扫描集成测试。"""

    def test_full_code_scan(self, tmp_path):
        """创建含已知漏洞的临时文件，运行 code 扫描，验证检测到漏洞。"""
        # 创建包含硬编码密码的文件
        vuln_file = tmp_path / "vulnerable.py"
        vuln_file.write_text(
            'api_key = "sk-1234567890abcdef1234567890abcdef"\n'
            'password = "supersecretpassword"\n'
            'database_url = "postgresql://user:pass@localhost/db"\n',
            encoding="utf-8",
        )

        # 创建一个干净的文件
        clean_file = tmp_path / "clean.py"
        clean_file.write_text(
            "import os\n\ndef hello():\n    return 'world'\n",
            encoding="utf-8",
        )

        # 只用内置代码扫描器（FileAnalyzer），跳过外部工具
        engine = ScanEngine(max_workers=2)
        report = engine.scan(
            str(tmp_path),
            mode="code",
            scanner_names=["FileAnalyzer"],
            skip_unavailable=True,
        )

        assert isinstance(report, ScanReport)
        assert report.scan_mode == "code"

        # FileAnalyzer 应该检测到硬编码密码
        all_vulns = report.all_vulnerabilities
        assert len(all_vulns) >= 1

        # 验证发现的漏洞涉及 hardcoded_secret
        vuln_names = [v.name for v in all_vulns]
        assert any("hardcoded_secret" in name.lower() or "secret" in name.lower() for name in vuln_names)


class TestCLIIntegration:
    """CLI 命令行集成测试。"""

    def test_cli_status(self):
        """运行 'python main.py status' 验证退出码为 0。"""
        result = subprocess.run(
            [sys.executable, "main.py", "status"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
            encoding="utf-8",
            errors="replace",
        )
        assert result.returncode == 0, (
            f"CLI status 命令返回非零退出码: {result.returncode}\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    def test_cli_help(self):
        """运行 'python main.py --help' 验证退出码为 0。"""
        result = subprocess.run(
            [sys.executable, "main.py", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
            encoding="utf-8",
            errors="replace",
        )
        assert result.returncode == 0
        assert "vulnscan" in result.stdout.lower() or "usage" in result.stdout.lower()

    def test_cli_web_scan(self, tmp_path):
        """运行 web 扫描 CLI 命令（使用 mock），验证报告文件生成。

        注意: 此测试通过环境变量控制 mock，如果无法 mock 则跳过。
        由于 CLI 是通过 subprocess 执行的，直接 mock 比较困难，
        这里改用 code 扫描 + 临时目录来验证 CLI 的端到端流程。
        """
        # 创建一个含漏洞的临时文件
        vuln_file = tmp_path / "test_vuln.py"
        vuln_file.write_text(
            'secret_key = "abcdefghijklmnop"\n',
            encoding="utf-8",
        )

        output_dir = tmp_path / "reports"
        output_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable, "main.py", "code",
                str(tmp_path),
                "-o", str(output_dir),
                "--scanners", "FileAnalyzer",
                "--format", "json",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
            encoding="utf-8",
            errors="replace",
        )

        assert result.returncode == 0, (
            f"CLI code 命令返回非零退出码: {result.returncode}\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

        # 验证报告文件被生成
        json_files = [f for f in os.listdir(str(output_dir)) if f.endswith(".json")]
        assert len(json_files) >= 1, (
            f"期望在 {output_dir} 中找到 JSON 报告文件，但只找到: {os.listdir(str(output_dir))}"
        )

        # 验证报告内容可解析
        report_path = os.path.join(str(output_dir), json_files[0])
        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert "target" in data
        assert "results" in data
