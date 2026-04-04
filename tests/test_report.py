# -*- coding: utf-8 -*-
"""vulnscan.report 报告生成器测试。"""

from __future__ import annotations

import json
import os

from vulnscan.models import ScanReport, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.report import ReportGenerator


class TestReportGenerator:
    """ReportGenerator 测试。"""

    def _make_report(self) -> ScanReport:
        """创建用于测试的 ScanReport。"""
        vuln = Vulnerability(
            name="TestVuln",
            severity=Severity.MEDIUM,
            description="A test vulnerability",
            scanner="TestScanner",
            scan_type=ScanType.DAST,
            evidence="test evidence",
            target="https://example.com",
        )
        result = ScanResult(
            scanner_name="TestScanner",
            scan_type=ScanType.DAST,
            target="https://example.com",
            success=True,
            vulnerabilities=[vuln],
            duration_seconds=2.5,
        )
        report = ScanReport(
            target="https://example.com",
            scan_mode="web",
            start_time=1700000000.0,
            end_time=1700000005.0,
        )
        report.results = [result]
        return report

    def test_generate_json(self, tmp_path):
        """生成 JSON 报告，验证文件存在且可解析。"""
        report = self._make_report()
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_json(report, filename="test_report.json")

        assert os.path.exists(path)
        assert path.endswith(".json")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["target"] == "https://example.com"
        assert data["scan_mode"] == "web"
        assert "summary" in data
        assert "results" in data
        assert len(data["results"]) == 1

    def test_generate_html(self, tmp_path):
        """生成 HTML 报告，验证文件存在且包含关键 HTML 标签。"""
        report = self._make_report()
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_html(report, filename="test_report.html")

        assert os.path.exists(path)
        assert path.endswith(".html")

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "<html" in content.lower()
        assert "</html>" in content.lower()
        assert "example.com" in content

    def test_output_dir_created(self, tmp_path):
        """指定不存在的输出目录时应自动创建。"""
        new_dir = os.path.join(str(tmp_path), "new_output_dir", "sub")
        assert not os.path.exists(new_dir)

        gen = ReportGenerator(output_dir=new_dir)
        assert os.path.isdir(new_dir)

    def test_generate_json_default_filename(self, tmp_path):
        """不指定 filename 时应生成默认文件名。"""
        report = self._make_report()
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_json(report)

        assert os.path.exists(path)
        basename = os.path.basename(path)
        assert basename.startswith("vulnscan_report_")
        assert basename.endswith(".json")

    def test_generate_html_default_filename(self, tmp_path):
        """不指定 filename 时 HTML 也应生成默认文件名。"""
        report = self._make_report()
        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_html(report)

        assert os.path.exists(path)
        basename = os.path.basename(path)
        assert basename.startswith("vulnscan_report_")
        assert basename.endswith(".html")

    def test_json_report_utf8_content(self, tmp_path):
        """验证 JSON 报告的中文内容不被转义（ensure_ascii=False）。"""
        vuln = Vulnerability(
            name="中文漏洞名",
            severity=Severity.HIGH,
            description="这是中文描述",
            scanner="Scanner",
            scan_type=ScanType.DAST,
        )
        result = ScanResult(
            scanner_name="Scanner",
            scan_type=ScanType.DAST,
            target="https://example.com",
            vulnerabilities=[vuln],
        )
        report = ScanReport(
            target="https://example.com",
            scan_mode="web",
            start_time=1700000000.0,
            end_time=1700000001.0,
        )
        report.results = [result]

        gen = ReportGenerator(output_dir=str(tmp_path))
        path = gen.generate_json(report, filename="utf8_test.json")

        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()

        # 中文字符不应被转义为 \uXXXX
        assert "中文漏洞名" in raw
        assert "这是中文描述" in raw
