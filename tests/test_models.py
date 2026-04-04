# -*- coding: utf-8 -*-
"""vulnscan.models 数据模型单元测试。"""

from __future__ import annotations

import json
import time

from vulnscan.models import (
    HttpOptions,
    ScanReport,
    ScanResult,
    ScanType,
    Severity,
    Vulnerability,
)


class TestHttpOptions:
    """HttpOptions 数据类测试。"""

    def test_has_custom_options_default(self):
        """默认情况下没有自定义选项，应返回 False。"""
        opts = HttpOptions()
        assert opts.has_custom_options() is False

    def test_has_custom_options_with_headers(self):
        """设置了 headers 时应返回 True。"""
        opts = HttpOptions(headers={"Authorization": "Bearer token"})
        assert opts.has_custom_options() is True

    def test_has_custom_options_with_cookies(self):
        """设置了 cookies 时应返回 True。"""
        opts = HttpOptions(cookies="session=abc123")
        assert opts.has_custom_options() is True

    def test_has_custom_options_with_data(self):
        """设置了 data 时应返回 True。"""
        opts = HttpOptions(data="key=value")
        assert opts.has_custom_options() is True

    def test_has_custom_options_with_method(self):
        """设置了非 GET 的 method 时应返回 True。"""
        opts = HttpOptions(method="POST")
        assert opts.has_custom_options() is True

    def test_has_custom_options_method_get(self):
        """method 为 GET 时（默认值），仅此项不算自定义选项。"""
        opts = HttpOptions(method="GET")
        assert opts.has_custom_options() is False

    def test_has_custom_options_multiple(self):
        """同时设置多个选项时应返回 True。"""
        opts = HttpOptions(
            headers={"X-Custom": "val"},
            cookies="c=1",
            data="body",
            method="PUT",
        )
        assert opts.has_custom_options() is True


class TestSeverity:
    """Severity 枚举测试。"""

    def test_severity_sort_key(self):
        """验证 sort_key 数值按严重程度从高到低递增。"""
        assert Severity.CRITICAL.sort_key < Severity.HIGH.sort_key
        assert Severity.HIGH.sort_key < Severity.MEDIUM.sort_key
        assert Severity.MEDIUM.sort_key < Severity.LOW.sort_key
        assert Severity.LOW.sort_key < Severity.INFO.sort_key

    def test_severity_sort_key_values(self):
        """验证 sort_key 具体值。"""
        assert Severity.CRITICAL.sort_key == 0
        assert Severity.HIGH.sort_key == 1
        assert Severity.MEDIUM.sort_key == 2
        assert Severity.LOW.sort_key == 3
        assert Severity.INFO.sort_key == 4


class TestVulnerability:
    """Vulnerability 数据类测试。"""

    def test_vulnerability_to_dict(self, sample_vulnerability: Vulnerability):
        """验证 to_dict() 输出包含所有必要字段且类型正确。"""
        d = sample_vulnerability.to_dict()

        assert d["name"] == "测试漏洞"
        assert d["severity"] == "high"
        assert d["scan_type"] == "dast"
        assert d["description"] == "这是一条用于测试的漏洞描述"
        assert d["scanner"] == "TestScanner"
        assert d["evidence"] == "示例证据"
        assert d["remediation"] == "示例修复建议"
        assert d["cve_id"] == "CVE-0000-0000"
        assert d["cwe_id"] == "CWE-000"
        assert d["confidence"] == "high"
        assert isinstance(d["timestamp"], float)

    def test_vulnerability_default_values(self):
        """验证可选字段的默认值。"""
        v = Vulnerability(
            name="minimal",
            severity=Severity.LOW,
            description="desc",
            scanner="s",
            scan_type=ScanType.SAST,
        )
        d = v.to_dict()
        assert d["evidence"] == ""
        assert d["remediation"] == ""
        assert d["reference"] == ""
        assert d["target"] == ""
        assert d["location"] == ""
        assert d["cve_id"] == ""
        assert d["cwe_id"] == ""
        assert d["confidence"] == "medium"


class TestScanResult:
    """ScanResult 数据类测试。"""

    def test_scan_result_to_dict(self, sample_scan_result: ScanResult):
        """验证 ScanResult 序列化输出。"""
        d = sample_scan_result.to_dict()

        assert d["scanner_name"] == "TestScanner"
        assert d["scan_type"] == "dast"
        assert d["target"] == "https://example.com"
        assert d["success"] is True
        assert d["error_message"] == ""
        assert d["duration_seconds"] == 1.23
        assert d["vulnerability_count"] == 1
        assert isinstance(d["vulnerabilities"], list)
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["name"] == "测试漏洞"

    def test_scan_result_empty_vulns(self):
        """验证无漏洞时 vulnerability_count 为 0。"""
        r = ScanResult(
            scanner_name="Empty",
            scan_type=ScanType.DAST,
            target="https://example.com",
        )
        d = r.to_dict()
        assert d["vulnerability_count"] == 0
        assert d["vulnerabilities"] == []


class TestScanReport:
    """ScanReport 数据类测试。"""

    def test_scan_report_summary(self):
        """验证 summary 统计多个严重程度的漏洞计数。"""
        now = time.time()

        vulns_high = [
            Vulnerability(
                name=f"high_{i}",
                severity=Severity.HIGH,
                description="",
                scanner="S",
                scan_type=ScanType.DAST,
            )
            for i in range(3)
        ]
        vulns_medium = [
            Vulnerability(
                name="medium_0",
                severity=Severity.MEDIUM,
                description="",
                scanner="S",
                scan_type=ScanType.DAST,
            )
        ]
        vulns_critical = [
            Vulnerability(
                name="crit_0",
                severity=Severity.CRITICAL,
                description="",
                scanner="S",
                scan_type=ScanType.DAST,
            )
        ]

        result = ScanResult(
            scanner_name="S",
            scan_type=ScanType.DAST,
            target="t",
            vulnerabilities=vulns_high + vulns_medium + vulns_critical,
        )

        report = ScanReport(
            target="t", scan_mode="web", start_time=now, end_time=now + 1
        )
        report.results = [result]

        summary = report.summary
        assert summary["critical"] == 1
        assert summary["high"] == 3
        assert summary["medium"] == 1
        assert summary["low"] == 0
        assert summary["info"] == 0
        assert summary["total"] == 5

    def test_scan_report_all_vulnerabilities_sorted(self):
        """验证 all_vulnerabilities 按 severity 从高到低排序。"""
        vulns = [
            Vulnerability(name="info", severity=Severity.INFO, description="", scanner="S", scan_type=ScanType.DAST),
            Vulnerability(name="critical", severity=Severity.CRITICAL, description="", scanner="S", scan_type=ScanType.DAST),
            Vulnerability(name="low", severity=Severity.LOW, description="", scanner="S", scan_type=ScanType.DAST),
            Vulnerability(name="high", severity=Severity.HIGH, description="", scanner="S", scan_type=ScanType.DAST),
            Vulnerability(name="medium", severity=Severity.MEDIUM, description="", scanner="S", scan_type=ScanType.DAST),
        ]

        result = ScanResult(
            scanner_name="S", scan_type=ScanType.DAST, target="t",
            vulnerabilities=vulns,
        )
        report = ScanReport(target="t", scan_mode="web")
        report.results = [result]

        sorted_vulns = report.all_vulnerabilities
        severities = [v.severity for v in sorted_vulns]
        assert severities == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

    def test_scan_report_to_json(self, sample_report: ScanReport):
        """验证 to_json() 返回合法 JSON 字符串。"""
        json_str = sample_report.to_json()
        data = json.loads(json_str)

        assert data["target"] == "https://example.com"
        assert data["scan_mode"] == "web"
        assert "summary" in data
        assert "results" in data
        assert isinstance(data["results"], list)
        assert data["summary"]["total"] >= 0

    def test_scan_report_to_dict_duration(self):
        """验证 to_dict 中 duration_seconds 的计算。"""
        report = ScanReport(
            target="t",
            scan_mode="web",
            start_time=1000.0,
            end_time=1005.5,
        )
        d = report.to_dict()
        assert d["duration_seconds"] == 5.5


class TestDedupKey:
    """Vulnerability.dedup_key 去重键测试。"""

    def test_dedup_key_cve_id(self):
        """有 cve_id 时使用 cve: 前缀。"""
        v = Vulnerability(
            name="Some Vuln", severity=Severity.HIGH, description="",
            scanner="S", scan_type=ScanType.SCA, cve_id="CVE-2023-1234",
        )
        assert v.dedup_key == "cve:CVE-2023-1234"

    def test_dedup_key_cve_in_name(self):
        """name 为 CVE 格式且无 cve_id 时也使用 cve: 前缀。"""
        v = Vulnerability(
            name="CVE-2023-5678", severity=Severity.HIGH, description="",
            scanner="S", scan_type=ScanType.SCA,
        )
        assert v.dedup_key == "cve:CVE-2023-5678"

    def test_dedup_key_port(self):
        """INFRASTRUCTURE 类型使用 port: 前缀。"""
        v = Vulnerability(
            name="Open Port", severity=Severity.INFO, description="",
            scanner="S", scan_type=ScanType.INFRASTRUCTURE,
            location="example.com:80",
        )
        assert v.dedup_key == "port:example.com:80"

    def test_dedup_key_fallback(self):
        """兜底使用 name:location。"""
        v = Vulnerability(
            name="Missing Header", severity=Severity.MEDIUM, description="",
            scanner="S", scan_type=ScanType.DAST, location="https://example.com",
        )
        assert v.dedup_key == "Missing Header:https://example.com"


class TestDeduplication:
    """ScanReport.deduplicated_vulnerabilities 去重测试。"""

    def test_dedup_same_cve_different_scanners(self):
        """同一 CVE 被两个扫描器报告应合并为一条。"""
        v1 = Vulnerability(
            name="CVE-2023-1234", severity=Severity.HIGH, description="desc1",
            scanner="Trivy", scan_type=ScanType.SCA, cve_id="CVE-2023-1234",
        )
        v2 = Vulnerability(
            name="CVE-2023-1234", severity=Severity.MEDIUM, description="desc2",
            scanner="Grype", scan_type=ScanType.SCA, cve_id="CVE-2023-1234",
            reference="https://nvd.nist.gov/...",
        )
        r1 = ScanResult(scanner_name="Trivy", scan_type=ScanType.SCA,
                         target=".", vulnerabilities=[v1])
        r2 = ScanResult(scanner_name="Grype", scan_type=ScanType.SCA,
                         target=".", vulnerabilities=[v2])

        report = ScanReport(target=".", scan_mode="code")
        report.results = [r1, r2]

        deduped = report.deduplicated_vulnerabilities
        assert len(deduped) == 1
        assert "Grype" in deduped[0].scanner
        assert "Trivy" in deduped[0].scanner
        # 取最高严重级别
        assert deduped[0].severity == Severity.HIGH
        # reference 从非空的那个取
        assert deduped[0].reference == "https://nvd.nist.gov/..."

    def test_dedup_same_port_different_scanners(self):
        """同一端口被 PortScanner 和 Nmap 报告应合并。"""
        v1 = Vulnerability(
            name="开放端口: 80/HTTP", severity=Severity.INFO, description="",
            scanner="PortScanner", scan_type=ScanType.INFRASTRUCTURE,
            location="example.com:80",
        )
        v2 = Vulnerability(
            name="开放端口: 80/tcp (http)", severity=Severity.INFO, description="",
            scanner="Nmap", scan_type=ScanType.INFRASTRUCTURE,
            location="example.com:80",
        )
        r1 = ScanResult(scanner_name="PortScanner", scan_type=ScanType.INFRASTRUCTURE,
                         target="example.com", vulnerabilities=[v1])
        r2 = ScanResult(scanner_name="Nmap", scan_type=ScanType.INFRASTRUCTURE,
                         target="example.com", vulnerabilities=[v2])

        report = ScanReport(target="example.com", scan_mode="web")
        report.results = [r1, r2]

        deduped = report.deduplicated_vulnerabilities
        assert len(deduped) == 1
        assert "Nmap" in deduped[0].scanner
        assert "PortScanner" in deduped[0].scanner

    def test_dedup_no_duplicates(self):
        """无重复时不合并。"""
        v1 = Vulnerability(
            name="Missing CSP", severity=Severity.MEDIUM, description="",
            scanner="HeaderScanner", scan_type=ScanType.DAST,
            location="https://example.com",
        )
        v2 = Vulnerability(
            name="Missing HSTS", severity=Severity.MEDIUM, description="",
            scanner="HeaderScanner", scan_type=ScanType.DAST,
            location="https://example.com",
        )
        r = ScanResult(scanner_name="HeaderScanner", scan_type=ScanType.DAST,
                        target="https://example.com", vulnerabilities=[v1, v2])

        report = ScanReport(target="https://example.com", scan_mode="web")
        report.results = [r]

        deduped = report.deduplicated_vulnerabilities
        assert len(deduped) == 2

    def test_summary_uses_dedup(self):
        """summary 应基于去重结果计数。"""
        v1 = Vulnerability(
            name="CVE-2023-1", severity=Severity.HIGH, description="",
            scanner="A", scan_type=ScanType.SCA, cve_id="CVE-2023-1",
        )
        v2 = Vulnerability(
            name="CVE-2023-1", severity=Severity.MEDIUM, description="",
            scanner="B", scan_type=ScanType.SCA, cve_id="CVE-2023-1",
        )
        r1 = ScanResult(scanner_name="A", scan_type=ScanType.SCA,
                         target=".", vulnerabilities=[v1])
        r2 = ScanResult(scanner_name="B", scan_type=ScanType.SCA,
                         target=".", vulnerabilities=[v2])

        report = ScanReport(target=".", scan_mode="code")
        report.results = [r1, r2]

        # all_vulnerabilities 有 2 条，但 summary 基于去重后只有 1 条
        assert len(report.all_vulnerabilities) == 2
        assert report.summary["total"] == 1
        assert report.summary["high"] == 1
