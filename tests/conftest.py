# -*- coding: utf-8 -*-
"""共享 pytest fixtures，供所有测试模块使用。"""

from __future__ import annotations

import os
import time

import pytest

from vulnscan.models import (
    ScanReport,
    ScanResult,
    ScanType,
    Severity,
    Vulnerability,
)


@pytest.fixture
def sample_vulnerability() -> Vulnerability:
    """返回一个示例 Vulnerability 实例。"""
    return Vulnerability(
        name="测试漏洞",
        severity=Severity.HIGH,
        description="这是一条用于测试的漏洞描述",
        scanner="TestScanner",
        scan_type=ScanType.DAST,
        evidence="示例证据",
        remediation="示例修复建议",
        reference="https://example.com/cve-0000",
        target="https://example.com",
        location="https://example.com/path",
        cve_id="CVE-0000-0000",
        cwe_id="CWE-000",
        confidence="high",
    )


@pytest.fixture
def sample_scan_result(sample_vulnerability: Vulnerability) -> ScanResult:
    """返回一个包含单条漏洞的示例 ScanResult 实例。"""
    return ScanResult(
        scanner_name="TestScanner",
        scan_type=ScanType.DAST,
        target="https://example.com",
        success=True,
        duration_seconds=1.23,
        vulnerabilities=[sample_vulnerability],
    )


@pytest.fixture
def sample_report(sample_scan_result: ScanResult) -> ScanReport:
    """返回一个包含单条扫描结果的示例 ScanReport 实例。"""
    report = ScanReport(
        target="https://example.com",
        scan_mode="web",
        start_time=time.time(),
    )
    report.end_time = report.start_time + 5.0
    report.results = [sample_scan_result]
    return report


@pytest.fixture
def tmp_output_dir(tmp_path) -> str:
    """返回一个临时输出目录路径（字符串）。"""
    output = os.path.join(str(tmp_path), "reports")
    # 故意不创建目录，留给被测代码自动创建
    return output
