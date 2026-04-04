"""Bandit Python 安全代码扫描器"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner

_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class BanditScanner(ExternalScanner):
    """Bandit - Python security linter (SAST)"""

    name = "Bandit"
    description = "Python security linter (SAST)"
    executable = "bandit"
    install_hint = "Install: pip install bandit"
    target_mode = "file"
    scan_type = ScanType.SAST

    def get_install_url(self) -> str:
        return "https://github.com/PyCQA/bandit"

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[Bandit] 正在扫描 {target} ...")

        try:
            result = self._run_command(
                [self.executable, "-r", target, "-f", "json", "-l", "--exit-zero"],
                timeout=300,
            )
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
            callback("[Bandit] 命令执行完成，正在解析结果 ...")

        raw_output = result.stdout or ""

        try:
            data = json.loads(raw_output) if raw_output.strip() else {}
            results = data.get("results", [])

            for item in results:
                raw_severity = item.get("issue_severity", "LOW")
                severity = _SEVERITY_MAP.get(raw_severity, Severity.LOW)

                test_name = item.get("test_name", "")
                test_id = item.get("test_id", "")
                name = f"{test_name} ({test_id})" if test_id else test_name

                filename = item.get("filename", "")
                line_number = item.get("line_number", "")
                location = f"{filename}:{line_number}" if line_number else filename

                # CWE 信息
                cwe_id = ""
                issue_cwe = item.get("issue_cwe", {})
                if isinstance(issue_cwe, dict) and issue_cwe.get("id"):
                    cwe_id = f"CWE-{issue_cwe['id']}"

                vulns.append(
                    Vulnerability(
                        name=name,
                        severity=severity,
                        description=item.get("issue_text", ""),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=item.get("code", ""),
                        target=target,
                        location=location,
                        cwe_id=cwe_id,
                        confidence=item.get("issue_confidence", "medium").lower(),
                    )
                )
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
            callback(f"[Bandit] 扫描完成，发现 {len(vulns)} 个安全问题")

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
            raw_output=raw_output,
        )
