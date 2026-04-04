"""Grype 依赖漏洞扫描器 (SCA)"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner, _PLATFORM

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "negligible": Severity.INFO,
}


class GrypeScanner(ExternalScanner):
    """Grype - Dependency vulnerability scanner (SCA)"""

    name = "Grype"
    description = "Dependency vulnerability scanner (SCA)"
    executable = "grype"
    target_mode = "file"
    scan_type = ScanType.SCA

    def get_install_hint(self) -> str:
        if _PLATFORM == "Windows":
            return "Download from https://github.com/anchore/grype/releases"
        elif _PLATFORM == "Darwin":
            return "brew install grype"
        else:
            return (
                "curl -sSfL https://raw.githubusercontent.com/anchore/grype"
                "/main/install.sh | sh -s -- -b /usr/local/bin"
            )

    def get_install_url(self) -> str:
        return "https://github.com/anchore/grype/releases"

    # ---- 扫描 ----

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[Grype] 正在扫描 {target} ...")

        try:
            result = self._run_command(
                [
                    self.executable,
                    f"dir:{target}",
                    "-o", "json",
                    "--add-cpes-if-none",
                    "--by-cve",
                ],
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
            callback("[Grype] 命令执行完成，正在解析结果 ...")

        raw_output = result.stdout or ""

        try:
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
            callback(f"[Grype] 扫描完成，发现 {len(vulns)} 个漏洞")

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
        """解析 Grype JSON 输出。"""
        vulns: list[Vulnerability] = []

        data = json.loads(output) if output.strip() else {}
        matches = data.get("matches", [])

        for match in matches:
            vuln_info = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            vuln_id = vuln_info.get("id", "")
            raw_severity = vuln_info.get("severity", "Low")
            severity = _SEVERITY_MAP.get(raw_severity.lower(), Severity.INFO)
            description = vuln_info.get("description", "")

            # 修复版本
            fix_info = vuln_info.get("fix", {})
            fix_versions = fix_info.get("versions", [])

            # 包信息
            pkg_name = artifact.get("name", "")
            pkg_version = artifact.get("version", "")
            locations = artifact.get("locations", [])
            location = ""
            if locations and isinstance(locations[0], dict):
                location = locations[0].get("path", "")

            # 参考链接
            urls = vuln_info.get("urls", [])
            reference = urls[0] if urls else ""

            # CVE ID
            cve_id = vuln_id if vuln_id.startswith("CVE-") else ""

            # 证据
            evidence = f"{pkg_name} {pkg_version}"

            # 修复建议
            remediation = ""
            if fix_versions:
                remediation = f"Update to version {fix_versions[0]}"

            vulns.append(
                Vulnerability(
                    name=vuln_id,
                    severity=severity,
                    description=description or f"{pkg_name} {pkg_version} 存在已知漏洞 {vuln_id}",
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=evidence,
                    remediation=remediation,
                    reference=reference,
                    target=target,
                    location=location,
                    cve_id=cve_id,
                )
            )

        return vulns
