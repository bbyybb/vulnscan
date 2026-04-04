"""Semgrep 多语言静态代码分析扫描器"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner, _PLATFORM

_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


class SemgrepScanner(ExternalScanner):
    """Semgrep - Multi-language static analysis (SAST)"""

    name = "Semgrep"
    description = "Multi-language static analysis (SAST)"
    executable = "semgrep"
    target_mode = "file"
    scan_type = ScanType.SAST

    def get_install_hint(self) -> str:
        if _PLATFORM == "Darwin":
            return "brew install semgrep  OR  pip install semgrep"
        return "pip install semgrep"

    def get_install_url(self) -> str:
        return "https://github.com/semgrep/semgrep"

    # ---- 扫描 ----

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[Semgrep] 正在扫描 {target} ...")

        try:
            result = self._run_command(
                [
                    self.executable, "scan",
                    "--config", "auto",
                    "--config", "p/security-audit",
                    "--config", "p/secrets",
                    "--config", "p/owasp-top-ten",
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    "--timeout", "30",
                    "--max-target-bytes", "1000000",
                    target,
                ],
                timeout=600,
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
            callback("[Semgrep] 命令执行完成，正在解析结果 ...")

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
            callback(f"[Semgrep] 扫描完成，发现 {len(vulns)} 个漏洞")

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
        """解析 Semgrep JSON 输出。"""
        vulns: list[Vulnerability] = []

        data = json.loads(output) if output.strip() else {}
        results_list = data.get("results", [])

        for item in results_list:
            check_id = item.get("check_id", "")
            path = item.get("path", "")
            start_line = item.get("start", {}).get("line", 0)
            end_line = item.get("end", {}).get("line", 0)

            extra = item.get("extra", {})
            message = extra.get("message", "")
            raw_severity = extra.get("severity", "INFO").upper()
            severity = _SEVERITY_MAP.get(raw_severity, Severity.LOW)

            metadata = extra.get("metadata", {})
            matched_lines = extra.get("lines", "")

            # CWE 列表
            cwe_list = metadata.get("cwe", [])
            if isinstance(cwe_list, str):
                cwe_list = [cwe_list]
            cwe_id = cwe_list[0] if cwe_list else ""

            # OWASP 列表
            owasp_list = metadata.get("owasp", [])
            if isinstance(owasp_list, str):
                owasp_list = [owasp_list]

            # 位置信息
            location = f"{path}:{start_line}"
            if end_line and end_line != start_line:
                location = f"{path}:{start_line}-{end_line}"

            # 参考链接
            references = []
            if cwe_list:
                references.append(f"CWE: {', '.join(str(c) for c in cwe_list)}")
            if owasp_list:
                references.append(f"OWASP: {', '.join(str(o) for o in owasp_list)}")
            reference = "; ".join(references)

            vulns.append(
                Vulnerability(
                    name=check_id,
                    severity=severity,
                    description=message,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=matched_lines[:500] if matched_lines else "",
                    reference=reference,
                    target=target,
                    location=location,
                    cwe_id=cwe_id,
                )
            )

        return vulns
