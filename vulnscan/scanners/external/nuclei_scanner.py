"""Nuclei 模板化漏洞扫描器"""

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
    "info": Severity.INFO,
}


class NucleiScanner(ExternalScanner):
    """Nuclei - Template-based vulnerability scanner (ProjectDiscovery)"""

    name = "Nuclei"
    description = "Template-based vulnerability scanner (ProjectDiscovery)"
    executable = "nuclei"
    install_hint = "Download from https://github.com/projectdiscovery/nuclei/releases"
    target_mode = "url"
    scan_type = ScanType.DAST

    def get_install_hint(self) -> str:
        base = "https://github.com/projectdiscovery/nuclei/releases"
        if _PLATFORM == "Windows":
            return f"Download nuclei_*_windows_amd64.zip from {base}"
        elif _PLATFORM == "Darwin":
            return f"brew install nuclei  OR  download from {base}"
        else:
            return f"Download nuclei_*_linux_amd64.zip from {base}"

    def get_install_url(self) -> str:
        return "https://github.com/projectdiscovery/nuclei/releases"

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[Nuclei] 正在扫描 {target} ...")

        cmd = [
            self.executable,
            "-u", target,
            "-jsonl",
            "-silent",
            "-severity", "info,low,medium,high,critical",
            "-nc",
            "-rl", "100",
            "-c", "25",
            "-timeout", "10",
            "-retries", "2",
        ]

        if http_options:
            for key, value in http_options.headers.items():
                cmd.extend(["-H", f"{key}: {value}"])
            if http_options.cookies:
                cmd.extend(["-H", f"Cookie: {http_options.cookies}"])

        try:
            result = self._run_command(
                cmd,
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
            callback("[Nuclei] 命令执行完成，正在解析结果 ...")

        raw_output = result.stdout or ""

        try:
            for line in raw_output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue

                info = item.get("info", {})
                raw_severity = info.get("severity", "info").lower()
                severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)

                # 参考链接: 取列表第一个
                refs = info.get("reference", [])
                reference = refs[0] if isinstance(refs, list) and refs else ""

                # 证据
                evidence = item.get("matcher-name", "")
                if not evidence:
                    extracted = item.get("extracted-results", "")
                    if isinstance(extracted, list):
                        evidence = ", ".join(str(e) for e in extracted)
                    else:
                        evidence = str(extracted) if extracted else ""

                vulns.append(
                    Vulnerability(
                        name=info.get("name", "Unknown"),
                        severity=severity,
                        description=info.get("description", ""),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=evidence,
                        reference=reference,
                        target=target,
                        location=item.get("matched-at", ""),
                    )
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
            callback(f"[Nuclei] 扫描完成，发现 {len(vulns)} 个漏洞")

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
            raw_output=raw_output,
        )
