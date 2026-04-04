"""Trivy 文件系统漏洞扫描器"""

from __future__ import annotations

import json
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner, _PLATFORM

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyScanner(ExternalScanner):
    """Trivy - Filesystem vulnerability scanner (SCA)"""

    name = "Trivy"
    description = "Filesystem vulnerability scanner (SCA)"
    executable = "trivy"
    install_hint = "Download from https://github.com/aquasecurity/trivy/releases"
    target_mode = "file"
    scan_type = ScanType.SCA

    def get_install_hint(self) -> str:
        base = "https://github.com/aquasecurity/trivy/releases"
        if _PLATFORM == "Windows":
            return f"Download trivy_*_Windows-64bit.zip from {base}"
        elif _PLATFORM == "Darwin":
            return f"brew install trivy  OR  download from {base}"
        else:
            return f"sudo apt install trivy  OR  download from {base}"

    def get_install_url(self) -> str:
        return "https://github.com/aquasecurity/trivy/releases"

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[Trivy] 正在扫描 {target} ...")

        try:
            result = self._run_command(
                [
                    self.executable, "fs",
                    "--scanners", "vuln,secret,misconfig",
                    "--format", "json",
                    "--exit-code", "0",
                    "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
                    target,
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
            callback("[Trivy] 命令执行完成，正在解析结果 ...")

        raw_output = result.stdout or ""

        try:
            data = json.loads(raw_output) if raw_output.strip() else {}
            results_list = data.get("Results", [])

            for res in results_list:
                target_name = res.get("Target", "")
                vuln_list = res.get("Vulnerabilities") or []

                for vuln in vuln_list:
                    vuln_id = vuln.get("VulnerabilityID", "")
                    raw_severity = vuln.get("Severity", "UNKNOWN").upper()
                    severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)

                    # 描述: 优先 Title, 其次 Description
                    description = vuln.get("Title", "") or vuln.get("Description", "")

                    # CVE ID
                    cve_id = vuln_id if vuln_id.startswith("CVE-") else ""

                    # 证据: 包名 + 安装版本 + 修复版本
                    pkg_name = vuln.get("PkgName", "")
                    installed = vuln.get("InstalledVersion", "")
                    fixed = vuln.get("FixedVersion", "N/A")
                    evidence = f"{pkg_name} {installed} (fixed: {fixed})"

                    # 修复建议
                    remediation = ""
                    if vuln.get("FixedVersion"):
                        remediation = f"Update to version {vuln['FixedVersion']}"

                    vulns.append(
                        Vulnerability(
                            name=vuln_id,
                            severity=severity,
                            description=description,
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=evidence,
                            remediation=remediation,
                            reference=vuln.get("PrimaryURL", ""),
                            target=target,
                            location=target_name,
                            cve_id=cve_id,
                        )
                    )

                # 解析密钥泄露 (secret) 结果
                secret_list = res.get("Secrets") or []
                for secret in secret_list:
                    raw_severity = secret.get("Severity", "UNKNOWN").upper()
                    severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)
                    title = secret.get("Title", "Secret Detected")
                    match = secret.get("Match", "")

                    vulns.append(
                        Vulnerability(
                            name=f"Secret: {title}",
                            severity=severity,
                            description=f"检测到密钥泄露: {title}",
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=match[:200] if match else "",
                            target=target,
                            location=target_name,
                            remediation="移除泄露的密钥并轮换凭据",
                        )
                    )

                # 解析配置错误 (misconfig) 结果
                misconfig_list = res.get("Misconfigurations") or []
                for misconfig in misconfig_list:
                    raw_severity = misconfig.get("Severity", "UNKNOWN").upper()
                    severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)
                    title = misconfig.get("Title", "Misconfiguration")
                    message = misconfig.get("Message", "")
                    resolution = misconfig.get("Resolution", "")

                    vulns.append(
                        Vulnerability(
                            name=f"Misconfig: {title}",
                            severity=severity,
                            description=message or title,
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=message[:200] if message else "",
                            remediation=resolution,
                            target=target,
                            location=target_name,
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
            callback(f"[Trivy] 扫描完成，发现 {len(vulns)} 个漏洞")

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
            raw_output=raw_output,
        )
