"""SQLMap SQL 注入检测扫描器"""

from __future__ import annotations

import re
import shutil
import tempfile
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner


class SqlmapScanner(ExternalScanner):
    """SQLMap - SQL injection detection tool"""

    name = "SQLMap"
    description = "SQL injection detection tool"
    executable = "sqlmap"
    install_hint = "Install: pip install sqlmap"
    target_mode = "url"
    scan_type = ScanType.DAST

    def get_install_url(self) -> str:
        return "https://github.com/sqlmapproject/sqlmap/releases"

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()

        # 创建临时输出目录
        tmp_dir = tempfile.mkdtemp(prefix="sqlmap_")

        try:
            return self._do_scan(target, tmp_dir, callback, http_options, start)
        finally:
            self._cleanup(tmp_dir)

    def _do_scan(
        self,
        target: str,
        tmp_dir: str,
        callback: Optional[Callable[[str], None]],
        http_options: Optional[HttpOptions],
        start: float,
    ) -> ScanResult:
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[SQLMap] 正在扫描 {target} ...")

        cmd = [
            self.executable,
            "-u", target,
            "--batch",
            "--level=5",
            "--risk=3",
            "--tamper=space2comment,between,randomcase",
            "--technique=BEUSTQ",
            "--forms",
            "--crawl=3",
            "--random-agent",
            "--threads=4",
            f"--output-dir={tmp_dir}",
            "--disable-coloring",
        ]

        if http_options:
            if http_options.headers:
                # SQLMap 用换行分隔多个 header
                header_str = "\\n".join(f"{k}: {v}" for k, v in http_options.headers.items())
                cmd.extend(["--headers", header_str])
            if http_options.cookies:
                cmd.extend(["--cookie", http_options.cookies])
            if http_options.data:
                cmd.extend(["--data", http_options.data])
            if http_options.method and http_options.method.upper() != "GET":
                cmd.extend(["--method", http_options.method.upper()])

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
            callback("[SQLMap] 命令执行完成，正在解析结果 ...")

        raw_output = result.stdout or ""

        try:
            vulns = self._parse_output(raw_output, target)
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
            callback(f"[SQLMap] 扫描完成，发现 {len(vulns)} 个 SQL 注入漏洞")

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
            raw_output=raw_output,
        )

    def _parse_output(self, output: str, target: str) -> list[Vulnerability]:
        """解析 SQLMap 的 stdout 文本输出。"""
        vulns: list[Vulnerability] = []

        # 检查是否发现注入
        if not re.search(r"is vulnerable|injectable", output, re.IGNORECASE):
            return vulns

        # 按段落分割, 查找注入信息块
        current_parameter = ""
        current_type = ""
        current_payload = ""

        for line in output.splitlines():
            line = line.strip()

            # 提取参数名
            param_match = re.match(r"Parameter:\s*(.+)", line, re.IGNORECASE)
            if param_match:
                # 如果已有累积的注入信息, 先保存
                if current_parameter and current_type:
                    vulns.append(self._make_vuln(
                        target, current_parameter, current_type, current_payload
                    ))
                current_parameter = param_match.group(1).strip()
                current_type = ""
                current_payload = ""
                continue

            # 提取注入类型
            type_match = re.match(r"Type:\s*(.+)", line, re.IGNORECASE)
            if type_match:
                # 如果已有类型信息, 先保存前一个
                if current_parameter and current_type:
                    vulns.append(self._make_vuln(
                        target, current_parameter, current_type, current_payload
                    ))
                current_type = type_match.group(1).strip()
                current_payload = ""
                continue

            # 提取 Payload
            payload_match = re.match(r"Payload:\s*(.+)", line, re.IGNORECASE)
            if payload_match:
                current_payload = payload_match.group(1).strip()
                continue

        # 保存最后一个
        if current_parameter and current_type:
            vulns.append(self._make_vuln(
                target, current_parameter, current_type, current_payload
            ))

        # 如果检测到 "vulnerable/injectable" 但没解析出具体参数, 生成一个通用漏洞
        if not vulns:
            vulns.append(
                Vulnerability(
                    name="SQL Injection Detected",
                    severity=Severity.HIGH,
                    description="SQLMap 检测到目标存在 SQL 注入漏洞",
                    scanner=self.name,
                    scan_type=self.scan_type,
                    target=target,
                    location=target,
                    cwe_id="CWE-89",
                    remediation="使用参数化查询或预编译语句，避免直接拼接 SQL",
                )
            )

        return vulns

    def _make_vuln(
        self, target: str, parameter: str, injection_type: str, payload: str
    ) -> Vulnerability:
        """根据解析到的信息创建漏洞条目。"""
        evidence_parts = [f"Parameter: {parameter}", f"Type: {injection_type}"]
        if payload:
            evidence_parts.append(f"Payload: {payload}")

        return Vulnerability(
            name=f"SQL Injection - {parameter}",
            severity=Severity.HIGH,
            description=f"参数 '{parameter}' 存在 {injection_type} SQL 注入漏洞",
            scanner=self.name,
            scan_type=self.scan_type,
            evidence="\n".join(evidence_parts),
            target=target,
            location=target,
            cwe_id="CWE-89",
            remediation="使用参数化查询或预编译语句，避免直接拼接 SQL",
        )

    @staticmethod
    def _cleanup(tmp_dir: str) -> None:
        """安全删除临时目录。"""
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
