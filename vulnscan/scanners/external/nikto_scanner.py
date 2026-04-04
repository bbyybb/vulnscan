"""Nikto Web 服务器漏洞扫描器"""

from __future__ import annotations

import json
import re
import shutil
import time
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner, _PLATFORM


class NiktoScanner(ExternalScanner):
    """Nikto - Web server vulnerability scanner"""

    name = "Nikto"
    description = "Web server vulnerability scanner"
    executable = "nikto"
    target_mode = "url"
    scan_type = ScanType.DAST

    # ---- 可用性检测 ----

    def is_available(self) -> tuple[bool, str]:
        """优先检查 nikto，不行则检查 nikto.pl"""
        path = shutil.which("nikto")
        if path:
            self.executable = "nikto"
            return True, f"found at {path}"
        path = shutil.which("nikto.pl")
        if path:
            self.executable = "nikto.pl"
            return True, f"found at {path}"
        return False, f"'nikto' not found in PATH. {self.get_install_hint()}"

    def get_install_hint(self) -> str:
        if _PLATFORM == "Windows":
            return (
                "Download from https://github.com/sullo/nikto "
                "or install via Chocolatey: choco install nikto"
            )
        elif _PLATFORM == "Darwin":
            return "brew install nikto"
        else:
            return "sudo apt install nikto  OR  sudo yum install nikto"

    def get_install_url(self) -> str:
        return "https://github.com/sullo/nikto"

    # ---- 扫描 ----

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        if callback:
            callback(f"[Nikto] 正在扫描 {target} ...")

        # Windows 上 -output /dev/stdout 不可用，用 -output -
        output_arg = "-" if _PLATFORM == "Windows" else "/dev/stdout"

        cmd = [
            self.executable,
            "-h", target,
            "-Format", "json",
            "-output", output_arg,
            "-Tuning", "123456789abcd",
            "-C", "all",
            "-maxtime", "600s",
            "-nointeractive",
        ]

        if http_options:
            if http_options.cookies:
                # Nikto 没有直接的 cookie 参数，通过设置 User-Agent 头传递不合适
                # 仅在有 User-Agent header 时使用 -useragent
                pass
            ua = http_options.headers.get("User-Agent")
            if ua:
                cmd.extend(["-useragent", ua])

        try:
            result = self._run_command(
                cmd,
                timeout=660,
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
            callback("[Nikto] 命令执行完成，正在解析结果 ...")

        raw_output = result.stdout or ""

        try:
            vulns = self._parse_json(raw_output, target)
        except Exception:
            # JSON 解析失败，回退到文本解析
            vulns = self._parse_text(raw_output, target)

        if callback:
            callback(f"[Nikto] 扫描完成，发现 {len(vulns)} 个漏洞")

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

    def _parse_json(self, output: str, target: str) -> list[Vulnerability]:
        """解析 Nikto JSON 输出。"""
        vulns: list[Vulnerability] = []

        # Nikto 的 JSON 输出可能被其他文本包围，尝试提取 JSON 部分
        json_text = output.strip()
        # 尝试找到 JSON 对象
        brace_start = json_text.find("{")
        if brace_start == -1:
            raise ValueError("No JSON object found")
        json_text = json_text[brace_start:]

        data = json.loads(json_text)

        # Nikto JSON 格式: 顶层可能是对象或数组
        vuln_list = []
        if isinstance(data, dict):
            vuln_list = data.get("vulnerabilities", [])
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    vuln_list.extend(item.get("vulnerabilities", []))

        for item in vuln_list:
            osvdb = item.get("OSVDB", "0")
            method = item.get("method", "GET")
            url = item.get("url", "")
            msg = item.get("msg", "")
            vuln_id = item.get("id", "")

            # 有 OSVDB 编号的报 MEDIUM，无编号的报 LOW
            has_osvdb = osvdb and osvdb != "0"
            severity = Severity.MEDIUM if has_osvdb else Severity.LOW

            evidence = f"{method} {url}"
            reference = f"OSVDB-{osvdb}" if has_osvdb else ""

            vulns.append(
                Vulnerability(
                    name=msg or f"Nikto Finding #{vuln_id}",
                    severity=severity,
                    description=msg,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=evidence,
                    reference=reference,
                    target=target,
                    location=url,
                )
            )

        return vulns

    def _parse_text(self, output: str, target: str) -> list[Vulnerability]:
        """回退: 按行解析 Nikto 文本输出（以 + 开头的行）。"""
        vulns: list[Vulnerability] = []

        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("+"):
                continue

            # 去掉前导 "+"
            content = line.lstrip("+ ").strip()
            if not content:
                continue

            # 尝试提取 OSVDB 编号
            osvdb_match = re.search(r"OSVDB-(\d+)", content)
            has_osvdb = bool(osvdb_match)
            severity = Severity.MEDIUM if has_osvdb else Severity.LOW
            reference = osvdb_match.group(0) if osvdb_match else ""

            vulns.append(
                Vulnerability(
                    name=content[:120],
                    severity=severity,
                    description=content,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    reference=reference,
                    target=target,
                )
            )

        return vulns
