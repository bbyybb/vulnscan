"""Nmap 端口和服务扫描器"""

from __future__ import annotations

import time
from typing import Callable, Optional
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import XMLParser

from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import ExternalScanner, _PLATFORM
from vulnscan.utils import parse_host_port

# 高危服务关键词 (数据库、远程管理、文件传输等)
_HIGH_RISK_SERVICES = {
    "mysql", "postgresql", "postgres", "mssql", "ms-sql", "oracle",
    "mongodb", "redis", "memcached", "cassandra", "couchdb",
    "telnet", "vnc", "rdp", "ms-wbt-server",
    "ftp", "tftp", "smb", "microsoft-ds", "netbios-ssn",
    "rlogin", "rexec", "rsh",
}


class NmapScanner(ExternalScanner):
    """Nmap - Network port and service scanner"""

    name = "Nmap"
    description = "Network port and service scanner"
    executable = "nmap"
    install_hint = "Download from https://nmap.org/download.html"
    target_mode = "url"
    scan_type = ScanType.INFRASTRUCTURE

    def get_install_hint(self) -> str:
        if _PLATFORM == "Windows":
            return "Download installer from https://nmap.org/download.html#windows"
        elif _PLATFORM == "Darwin":
            return "brew install nmap"
        else:
            return "sudo apt install nmap  OR  sudo yum install nmap"

    def get_install_url(self) -> str:
        if _PLATFORM == "Windows":
            return "https://nmap.org/download.html#windows"
        return "https://nmap.org/download.html"

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        # 从 URL 提取主机名
        host, _ = parse_host_port(target)
        if not host:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=f"无法从目标提取主机名: {target}",
                duration_seconds=time.time() - start,
            )

        if callback:
            callback(f"[Nmap] 正在扫描 {host} ...")

        try:
            result = self._run_command(
                [
                    self.executable,
                    "-sV", "-sC", "-A",
                    "--top-ports", "1000",
                    "--script", "vuln,default",
                    "-oX", "-", host,
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
            callback("[Nmap] 命令执行完成，正在解析 XML 结果 ...")

        raw_output = result.stdout or ""

        try:
            # 使用禁用外部实体的解析器防止 XXE 攻击
            parser = XMLParser()
            parser.feed(raw_output)
            root = parser.close()

            for port_elem in root.iter("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                portid = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = ""
                service_version = ""
                if service_elem is not None:
                    service_name = service_elem.get("name", "")
                    product = service_elem.get("product", "")
                    version = service_elem.get("version", "")
                    service_version = f"{product} {version}".strip()

                # 判断严重程度
                is_high_risk = service_name.lower() in _HIGH_RISK_SERVICES
                severity = Severity.MEDIUM if is_high_risk else Severity.INFO

                vuln_name = (
                    f"开放端口: {portid}/{protocol} ({service_name})"
                    if service_name
                    else f"开放端口: {portid}/{protocol}"
                )

                description = (
                    f"高危服务 {service_name} 开放在 {portid}/{protocol}"
                    if is_high_risk
                    else f"端口 {portid}/{protocol} 开放"
                )

                evidence = (
                    f"服务: {service_name}, 版本: {service_version}"
                    if service_version
                    else f"服务: {service_name}"
                )

                vulns.append(
                    Vulnerability(
                        name=vuln_name,
                        severity=severity,
                        description=description,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=evidence,
                        target=target,
                        location=f"{host}:{portid}",
                        remediation=(
                            f"关闭或限制对 {service_name} 服务的访问"
                            if is_high_risk
                            else ""
                        ),
                    )
                )

                # 解析端口级脚本输出
                for script_elem in port_elem.findall("script"):
                    script_id = script_elem.get("id", "")
                    script_output = script_elem.get("output", "")
                    if any(
                        kw in script_output.upper()
                        for kw in ["VULNERABLE", "CVE-", "EXPLOIT"]
                    ):
                        vulns.append(
                            Vulnerability(
                                name=f"Nmap script: {script_id}",
                                severity=Severity.HIGH,
                                description=script_output[:500],
                                scanner=self.name,
                                scan_type=self.scan_type,
                                evidence=script_output[:200],
                                target=target,
                                location=f"{host}:{portid}",
                                confidence="high",
                            )
                        )

            # 解析主机级脚本输出 (hostscript)
            for hostscript in root.findall(".//hostscript/script"):
                script_id = hostscript.get("id", "")
                script_output = hostscript.get("output", "")
                if any(
                    kw in script_output.upper()
                    for kw in ["VULNERABLE", "CVE-", "EXPLOIT"]
                ):
                    vulns.append(
                        Vulnerability(
                            name=f"Nmap hostscript: {script_id}",
                            severity=Severity.HIGH,
                            description=script_output[:500],
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=script_output[:200],
                            target=target,
                            location=host,
                            confidence="high",
                        )
                    )

            # ---- UDP 扫描 (top 100 端口) ----
            try:
                if callback:
                    callback("[Nmap] TCP 扫描完成，正在进行 UDP 扫描 (top 100) ...")

                udp_result = self._run_command(
                    [
                        self.executable,
                        "-sU", "--top-ports", "100",
                        "-sV",
                        "-oX", "-", host,
                    ],
                    timeout=300,
                )

                udp_raw = udp_result.stdout or ""
                udp_parser = XMLParser()
                udp_parser.feed(udp_raw)
                udp_root = udp_parser.close()
                raw_output += "\n<!-- UDP Scan Results -->\n" + udp_raw

                for port_elem in udp_root.iter("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    portid = port_elem.get("portid", "")
                    protocol = port_elem.get("protocol", "udp")

                    service_elem = port_elem.find("service")
                    service_name = ""
                    service_version = ""
                    if service_elem is not None:
                        service_name = service_elem.get("name", "")
                        product = service_elem.get("product", "")
                        version = service_elem.get("version", "")
                        service_version = f"{product} {version}".strip()

                    is_high_risk = service_name.lower() in _HIGH_RISK_SERVICES
                    severity = Severity.MEDIUM if is_high_risk else Severity.INFO

                    vuln_name = (
                        f"开放端口: {portid}/{protocol} ({service_name})"
                        if service_name
                        else f"开放端口: {portid}/{protocol}"
                    )

                    description = (
                        f"高危服务 {service_name} 开放在 {portid}/{protocol}"
                        if is_high_risk
                        else f"端口 {portid}/{protocol} 开放"
                    )

                    evidence = (
                        f"服务: {service_name}, 版本: {service_version}"
                        if service_version
                        else f"服务: {service_name}"
                    )

                    vulns.append(
                        Vulnerability(
                            name=vuln_name,
                            severity=severity,
                            description=description,
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=evidence,
                            target=target,
                            location=f"{host}:{portid}",
                            remediation=(
                                f"关闭或限制对 {service_name} 服务的访问"
                                if is_high_risk
                                else ""
                            ),
                        )
                    )
            except Exception:
                # UDP 扫描失败不影响 TCP 结果（可能需要 root 权限）
                if callback:
                    callback("[Nmap] UDP 扫描失败（可能需要管理员/root 权限），仅返回 TCP 结果")

        except ET.ParseError as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=f"XML 解析失败: {exc}",
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
            callback(f"[Nmap] 扫描完成，发现 {len(vulns)} 个开放端口")

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
            raw_output=raw_output,
        )
