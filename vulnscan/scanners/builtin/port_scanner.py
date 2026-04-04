"""基于 socket 的 TCP 端口扫描器"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner
from vulnscan.utils import normalize_url, parse_host_port

logger = logging.getLogger(__name__)

def _get_data_file():
    from vulnscan.utils import get_base_dir
    return os.path.join(get_base_dir(), 'data', 'common_ports.json')

# risk 字符串 -> Severity 枚举映射
_RISK_SEVERITY_MAP = {
    "high": Severity.MEDIUM,
    "medium": Severity.LOW,
}


def _load_common_ports() -> dict[int, dict]:
    """加载常见端口字典。

    Returns:
        {port_number: {"service": ..., "risk": ..., "note": ...}, ...}
    """
    try:
        with open(_get_data_file(), encoding="utf-8") as f:
            raw = json.load(f)
        return {int(k): v for k, v in raw.items()}
    except (OSError, json.JSONDecodeError) as exc:
        logger.error(t("scanner.port.load_error"), exc)
        return {}


class PortScanner(Scanner):
    """TCP 端口扫描并抓取 Banner"""

    name = "PortScanner"
    description = "TCP port scanner with banner grabbing"
    target_mode = "url"
    scan_type = ScanType.INFRASTRUCTURE

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        url = normalize_url(target)
        host, _ = parse_host_port(url)

        if not host:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=t("scanner.port.no_host"),
                duration_seconds=time.time() - start,
            )

        if callback:
            callback(t("scanner.port.loading", host=host))

        port_db = _load_common_ports()
        ports = list(port_db.keys())
        total = len(ports)

        if callback:
            callback(t("scanner.port.starting", host=host, total=total))

        # ------------------------------------------------------------------
        # 单端口扫描
        # ------------------------------------------------------------------
        def _scan_port(port: int) -> Optional[Vulnerability]:
            banner = ""
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.5)
                result = sock.connect_ex((host, port))
                if result != 0:
                    return None

                # 端口开放，尝试抓取 banner
                try:
                    sock.settimeout(2)
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    pass

            except OSError:
                return None
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

            # 根据端口信息判定严重程度
            info = port_db.get(port, {})
            service = info.get("service", "Unknown")
            risk = info.get("risk", "info")
            note = info.get("note", "")
            severity = _RISK_SEVERITY_MAP.get(risk, Severity.INFO)

            # 构造 evidence
            evidence_parts = [t("scanner.port.evidence_open", host=host, port=port, service=service)]
            if banner:
                evidence_parts.append(f"Banner: {banner[:200]}")
            if note:
                evidence_parts.append(t("scanner.port.evidence_note", note=note))
            evidence = " | ".join(evidence_parts)

            return Vulnerability(
                name=t("scanner.port.open_port", port=port, service=service),
                severity=severity,
                description=t("scanner.port.open_port_desc", host=host, port=port, service=service),
                scanner=self.name,
                scan_type=self.scan_type,
                evidence=evidence,
                remediation=t("scanner.port.remediation"),
                target=target,
                location=f"{host}:{port}",
                confidence="high",
            )

        # ------------------------------------------------------------------
        # 并发执行
        # ------------------------------------------------------------------
        completed = 0
        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(_scan_port, port): port for port in ports}
            for future in as_completed(futures):
                completed += 1
                if callback and completed % 10 == 0:
                    callback(t("scanner.port.progress", completed=completed, total=total))
                result = future.result()
                if result is not None:
                    vulns.append(result)

        # 按端口号排序，方便阅读
        vulns.sort(key=lambda v: int(v.location.split(":")[-1]))

        if callback:
            callback(t("scanner.port.complete", count=len(vulns)))

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
        )
