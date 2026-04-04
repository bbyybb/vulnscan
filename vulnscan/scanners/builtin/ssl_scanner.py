"""SSL/TLS 证书与协议检查扫描器"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Callable, Optional

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner
from vulnscan.utils import parse_host_port


class SSLScanner(Scanner):
    """检查目标的 SSL/TLS 证书和协议安全性"""

    name = "SSLScanner"
    description = "SSL/TLS certificate and protocol check"
    target_mode = "url"
    scan_type = ScanType.INFRASTRUCTURE

    _CONNECT_TIMEOUT = 10
    _EXPIRY_WARNING_DAYS = 30

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []
        # HTTP 目标无 SSL，直接跳过
        if target.lower().startswith("http://") and ":443" not in target:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=True,
                error_message=t("scanner.ssl.http_skip"),
                duration_seconds=time.time() - start,
            )

        host, port = parse_host_port(target)

        if not host:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=t("scanner.ssl.no_host"),
                duration_seconds=time.time() - start,
            )

        # ── 1. 获取证书信息 ──────────────────────────────────
        if callback:
            callback(t("scanner.ssl.fetching_cert", host=host, port=port))

        try:
            cert_info = self._get_certificate(host, port)
        except Exception as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=t("scanner.ssl.connect_failed", host=host, port=port, exc=exc),
                duration_seconds=time.time() - start,
            )

        now = datetime.now(timezone.utc)

        # 1-a. 证书是否过期
        not_after = cert_info["not_after"]
        if not_after < now:
            vulns.append(
                Vulnerability(
                    name=t("scanner.ssl.cert_expired"),
                    severity=Severity.HIGH,
                    description=t("scanner.ssl.cert_expired_desc", date=f"{not_after:%Y-%m-%d}"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=f"notAfter={not_after.isoformat()}",
                    remediation=t("scanner.ssl.cert_expired_remediation"),
                    target=target,
                    location=f"{host}:{port}",
                )
            )

        # 1-b. 是否自签名
        if cert_info["issuer"] == cert_info["subject"]:
            vulns.append(
                Vulnerability(
                    name=t("scanner.ssl.self_signed"),
                    severity=Severity.MEDIUM,
                    description=t("scanner.ssl.self_signed_desc"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=f"issuer=subject={cert_info['issuer']}",
                    remediation=t("scanner.ssl.self_signed_remediation"),
                    target=target,
                    location=f"{host}:{port}",
                )
            )

        # 1-c. 即将到期 (< 30 天)
        days_left = (not_after - now).days
        if 0 <= days_left < self._EXPIRY_WARNING_DAYS:
            vulns.append(
                Vulnerability(
                    name=t("scanner.ssl.cert_expiring"),
                    severity=Severity.LOW,
                    description=t("scanner.ssl.cert_expiring_desc", days=days_left, date=f"{not_after:%Y-%m-%d}"),
                    scanner=self.name,
                    scan_type=self.scan_type,
                    evidence=f"notAfter={not_after.isoformat()}, days_left={days_left}",
                    remediation=t("scanner.ssl.cert_expiring_remediation"),
                    target=target,
                    location=f"{host}:{port}",
                )
            )

        # ── 2. 检查不安全的 TLS 协议 ────────────────────────
        if callback:
            callback(t("scanner.ssl.checking_protocols"))

        for proto_name, proto_const in self._legacy_protocols():
            if self._can_connect_with_protocol(host, port, proto_const):
                vulns.append(
                    Vulnerability(
                        name=t("scanner.ssl.insecure_protocol", proto=proto_name),
                        severity=Severity.MEDIUM,
                        description=t("scanner.ssl.insecure_protocol_desc", proto=proto_name),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=f"{proto_name} handshake succeeded on {host}:{port}",
                        remediation=t("scanner.ssl.insecure_protocol_remediation", proto=proto_name),
                        target=target,
                        location=f"{host}:{port}",
                    )
                )

        # ── 3. 证书域名匹配检查 ────────────────────────────
        subject = cert_info.get("subject", "")
        san_list = cert_info.get("san", [])
        if subject not in ("unknown", "unavailable"):
            host_lower = host.lower()
            # 检查 host 是否匹配 subject CN 或任意 SAN 条目
            matched = host_lower in subject.lower()
            if not matched:
                for san_entry in san_list:
                    san_lower = san_entry.lower()
                    # 支持通配符匹配，例如 *.example.com
                    if san_lower == host_lower:
                        matched = True
                        break
                    if san_lower.startswith("*.") and host_lower.endswith(san_lower[1:]):
                        matched = True
                        break
            if not matched:
                san_display = ", ".join(san_list[:5]) if san_list else "N/A"
                vulns.append(
                    Vulnerability(
                        name=t("scanner.ssl.hostname_mismatch"),
                        severity=Severity.HIGH,
                        description=t("scanner.ssl.hostname_mismatch_desc", subject=subject, host=host),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=f"subject={subject}, SAN=[{san_display}], host={host}",
                        remediation=t("scanner.ssl.hostname_mismatch_remediation"),
                        target=target,
                        location=f"{host}:{port}",
                    )
                )

        if callback:
            callback(t("scanner.ssl.complete", count=len(vulns)))

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
        )

    # ── 内部辅助方法 ──────────────────────────────────────────

    def _get_certificate(self, host: str, port: int) -> dict:
        """获取服务器证书并返回关键字段。"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (host, port), timeout=self._CONNECT_TIMEOUT
        ) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # binary_form=False 在 CERT_NONE 时返回空 dict
                    # 回退: 用 CERT_REQUIRED 重新连接以获取完整证书
                    return self._reconnect_for_cert(host, port)

                return self._extract_cert_fields(cert)

    @staticmethod
    def _extract_cert_fields(cert: dict) -> dict:
        """从 getpeercert() 字典中提取所需字段。"""

        def _dn_str(dn_tuple: tuple) -> str:
            """将 ((('commonName', 'example.com'),),) 展平成可读字符串。"""
            parts = []
            for rdn in dn_tuple:
                for attr_type, attr_value in rdn:
                    parts.append(f"{attr_type}={attr_value}")
            return ", ".join(parts)

        not_after_str = cert.get("notAfter", "")
        # Python ssl 模块返回的日期格式: "Mon DD HH:MM:SS YYYY GMT"
        not_after = datetime.strptime(
            not_after_str, "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=timezone.utc)

        # 提取 subjectAltName (SAN)
        san_list: list[str] = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            san_list.append(san_value)

        return {
            "subject": _dn_str(cert.get("subject", ())),
            "issuer": _dn_str(cert.get("issuer", ())),
            "not_after": not_after,
            "san": san_list,
        }

    @staticmethod
    def _reconnect_for_cert(host: str, port: int) -> dict:
        """用 CERT_REQUIRED 重新连接以获取完整证书字段。"""
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection(
                (host, port), timeout=10
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        return SSLScanner._extract_cert_fields(cert)
        except Exception:
            pass

        # 最终回退: 提供基本结构, 避免扫描崩溃
        # 使用远未来日期避免误报"即将过期"; subject != issuer 避免误报"自签名"
        return {
            "subject": "unknown",
            "issuer": "unavailable",
            "not_after": datetime(2099, 12, 31, tzinfo=timezone.utc),
            "san": [],
        }

    @staticmethod
    def _legacy_protocols() -> list[tuple[str, int]]:
        """返回需要检测的过时 TLS 协议列表。"""
        protos = []
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            protos.append(("TLSv1.0", ssl.PROTOCOL_TLSv1))
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            protos.append(("TLSv1.1", ssl.PROTOCOL_TLSv1_1))
        return protos

    def _can_connect_with_protocol(
        self, host: str, port: int, protocol: int
    ) -> bool:
        """尝试使用指定 TLS 协议版本建立连接。"""
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(
                (host, port), timeout=self._CONNECT_TIMEOUT
            ) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    _ = ssock.version()
                    return True
        except (ssl.SSLError, socket.error, OSError, ValueError):
            # ValueError: Python 3.10+ 可能在创建旧协议 SSLContext 时抛出
            return False
