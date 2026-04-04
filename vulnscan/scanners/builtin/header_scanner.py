"""HTTP 安全头检查扫描器"""

from __future__ import annotations

import time
from typing import Callable, Optional

import requests
import urllib3

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner


class HeaderScanner(Scanner):
    """检查 HTTP 响应中是否缺失关键安全头"""

    name = "HeaderScanner"
    description = "HTTP security headers check"
    target_mode = "url"
    scan_type = ScanType.DAST

    # (头名称, 严重程度, 描述 i18n key, 修复建议 i18n key,
    #  校验函数(值 -> 问题描述 i18n key | None))
    _CHECKS: list[
        tuple[str, Severity, str, str, Optional[Callable[[str], Optional[str]]]]
    ] = [
        (
            "X-Frame-Options",
            Severity.MEDIUM,
            "scanner.header.missing_xframe",
            "scanner.header.remediation_xframe",
            lambda v: (
                "scanner.header.bad_xframe"
                if v.upper() not in ("DENY", "SAMEORIGIN")
                else None
            ),
        ),
        (
            "Content-Security-Policy",
            Severity.MEDIUM,
            "scanner.header.missing_csp",
            "scanner.header.remediation_csp",
            lambda v: (
                "scanner.header.csp_unsafe_inline"
                if "'unsafe-inline'" in v.lower()
                else (
                    "scanner.header.csp_unsafe_eval"
                    if "'unsafe-eval'" in v.lower()
                    else None
                )
            ),
        ),
        (
            "Strict-Transport-Security",
            Severity.MEDIUM,
            "scanner.header.missing_hsts",
            "scanner.header.remediation_hsts",
            lambda v: (
                "scanner.header.hsts_no_maxage"
                if "max-age" not in v.lower()
                else None
            ),
        ),
        (
            "X-Content-Type-Options",
            Severity.LOW,
            "scanner.header.missing_xcto",
            "scanner.header.remediation_xcto",
            lambda v: (
                "scanner.header.bad_xcto"
                if v.lower() != "nosniff"
                else None
            ),
        ),
        (
            "Referrer-Policy",
            Severity.LOW,
            "scanner.header.missing_referrer",
            "scanner.header.remediation_referrer",
            None,
        ),
        (
            "Permissions-Policy",
            Severity.LOW,
            "scanner.header.missing_permissions",
            "scanner.header.remediation_permissions",
            None,
        ),
        (
            "Cross-Origin-Embedder-Policy",
            Severity.LOW,
            "scanner.header.missing_coep",
            "scanner.header.remediation_coep",
            None,
        ),
        (
            "Cross-Origin-Opener-Policy",
            Severity.LOW,
            "scanner.header.missing_coop",
            "scanner.header.remediation_coop",
            None,
        ),
        (
            "Cross-Origin-Resource-Policy",
            Severity.LOW,
            "scanner.header.missing_corp",
            "scanner.header.remediation_corp",
            None,
        ),
    ]

    def run(
        self,
        target: str,
        callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        try:
            if callback:
                callback(t("scanner.header.requesting", target=target))

            req_kwargs = dict(timeout=10, verify=False, allow_redirects=True)
            if http_options:
                if http_options.headers:
                    req_kwargs["headers"] = http_options.headers
                if http_options.cookies:
                    req_kwargs["cookies"] = dict(
                        item.strip().split("=", 1)
                        for item in http_options.cookies.split(";")
                        if "=" in item
                    )
            method = (http_options.method if http_options else "GET").upper()
            if method == "GET":
                resp = requests.get(target, **req_kwargs)
            else:
                req_kwargs["data"] = http_options.data if http_options else None
                resp = requests.request(method, target, **req_kwargs)
            headers = resp.headers

            # 逐项检查安全头
            for header_name, severity, desc_key, remediation_key, validator in self._CHECKS:
                value = headers.get(header_name)
                if value is None:
                    # 头缺失
                    vulns.append(
                        Vulnerability(
                            name=t("scanner.header.missing_header_name", header=header_name),
                            severity=severity,
                            description=t(desc_key),
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=t("scanner.header.evidence_missing", header=header_name),
                            remediation=t(remediation_key),
                            target=target,
                            location=target,
                        )
                    )
                elif validator:
                    # 头存在但值不合规
                    issue_key = validator(value)
                    if issue_key:
                        vulns.append(
                            Vulnerability(
                                name=t("scanner.header.misconfigured_name", header=header_name),
                                severity=severity,
                                description=t(issue_key),
                                scanner=self.name,
                                scan_type=self.scan_type,
                                evidence=f"{header_name}: {value}",
                                remediation=t(remediation_key),
                                target=target,
                                location=target,
                            )
                        )

            # 额外检查: CORS 过于宽松
            acao = headers.get("Access-Control-Allow-Origin")
            if acao and acao.strip() == "*":
                vulns.append(
                    Vulnerability(
                        name=t("scanner.header.cors_too_permissive"),
                        severity=Severity.MEDIUM,
                        description=t("scanner.header.cors_desc"),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        remediation=t("scanner.header.cors_remediation"),
                        target=target,
                        location=target,
                    )
                )

            # 额外检查: X-XSS-Protection（已废弃但仍值得检查）
            xxss = headers.get("X-XSS-Protection")
            if xxss is None:
                vulns.append(
                    Vulnerability(
                        name=t("scanner.header.missing_xxss"),
                        severity=Severity.INFO,
                        description=t("scanner.header.missing_xxss_desc"),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=t("scanner.header.missing_xxss_evidence"),
                        remediation=t("scanner.header.missing_xxss_remediation"),
                        target=target,
                        location=target,
                    )
                )
            elif xxss.strip() == "0":
                vulns.append(
                    Vulnerability(
                        name=t("scanner.header.xxss_deprecated_ok"),
                        severity=Severity.INFO,
                        description=t("scanner.header.xxss_deprecated_ok_desc"),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=f"X-XSS-Protection: {xxss}",
                        remediation=t("scanner.header.xxss_deprecated_ok_remediation"),
                        target=target,
                        location=target,
                    )
                )

            # 额外检查: Cache-Control（仅针对 HTML 页面）
            content_type = headers.get("Content-Type", "")
            if "text/html" in content_type.lower():
                cache_control = headers.get("Cache-Control", "")
                cc_lower = cache_control.lower()
                if "no-store" not in cc_lower and "no-cache" not in cc_lower:
                    vulns.append(
                        Vulnerability(
                            name=t("scanner.header.cache_control_missing"),
                            severity=Severity.LOW,
                            description=t("scanner.header.cache_control_desc"),
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=t("scanner.header.cache_control_evidence_value", value=cache_control) if cache_control else t("scanner.header.cache_control_evidence_missing"),
                            remediation=t("scanner.header.cache_control_remediation"),
                            target=target,
                            location=target,
                        )
                    )

            # 额外检查: Set-Cookie 安全属性 (遍历所有 Set-Cookie 头)
            set_cookie_headers = [
                v for k, v in resp.raw.headers.items()
                if k.lower() == "set-cookie"
            ]
            for set_cookie in set_cookie_headers:
                cookie_lower = set_cookie.lower()
                if "httponly" not in cookie_lower:
                    vulns.append(
                        Vulnerability(
                            name=t("scanner.header.cookie_no_httponly"),
                            severity=Severity.MEDIUM,
                            description=t("scanner.header.cookie_no_httponly_desc"),
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=f"Set-Cookie: {set_cookie[:100]}",
                            remediation=t("scanner.header.cookie_no_httponly_remediation"),
                            target=target,
                            location=target,
                        )
                    )
                if "secure" not in cookie_lower:
                    vulns.append(
                        Vulnerability(
                            name=t("scanner.header.cookie_no_secure"),
                            severity=Severity.LOW,
                            description=t("scanner.header.cookie_no_secure_desc"),
                            scanner=self.name,
                            scan_type=self.scan_type,
                            evidence=f"Set-Cookie: {set_cookie[:100]}",
                            remediation=t("scanner.header.cookie_no_secure_remediation"),
                            target=target,
                            location=target,
                        )
                    )

            if callback:
                callback(t("scanner.header.complete", count=len(vulns)))

            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=True,
                vulnerabilities=vulns,
                duration_seconds=time.time() - start,
            )

        except requests.RequestException as exc:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=t("scanner.header.request_failed", exc=exc),
                duration_seconds=time.time() - start,
            )
