"""敏感路径暴露检测扫描器"""

from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

import requests

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner
from vulnscan.utils import normalize_url

logger = logging.getLogger(__name__)

# severity 字符串 -> Severity 枚举映射
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

def _get_data_file():
    from vulnscan.utils import get_base_dir
    return os.path.join(get_base_dir(), 'data', 'sensitive_paths.txt')


def _load_sensitive_paths() -> list[tuple[str, Severity, str]]:
    """加载敏感路径字典。

    Returns:
        [(path, severity, description), ...]
    """
    entries: list[tuple[str, Severity, str]] = []
    try:
        with open(_get_data_file(), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(";", 2)
                if len(parts) != 3:
                    continue
                path, sev_str, desc = parts
                severity = _SEVERITY_MAP.get(sev_str.strip().lower(), Severity.INFO)
                entries.append((path.strip(), severity, desc.strip()))
    except OSError as exc:
        logger.error(t("scanner.dir.load_error"), exc)
    return entries


class DirectoryScanner(Scanner):
    """检测目标站点是否暴露敏感路径和文件"""

    name = "DirectoryScanner"
    description = "Sensitive path and file exposure detection"
    target_mode = "url"
    scan_type = ScanType.DAST

    def run(
        self,
        target: str,
        callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []
        base_url = normalize_url(target).rstrip("/")

        # 构建用户自定义 HTTP 选项
        req_headers = http_options.headers if http_options and http_options.headers else {}
        req_cookies_dict: dict[str, str] = {}
        if http_options and http_options.cookies:
            req_cookies_dict = dict(
                item.strip().split("=", 1)
                for item in http_options.cookies.split(";")
                if "=" in item
            )

        if callback:
            callback(t("scanner.dir.loading_paths"))

        paths = _load_sensitive_paths()
        total = len(paths)

        if callback:
            callback(t("scanner.dir.loaded_paths", total=total))

        # ------------------------------------------------------------------
        # 单条路径探测
        # ------------------------------------------------------------------
        def _probe(entry: tuple[str, Severity, str]) -> Optional[Vulnerability]:
            path, severity, description = entry
            url = f"{base_url}{path}"

            try:
                resp = requests.head(
                    url, timeout=5, verify=False, allow_redirects=False,
                    headers=req_headers, cookies=req_cookies_dict,
                )
                status = resp.status_code

                if status == 200:
                    return _handle_200(url, path, severity, description)
                if status == 403:
                    return Vulnerability(
                        name=t("scanner.dir.path_forbidden", path=path),
                        severity=Severity.INFO,
                        description=t("scanner.dir.path_forbidden_desc", path=path),
                        scanner=self.name,
                        scan_type=self.scan_type,
                        evidence=f"HEAD {url} -> 403 Forbidden",
                        target=target,
                        location=url,
                        confidence="low",
                    )
            except requests.RequestException:
                pass

            return None

        # ------------------------------------------------------------------
        # status 200 的深度确认
        # ------------------------------------------------------------------
        def _handle_200(
            url: str, path: str, severity: Severity, description: str
        ) -> Vulnerability:
            evidence = f"HEAD {url} -> 200 OK"

            # 特殊处理: /.git/HEAD
            if path == "/.git/HEAD":
                try:
                    r = requests.get(
                        url, timeout=5, verify=False,
                        headers=req_headers, cookies=req_cookies_dict,
                    )
                    body = r.text.strip()
                    if body.startswith("ref:"):
                        evidence = t("scanner.dir.git_confirmed", url=url, body=body[:80])
                        severity = Severity.HIGH
                    else:
                        evidence = t("scanner.dir.git_not_confirmed", url=url)
                        severity = Severity.INFO
                except requests.RequestException:
                    pass

            # 特殊处理: /.env
            elif path == "/.env":
                try:
                    r = requests.get(
                        url, timeout=5, verify=False,
                        headers=req_headers, cookies=req_cookies_dict,
                    )
                    body = r.text
                    # 检查是否包含典型的 KEY=VALUE 行格式（排除 HTML 页面）
                    import re as _re
                    env_pattern = _re.compile(
                        r"^[A-Za-z_][A-Za-z0-9_]*\s*=", _re.MULTILINE
                    )
                    if env_pattern.search(body) and "<html" not in body.lower():
                        evidence = t("scanner.dir.env_confirmed", url=url)
                        severity = Severity.CRITICAL
                    else:
                        evidence = t("scanner.dir.env_not_confirmed", url=url)
                        severity = Severity.INFO
                except requests.RequestException:
                    pass

            return Vulnerability(
                name=t("scanner.dir.sensitive_path_exposed", path=path),
                severity=severity,
                description=description,
                scanner=self.name,
                scan_type=self.scan_type,
                evidence=evidence,
                remediation=t("scanner.dir.remediation"),
                target=target,
                location=url,
                confidence="high",
            )

        # ------------------------------------------------------------------
        # 并发执行
        # ------------------------------------------------------------------
        completed = 0
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_probe, entry): entry for entry in paths}
            for future in as_completed(futures):
                completed += 1
                if callback and completed % 20 == 0:
                    callback(t("scanner.dir.progress", completed=completed, total=total))
                result = future.result()
                if result is not None:
                    vulns.append(result)

        if callback:
            callback(t("scanner.dir.complete", count=len(vulns)))

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
        )
