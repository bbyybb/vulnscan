"""依赖文件 CVE 检查扫描器 (SCA)"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Callable, Optional

import requests

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner

logger = logging.getLogger(__name__)

# OSV API 端点
_OSV_API_URL = "https://api.osv.dev/v1/query"

# 请求超时 (秒)
_REQUEST_TIMEOUT = 5

# 请求间隔 (秒)
_REQUEST_INTERVAL = 0.2

# severity 字符串 -> Severity 枚举映射
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _parse_requirements_txt(filepath: str) -> list[tuple[str, str, str]]:
    """解析 requirements.txt，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                # 跳过注释和空行
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # 匹配 package==version 或 package>=version
                match = re.match(r'^([A-Za-z0-9_.-]+)\s*[=><~!]+\s*([^\s,;]+)', line)
                if match:
                    results.append((match.group(1), match.group(2), "PyPI"))
    except OSError as exc:
        logger.warning(t("scanner.dep.parse_warning"), filepath, exc)
    return results


def _parse_package_json(filepath: str) -> list[tuple[str, str, str]]:
    """解析 package.json，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                # 移除版本前缀符号 (^, ~, >=, etc.)
                clean_ver = re.sub(r'^[^0-9]*', '', str(ver))
                if clean_ver:
                    results.append((pkg, clean_ver, "npm"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(t("scanner.dep.parse_error"), filepath, exc)
    return results


def _parse_pipfile_lock(filepath: str) -> list[tuple[str, str, str]]:
    """解析 Pipfile.lock，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)
        for section in ("default", "develop"):
            deps = data.get(section, {})
            if not isinstance(deps, dict):
                continue
            for pkg, info in deps.items():
                if isinstance(info, dict):
                    ver = info.get("version", "")
                    # 移除 "==" 前缀
                    clean_ver = re.sub(r'^[=]+', '', str(ver))
                    if clean_ver:
                        results.append((pkg, clean_ver, "PyPI"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(t("scanner.dep.parse_error"), filepath, exc)
    return results


def _parse_go_sum(filepath: str) -> list[tuple[str, str, str]]:
    """解析 go.sum，返回 [(module, version, ecosystem), ...]"""
    results = []
    seen = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2:
                    module = parts[0]
                    version = parts[1]
                    # 去除 /go.mod 后缀和 v 前缀
                    version = version.split('/')[0]
                    if version.startswith('v'):
                        version = version[1:]
                    # 去除 +incompatible 后缀
                    version = version.replace('+incompatible', '')
                    key = (module, version)
                    if key not in seen:
                        seen.add(key)
                        results.append((module, version, "Go"))
    except OSError as exc:
        logger.warning(t("scanner.dep.parse_warning"), filepath, exc)
    return results


def _parse_package_lock_json(filepath: str) -> list[tuple[str, str, str]]:
    """解析 package-lock.json (npm)，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        # package-lock.json v2/v3: "packages" 字段
        packages = data.get("packages", {})
        if isinstance(packages, dict):
            for pkg_path, info in packages.items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version", "")
                if not version:
                    continue
                # 包路径如 "node_modules/lodash"，提取包名
                if pkg_path:
                    name = pkg_path.rsplit("node_modules/", 1)[-1]
                else:
                    # 空键表示根项目，跳过
                    continue
                if name:
                    results.append((name, version, "npm"))

        # package-lock.json v1: "dependencies" 字段（如果 packages 为空则用此）
        if not results:
            deps = data.get("dependencies", {})
            if isinstance(deps, dict):
                for pkg, info in deps.items():
                    if isinstance(info, dict):
                        version = info.get("version", "")
                        if version:
                            results.append((pkg, version, "npm"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(t("scanner.dep.parse_error"), filepath, exc)
    return results


def _parse_yarn_lock(filepath: str) -> list[tuple[str, str, str]]:
    """解析 yarn.lock，返回 [(package, version, ecosystem), ...]"""
    results = []
    seen = set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # yarn.lock v1 格式:
        #   name@version:
        #     version "x.y.z"
        # yarn.lock v2 (berry) 格式:
        #   "name@npm:version":
        #     version: x.y.z
        current_name = None
        for line in content.splitlines():
            # 匹配包头行，如: lodash@^4.17.0: 或 "lodash@npm:^4.17.0":
            header_match = re.match(
                r'^"?(@?[^@\s"]+)@', line
            )
            if header_match and not line.startswith(' '):
                current_name = header_match.group(1)
                continue

            # 匹配 version 行
            if current_name:
                ver_match = re.match(r'^\s+version\s+[":]*([^"\s]+)', line)
                if ver_match:
                    version = ver_match.group(1).strip('"')
                    key = (current_name, version)
                    if key not in seen:
                        seen.add(key)
                        results.append((current_name, version, "npm"))
                    current_name = None
    except OSError as exc:
        logger.warning(t("scanner.dep.parse_warning"), filepath, exc)
    return results


def _parse_poetry_lock(filepath: str) -> list[tuple[str, str, str]]:
    """解析 poetry.lock (TOML-like)，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # 匹配 [[package]] 段中的 name 和 version
        # 格式:
        # [[package]]
        # name = "requests"
        # version = "2.28.0"
        blocks = re.split(r'^\[\[package\]\]\s*$', content, flags=re.MULTILINE)
        for block in blocks:
            name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            ver_match = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if name_match and ver_match:
                results.append((name_match.group(1), ver_match.group(1), "PyPI"))
    except OSError as exc:
        logger.warning(t("scanner.dep.parse_warning"), filepath, exc)
    return results


def _parse_composer_lock(filepath: str) -> list[tuple[str, str, str]]:
    """解析 composer.lock (PHP)，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = json.load(f)

        for section in ("packages", "packages-dev"):
            pkgs = data.get(section, [])
            if not isinstance(pkgs, list):
                continue
            for pkg in pkgs:
                if not isinstance(pkg, dict):
                    continue
                name = pkg.get("name", "")
                version = pkg.get("version", "")
                if name and version:
                    # 移除 "v" 前缀
                    clean_ver = version.lstrip("v")
                    if clean_ver:
                        results.append((name, clean_ver, "Packagist"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(t("scanner.dep.parse_error"), filepath, exc)
    return results


def _parse_cargo_lock(filepath: str) -> list[tuple[str, str, str]]:
    """解析 Cargo.lock (Rust, TOML-like)，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # 匹配 [[package]] 段中的 name 和 version
        blocks = re.split(r'^\[\[package\]\]\s*$', content, flags=re.MULTILINE)
        for block in blocks:
            name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
            ver_match = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            if name_match and ver_match:
                results.append((name_match.group(1), ver_match.group(1), "crates.io"))
    except OSError as exc:
        logger.warning(t("scanner.dep.parse_warning"), filepath, exc)
    return results


def _parse_gemfile_lock(filepath: str) -> list[tuple[str, str, str]]:
    """解析 Gemfile.lock (Ruby)，返回 [(package, version, ecosystem), ...]"""
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # 查找 SPECS 段中的 gem 名称和版本
        # 格式:
        #   specs:
        #     actioncable (7.0.4)
        #     actionmailbox (7.0.4)
        in_specs = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped == "specs:":
                in_specs = True
                continue
            if in_specs:
                # SPECS 段中的条目有 4+ 个空格的缩进
                if line.startswith("    ") or line.startswith("\t"):
                    # 匹配 "name (version)" 格式
                    match = re.match(r'^\s{4,}(\S+)\s+\(([^)]+)\)', line)
                    if match:
                        name = match.group(1)
                        version = match.group(2)
                        results.append((name, version, "RubyGems"))
                elif stripped and not line.startswith(" "):
                    # 遇到新段落，结束 SPECS 解析
                    in_specs = False
    except OSError as exc:
        logger.warning(t("scanner.dep.parse_warning"), filepath, exc)
    return results


# 依赖文件名 -> 解析函数的映射
_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "Pipfile.lock": _parse_pipfile_lock,
    "go.sum": _parse_go_sum,
    "package-lock.json": _parse_package_lock_json,
    "yarn.lock": _parse_yarn_lock,
    "poetry.lock": _parse_poetry_lock,
    "composer.lock": _parse_composer_lock,
    "Cargo.lock": _parse_cargo_lock,
    "Gemfile.lock": _parse_gemfile_lock,
}


class DependencyScanner(Scanner):
    """通过 OSV API 检查项目依赖中已知漏洞的扫描器"""

    name = "DependencyScanner"
    description = "Dependency vulnerability check via OSV API"
    target_mode = "file"
    scan_type = ScanType.SCA

    def _find_dependency_files(
        self, target: str
    ) -> list[tuple[str, str]]:
        """在目标目录下查找依赖文件。

        Returns:
            列表，每项为 (文件完整路径, 文件名)
        """
        found = []
        if os.path.isfile(target):
            basename = os.path.basename(target)
            if basename in _PARSERS:
                found.append((target, basename))
            return found

        _skip = {"node_modules", ".git", "__pycache__", "venv", ".venv",
                 "dist", "build", ".tox", ".nox"}
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in _skip]
            for fname in files:
                if fname in _PARSERS:
                    found.append((os.path.join(root, fname), fname))
        return found

    def _query_osv(
        self, package: str, version: str, ecosystem: str
    ) -> list[dict] | None:
        """查询 OSV API，返回漏洞列表。网络失败时返回 None。"""
        try:
            resp = requests.post(
                _OSV_API_URL,
                json={
                    "package": {
                        "name": package,
                        "ecosystem": ecosystem,
                    },
                    "version": version,
                },
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("vulns", [])
        except (requests.RequestException, json.JSONDecodeError, KeyError) as exc:
            logger.error(
                t("scanner.dep.osv_query_failed"),
                package, version, ecosystem, exc,
            )
            return None

    def _map_severity(self, vuln: dict) -> Severity:
        """从 OSV 漏洞条目中提取严重程度。"""
        # 优先从 database_specific.severity 获取
        db_specific = vuln.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev = db_specific.get("severity", "")
            if isinstance(sev, str) and sev.lower() in _SEVERITY_MAP:
                return _SEVERITY_MAP[sev.lower()]

        # 其次从 severity 字段获取
        sev_list = vuln.get("severity", [])
        if isinstance(sev_list, list):
            for item in sev_list:
                if isinstance(item, dict):
                    score = item.get("score", "")
                    # CVSS 向量或数字分数映射
                    if isinstance(score, str) and score:
                        try:
                            # 尝试直接解析为数字
                            cvss = float(score)
                        except ValueError:
                            # 可能是 CVSS 向量字符串, 尝试从中提取基础分数
                            # 向量格式: CVSS:3.1/AV:N/AC:L/...
                            # 无法直接从向量提取数字分数, 使用 type 字段判断
                            cvss = -1.0
                            cvss_type = item.get("type", "")
                            if cvss_type.startswith("CVSS_V3"):
                                # 从向量中无法直接得到分数, 跳过
                                continue
                        if cvss >= 9.0:
                            return Severity.CRITICAL
                        if cvss >= 7.0:
                            return Severity.HIGH
                        if cvss >= 4.0:
                            return Severity.MEDIUM
                        if cvss >= 0:
                            return Severity.LOW
        elif isinstance(sev_list, str) and sev_list.lower() in _SEVERITY_MAP:
            return _SEVERITY_MAP[sev_list.lower()]

        return Severity.MEDIUM

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        # 查找依赖文件
        dep_files = self._find_dependency_files(target)

        if not dep_files:
            if callback:
                callback(t("scanner.dep.no_dep_files"))
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=True,
                vulnerabilities=[],
                duration_seconds=time.time() - start,
            )

        # 收集所有依赖
        all_packages: list[tuple[str, str, str]] = []
        for fpath, fname in dep_files:
            parser = _PARSERS.get(fname)
            if parser:
                all_packages.extend(parser(fpath))

        if callback:
            callback(t("scanner.dep.found_deps", count=len(all_packages)))

        # 逐个查询 OSV API
        last_request_time = 0.0
        query_failures = 0
        for package, version, ecosystem in all_packages:
            if callback:
                callback(package)

            # 限速: 确保请求间隔不低于 _REQUEST_INTERVAL
            elapsed = time.time() - last_request_time
            if elapsed < _REQUEST_INTERVAL:
                time.sleep(_REQUEST_INTERVAL - elapsed)

            last_request_time = time.time()
            osv_vulns = self._query_osv(package, version, ecosystem)
            if osv_vulns is None:
                query_failures += 1
                continue

            for v in osv_vulns:
                vuln_id = v.get("id", "UNKNOWN")
                summary = v.get("summary", "No description available")
                severity = self._map_severity(v)

                # 提取参考链接
                reference = ""
                refs = v.get("references", [])
                if isinstance(refs, list) and refs:
                    first_ref = refs[0]
                    if isinstance(first_ref, dict):
                        reference = first_ref.get("url", "")

                vulns.append(
                    Vulnerability(
                        name=vuln_id,
                        severity=severity,
                        description=summary,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        reference=reference,
                        target=target,
                        location=f"{package}=={version}",
                    )
                )

        # 检查是否所有查询都失败（可能是离线环境）
        if all_packages and query_failures == len(all_packages):
            error_msg = t("scanner.dep.all_queries_failed", count=query_failures)
            if callback:
                callback(error_msg)
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=error_msg,
                vulnerabilities=[],
                duration_seconds=time.time() - start,
            )

        if callback:
            callback(t("scanner.dep.complete", count=len(vulns)))

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
        )
