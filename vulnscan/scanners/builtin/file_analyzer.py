"""源码漏洞模式匹配扫描器 (SAST)"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Callable, Optional

from vulnscan.i18n import t
from vulnscan.models import HttpOptions, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner
from vulnscan.utils import walk_source_files

logger = logging.getLogger(__name__)

# 漏洞模式数据文件路径
def _get_patterns_file():
    from vulnscan.utils import get_base_dir
    return os.path.join(get_base_dir(), 'data', 'vuln_patterns.json')

# severity 字符串 -> Severity 枚举映射
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# 同一文件同一规则类别的最大报告数
_MAX_MATCHES_PER_RULE = 5


class FileAnalyzer(Scanner):
    """基于正则模式匹配的源码漏洞扫描器"""

    name = "FileAnalyzer"
    description = "Source code vulnerability pattern matching"
    target_mode = "file"
    scan_type = ScanType.SAST

    def __init__(self) -> None:
        self._rules: dict | None = None

    def _load_rules(self) -> dict:
        """加载漏洞模式规则文件，带缓存。"""
        if self._rules is not None:
            return self._rules

        try:
            with open(_get_patterns_file(), 'r', encoding='utf-8') as f:
                self._rules = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error(t("scanner.file.load_error"), exc)
            self._rules = {}

        return self._rules

    def _compile_rules(
        self, rules: dict
    ) -> list[tuple[str, list[re.Pattern], Severity, str, str, str]]:
        """将规则中的正则表达式预编译。

        Returns:
            列表，每项为 (规则名, 编译后的 patterns, 严重程度, 描述, cwe_id, 修复建议)
        """
        compiled = []
        for rule_name, rule_def in rules.items():
            patterns = []
            for p in rule_def.get("patterns", []):
                try:
                    patterns.append(re.compile(p))
                except re.error as exc:
                    logger.warning(t("scanner.file.skip_invalid_regex"), rule_name, exc)
            if patterns:
                severity = _SEVERITY_MAP.get(
                    rule_def.get("severity", "medium").lower(), Severity.MEDIUM
                )
                compiled.append((
                    rule_name,
                    patterns,
                    severity,
                    rule_def.get("description", ""),
                    rule_def.get("cwe_id", ""),
                    rule_def.get("remediation", ""),
                ))
        return compiled

    def run(
        self, target: str, callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        start = time.time()
        vulns: list[Vulnerability] = []

        # 加载并编译规则
        rules = self._load_rules()
        if not rules:
            return ScanResult(
                scanner_name=self.name,
                scan_type=self.scan_type,
                target=target,
                success=False,
                error_message=t("scanner.file.load_failed"),
                duration_seconds=time.time() - start,
            )

        compiled_rules = self._compile_rules(rules)

        # 遍历所有源码文件
        for fpath in walk_source_files(target):
            if callback:
                callback(os.path.basename(fpath))

            # 每个文件对每个规则类别的匹配计数
            match_counts: dict[str, int] = {}

            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_number, line in enumerate(f, start=1):
                        for (
                            rule_name,
                            patterns,
                            severity,
                            description,
                            cwe_id,
                            remediation,
                        ) in compiled_rules:
                            # 检查此规则是否已达上限
                            if match_counts.get(rule_name, 0) >= _MAX_MATCHES_PER_RULE:
                                continue

                            for pattern in patterns:
                                if pattern.search(line):
                                    match_counts[rule_name] = (
                                        match_counts.get(rule_name, 0) + 1
                                    )

                                    # 截取证据，最多 120 字符
                                    evidence = line.rstrip('\n\r')
                                    if len(evidence) > 120:
                                        evidence = evidence[:120] + "..."

                                    vulns.append(
                                        Vulnerability(
                                            name=rule_name,
                                            severity=severity,
                                            description=description,
                                            scanner=self.name,
                                            scan_type=self.scan_type,
                                            evidence=evidence,
                                            remediation=remediation,
                                            cwe_id=cwe_id,
                                            target=target,
                                            location=f"{fpath}:{line_number}",
                                        )
                                    )
                                    # 同一行同一规则只报一次，跳出 patterns 循环
                                    break

            except OSError as exc:
                logger.warning(t("scanner.file.read_error"), fpath, exc)
                continue

        if callback:
            callback(t("scanner.file.complete", count=len(vulns)))

        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=vulns,
            duration_seconds=time.time() - start,
        )
