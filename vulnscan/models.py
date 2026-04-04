"""统一漏洞数据模型

所有扫描器的输出都转换为这些标准数据结构，
确保 CLI/GUI/报告层可以统一处理。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


@dataclass
class HttpOptions:
    """自定义 HTTP 请求选项，用于需要认证或特殊请求头的 Web 扫描。"""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: str = ""       # 原始 cookie 字符串 "k1=v1; k2=v2"
    data: str = ""          # POST body
    method: str = "GET"     # HTTP 方法

    def has_custom_options(self) -> bool:
        """是否设置了任何自定义选项。"""
        return bool(self.headers or self.cookies or self.data or self.method != "GET")


class Severity(str, Enum):
    """漏洞严重程度"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_key(self) -> int:
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[
            self.value
        ]


class ScanType(str, Enum):
    """扫描类型"""

    DAST = "dast"  # 动态 Web 扫描
    SAST = "sast"  # 静态代码扫描
    SCA = "sca"  # 软件成分分析
    INFRASTRUCTURE = "infra"  # 端口/SSL 等基础设施


@dataclass
class Vulnerability:
    """单条漏洞条目"""

    name: str  # 漏洞名称
    severity: Severity  # 严重程度
    description: str  # 漏洞描述
    scanner: str  # 发现此漏洞的扫描器名称
    scan_type: ScanType  # 扫描类型
    evidence: str = ""  # 证据 (响应头片段/匹配到的代码行等)
    remediation: str = ""  # 修复建议
    reference: str = ""  # 参考链接 (CVE/CWE/OWASP)
    target: str = ""  # 目标 (URL/文件路径)
    location: str = ""  # 具体位置 (文件:行号 / URL路径)
    cve_id: str = ""  # CVE编号
    cwe_id: str = ""  # CWE编号
    confidence: str = "medium"  # 置信度: high/medium/low
    timestamp: float = field(default_factory=time.time)

    @property
    def dedup_key(self) -> str:
        """生成去重键，用于识别相同漏洞。"""
        # 1. CVE ID 精确匹配
        cve = self.cve_id
        if not cve and re.match(r"^CVE-\d{4}-\d+", self.name):
            cve = self.name
        if cve:
            return f"cve:{cve}"
        # 2. 端口类: 按 location (host:port) 去重
        if self.scan_type == ScanType.INFRASTRUCTURE and ":" in self.location:
            return f"port:{self.location}"
        # 3. 兜底: name + location
        return f"{self.name}:{self.location}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["scan_type"] = self.scan_type.value
        return d


@dataclass
class ScanResult:
    """单个扫描器的执行结果"""

    scanner_name: str
    scan_type: ScanType
    target: str
    success: bool = True
    error_message: str = ""
    duration_seconds: float = 0.0
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    raw_output: str = ""  # 原始输出 (调试用)

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "scan_type": self.scan_type.value,
            "target": self.target,
            "success": self.success,
            "error_message": self.error_message,
            "duration_seconds": round(self.duration_seconds, 2),
            "vulnerability_count": len(self.vulnerabilities),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


@dataclass
class ScanReport:
    """完整扫描报告"""

    target: str  # 扫描目标
    scan_mode: str  # "web" / "code" / "full"
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    results: list[ScanResult] = field(default_factory=list)

    @property
    def all_vulnerabilities(self) -> list[Vulnerability]:
        vulns = []
        for r in self.results:
            vulns.extend(r.vulnerabilities)
        vulns.sort(key=lambda v: v.severity.sort_key)
        return vulns

    @property
    def deduplicated_vulnerabilities(self) -> list[Vulnerability]:
        """去重后的漏洞列表。

        相同 dedup_key 的漏洞合并为一条：
        - scanner 字段变为逗号分隔的多扫描器名称
        - severity 取最高级别
        - reference / cve_id / cwe_id 优先取非空值
        """
        groups: dict[str, list[Vulnerability]] = {}
        for v in self.all_vulnerabilities:
            groups.setdefault(v.dedup_key, []).append(v)

        result: list[Vulnerability] = []
        for vulns in groups.values():
            if len(vulns) == 1:
                result.append(vulns[0])
                continue
            # 取最高严重级别的作为主记录
            primary = min(vulns, key=lambda v: v.severity.sort_key)
            scanners = sorted(set(v.scanner for v in vulns))
            merged = Vulnerability(
                name=primary.name,
                severity=primary.severity,
                description=primary.description,
                scanner=", ".join(scanners),
                scan_type=primary.scan_type,
                evidence=primary.evidence,
                remediation=primary.remediation,
                reference=primary.reference or next(
                    (v.reference for v in vulns if v.reference), ""
                ),
                target=primary.target,
                location=primary.location,
                cve_id=primary.cve_id or next(
                    (v.cve_id for v in vulns if v.cve_id), ""
                ),
                cwe_id=primary.cwe_id or next(
                    (v.cwe_id for v in vulns if v.cwe_id), ""
                ),
                confidence=primary.confidence,
            )
            result.append(merged)

        result.sort(key=lambda v: v.severity.sort_key)
        return result

    @property
    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for v in self.deduplicated_vulnerabilities:
            counts[v.severity.value] += 1
        counts["total"] = sum(counts.values())
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_mode": self.scan_mode,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.end_time - self.start_time, 2),
            "summary": self.summary,
            "results": [r.to_dict() for r in self.results],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)
