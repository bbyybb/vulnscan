"""扫描器注册表 + 可用性检测

所有扫描器在这里统一注册，engine 和 UI 层通过此模块获取可用扫描器。
"""

from __future__ import annotations

from vulnscan.scanners.base import Scanner

# --- 内置扫描器 ---
from vulnscan.scanners.builtin.header_scanner import HeaderScanner
from vulnscan.scanners.builtin.ssl_scanner import SSLScanner
from vulnscan.scanners.builtin.directory_scanner import DirectoryScanner
from vulnscan.scanners.builtin.info_leak_scanner import InfoLeakScanner
from vulnscan.scanners.builtin.port_scanner import PortScanner
from vulnscan.scanners.builtin.file_analyzer import FileAnalyzer
from vulnscan.scanners.builtin.dependency_scanner import DependencyScanner

# --- 外部工具扫描器 ---
from vulnscan.scanners.external.nuclei_scanner import NucleiScanner
from vulnscan.scanners.external.nmap_scanner import NmapScanner
from vulnscan.scanners.external.bandit_scanner import BanditScanner
from vulnscan.scanners.external.trivy_scanner import TrivyScanner
from vulnscan.scanners.external.sqlmap_scanner import SqlmapScanner
from vulnscan.scanners.external.nikto_scanner import NiktoScanner
from vulnscan.scanners.external.ffuf_scanner import FfufScanner
from vulnscan.scanners.external.semgrep_scanner import SemgrepScanner
from vulnscan.scanners.external.grype_scanner import GrypeScanner

# 全局注册表
ALL_SCANNERS: list[type[Scanner]] = [
    # 内置 - Web (DAST / Infrastructure)
    HeaderScanner,
    SSLScanner,
    DirectoryScanner,
    InfoLeakScanner,
    PortScanner,
    # 内置 - Code (SAST / SCA)
    FileAnalyzer,
    DependencyScanner,
    # 外部 - Web
    NucleiScanner,
    NmapScanner,
    SqlmapScanner,
    NiktoScanner,
    FfufScanner,
    # 外部 - Code
    BanditScanner,
    SemgrepScanner,
    TrivyScanner,
    GrypeScanner,
]


def get_scanners_for_mode(mode: str) -> list[type[Scanner]]:
    """按模式筛选扫描器。"""
    if mode == "web":
        return [s for s in ALL_SCANNERS if s.target_mode in ("url", "both")]
    elif mode == "code":
        return [s for s in ALL_SCANNERS if s.target_mode in ("file", "both")]
    return list(ALL_SCANNERS)  # "full"


def check_all_tools() -> list[dict]:
    """检查所有扫描器的可用性，返回状态列表。"""
    results = []
    for cls in ALL_SCANNERS:
        instance = cls()
        available, reason = instance.is_available()
        results.append(
            {
                "name": instance.name,
                "description": instance.description,
                "builtin": instance.is_builtin,
                "available": available,
                "reason": reason,
                "target_mode": instance.target_mode,
                "scan_type": instance.scan_type.value,
                "install_url": instance.get_install_url() if hasattr(instance, 'get_install_url') else "",
                "install_hint": instance.get_install_hint() if hasattr(instance, 'get_install_hint') else "",
            }
        )
    return results
