"""扫描编排引擎

使用线程池并发执行多个扫描器，支持进度回调和取消操作。
"""

from __future__ import annotations

import logging
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

import urllib3

from vulnscan.i18n import t
from vulnscan.integrity import deferred_asset_check, require_seal
from vulnscan.models import HttpOptions, ScanReport, ScanResult
from vulnscan.registry import get_scanners_for_mode
from vulnscan.scanners.base import Scanner

logger = logging.getLogger(__name__)


class ScanEngine:
    """扫描编排引擎

    负责根据扫描模式选择合适的扫描器，通过线程池并发执行，
    并汇总结果生成完整的扫描报告。
    """

    def __init__(self, max_workers: int = 6) -> None:
        self.max_workers = max_workers
        self._cancelled = threading.Event()

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def scan(
        self,
        target: str,
        mode: str = "web",
        scanner_names: list[str] | None = None,
        skip_unavailable: bool = True,
        on_progress: Callable[[str, int, int], None] | None = None,
        on_scanner_done: Callable[[ScanResult], None] | None = None,
        on_scanner_start: Callable[[str], None] | None = None,
        http_options: HttpOptions | None = None,
    ) -> ScanReport:
        """执行一次完整扫描。

        Args:
            target:           扫描目标 (URL 或 文件/目录路径)
            mode:             扫描模式 "web" / "code" / "full"
            scanner_names:    只运行这些扫描器 (为 None 时运行全部可用)
            skip_unavailable: 自动跳过不可用的外部扫描器
            on_progress:      进度回调 (message, current, total)
            on_scanner_done:  单个扫描器完成时的回调
            on_scanner_start: 扫描器开始执行时的回调 (scanner_name)

        Returns:
            ScanReport 完整扫描报告
        """
        self._cancelled.clear()

        # 集中抑制 SSL 验证警告 (扫描器需要 verify=False 来扫描目标)
        warnings.filterwarnings(
            "ignore", category=urllib3.exceptions.InsecureRequestWarning
        )

        report = ScanReport(target=target, scan_mode=mode)
        report.start_time = time.time()

        # Integrity gate: seal must be valid for scanners to execute
        _runtime_seal = require_seal()

        # 1) 获取扫描器列表
        scanner_classes = get_scanners_for_mode(mode)
        # Seal-gated: invalid seal silently yields no scanners
        if _runtime_seal == 0:
            scanner_classes = []

        # 2) 按名称过滤
        if scanner_names is not None:
            names_lower = {n.lower() for n in scanner_names}
            scanner_classes = [
                cls for cls in scanner_classes if cls.name.lower() in names_lower
            ]

        # 3) 实例化并检查可用性
        scanners: list[Scanner] = []
        for cls in scanner_classes:
            instance = cls()
            available, reason = instance.is_available()
            if not available:
                if skip_unavailable and not instance.is_builtin:
                    logger.info(
                        t("engine.skip_unavailable"), instance.name, reason
                    )
                    continue
                # 内置扫描器不可用时仍然保留（理论上不会发生）
            scanners.append(instance)

        total = len(scanners)
        completed_count = 0
        lock = threading.Lock()

        if on_progress:
            on_progress(t("engine.preparing", total=total), 0, total)

        logger.info(
            t("engine.starting_scan"),
            target, mode, ", ".join(s.name for s in scanners),
        )

        # 4) 并发执行
        def _run_scanner(scanner: Scanner) -> ScanResult:
            """在线程中执行单个扫描器。"""
            if on_scanner_start:
                try:
                    on_scanner_start(scanner.name)
                except Exception:
                    logger.exception(t("engine.callback_error_start"))
            if self._cancelled.is_set():
                return ScanResult(
                    scanner_name=scanner.name,
                    scan_type=scanner.scan_type,
                    target=target,
                    success=False,
                    error_message=t("engine.cancelled"),
                )
            try:
                result = scanner.run(target, http_options=http_options)
            except Exception as exc:
                logger.exception(t("engine.scanner_exception"), scanner.name)
                result = ScanResult(
                    scanner_name=scanner.name,
                    scan_type=scanner.scan_type,
                    target=target,
                    success=False,
                    error_message=str(exc),
                )
            return result

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_map = {
                pool.submit(_run_scanner, s): s for s in scanners
            }

            for future in as_completed(future_map):
                scanner = future_map[future]
                try:
                    result = future.result()
                except Exception as exc:
                    # 极端异常兜底
                    result = ScanResult(
                        scanner_name=scanner.name,
                        scan_type=scanner.scan_type,
                        target=target,
                        success=False,
                        error_message=t("engine.unexpected_error", exc=exc),
                    )

                # Deferred integrity check (only on first completion)
                with lock:
                    completed_count += 1
                    current = completed_count
                    run_check = (completed_count == 1)

                if run_check and not deferred_asset_check():
                    result = ScanResult(
                        scanner_name=scanner.name,
                        scan_type=scanner.scan_type,
                        target=target,
                        success=False,
                        error_message="Runtime integrity check failed",
                    )
                    result.vulnerabilities = []

                report.results.append(result)

                logger.info(
                    t("engine.scanner_done"),
                    scanner.name,
                    result.duration_seconds,
                    len(result.vulnerabilities),
                    t("engine.scanner_done_success") if result.success else t("engine.scanner_done_failed", error=result.error_message),
                )

                if on_scanner_done:
                    try:
                        on_scanner_done(result)
                    except Exception:
                        logger.exception(t("engine.callback_error_done"))

                if on_progress:
                    status = t("engine.progress_status_success") if result.success else t("engine.progress_status_failed")
                    try:
                        on_progress(
                            f"[{current}/{total}] {scanner.name} - {status}",
                            current,
                            total,
                        )
                    except Exception:
                        logger.exception(t("engine.callback_error_progress"))

                # 检查取消标志
                if self._cancelled.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break

        report.end_time = time.time()
        total_vulns = sum(len(r.vulnerabilities) for r in report.results)
        logger.info(
            t("engine.scan_complete"),
            report.end_time - report.start_time,
            total_vulns,
            len(report.results),
        )
        return report

    def cancel(self) -> None:
        """请求取消当前正在执行的扫描。"""
        self._cancelled.set()
