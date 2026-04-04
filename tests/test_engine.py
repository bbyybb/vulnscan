# -*- coding: utf-8 -*-
"""vulnscan.engine 扫描引擎测试。"""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

from vulnscan.engine import ScanEngine
from vulnscan.models import ScanReport, ScanResult, ScanType, Severity, Vulnerability
from vulnscan.scanners.base import Scanner


def _make_mock_scanner_class(
    name: str = "MockScanner",
    available: bool = True,
    is_builtin: bool = True,
    target_mode: str = "url",
    vulnerabilities: list | None = None,
    side_effect: Exception | None = None,
) -> type:
    """动态创建 mock 扫描器类。

    通过 type() 构造，确保 run 方法定义在类体中从而满足 ABC 约束。
    """
    _avail = available
    _vulns = vulnerabilities or []
    _err = side_effect

    def _is_available(self):
        if _avail:
            return True, "mock available"
        return False, "mock not available"

    def _run(self, target, callback=None, http_options=None):
        if _err:
            raise _err
        return ScanResult(
            scanner_name=self.name,
            scan_type=self.scan_type,
            target=target,
            success=True,
            vulnerabilities=list(_vulns),
            duration_seconds=0.01,
        )

    cls = type(
        "_MockScanner",
        (Scanner,),
        {
            "name": name,
            "is_builtin": is_builtin,
            "target_mode": target_mode,
            "scan_type": ScanType.DAST,
            "is_available": _is_available,
            "run": _run,
        },
    )
    return cls


class TestScanEngine:
    """ScanEngine 测试。"""

    def test_engine_scan_basic(self):
        """基本扫描流程：注入 mock 扫描器，验证返回 ScanReport。"""
        vuln = Vulnerability(
            name="TestVuln",
            severity=Severity.LOW,
            description="test",
            scanner="MockScanner",
            scan_type=ScanType.DAST,
        )
        MockCls = _make_mock_scanner_class(vulnerabilities=[vuln])

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[MockCls],
        ):
            engine = ScanEngine(max_workers=2)
            report = engine.scan("https://example.com", mode="web")

        assert isinstance(report, ScanReport)
        assert report.target == "https://example.com"
        assert report.scan_mode == "web"
        assert len(report.results) == 1
        assert report.results[0].success is True
        assert len(report.results[0].vulnerabilities) == 1
        assert report.end_time > report.start_time

    def test_engine_skip_unavailable(self):
        """不可用的外部扫描器在 skip_unavailable=True 时应被跳过。"""
        AvailableCls = _make_mock_scanner_class(name="Available", available=True)
        UnavailableCls = _make_mock_scanner_class(
            name="Unavailable", available=False, is_builtin=False
        )

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[AvailableCls, UnavailableCls],
        ):
            engine = ScanEngine(max_workers=2)
            report = engine.scan(
                "https://example.com", mode="web", skip_unavailable=True
            )

        assert len(report.results) == 1
        assert report.results[0].scanner_name == "Available"

    def test_engine_scanner_error(self):
        """扫描器运行时抛异常，结果应为 success=False。"""
        ErrorCls = _make_mock_scanner_class(
            name="ErrorScanner",
            side_effect=RuntimeError("扫描器内部错误"),
        )

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[ErrorCls],
        ):
            engine = ScanEngine(max_workers=2)
            report = engine.scan("https://example.com", mode="web")

        assert len(report.results) == 1
        assert report.results[0].success is False
        assert "扫描器内部错误" in report.results[0].error_message

    def test_engine_cancel(self):
        """启动扫描后立即取消，验证不崩溃。"""

        class SlowScanner(Scanner):
            name = "SlowScanner"
            is_builtin = True
            target_mode = "url"
            scan_type = ScanType.DAST

            def run(self, target, callback=None, http_options=None):
                time.sleep(5)
                return ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    target=target,
                )

            def is_available(self):
                return True, "builtin"

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[SlowScanner],
        ):
            engine = ScanEngine(max_workers=1)

            def cancel_soon():
                time.sleep(0.1)
                engine.cancel()

            t = threading.Thread(target=cancel_soon)
            t.start()

            report = engine.scan("https://example.com", mode="web")
            t.join(timeout=10)

        assert isinstance(report, ScanReport)
        # 取消后的结果可能 success=False 且包含 "已取消"，或正常完成
        # 关键是不崩溃

    def test_engine_callbacks(self):
        """验证 on_progress 和 on_scanner_done 回调被调用。"""
        MockCls = _make_mock_scanner_class()

        progress_calls = []
        done_calls = []

        def on_progress(msg, current, total):
            progress_calls.append((msg, current, total))

        def on_scanner_done(result):
            done_calls.append(result)

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[MockCls],
        ):
            engine = ScanEngine(max_workers=2)
            engine.scan(
                "https://example.com",
                mode="web",
                on_progress=on_progress,
                on_scanner_done=on_scanner_done,
            )

        # on_progress 至少被调用两次（初始化 + 完成）
        assert len(progress_calls) >= 2
        # on_scanner_done 应被调用一次
        assert len(done_calls) == 1
        assert isinstance(done_calls[0], ScanResult)

    def test_engine_scanner_names_filter(self):
        """scanner_names 参数应过滤只运行指定名称的扫描器。"""
        Scanner1 = _make_mock_scanner_class(name="Alpha")
        Scanner2 = _make_mock_scanner_class(name="Beta")

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[Scanner1, Scanner2],
        ):
            engine = ScanEngine(max_workers=2)
            report = engine.scan(
                "https://example.com",
                mode="web",
                scanner_names=["Alpha"],
            )

        assert len(report.results) == 1
        assert report.results[0].scanner_name == "Alpha"

    def test_engine_on_scanner_start_callback(self):
        """验证 on_scanner_start 回调在扫描器开始时被调用。"""
        MockCls = _make_mock_scanner_class(name="TestScanner")

        start_calls = []

        def on_scanner_start(name):
            start_calls.append(name)

        with patch(
            "vulnscan.engine.get_scanners_for_mode",
            return_value=[MockCls],
        ):
            engine = ScanEngine(max_workers=2)
            engine.scan(
                "https://example.com",
                mode="web",
                on_scanner_start=on_scanner_start,
            )

        assert len(start_calls) == 1
        assert start_calls[0] == "TestScanner"
