# -*- coding: utf-8 -*-
"""CLI 模块 (vulnscan/cli.py) 单元测试。

测试覆盖:
- _build_parser() 参数解析
- cmd_web / cmd_code / cmd_status 子命令处理
- main() 入口函数 (无参数帮助、--lang 切换)
"""

from __future__ import annotations

import argparse
import time
from unittest.mock import MagicMock, patch

import pytest

from vulnscan.models import (
    ScanReport,
    ScanResult,
    ScanType,
    Severity,
    Vulnerability,
)


# ------------------------------------------------------------------
# fixtures
# ------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _init_i18n():
    """确保每个测试运行前 i18n 已初始化。"""
    from vulnscan.locale.messages import register_all
    from vulnscan.i18n import set_language

    register_all()
    set_language("en")


def _make_dummy_report(target: str = "https://example.com", mode: str = "web") -> ScanReport:
    """构造一个包含单条漏洞的 ScanReport，用于 mock 返回值。"""
    vuln = Vulnerability(
        name="TestVuln",
        severity=Severity.MEDIUM,
        description="A test vulnerability",
        scanner="MockScanner",
        scan_type=ScanType.DAST,
        target=target,
    )
    result = ScanResult(
        scanner_name="MockScanner",
        scan_type=ScanType.DAST,
        target=target,
        success=True,
        vulnerabilities=[vuln],
        duration_seconds=1.5,
    )
    report = ScanReport(target=target, scan_mode=mode, start_time=time.time())
    report.end_time = report.start_time + 2.0
    report.results = [result]
    return report


# ==================================================================
# _build_parser 测试
# ==================================================================


class TestBuildParser:
    """验证 _build_parser 能正确创建参数解析器。"""

    def _get_parser(self):
        from vulnscan.cli import _build_parser

        return _build_parser()

    # -- 顶层参数 --

    def test_version_flag(self):
        """--version / -V 应输出版本号并退出。"""
        from vulnscan import __version__

        parser = self._get_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_lang_choices(self):
        """--lang 只接受 en / zh。"""
        parser = self._get_parser()
        args = parser.parse_args(["--lang", "en", "status"])
        assert args.lang == "en"

        args = parser.parse_args(["--lang", "zh", "status"])
        assert args.lang == "zh"

    def test_lang_invalid_choice(self):
        """--lang 传入无效值时解析器应报错。"""
        parser = self._get_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--lang", "fr", "status"])

    def test_log_file_argument(self):
        """--log-file 参数能正确解析。"""
        parser = self._get_parser()
        args = parser.parse_args(["--log-file", "/tmp/scan.log", "status"])
        assert args.log_file == "/tmp/scan.log"

    def test_log_file_default_none(self):
        """--log-file 默认为 None。"""
        parser = self._get_parser()
        args = parser.parse_args(["status"])
        assert args.log_file is None

    # -- web 子命令 --

    def test_web_subcommand_defaults(self):
        """web 子命令能正确解析 url 及默认值。"""
        parser = self._get_parser()
        args = parser.parse_args(["web", "https://example.com"])
        assert args.command == "web"
        assert args.url == "https://example.com"
        assert args.output == "."
        assert args.scanners is None
        assert args.format == "both"
        assert args.workers == 6

    def test_web_subcommand_all_options(self):
        """web 子命令所有可选参数都能正确解析。"""
        parser = self._get_parser()
        args = parser.parse_args([
            "web", "https://target.com",
            "-o", "/tmp/reports",
            "--scanners", "HeaderScanner", "SSLScanner",
            "--format", "json",
            "--workers", "10",
        ])
        assert args.url == "https://target.com"
        assert args.output == "/tmp/reports"
        assert args.scanners == ["HeaderScanner", "SSLScanner"]
        assert args.format == "json"
        assert args.workers == 10

    def test_web_http_options(self):
        """web 子命令的 --header/--cookie/--data/--method 参数解析。"""
        parser = self._get_parser()
        args = parser.parse_args([
            "web", "https://target.com",
            "-H", "Authorization: Bearer token",
            "-H", "Accept: application/json",
            "--cookie", "session=abc; user=test",
            "--data", '{"key": "value"}',
            "--method", "POST",
        ])
        assert args.header == ["Authorization: Bearer token", "Accept: application/json"]
        assert args.cookie == "session=abc; user=test"
        assert args.data == '{"key": "value"}'
        assert args.method == "POST"

    def test_web_http_options_defaults(self):
        """web 子命令 HTTP 选项的默认值为 None。"""
        parser = self._get_parser()
        args = parser.parse_args(["web", "https://target.com"])
        assert args.header is None
        assert args.cookie is None
        assert args.data is None
        assert args.method is None

    def test_web_missing_url_exits(self):
        """web 子命令缺少 url 参数时应退出。"""
        parser = self._get_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["web"])

    # -- code 子命令 --

    def test_code_subcommand_defaults(self):
        """code 子命令能正确解析 path 及默认值。"""
        parser = self._get_parser()
        args = parser.parse_args(["code", "/src/project"])
        assert args.command == "code"
        assert args.path == "/src/project"
        assert args.output == "."
        assert args.scanners is None
        assert args.format == "both"

    def test_code_subcommand_all_options(self):
        """code 子命令所有可选参数都能正确解析。"""
        parser = self._get_parser()
        args = parser.parse_args([
            "code", "/src/project",
            "-o", "/tmp/out",
            "--scanners", "FileAnalyzer", "BanditScanner",
            "--format", "html",
        ])
        assert args.path == "/src/project"
        assert args.output == "/tmp/out"
        assert args.scanners == ["FileAnalyzer", "BanditScanner"]
        assert args.format == "html"

    # -- status 子命令 --

    def test_status_subcommand(self):
        """status 子命令解析成功且设置了 func。"""
        parser = self._get_parser()
        args = parser.parse_args(["status"])
        assert args.command == "status"
        assert hasattr(args, "func")

    # -- gui 子命令 --

    def test_gui_subcommand(self):
        """gui 子命令解析成功且设置了 func。"""
        parser = self._get_parser()
        args = parser.parse_args(["gui"])
        assert args.command == "gui"
        assert hasattr(args, "func")

    # -- 无子命令 --

    def test_no_subcommand(self):
        """不传入子命令时 command 为 None。"""
        parser = self._get_parser()
        args = parser.parse_args([])
        assert args.command is None

    # -- format 非法值 --

    def test_format_invalid_choice(self):
        """--format 传入无效值时解析器应报错。"""
        parser = self._get_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["web", "https://example.com", "--format", "xml"])


# ==================================================================
# cmd_web 测试
# ==================================================================


class TestCmdWeb:
    """验证 cmd_web 子命令处理函数。"""

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_web_calls_engine_scan(self, mock_engine_cls, mock_report_gen_cls):
        """cmd_web 应调用 ScanEngine.scan 并使用正确参数。"""
        from vulnscan.cli import cmd_web

        dummy_report = _make_dummy_report("https://target.com", "web")
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/report.json"
        mock_gen.generate_html.return_value = "/tmp/report.html"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            url="https://target.com",
            output=".",
            scanners=None,
            format="both",
            workers=6,
        )
        cmd_web(args)

        mock_engine.scan.assert_called_once()
        call_kwargs = mock_engine.scan.call_args
        assert call_kwargs.kwargs["target"] == "https://target.com"
        assert call_kwargs.kwargs["mode"] == "web"
        assert call_kwargs.kwargs["scanner_names"] is None

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_web_generates_reports(self, mock_engine_cls, mock_report_gen_cls):
        """cmd_web 默认 format=both 时应同时生成 JSON 和 HTML 报告。"""
        from vulnscan.cli import cmd_web

        dummy_report = _make_dummy_report()
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/report.json"
        mock_gen.generate_html.return_value = "/tmp/report.html"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            url="https://example.com",
            output="/tmp",
            scanners=None,
            format="both",
            workers=6,
        )
        cmd_web(args)

        mock_report_gen_cls.assert_called_once_with(output_dir="/tmp")
        mock_gen.generate_json.assert_called_once_with(dummy_report)
        mock_gen.generate_html.assert_called_once_with(dummy_report)

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_web_json_only(self, mock_engine_cls, mock_report_gen_cls):
        """format=json 时仅生成 JSON 报告。"""
        from vulnscan.cli import cmd_web

        dummy_report = _make_dummy_report()
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/report.json"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            url="https://example.com",
            output=".",
            scanners=None,
            format="json",
            workers=6,
        )
        cmd_web(args)

        mock_gen.generate_json.assert_called_once()
        mock_gen.generate_html.assert_not_called()

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_web_with_scanners(self, mock_engine_cls, mock_report_gen_cls):
        """指定 --scanners 时应传递给 engine.scan。"""
        from vulnscan.cli import cmd_web

        dummy_report = _make_dummy_report()
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/report.json"
        mock_gen.generate_html.return_value = "/tmp/report.html"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            url="https://example.com",
            output=".",
            scanners=["HeaderScanner", "SSLScanner"],
            format="both",
            workers=4,
        )
        cmd_web(args)

        call_kwargs = mock_engine.scan.call_args.kwargs
        assert call_kwargs["scanner_names"] == ["HeaderScanner", "SSLScanner"]
        mock_engine_cls.assert_called_once_with(max_workers=4)


# ==================================================================
# cmd_code 测试
# ==================================================================


class TestCmdCode:
    """验证 cmd_code 子命令处理函数。"""

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_code_calls_engine_scan(self, mock_engine_cls, mock_report_gen_cls):
        """cmd_code 应使用 mode='code' 调用 engine.scan。"""
        from vulnscan.cli import cmd_code

        dummy_report = _make_dummy_report("/src/project", "code")
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/report.json"
        mock_gen.generate_html.return_value = "/tmp/report.html"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            path="/src/project",
            output=".",
            scanners=None,
            format="both",
            workers=6,
        )
        cmd_code(args)

        mock_engine.scan.assert_called_once()
        call_kwargs = mock_engine.scan.call_args.kwargs
        assert call_kwargs["target"] == "/src/project"
        assert call_kwargs["mode"] == "code"

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_code_html_only(self, mock_engine_cls, mock_report_gen_cls):
        """format=html 时仅生成 HTML 报告。"""
        from vulnscan.cli import cmd_code

        dummy_report = _make_dummy_report("/src", "code")
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_html.return_value = "/tmp/report.html"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            path="/src",
            output=".",
            scanners=None,
            format="html",
            workers=6,
        )
        cmd_code(args)

        mock_gen.generate_html.assert_called_once()
        mock_gen.generate_json.assert_not_called()

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_cmd_code_with_scanners_and_output(self, mock_engine_cls, mock_report_gen_cls):
        """验证自定义 scanners、output 能正确传递。"""
        from vulnscan.cli import cmd_code

        dummy_report = _make_dummy_report("/app", "code")
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/out/report.json"
        mock_gen.generate_html.return_value = "/out/report.html"
        mock_report_gen_cls.return_value = mock_gen

        args = argparse.Namespace(
            path="/app",
            output="/out",
            scanners=["FileAnalyzer"],
            format="both",
            workers=6,
        )
        cmd_code(args)

        call_kwargs = mock_engine.scan.call_args.kwargs
        assert call_kwargs["scanner_names"] == ["FileAnalyzer"]
        mock_report_gen_cls.assert_called_once_with(output_dir="/out")


# ==================================================================
# cmd_status 测试
# ==================================================================


class TestCmdStatus:
    """验证 cmd_status 子命令处理函数。"""

    @patch("vulnscan.cli.check_all_tools")
    def test_cmd_status_calls_check_all_tools(self, mock_check):
        """cmd_status 应调用 check_all_tools 并输出表格。"""
        from vulnscan.cli import cmd_status

        mock_check.return_value = [
            {
                "name": "HeaderScanner",
                "scan_type": "dast",
                "target_mode": "url",
                "builtin": True,
                "available": True,
                "reason": "Built-in scanner",
            },
            {
                "name": "NucleiScanner",
                "scan_type": "dast",
                "target_mode": "url",
                "builtin": False,
                "available": False,
                "reason": "nuclei not found in PATH",
            },
        ]

        args = argparse.Namespace()
        # 不应抛出异常
        cmd_status(args)
        mock_check.assert_called_once()

    @patch("vulnscan.cli.check_all_tools")
    def test_cmd_status_empty_tools(self, mock_check):
        """即使没有扫描器也应正常输出空表格。"""
        from vulnscan.cli import cmd_status

        mock_check.return_value = []
        args = argparse.Namespace()
        cmd_status(args)
        mock_check.assert_called_once()


# ==================================================================
# main() 测试
# ==================================================================


class TestMain:
    """验证 main() 入口函数行为。"""

    def test_main_no_args_prints_help_and_exits(self, capsys):
        """无参数时 main() 应打印帮助信息并退出。"""
        from vulnscan.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(argv=[], _skip_init=True)

        assert exc_info.value.code == 0

        captured = capsys.readouterr()
        # 帮助信息应包含 'usage' 或 'vulnscan'
        output = captured.out.lower()
        assert "usage" in output or "vulnscan" in output

    def test_main_lang_zh_switches_language(self):
        """--lang zh 应将语言切换为中文。"""
        from vulnscan.cli import main
        from vulnscan.i18n import get_language

        with patch("vulnscan.cli.check_all_tools", return_value=[]):
            main(argv=["--lang", "zh", "status"], _skip_init=True)

        assert get_language() == "zh"

    def test_main_lang_en_switches_language(self):
        """--lang en 应将语言切换为英文。"""
        from vulnscan.cli import main
        from vulnscan.i18n import set_language, get_language

        # 先设为中文
        set_language("zh")

        with patch("vulnscan.cli.check_all_tools", return_value=[]):
            main(argv=["--lang", "en", "status"], _skip_init=True)

        assert get_language() == "en"

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_main_web_command(self, mock_engine_cls, mock_report_gen_cls):
        """通过 main() 调用 web 子命令应触发扫描流程。"""
        from vulnscan.cli import main

        dummy_report = _make_dummy_report()
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/r.json"
        mock_gen.generate_html.return_value = "/tmp/r.html"
        mock_report_gen_cls.return_value = mock_gen

        main(argv=["web", "https://example.com"], _skip_init=True)
        mock_engine.scan.assert_called_once()

    @patch("vulnscan.cli.ReportGenerator")
    @patch("vulnscan.cli.ScanEngine")
    def test_main_code_command(self, mock_engine_cls, mock_report_gen_cls):
        """通过 main() 调用 code 子命令应触发代码扫描。"""
        from vulnscan.cli import main

        dummy_report = _make_dummy_report("/project", "code")
        mock_engine = MagicMock()
        mock_engine.scan.return_value = dummy_report
        mock_engine_cls.return_value = mock_engine

        mock_gen = MagicMock()
        mock_gen.generate_json.return_value = "/tmp/r.json"
        mock_gen.generate_html.return_value = "/tmp/r.html"
        mock_report_gen_cls.return_value = mock_gen

        main(argv=["code", "/project"], _skip_init=True)

        call_kwargs = mock_engine.scan.call_args.kwargs
        assert call_kwargs["target"] == "/project"
        assert call_kwargs["mode"] == "code"

    def test_main_status_command(self):
        """通过 main() 调用 status 子命令应展示扫描器状态。"""
        from vulnscan.cli import main

        with patch("vulnscan.cli.check_all_tools", return_value=[]) as mock_check:
            main(argv=["status"], _skip_init=True)

        mock_check.assert_called_once()

    @patch("vulnscan.cli.startup_check")
    @patch("vulnscan.cli.register_all")
    @patch("vulnscan.cli.auto_detect_language", return_value="en")
    @patch("vulnscan.cli.set_language")
    @patch("vulnscan.cli.check_all_tools", return_value=[])
    def test_main_without_skip_init(
        self,
        mock_check_tools,
        mock_set_lang,
        mock_auto_detect,
        mock_register,
        mock_startup,
    ):
        """_skip_init=False 时应执行初始化流程。"""
        from vulnscan.cli import main

        main(argv=["status"], _skip_init=False)

        mock_register.assert_called_once()
        mock_startup.assert_called_once()
        mock_auto_detect.assert_called_once()
