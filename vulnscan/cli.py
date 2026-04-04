"""Command-line interface for VulnScan.

Provides subcommands for web scanning, code scanning, scanner status,
and launching the GUI. Uses argparse for argument parsing and rich for
formatted terminal output.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

from vulnscan.engine import ScanEngine
from vulnscan.i18n import auto_detect_language, set_language, t
from vulnscan.integrity import startup_check
from vulnscan.locale.messages import register_all
from vulnscan.models import HttpOptions
from vulnscan.registry import check_all_tools
from vulnscan.report import ReportGenerator

console = Console()


# ------------------------------------------------------------------
# Subcommand handlers
# ------------------------------------------------------------------


def _run_scan(target: str, mode: str, args: argparse.Namespace) -> None:
    """Execute a scan and produce reports (shared by web / code)."""
    engine = ScanEngine(max_workers=getattr(args, "workers", 6))
    scanner_names: list[str] | None = getattr(args, "scanners", None)
    output_dir: str = getattr(args, "output", ".")
    fmt: str = getattr(args, "format", "both")

    # 构建 HTTP 选项
    http_options: HttpOptions | None = None
    raw_headers = getattr(args, "header", None)
    cookie = getattr(args, "cookie", None)
    data = getattr(args, "data", None)
    method = getattr(args, "method", None)
    if raw_headers or cookie or data or method:
        headers_dict: dict[str, str] = {}
        for h in (raw_headers or []):
            if ":" in h:
                k, _, v = h.partition(":")
                headers_dict[k.strip()] = v.strip()
        http_options = HttpOptions(
            headers=headers_dict,
            cookies=cookie or "",
            data=data or "",
            method=(method or "GET").upper(),
        )

    # --- rich progress bar ---
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task(t("cli.initializing"), total=None)

        def on_progress(message: str, current: int, total: int) -> None:
            progress.update(task_id, description=message, completed=current, total=total)

        def on_scanner_done(result) -> None:  # noqa: ANN001
            status = "[green]OK[/green]" if result.success else "[red]FAIL[/red]"
            console.print(
                f"  {result.scanner_name}: {status}"
                + (f" - {result.error_message}" if result.error_message else "")
            )

        report = engine.scan(
            target=target,
            mode=mode,
            scanner_names=scanner_names,
            on_progress=on_progress,
            on_scanner_done=on_scanner_done,
            http_options=http_options,
        )

    # --- summary panel ---
    summary = report.summary
    duration = round(report.end_time - report.start_time, 2)

    summary_lines = [
        f"[red]{t('common.critical')}: {summary.get('critical', 0)}[/red]",
        f"[bright_red]{t('common.high')}:     {summary.get('high', 0)}[/bright_red]",
        f"[yellow]{t('common.medium')}:   {summary.get('medium', 0)}[/yellow]",
        f"[blue]{t('common.low')}:      {summary.get('low', 0)}[/blue]",
        f"[dim]{t('common.info')}:     {summary.get('info', 0)}[/dim]",
        "",
        f"{t('cli.total')}: {summary.get('total', 0)}  |  {t('cli.duration')}: {duration}s",
    ]

    console.print(
        Panel(
            "\n".join(summary_lines),
            title=t("cli.scan_summary"),
            border_style="bold cyan",
        )
    )

    # --- generate reports ---
    gen = ReportGenerator(output_dir=output_dir)

    if fmt in ("json", "both"):
        path = gen.generate_json(report)
        console.print(f"[green]{t('cli.report_saved_json')}:[/green] {path}")

    if fmt in ("html", "both"):
        path = gen.generate_html(report)
        console.print(f"[green]{t('cli.report_saved_html')}:[/green] {path}")


def cmd_web(args: argparse.Namespace) -> None:
    """Handle the 'web' subcommand."""
    console.print(
        f"[bold cyan]{t('cli.starting_scan', mode=t('common.web'), target=args.url)}[/bold cyan]"
    )
    _run_scan(target=args.url, mode="web", args=args)


def cmd_code(args: argparse.Namespace) -> None:
    """Handle the 'code' subcommand."""
    console.print(
        f"[bold cyan]{t('cli.starting_scan', mode=t('common.code'), target=args.path)}[/bold cyan]"
    )
    _run_scan(target=args.path, mode="code", args=args)


def cmd_status(_args: argparse.Namespace) -> None:
    """Handle the 'status' subcommand -- show scanner availability."""
    tools = check_all_tools()

    table = Table(title=t("cli.scanner_status_title"), show_lines=True)
    table.add_column(t("report.scanner"), style="bold")
    table.add_column(t("report.type"))
    table.add_column(t("report.target"))
    table.add_column(t("gui.builtin_only").split()[0])  # "Built-in" / "内置"
    table.add_column(t("report.status"))
    table.add_column(t("report.details"))

    for tool in tools:
        available_str = (
            f"[green]{t('common.yes')}[/green]"
            if tool["available"]
            else f"[red]{t('common.no')}[/red]"
        )
        builtin_str = t("common.yes") if tool["builtin"] else t("common.no")
        table.add_row(
            tool["name"],
            tool["scan_type"],
            tool["target_mode"],
            builtin_str,
            available_str,
            tool["reason"],
        )

    console.print(table)


def cmd_gui(_args: argparse.Namespace) -> None:
    """Handle the 'gui' subcommand -- launch the tkinter GUI."""
    from vulnscan.gui import launch_gui

    launch_gui()


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    from vulnscan import __version__

    parser = argparse.ArgumentParser(
        prog="vulnscan",
        description=t("cli.desc"),
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--lang",
        choices=["en", "zh"],
        default=None,
        help="Language / 语言",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        metavar="PATH",
        help="Write debug log to file / 将调试日志写入文件",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- web --
    web_parser = subparsers.add_parser("web", help=t("cli.web_help"))
    web_parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    web_parser.add_argument(
        "-o", "--output", default=".", help="Report output directory (default: .)"
    )
    web_parser.add_argument(
        "--scanners", nargs="+", default=None, help="Scanner names to use (optional)"
    )
    web_parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Report format (default: both)",
    )
    web_parser.add_argument(
        "--workers", type=int, default=6, help="Concurrent worker threads (default: 6)"
    )
    web_parser.add_argument(
        "--header", "-H", action="append", default=None, metavar="'Key: Value'",
        help="Custom HTTP header (can be used multiple times) / 自定义 HTTP 头（可多次使用）",
    )
    web_parser.add_argument(
        "--cookie", default=None, metavar="'k1=v1; k2=v2'",
        help="HTTP cookies / HTTP Cookies",
    )
    web_parser.add_argument(
        "--data", default=None, metavar="'key=value'",
        help="HTTP POST data / HTTP POST 数据",
    )
    web_parser.add_argument(
        "--method", default=None, choices=["GET", "POST", "PUT", "DELETE", "HEAD"],
        help="HTTP method (default: GET) / HTTP 方法",
    )
    web_parser.set_defaults(func=cmd_web)

    # -- code --
    code_parser = subparsers.add_parser("code", help=t("cli.code_help"))
    code_parser.add_argument("path", help="Target file or directory path")
    code_parser.add_argument(
        "-o", "--output", default=".", help="Report output directory (default: .)"
    )
    code_parser.add_argument(
        "--scanners", nargs="+", default=None, help="Scanner names to use (optional)"
    )
    code_parser.add_argument(
        "--format",
        choices=["json", "html", "both"],
        default="both",
        help="Report format (default: both)",
    )
    code_parser.set_defaults(func=cmd_code)

    # -- status --
    status_parser = subparsers.add_parser("status", help=t("cli.status_help"))
    status_parser.set_defaults(func=cmd_status)

    # -- gui --
    gui_parser = subparsers.add_parser("gui", help=t("cli.gui_help"))
    gui_parser.set_defaults(func=cmd_gui)

    return parser


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def main(argv: list[str] | None = None, *, _skip_init: bool = False) -> None:
    """CLI entry point."""
    if not _skip_init:
        # 初始化国际化
        register_all()
        set_language(auto_detect_language())

        # 完整性校验
        startup_check()

    # 先做一次预解析以获取 --lang 和 --log-file 参数
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--lang", choices=["en", "zh"], default=None)
    pre_parser.add_argument("--log-file", default=None)
    pre_args, _ = pre_parser.parse_known_args(argv)

    if pre_args.lang:
        set_language(pre_args.lang)

    # 配置日志文件输出
    if pre_args.log_file:
        logging.basicConfig(
            filename=pre_args.log_file,
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            encoding="utf-8",
        )

    # 正式解析（此时 t() 已经能返回正确语言的文本）
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
