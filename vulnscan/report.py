"""报告生成器

支持将扫描报告导出为 JSON 和 HTML 格式。
HTML 报告基于 Jinja2 模板引擎渲染。
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import jinja2

from vulnscan.i18n import t
from vulnscan.models import ScanReport


# 报告模板中需要翻译的所有 key
_REPORT_I18N_KEYS = [
    "report.title",
    "report.target",
    "report.mode",
    "report.start_time",
    "report.end_time",
    "report.duration",
    "report.summary",
    "report.vuln_list",
    "report.severity",
    "report.name",
    "report.scanner",
    "report.location",
    "report.confidence",
    "report.description",
    "report.evidence",
    "report.remediation",
    "report.reference",
    "report.scanner_summary",
    "report.status",
    "report.success",
    "report.failed",
    "report.found",
    "report.generated_by",
    "report.no_vulns",
    "report.type",
    "report.findings",
    "report.details",
    "common.critical",
    "common.high",
    "common.medium",
    "common.low",
    "common.info",
]


def _build_i18n_dict(**kwargs: object) -> dict[str, str]:
    """为模板构建翻译字典。"""
    result = {}
    for key in _REPORT_I18N_KEYS:
        # 将 "report.title" 转为模板变量名 "report_title"
        var_name = key.replace(".", "_")
        try:
            result[var_name] = t(key, **kwargs)
        except (KeyError, IndexError):
            result[var_name] = t(key)
    return result


class ReportGenerator:
    """扫描报告生成器

    将 ScanReport 导出为 JSON 或 HTML 文件。
    """

    # 模板目录: vulnscan/data/ (兼容 PyInstaller)
    @staticmethod
    def _get_template_dir() -> Path:
        from vulnscan.utils import get_base_dir
        return Path(get_base_dir()) / "data"

    def __init__(self, output_dir: str = ".") -> None:
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def generate_json(
        self, report: ScanReport, filename: str | None = None
    ) -> str:
        """导出 JSON 报告，返回文件路径。"""
        if filename is None:
            filename = self._default_filename(report, "json")

        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(report.to_json())

        return filepath

    def generate_html(
        self, report: ScanReport, filename: str | None = None
    ) -> str:
        """导出 HTML 报告，返回文件路径。"""
        if filename is None:
            filename = self._default_filename(report, "html")

        env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self._get_template_dir())),
            autoescape=True,
        )
        # 注册时间戳格式化过滤器
        env.filters["timestamp_fmt"] = lambda ts: datetime.fromtimestamp(
            ts, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""

        template = env.get_template("report_template.html")

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 构建 i18n 翻译字典传给模板
        from vulnscan import __version__
        i18n = _build_i18n_dict(version=__version__)

        html = template.render(
            report=report,
            summary=report.summary,
            vulnerabilities=report.deduplicated_vulnerabilities,
            results=report.results,
            generated_at=generated_at,
            i18n=i18n,
        )

        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    # ------------------------------------------------------------------
    # 内部方法
    # ------------------------------------------------------------------

    @staticmethod
    def _default_filename(report: ScanReport, ext: str) -> str:
        """生成默认文件名: vulnscan_report_{timestamp}.{ext}"""
        ts = datetime.fromtimestamp(report.start_time, tz=timezone.utc)
        timestamp_str = ts.strftime("%Y%m%d_%H%M%S")
        return f"vulnscan_report_{timestamp_str}.{ext}"
