"""Tkinter GUI for VulnScan.

Provides a graphical interface with a left control panel and a right
results/log panel. Scanning runs in a background thread; UI updates are
dispatched via root.after() for thread safety.
"""

from __future__ import annotations

import os
import platform
import threading
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk
from typing import Optional

try:
    from PIL import Image, ImageTk
    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False

from vulnscan.engine import ScanEngine
from vulnscan.i18n import auto_detect_language, get_language, set_language, t
from vulnscan.integrity import (
    get_assets_dir,
    get_protected_author,
    get_protected_donate_url,
    startup_check,
)
from vulnscan.locale.messages import register_all
from vulnscan.models import HttpOptions, ScanReport
from vulnscan.utils import parse_curl
from vulnscan.registry import check_all_tools
from vulnscan.report import ReportGenerator

_IS_MACOS = platform.system() == "Darwin"


def _detect_system_dark_mode() -> bool:
    """检测操作系统是否处于深色模式。"""
    if _IS_MACOS:
        try:
            import subprocess
            result = subprocess.run(
                ["defaults", "read", "-g", "AppleInterfaceStyle"],
                capture_output=True, text=True, timeout=3,
            )
            return result.stdout.strip().lower() == "dark"
        except Exception:
            return False
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            )
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return value == 0  # 0 = 深色模式
        except Exception:
            return False
    return False


# ------------------------------------------------------------------
# Color mapping for severity tags
# ------------------------------------------------------------------

def _get_severity_colors(theme_name: str) -> dict[str, str]:
    """返回指定主题下的严重程度颜色（确保在不同背景上都可读）。"""
    if theme_name == "aqua":
        # 深色背景上使用 Apple 亮色系
        return {
            "critical": "#ff453a",
            "high": "#ff9f0a",
            "medium": "#ffd60a",
            "low": "#64d2ff",
            "info": "#98989d",
        }
    else:  # light
        # 浅色背景上使用 Apple 深色系
        return {
            "critical": "#ff3b30",
            "high": "#ff9500",
            "medium": "#c69500",
            "low": "#007aff",
            "info": "#8e8e93",
        }

# 向后兼容: 默认导出 light 主题的颜色
SEVERITY_COLORS: dict[str, str] = _get_severity_colors("light")

# ------------------------------------------------------------------
# Theme definitions / 主题定义
# ------------------------------------------------------------------

# 色板参考: Apple Human Interface Guidelines
# Light = macOS 浅色外观; Aqua = macOS 深色外观
THEMES: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#f5f5f7",
        "fg": "#1d1d1f",
        "frame_bg": "#ffffff",
        "border": "#d2d2d7",
        "entry_bg": "#ffffff",
        "entry_fg": "#1d1d1f",
        "text_bg": "#ffffff",
        "text_fg": "#1d1d1f",
        "btn_bg": "#e5e5ea",
        "btn_fg": "#1d1d1f",
        "label_bg": "#ffffff",
        "label_fg": "#3a3a3c",
        "status_bg": "#e5e5ea",
        "status_fg": "#3a3a3c",
        "link_fg": "#007aff",
        "tooltip_bg": "#f2f2f7",
        "tooltip_fg": "#3a3a3c",
        "tree_bg": "#ffffff",
        "tree_fg": "#1d1d1f",
        "tree_sel_bg": "#007aff",
        "tree_sel_fg": "#ffffff",
        "tree_heading_bg": "#e5e5ea",
        "tree_heading_fg": "#3a3a3c",
        "tab_bg": "#e5e5ea",
        "tab_sel_bg": "#ffffff",
        "scrollbar": "#c7c7cc",
        "scrollbar_trough": "#f2f2f7",
        "progress_fg": "#34c759",
        "donate_fg": "#ff9500",
        "start_bg": "#34c759",
        "start_hover": "#30d158",
        "stop_bg": "#ff3b30",
        "stop_hover": "#ff453a",
        "btn_text": "#ffffff",
    },
    "aqua": {
        "bg": "#1c1c1e",
        "fg": "#f5f5f7",
        "frame_bg": "#2c2c2e",
        "border": "#38383a",
        "entry_bg": "#3a3a3c",
        "entry_fg": "#f5f5f7",
        "text_bg": "#1c1c1e",
        "text_fg": "#f5f5f7",
        "btn_bg": "#3a3a3c",
        "btn_fg": "#f5f5f7",
        "label_bg": "#2c2c2e",
        "label_fg": "#98989d",
        "status_bg": "#1c1c1e",
        "status_fg": "#0a84ff",
        "link_fg": "#0a84ff",
        "tooltip_bg": "#3a3a3c",
        "tooltip_fg": "#f5f5f7",
        "tree_bg": "#1c1c1e",
        "tree_fg": "#f5f5f7",
        "tree_sel_bg": "#0a84ff",
        "tree_sel_fg": "#ffffff",
        "tree_heading_bg": "#2c2c2e",
        "tree_heading_fg": "#98989d",
        "tab_bg": "#2c2c2e",
        "tab_sel_bg": "#1c1c1e",
        "scrollbar": "#48484a",
        "scrollbar_trough": "#2c2c2e",
        "progress_fg": "#0a84ff",
        "donate_fg": "#ff9f0a",
        "start_bg": "#30d158",
        "start_hover": "#34c759",
        "stop_bg": "#ff453a",
        "stop_hover": "#ff3b30",
        "btn_text": "#ffffff",
    },
}


class VulnScanGUI:
    """Main application window."""

    def __init__(self, *, _skip_init: bool = False) -> None:
        if not _skip_init:
            # 初始化国际化
            register_all()
            set_language(auto_detect_language())

            # 完整性校验
            startup_check()

        self.root = tk.Tk()
        self.root.title(t("gui.title"))
        self.root.geometry("1100x700")
        self.root.minsize(750, 500)

        # 设置窗口图标
        try:
            icon_path = os.path.join(get_assets_dir(), "icon.ico")
            if os.path.isfile(icon_path):
                self.root.iconbitmap(icon_path)
            else:
                # 尝试 PNG 图标 (Linux/macOS)
                png_path = os.path.join(get_assets_dir(), "icon.png")
                if os.path.isfile(png_path):
                    icon_img = tk.PhotoImage(file=png_path)
                    self.root.iconphoto(True, icon_img)
                    self._icon_ref = icon_img  # 防止 GC
        except tk.TclError:
            pass

        # macOS: 高 DPI (Retina) 支持
        if _IS_MACOS:
            try:
                self.root.tk.call(
                    "tk", "scaling", self.root.winfo_fpixels("1i") / 72
                )
            except tk.TclError:
                pass

        # State
        self.scan_mode = tk.StringVar(value="web")
        self.target_var = tk.StringVar()
        self.engine: Optional[ScanEngine] = None
        self.report: Optional[ScanReport] = None
        self.scanner_vars: list[tuple[str, tk.BooleanVar, bool]] = []
        # (name, checked_var, is_available)
        self._scan_thread: Optional[threading.Thread] = None
        self._scanning = False  # 是否正在扫描
        self._vuln_index: dict = {}  # treeview item_id -> Vulnerability object
        self._scanner_status_labels: dict[str, tk.Label] = {}  # 扫描器状态 Label
        self._link_widgets: list[tk.Label] = []  # 需要保持 link_fg 的标签
        # 根据系统深色/浅色模式自动选择初始主题
        self._current_theme = "aqua" if _detect_system_dark_mode() else "light"

        # 保存需要刷新文本的控件引用
        self._text_refs: dict[str, object] = {}

        self._build_ui()
        self._refresh_scanner_list()

        # 立即应用主题 (确保从启动就是一致的外观，避免原生主题→自定义主题的闪烁)
        self._apply_theme()
        # 更新主题切换按钮文字
        if self._current_theme == "aqua":
            self.theme_btn.configure(text=t("gui.light_theme"))
        else:
            self.theme_btn.configure(text=t("gui.dark_theme"))

    # ==================================================================
    # UI Construction
    # ==================================================================

    def _build_ui(self) -> None:
        # Main PanedWindow (horizontal split)
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL, sashwidth=4)
        paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Left panel
        left_frame = tk.Frame(paned, width=280)
        paned.add(left_frame, minsize=240)
        self._build_left_panel(left_frame)

        # Right panel
        right_frame = tk.Frame(paned)
        paned.add(right_frame, minsize=300)
        self._build_right_panel(right_frame)

        # Bottom status bar
        self.status_var = tk.StringVar(value=t("gui.ready"))
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padx=6,
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Left panel ---------------------------------------------------

    def _build_left_panel(self, parent: tk.Frame) -> None:
        # ── 先 pack 底部固定区域 (确保小窗口/远程桌面下始终可见) ──

        # Author & Donate (最底部)
        about_frame = tk.Frame(parent)
        about_frame.pack(fill=tk.X, padx=4, pady=(2, 4), side=tk.BOTTOM)

        author_label = tk.Label(
            about_frame,
            text=t("gui.author") + ": " + get_protected_author(),
            font=("", 9), fg="#888888",
        )
        author_label.pack(side=tk.LEFT)
        self._text_refs["author_label"] = author_label

        self.donate_btn = ttk.Button(
            about_frame, text=t("gui.donate"),
            style="Donate.TButton",
            command=self._show_donate_dialog,
        )
        try:
            self.donate_btn.configure(cursor="hand2")
        except tk.TclError:
            pass
        self.donate_btn.pack(side=tk.RIGHT)

        # Action buttons (开始/停止, 在 about_frame 之上)
        action_frame = tk.Frame(parent)
        action_frame.pack(fill=tk.X, padx=4, pady=4, side=tk.BOTTOM)

        self.start_btn = ttk.Button(
            action_frame, text=t("gui.start_scan"),
            style="Start.TButton", command=self._start_scan,
        )
        self.start_btn.pack(fill=tk.X, pady=(0, 2))
        self.stop_btn = ttk.Button(
            action_frame, text=t("gui.stop_scan"),
            style="Stop.TButton", command=self._stop_scan, state=tk.DISABLED,
        )
        self.stop_btn.pack(fill=tk.X)

        # ── 然后 pack 顶部和中间区域 ──

        # Language selector
        lang_frame = ttk.LabelFrame(parent, text=t("gui.language"), padding=(6, 4))
        lang_frame.pack(fill=tk.X, padx=4, pady=(4, 2))
        self._text_refs["lang_frame"] = lang_frame

        lang_btn_row = tk.Frame(lang_frame)
        lang_btn_row.pack(fill=tk.X)

        self.lang_en_btn = ttk.Button(
            lang_btn_row, text="English",
            command=lambda: self._switch_language("en"),
        )
        self.lang_en_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.lang_zh_btn = ttk.Button(
            lang_btn_row, text="中文",
            command=lambda: self._switch_language("zh"),
        )
        self.lang_zh_btn.pack(side=tk.LEFT)

        # 主题切换按钮
        self.theme_btn = ttk.Button(
            lang_btn_row, text=t("gui.dark_theme"),
            command=self._toggle_theme,
        )
        self.theme_btn.pack(side=tk.RIGHT)

        self._update_lang_btn_state()

        # Scan mode
        self.mode_frame = ttk.LabelFrame(parent, text=t("gui.scan_mode"), padding=(6, 4))
        self.mode_frame.pack(fill=tk.X, padx=4, pady=(4, 2))

        self.web_radio = ttk.Radiobutton(
            self.mode_frame, text=t("gui.web_scan"), variable=self.scan_mode,
            value="web", command=self._on_mode_change,
        )
        self.web_radio.pack(anchor=tk.W)
        self.code_radio = ttk.Radiobutton(
            self.mode_frame, text=t("gui.code_scan"), variable=self.scan_mode,
            value="code", command=self._on_mode_change,
        )
        self.code_radio.pack(anchor=tk.W)

        # Target input
        self.target_frame = ttk.LabelFrame(parent, text=t("gui.target"), padding=(6, 4))
        self.target_frame.pack(fill=tk.X, padx=4, pady=2)

        entry_row = tk.Frame(self.target_frame)
        entry_row.pack(fill=tk.X)
        self.target_entry = tk.Entry(entry_row, textvariable=self.target_var)
        self.target_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.browse_btn = ttk.Button(entry_row, text=t("gui.browse"), command=self._browse)
        self.browse_btn.pack(side=tk.RIGHT, padx=(4, 0))
        # Browse only active in code mode
        self._update_browse_state()

        # HTTP Options (Web 模式直接显示, Code 模式隐藏)
        self.http_opts_frame = ttk.LabelFrame(parent, text=t("gui.http_options"), padding=(6, 4))
        self.http_opts_frame.pack(fill=tk.X, padx=4, pady=2)

        # HTTP 方法 + Parse curl 按钮
        method_row = tk.Frame(self.http_opts_frame)
        method_row.pack(fill=tk.X, pady=(0, 2))
        tk.Label(method_row, text="Method:", width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.http_method_var = tk.StringVar(value="GET")
        ttk.Combobox(
            method_row, textvariable=self.http_method_var,
            values=["GET", "POST", "PUT", "DELETE", "HEAD"],
            state="readonly", width=10,
        ).pack(side=tk.LEFT)
        self.curl_btn = ttk.Button(
            method_row, text=t("gui.parse_curl"), command=self._show_curl_dialog,
        )
        self.curl_btn.pack(side=tk.RIGHT)

        # Headers
        tk.Label(self.http_opts_frame, text="Headers (Key: Value):", anchor=tk.W, font=("", 8)).pack(fill=tk.X)
        self.headers_text = tk.Text(self.http_opts_frame, height=3, wrap=tk.WORD)
        self.headers_text.pack(fill=tk.X)

        # Cookies
        cookie_row = tk.Frame(self.http_opts_frame)
        cookie_row.pack(fill=tk.X, pady=(2, 0))
        tk.Label(cookie_row, text="Cookies:", width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.cookies_var = tk.StringVar()
        tk.Entry(cookie_row, textvariable=self.cookies_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # POST Data
        tk.Label(self.http_opts_frame, text="Data:", anchor=tk.W, font=("", 8)).pack(fill=tk.X, pady=(2, 0))
        self.data_text = tk.Text(self.http_opts_frame, height=2, wrap=tk.WORD)
        self.data_text.pack(fill=tk.X)

        # Scanner list (scrollable)
        self.scanner_frame = ttk.LabelFrame(parent, text=t("gui.scanners"), padding=(6, 4))
        self.scanner_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

        btn_row = tk.Frame(self.scanner_frame)
        btn_row.pack(fill=tk.X, pady=(0, 4))
        self.select_all_btn = ttk.Button(
            btn_row, text=t("gui.select_all"), command=self._select_all_scanners
        )
        self.select_all_btn.pack(side=tk.LEFT, padx=(0, 4))
        self.builtin_only_btn = ttk.Button(
            btn_row, text=t("gui.builtin_only"), command=self._select_builtin_only
        )
        self.builtin_only_btn.pack(side=tk.LEFT)

        canvas = tk.Canvas(self.scanner_frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.scanner_frame, orient=tk.VERTICAL, command=canvas.yview)
        self.scanner_inner = tk.Frame(canvas)
        self.scanner_inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.create_window((0, 0), window=self.scanner_inner, anchor=tk.NW)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Progress
        self.progress_frame = ttk.LabelFrame(parent, text=t("gui.progress"), padding=(6, 4))
        self.progress_frame.pack(fill=tk.BOTH, expand=False, padx=4, pady=2)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            self.progress_frame, variable=self.progress_var, maximum=100
        )
        self.progress_bar.pack(fill=tk.X)
        self.progress_label = tk.Label(self.progress_frame, text=t("gui.idle"), anchor=tk.W)
        self.progress_label.pack(fill=tk.X)

        # 扫描器状态列表（扫描时动态填充）
        self._scanner_status_canvas = tk.Canvas(
            self.progress_frame, highlightthickness=0, height=50
        )
        self._scanner_status_scroll = ttk.Scrollbar(
            self.progress_frame, orient=tk.VERTICAL,
            command=self._scanner_status_canvas.yview,
        )
        self._scanner_status_inner = tk.Frame(self._scanner_status_canvas)
        self._scanner_status_inner.bind(
            "<Configure>",
            lambda e: self._scanner_status_canvas.configure(
                scrollregion=self._scanner_status_canvas.bbox("all")
            ),
        )
        self._scanner_status_canvas.create_window(
            (0, 0), window=self._scanner_status_inner, anchor=tk.NW
        )
        self._scanner_status_canvas.configure(
            yscrollcommand=self._scanner_status_scroll.set
        )
        self._scanner_status_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scanner_status_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # (Action buttons 和 Author/Donate 已在方法开头 pack 到 BOTTOM)

    # --- Right panel --------------------------------------------------

    def _build_right_panel(self, parent: tk.Frame) -> None:
        # ── 先 pack 底部导出按钮 (确保小窗口下始终可见) ──
        export_frame = tk.Frame(parent)
        export_frame.pack(fill=tk.X, padx=4, pady=4, side=tk.BOTTOM)

        self.export_json_btn = ttk.Button(
            export_frame, text=t("gui.export_json"), command=self._export_json
        )
        self.export_json_btn.pack(side=tk.LEFT, padx=(0, 4))
        self.export_html_btn = ttk.Button(
            export_frame, text=t("gui.export_html"), command=self._export_html
        )
        self.export_html_btn.pack(side=tk.LEFT, padx=(0, 4))
        self.export_both_btn = ttk.Button(
            export_frame, text=t("gui.export_both"), command=self._export_both
        )
        self.export_both_btn.pack(side=tk.LEFT)

        # ── 然后 pack 主内容区域 ──
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # ---- Results tab ----
        self.results_frame = tk.Frame(self.notebook)
        self.notebook.add(self.results_frame, text=t("gui.results"))

        # 上下可拖拽分割：Treeview（上）+ 详情（下）
        results_paned = tk.PanedWindow(
            self.results_frame, orient=tk.VERTICAL, sashwidth=5, sashrelief=tk.RAISED
        )
        results_paned.pack(fill=tk.BOTH, expand=True)

        # -- 上部: Treeview --
        tree_container = tk.Frame(results_paned)
        results_paned.add(tree_container, minsize=100)

        columns = ("severity", "name", "scanner", "location", "confidence")
        self.tree = ttk.Treeview(
            tree_container, columns=columns, show="headings", selectmode="browse"
        )
        # stretch=False 让列保持固定宽度，配合水平滚动条使用
        for col, i18n_key, width, minw in [
            ("severity", "report.severity", 70, 50),
            ("name", "report.name", 200, 100),
            ("scanner", "report.scanner", 100, 60),
            ("location", "report.location", 160, 80),
            ("confidence", "report.confidence", 70, 50),
        ]:
            self.tree.heading(col, text=t(i18n_key))
            self.tree.column(col, width=width, minwidth=minw, stretch=False)

        # Severity color tags
        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        # 垂直 + 水平滚动条
        tree_vscroll = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.tree.yview)
        tree_hscroll = ttk.Scrollbar(tree_container, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_vscroll.set,
                            xscrollcommand=tree_hscroll.set)
        tree_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_vscroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # -- 下部: 漏洞详情（可拖拽调整高度）--
        self.detail_frame = ttk.LabelFrame(
            results_paned, text=t("gui.vuln_detail"), padding=(6, 4)
        )
        results_paned.add(self.detail_frame, minsize=80)

        self.detail_text = tk.Text(self.detail_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
        detail_scroll = ttk.Scrollbar(self.detail_frame, orient=tk.VERTICAL, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_scroll.set)
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        detail_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # ---- Log tab ----
        log_frame = tk.Frame(self.notebook)
        self.notebook.add(log_frame, text=t("gui.log"))

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, state=tk.DISABLED)
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # (Export buttons 已在方法开头 pack 到 BOTTOM)

    # ==================================================================
    # Language switching
    # ==================================================================

    # ==================================================================
    # Theme switching / 主题切换
    # ==================================================================

    def _toggle_theme(self) -> None:
        """在 light 和 aqua 两个主题间切换。"""
        self._current_theme = "aqua" if self._current_theme == "light" else "light"
        self._apply_theme()
        if self._current_theme == "aqua":
            self.theme_btn.configure(text=t("gui.light_theme"))
        else:
            self.theme_btn.configure(text=t("gui.dark_theme"))

    def _apply_theme(self) -> None:
        """应用当前主题到所有控件（含 ttk 控件）。"""
        c = THEMES[self._current_theme]

        # 1) 根窗口
        self.root.configure(bg=c["bg"])

        # macOS: 告诉系统窗口使用 dark/light 外观
        # 避免系统 vibrant 效果覆盖自定义颜色
        if _IS_MACOS:
            appearance = "darkaqua" if self._current_theme == "aqua" else "aqua"
            try:
                self.root.tk.call(
                    "::tk::unsupported::MacWindowStyle",
                    "isdark", self.root, "1" if self._current_theme == "aqua" else "0"
                )
            except tk.TclError:
                pass
            try:
                self.root.wm_attributes("-appearance", appearance)
            except tk.TclError:
                pass

        # 2) ttk.Style — 使用 clam 主题引擎（支持完整颜色控制）
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Treeview",
                         background=c["tree_bg"], foreground=c["tree_fg"],
                         fieldbackground=c["tree_bg"], borderwidth=0,
                         rowheight=22)
        style.configure("Treeview.Heading",
                         background=c["tree_heading_bg"],
                         foreground=c["tree_heading_fg"],
                         bordercolor=c["border"],
                         relief="flat")
        style.map("Treeview",
                   background=[("selected", c["tree_sel_bg"])],
                   foreground=[("selected", c["tree_sel_fg"])])
        style.map("Treeview.Heading",
                   background=[("active", c["border"])])

        style.configure("TNotebook",
                         background=c["frame_bg"],
                         bordercolor=c["border"],
                         tabmargins=[2, 2, 2, 0])
        style.configure("TNotebook.Tab",
                         background=c["tab_bg"], foreground=c["fg"],
                         padding=[10, 4],
                         bordercolor=c["border"])
        style.map("TNotebook.Tab",
                   background=[("selected", c["tab_sel_bg"])],
                   foreground=[("selected", c["fg"])],
                   expand=[("selected", [0, 0, 0, 2])])

        style.configure("TProgressbar",
                         background=c["progress_fg"],
                         troughcolor=c["entry_bg"],
                         bordercolor=c["border"])

        style.configure("TCombobox",
                         fieldbackground=c["entry_bg"],
                         background=c["btn_bg"],
                         foreground=c["entry_fg"],
                         bordercolor=c["border"],
                         arrowcolor=c["fg"])
        style.map("TCombobox",
                   fieldbackground=[("readonly", c["entry_bg"])],
                   foreground=[("readonly", c["entry_fg"])],
                   background=[("readonly", c["btn_bg"])])
        # Combobox 下拉列表颜色
        self.root.option_add("*TCombobox*Listbox.background", c["entry_bg"])
        self.root.option_add("*TCombobox*Listbox.foreground", c["entry_fg"])
        self.root.option_add("*TCombobox*Listbox.selectBackground", c["tree_sel_bg"])
        self.root.option_add("*TCombobox*Listbox.selectForeground", c["tree_sel_fg"])

        style.configure("Vertical.TScrollbar",
                         background=c["scrollbar"],
                         troughcolor=c["scrollbar_trough"],
                         bordercolor=c["border"],
                         arrowcolor=c["fg"])
        style.configure("Horizontal.TScrollbar",
                         background=c["scrollbar"],
                         troughcolor=c["scrollbar_trough"],
                         bordercolor=c["border"],
                         arrowcolor=c["fg"])

        style.configure("TButton",
                         background=c["btn_bg"], foreground=c["btn_fg"],
                         bordercolor=c["border"])
        style.map("TButton",
                   background=[("active", c["border"])])

        # macOS 关键: ttk 控件样式 (macOS 上 tk 原生控件 fg 不生效)
        style.configure("TCheckbutton",
                         background=c["frame_bg"], foreground=c["fg"],
                         indicatorcolor=c["entry_bg"])
        style.map("TCheckbutton",
                   background=[("active", c["frame_bg"])],
                   foreground=[("active", c["fg"])],
                   indicatorcolor=[("selected", c["link_fg"])])

        style.configure("TRadiobutton",
                         background=c["frame_bg"], foreground=c["fg"],
                         indicatorcolor=c["entry_bg"])
        style.map("TRadiobutton",
                   background=[("active", c["frame_bg"])],
                   foreground=[("active", c["fg"])],
                   indicatorcolor=[("selected", c["link_fg"])])

        style.configure("TLabelframe",
                         background=c["frame_bg"],
                         bordercolor=c["border"])
        style.configure("TLabelframe.Label",
                         background=c["frame_bg"], foreground=c["fg"])

        # 3) 递归设置所有 tk 控件
        self._apply_colors_recursive(self.root, c)

        # 4) 特殊控件
        try:
            self.log_text.configure(bg=c["text_bg"], fg=c["text_fg"],
                                    insertbackground=c["text_fg"])
            self.detail_text.configure(bg=c["text_bg"], fg=c["text_fg"],
                                       insertbackground=c["text_fg"])
            self.headers_text.configure(bg=c["entry_bg"], fg=c["entry_fg"],
                                         insertbackground=c["entry_fg"])
            self.data_text.configure(bg=c["entry_bg"], fg=c["entry_fg"],
                                      insertbackground=c["entry_fg"])
        except (tk.TclError, AttributeError):
            pass

        # 5) 状态栏
        try:
            for w in self.root.winfo_children():
                if isinstance(w, tk.Label) and w.cget("relief") == tk.SUNKEN:
                    w.configure(bg=c["status_bg"], fg=c["status_fg"])
        except tk.TclError:
            pass

        # 6) 扫描器状态标签 (更新 bg 和 fg)
        for lbl in self._scanner_status_labels.values():
            try:
                current_fg = lbl.cget("fg")
                lbl.configure(bg=c["frame_bg"])
                # 保留状态颜色 (绿/红/蓝)，只更新初始灰色
                if current_fg == "#888888":
                    lbl.configure(fg=c["label_fg"])
            except tk.TclError:
                pass

        # 7) 开始/停止/打赏按钮 (ttk 样式)
        style.configure("Start.TButton",
                         background=c["start_bg"], foreground=c["btn_text"])
        style.map("Start.TButton",
                   background=[("active", c["start_hover"])])
        style.configure("Stop.TButton",
                         background=c["stop_bg"], foreground=c["btn_text"])
        style.map("Stop.TButton",
                   background=[("active", c["stop_hover"])])
        style.configure("Donate.TButton",
                         foreground=c["donate_fg"])

        # 9) 重新应用 Treeview severity 行颜色
        try:
            sev_colors = _get_severity_colors(self._current_theme)
            for sev, color in sev_colors.items():
                self.tree.tag_configure(sev, foreground=color)
        except (tk.TclError, AttributeError):
            pass

        # 10) 链接标签恢复 link_fg
        try:
            for w in self._link_widgets:
                if w.winfo_exists():
                    w.configure(fg=c["link_fg"])
        except (tk.TclError, AttributeError):
            pass

    def _apply_colors_recursive(self, widget: tk.Widget, c: dict) -> None:
        """递归为所有 tk 原生控件应用主题颜色。"""
        widget_type = widget.winfo_class()
        try:
            if widget_type in ("Frame", "PanedWindow"):
                widget.configure(bg=c["frame_bg"])
            elif widget_type == "Canvas":
                widget.configure(bg=c["frame_bg"],
                                 highlightbackground=c["frame_bg"],
                                 highlightcolor=c["frame_bg"])
            elif widget_type == "Labelframe":
                widget.configure(bg=c["frame_bg"], fg=c["fg"],
                                 highlightbackground=c["frame_bg"],
                                 highlightcolor=c["frame_bg"])
            elif widget_type == "Label":
                widget.configure(bg=c["label_bg"], fg=c["label_fg"])
            elif widget_type == "Button":
                widget.configure(bg=c["btn_bg"], fg=c["btn_fg"],
                                 activebackground=c["entry_bg"],
                                 activeforeground=c["fg"])
            elif widget_type == "Entry":
                widget.configure(bg=c["entry_bg"], fg=c["entry_fg"],
                                 insertbackground=c["entry_fg"])
            elif widget_type == "Text":
                widget.configure(bg=c["text_bg"], fg=c["text_fg"],
                                 insertbackground=c["text_fg"])
            elif widget_type == "Checkbutton":
                widget.configure(bg=c["frame_bg"], fg=c["fg"],
                                 selectcolor=c["entry_bg"],
                                 activebackground=c["frame_bg"],
                                 activeforeground=c["fg"])
            elif widget_type == "Radiobutton":
                widget.configure(bg=c["frame_bg"], fg=c["fg"],
                                 selectcolor=c["entry_bg"],
                                 activebackground=c["frame_bg"],
                                 activeforeground=c["fg"])
            elif widget_type == "Scrollbar":
                widget.configure(bg=c["btn_bg"], troughcolor=c["frame_bg"])
        except tk.TclError:
            pass

        for child in widget.winfo_children():
            self._apply_colors_recursive(child, c)

    def _switch_language(self, lang: str) -> None:
        """切换语言并刷新所有 UI 文本。"""
        if lang == get_language():
            return
        set_language(lang)
        self._refresh_texts()
        self._refresh_scanner_list()
        self._update_lang_btn_state()
        self._apply_theme()

    def _update_lang_btn_state(self) -> None:
        """更新语言按钮的视觉状态，高亮当前语言。"""
        current = get_language()
        # ttk.Button 用 disabled 状态表示"当前选中"
        if current == "en":
            self.lang_en_btn.state(["disabled"])
            self.lang_zh_btn.state(["!disabled"])
        else:
            self.lang_en_btn.state(["!disabled"])
            self.lang_zh_btn.state(["disabled"])

    def _refresh_texts(self) -> None:
        """刷新所有 UI 控件的文本为当前语言。"""
        # Window title
        self.root.title(t("gui.title"))

        # Language frame
        if "lang_frame" in self._text_refs:
            self._text_refs["lang_frame"].configure(text=t("gui.language"))

        # Left panel
        self.mode_frame.configure(text=t("gui.scan_mode"))
        self.web_radio.configure(text=t("gui.web_scan"))
        self.code_radio.configure(text=t("gui.code_scan"))
        self.target_frame.configure(text=t("gui.target"))
        self.browse_btn.configure(text=t("gui.browse"))
        self.http_opts_frame.configure(text=t("gui.http_options"))
        self.curl_btn.configure(text=t("gui.parse_curl"))
        if self._current_theme == "aqua":
            self.theme_btn.configure(text=t("gui.light_theme"))
        else:
            self.theme_btn.configure(text=t("gui.dark_theme"))
        self.scanner_frame.configure(text=t("gui.scanners"))
        self.select_all_btn.configure(text=t("gui.select_all"))
        self.builtin_only_btn.configure(text=t("gui.builtin_only"))
        self.progress_frame.configure(text=t("gui.progress"))

        # Progress label - 只在空闲时更新
        current_progress_text = self.progress_label.cget("text")
        # 检查是否是 "Idle" 或 "空闲" 等空闲状态
        idle_texts = {"Idle", "空闲"}
        if current_progress_text in idle_texts:
            self.progress_label.configure(text=t("gui.idle"))

        # Action buttons
        self.start_btn.configure(text=t("gui.start_scan"))
        self.stop_btn.configure(text=t("gui.stop_scan"))

        # Right panel - Notebook tabs
        self.notebook.tab(0, text=t("gui.results"))
        self.notebook.tab(1, text=t("gui.log"))

        # Treeview headings
        for col, i18n_key in [
            ("severity", "report.severity"),
            ("name", "report.name"),
            ("scanner", "report.scanner"),
            ("location", "report.location"),
            ("confidence", "report.confidence"),
        ]:
            self.tree.heading(col, text=t(i18n_key))

        # Detail frame
        self.detail_frame.configure(text=t("gui.vuln_detail"))

        # Export buttons
        self.export_json_btn.configure(text=t("gui.export_json"))
        self.export_html_btn.configure(text=t("gui.export_html"))
        self.export_both_btn.configure(text=t("gui.export_both"))

        # Author & Donate
        if "author_label" in self._text_refs:
            self._text_refs["author_label"].configure(
                text=t("gui.author") + ": " + get_protected_author()
            )
        self.donate_btn.configure(text=t("gui.donate"))

        # Status bar - 只在就绪状态时更新
        current_status = self.status_var.get()
        ready_texts = {"Ready", "就绪"}
        if current_status in ready_texts:
            self.status_var.set(t("gui.ready"))

    # ==================================================================
    # Scanner list management
    # ==================================================================

    def _refresh_scanner_list(self) -> None:
        """Rebuild the scanner checkbox list for the current mode."""
        for widget in self.scanner_inner.winfo_children():
            widget.destroy()
        self.scanner_vars.clear()

        mode = self.scan_mode.get()
        all_tools = check_all_tools()

        # Filter by mode
        valid_targets = {"url", "both"} if mode == "web" else {"file", "both"}

        for tool in all_tools:
            if tool["target_mode"] not in valid_targets:
                continue
            available = tool["available"]
            is_builtin = tool["builtin"]
            var = tk.BooleanVar(value=available)

            row = tk.Frame(self.scanner_inner)
            row.pack(fill=tk.X, anchor=tk.W)

            # 工具名称（不可用的非内置工具加 N/A 后缀）
            label = tool["name"]
            if not available and not is_builtin:
                label += " (N/A)"

            cb = ttk.Checkbutton(
                row, text=label, variable=var,
            )
            if not available and not is_builtin:
                cb.configure(state=tk.DISABLED)
            cb.pack(side=tk.LEFT)

            # 非内置工具: 始终显示 "浏览" + "安装" 按钮
            if not is_builtin:
                browse_btn = ttk.Button(
                    row, text=t("gui.browse_exe"),
                    command=lambda name=tool["name"]: self._browse_tool_path(name),
                )
                browse_btn.pack(side=tk.RIGHT, padx=(0, 2))

                install_url = tool.get("install_url", "")
                if install_url:
                    link = tk.Label(
                        row, text=t("gui.install"),
                        fg=THEMES[self._current_theme]["link_fg"],
                        font=("", 8, "underline"),
                    )
                    try:
                        link.configure(cursor="hand2")
                    except tk.TclError:
                        pass
                    link.pack(side=tk.RIGHT, padx=(0, 2))
                    link.bind("<Button-1>", lambda e, url=install_url: webbrowser.open(url))
                    self._link_widgets.append(link)

                # 悬浮提示: 显示当前可执行文件路径
                tooltip_text = tool.get("reason", "")
                self._bind_tooltip(cb, tooltip_text)

            self.scanner_vars.append((tool["name"], var, available))

    def _select_all_scanners(self) -> None:
        for _name, var, available in self.scanner_vars:
            if available:
                var.set(True)

    def _select_builtin_only(self) -> None:
        all_tools = {tool["name"]: tool for tool in check_all_tools()}
        for name, var, _avail in self.scanner_vars:
            tool = all_tools.get(name)
            var.set(bool(tool and tool["builtin"]))

    def _browse_tool_path(self, tool_name: str) -> None:
        """让用户手动选择工具的可执行文件路径。"""
        import shutil
        from vulnscan.scanners.base import save_tool_path

        filetypes = [("All files", "*.*")]
        if platform.system() == "Windows":
            filetypes.insert(0, ("Executables", "*.exe"))

        path = filedialog.askopenfilename(
            title=f"{t('gui.select_exe')} - {tool_name}",
            filetypes=filetypes,
        )
        if not path:
            return

        # 验证是否为可执行文件或支持的脚本
        import os as _os
        ext = _os.path.splitext(path)[1].lower()
        script_exts = {".py", ".pl", ".rb", ".sh", ".bat", ".cmd", ".jar", ".ps1"}
        if not shutil.which(path) and ext not in script_exts:
            messagebox.showwarning(
                t("gui.invalid_exe"),
                t("gui.invalid_exe_msg", path=path),
            )
            return

        save_tool_path(tool_name, path)
        messagebox.showinfo(
            t("gui.path_saved"),
            t("gui.path_saved_msg", tool=tool_name, path=path),
        )
        self._refresh_scanner_list()

    def _bind_tooltip(self, widget: tk.Widget, text: str) -> None:
        """为控件绑定鼠标悬浮提示。"""
        tip_window = None
        gui = self

        def _show(event):
            nonlocal tip_window
            if tip_window or not text:
                return
            c = THEMES[gui._current_theme]
            x = event.x_root + 15
            y = event.y_root + 10
            tip_window = tw = tk.Toplevel(widget)
            tw.wm_overrideredirect(True)
            tw.wm_geometry(f"+{x}+{y}")
            label = tk.Label(
                tw, text=text, justify=tk.LEFT,
                bg=c["tooltip_bg"], fg=c["tooltip_fg"],
                relief=tk.SOLID, borderwidth=1,
                font=("", 8), wraplength=350, padx=4, pady=2,
            )
            label.pack()

        def _hide(_event):
            nonlocal tip_window
            if tip_window:
                tip_window.destroy()
                tip_window = None

        widget.bind("<Enter>", _show)
        widget.bind("<Leave>", _hide)

    def _get_selected_scanners(self) -> list[str] | None:
        """Return selected scanner names, or None to use all available."""
        selected = [name for name, var, _ in self.scanner_vars if var.get()]
        # If all available are selected, return None (= use default)
        all_available = [name for name, _, avail in self.scanner_vars if avail]
        if set(selected) == set(all_available):
            return None
        return selected or None

    # ==================================================================
    # Mode / browse handling
    # ==================================================================

    def _on_mode_change(self) -> None:
        self._refresh_scanner_list()
        self._update_browse_state()
        # Web 模式显示 HTTP 选项面板, Code 模式隐藏
        if self.scan_mode.get() == "web":
            self.http_opts_frame.pack(
                fill=tk.X, padx=4, pady=2, after=self.target_frame,
            )
        else:
            self.http_opts_frame.pack_forget()
        # 重新应用主题到新建的控件
        self._apply_theme()

    def _update_browse_state(self) -> None:
        if self.scan_mode.get() == "web":
            self.browse_btn.configure(state=tk.DISABLED)
        else:
            self.browse_btn.configure(state=tk.NORMAL)

    def _browse(self) -> None:
        """弹出选择对话框，可选目录或单个文件。"""
        dlg = tk.Toplevel(self.root)
        dlg.title(t("gui.browse"))
        dlg.geometry("300x120")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(
            dlg, text=t("gui.browse_choose"), font=("", 10),
        ).pack(pady=(15, 10))

        btn_row = tk.Frame(dlg)
        btn_row.pack(pady=(0, 10))

        def _pick_dir():
            dlg.destroy()
            path = filedialog.askdirectory(title=t("gui.select_code_dir"))
            if path:
                self.target_var.set(path)

        def _pick_file():
            dlg.destroy()
            path = filedialog.askopenfilename(
                title=t("gui.select_code_file"),
                filetypes=[
                    ("Source files", "*.py *.js *.ts *.java *.php *.rb *.go *.c *.cpp *.cs"),
                    ("All files", "*.*"),
                ],
            )
            if path:
                self.target_var.set(path)

        ttk.Button(btn_row, text=t("gui.select_dir"), width=12, command=_pick_dir).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_row, text=t("gui.select_file"), width=12, command=_pick_file).pack(side=tk.LEFT, padx=8)

        # 应用当前主题
        self._apply_colors_recursive(dlg, THEMES[self._current_theme])

    def _show_curl_dialog(self) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title(t("gui.parse_curl"))
        dlg.geometry("500x300")
        dlg.transient(self.root)
        dlg.grab_set()

        tk.Label(dlg, text=t("gui.paste_curl_hint"), wraplength=460).pack(pady=(8, 4), padx=8)

        curl_text = tk.Text(dlg, height=10, wrap=tk.WORD)
        curl_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        def _parse_and_fill():
            cmd = curl_text.get("1.0", tk.END).strip()
            if not cmd:
                dlg.destroy()
                return
            url, headers, cookies, data, method = parse_curl(cmd)
            if url:
                self.target_var.set(url)
            self.http_method_var.set(method)
            self.headers_text.delete("1.0", tk.END)
            if headers:
                lines = [f"{k}: {v}" for k, v in headers.items()]
                self.headers_text.insert("1.0", "\n".join(lines))
            self.cookies_var.set(cookies)
            self.data_text.delete("1.0", tk.END)
            if data:
                self.data_text.insert("1.0", data)
            dlg.destroy()

        btn_row = tk.Frame(dlg)
        btn_row.pack(fill=tk.X, padx=8, pady=(0, 8))
        ttk.Button(btn_row, text=t("gui.parse_and_fill"), command=_parse_and_fill).pack(side=tk.LEFT)
        ttk.Button(btn_row, text=t("gui.close"), command=dlg.destroy).pack(side=tk.RIGHT)

        # 应用当前主题
        c = THEMES[self._current_theme]
        self._apply_colors_recursive(dlg, c)
        curl_text.configure(bg=c["entry_bg"], fg=c["entry_fg"],
                            insertbackground=c["entry_fg"])

    # ==================================================================
    # Scanning
    # ==================================================================

    def _start_scan(self) -> None:
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning(t("gui.input_required"), t("gui.no_target"))
            return

        mode = self.scan_mode.get()
        scanner_names = self._get_selected_scanners()

        # Reset UI
        self._clear_results()
        self._scanning = True
        self._vuln_index.clear()
        self.start_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.progress_var.set(0)
        self.progress_label.configure(text=t("gui.starting"))
        self.status_var.set(t("gui.scanning"))

        # 构建 HTTP 选项
        http_options = None
        if mode == "web":
            headers_raw = self.headers_text.get("1.0", tk.END).strip()
            headers_dict = {}
            for line in headers_raw.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers_dict[k.strip()] = v.strip()
            cookies = self.cookies_var.get().strip()
            data = self.data_text.get("1.0", tk.END).strip()
            method = self.http_method_var.get()
            if headers_dict or cookies or data or method != "GET":
                http_options = HttpOptions(
                    headers=headers_dict,
                    cookies=cookies,
                    data=data,
                    method=method,
                )

        self.engine = ScanEngine(max_workers=6)

        # 初始化扫描器状态列表
        self._init_scanner_status_labels(scanner_names)

        def _run() -> None:
            try:
                report = self.engine.scan(
                    target=target,
                    mode=mode,
                    scanner_names=scanner_names,
                    on_progress=self._on_progress,
                    on_scanner_done=self._on_scanner_done,
                    on_scanner_start=self._on_scanner_start,
                    http_options=http_options,
                )
                self.root.after(0, lambda: self._on_scan_finished(report))
            except Exception as exc:
                err_msg = str(exc)
                self.root.after(0, lambda: self._on_scan_error(err_msg))

        self._scan_thread = threading.Thread(target=_run, daemon=True)
        self._scan_thread.start()

    def _stop_scan(self) -> None:
        self._scanning = False
        if self.engine:
            self.engine.cancel()
        self._append_log(t("gui.scan_cancelled_by_user") + "\n")
        self.status_var.set(t("gui.scan_cancelled"))
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

    # --- Callbacks (called from worker thread) ---

    def _on_progress(self, message: str, current: int, total: int) -> None:
        def _update() -> None:
            pct = (current / total * 100) if total > 0 else 0
            self.progress_var.set(pct)
            self.progress_label.configure(text=message)

        self.root.after(0, _update)

    def _on_scanner_done(self, result) -> None:  # noqa: ANN001
        def _update() -> None:
            status = "OK" if result.success else "FAIL"
            msg = f"[{result.scanner_name}] {status}"
            if result.error_message:
                msg += f" - {result.error_message}"
            self._append_log(msg + "\n")

            # 更新扫描器状态标签
            self._update_scanner_status(result.scanner_name, result.success)

            # Add vulnerabilities to tree immediately
            for vuln in result.vulnerabilities:
                sev = vuln.severity.value
                item_id = self.tree.insert(
                    "",
                    tk.END,
                    values=(sev, vuln.name, vuln.scanner, vuln.location, vuln.confidence),
                    tags=(sev,),
                )
                self._vuln_index[item_id] = vuln

        self.root.after(0, _update)

    def _on_scan_finished(self, report: ScanReport) -> None:
        self.report = report
        # 如果用户已点击停止, 不覆盖按钮状态
        if not self._scanning:
            return
        self._scanning = False
        summary = report.summary
        duration = round(report.end_time - report.start_time, 2)

        self.progress_var.set(100)
        self.progress_label.configure(text=t("gui.scan_done"))
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

        stat = (
            f"Done | {t('common.critical')}: {summary.get('critical', 0)}  "
            f"{t('common.high')}: {summary.get('high', 0)}  "
            f"{t('common.medium')}: {summary.get('medium', 0)}  "
            f"{t('common.low')}: {summary.get('low', 0)}  "
            f"{t('common.info')}: {summary.get('info', 0)}  "
            f"{t('cli.total')}: {summary.get('total', 0)}  |  {duration}s"
        )
        self.status_var.set(stat)
        self._append_log(
            "\n" + t("gui.scan_finished_in", duration=duration) + "\n"
        )

        # 用去重后的漏洞列表刷新 Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        self._vuln_index.clear()
        for vuln in report.deduplicated_vulnerabilities:
            sev = vuln.severity.value
            item_id = self.tree.insert(
                "",
                tk.END,
                values=(sev, vuln.name, vuln.scanner, vuln.location, vuln.confidence),
                tags=(sev,),
            )
            self._vuln_index[item_id] = vuln

    def _on_scan_error(self, error_msg: str) -> None:
        self.start_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.status_var.set("Error")
        self._append_log(f"ERROR: {error_msg}\n")
        messagebox.showerror(t("gui.scan_error"), error_msg)

    # ==================================================================
    # Scanner status labels
    # ==================================================================

    def _init_scanner_status_labels(
        self, scanner_names: list[str] | None
    ) -> None:
        """根据选中的扫描器列表，初始化状态 Label。"""
        # 清除旧的
        for w in self._scanner_status_inner.winfo_children():
            w.destroy()
        self._scanner_status_labels.clear()

        # 获取将要运行的扫描器名称
        if scanner_names is None:
            names = [name for name, var, avail in self.scanner_vars if var.get()]
        else:
            names = list(scanner_names)

        for name in names:
            lbl = tk.Label(
                self._scanner_status_inner,
                text=f"  [ -- ]  {name}",
                anchor=tk.W,
                fg=THEMES[self._current_theme]["label_fg"],
                bg=THEMES[self._current_theme]["frame_bg"],
                font=("", 8),
            )
            lbl.pack(fill=tk.X, anchor=tk.W)
            self._scanner_status_labels[name] = lbl

    def _on_scanner_start(self, name: str) -> None:
        """回调: 扫描器开始执行。"""
        def _update() -> None:
            lbl = self._scanner_status_labels.get(name)
            if lbl:
                lbl.configure(text=f"  [ .. ]  {name}", fg="#2563eb")
        self.root.after(0, _update)

    def _update_scanner_status(self, name: str, success: bool) -> None:
        """更新扫描器状态为完成或失败。"""
        lbl = self._scanner_status_labels.get(name)
        if lbl:
            if success:
                lbl.configure(text=f"  [OK]  {name}", fg="#27ae60")
            else:
                lbl.configure(text=f"  [FAIL]  {name}", fg="#e74c3c")

    # ==================================================================
    # Tree selection -> detail view
    # ==================================================================

    def _on_tree_select(self, _event: tk.Event) -> None:
        selection = self.tree.selection()
        if not selection or self.report is None:
            return

        item_id = selection[0]
        vuln = self._vuln_index.get(item_id)

        if vuln is None:
            return

        detail_lines = [
            f"{t('report.name')}:        {vuln.name}",
            f"{t('report.severity')}:    {vuln.severity.value}",
            f"{t('report.scanner')}:     {vuln.scanner}",
            f"{t('report.location')}:    {vuln.location}",
            f"{t('report.confidence')}:  {vuln.confidence}",
            "",
            f"{t('report.description')}:",
            f"  {vuln.description}",
            "",
        ]
        if vuln.evidence:
            detail_lines += [f"{t('report.evidence')}:", f"  {vuln.evidence}", ""]
        if vuln.remediation:
            detail_lines += [f"{t('report.remediation')}:", f"  {vuln.remediation}", ""]
        if vuln.reference:
            detail_lines += [f"{t('report.reference')}: {vuln.reference}"]
        if vuln.cve_id:
            detail_lines.append(f"CVE: {vuln.cve_id}")
        if vuln.cwe_id:
            detail_lines.append(f"CWE: {vuln.cwe_id}")

        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "\n".join(detail_lines))
        self.detail_text.configure(state=tk.DISABLED)

    # ==================================================================
    # Export
    # ==================================================================

    def _export_json(self) -> None:
        self._export("json")

    def _export_html(self) -> None:
        self._export("html")

    def _export_both(self) -> None:
        self._export("both")

    def _export(self, fmt: str) -> None:
        if self.report is None:
            messagebox.showinfo(t("gui.no_data"), t("gui.run_scan_first"))
            return

        paths: list[str] = []

        if fmt in ("json", "both"):
            path = filedialog.asksaveasfilename(
                title=t("gui.save_json_report"),
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            )
            if path:
                output_dir = os.path.dirname(path) or "."
                filename = os.path.basename(path)
                gen = ReportGenerator(output_dir=output_dir)
                saved = gen.generate_json(self.report, filename=filename)
                paths.append(saved)

        if fmt in ("html", "both"):
            path = filedialog.asksaveasfilename(
                title=t("gui.save_html_report"),
                defaultextension=".html",
                filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            )
            if path:
                output_dir = os.path.dirname(path) or "."
                filename = os.path.basename(path)
                gen = ReportGenerator(output_dir=output_dir)
                saved = gen.generate_html(self.report, filename=filename)
                paths.append(saved)

        if paths:
            messagebox.showinfo(
                t("gui.export_complete"),
                t("gui.saved") + "\n" + "\n".join(paths),
            )

    # ==================================================================
    # Helpers
    # ==================================================================

    # ==================================================================
    # Donate dialog
    # ==================================================================

    def _show_donate_dialog(self) -> None:
        """弹出打赏窗口，包含微信/支付宝/BuyMeACoffee三个Tab。"""
        dlg = tk.Toplevel(self.root)
        dlg.title(t("gui.donate"))
        dlg.geometry("420x520")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        # 资源目录 (从 integrity 模块获取)
        assets_dir = get_assets_dir()
        donate_url = get_protected_donate_url()

        # 标题
        tk.Label(
            dlg, text=t("gui.donate_title"),
            font=("", 14, "bold"), fg="#e67e22",
        ).pack(pady=(12, 6))

        tk.Label(
            dlg, text=t("gui.donate_desc"), font=("", 10), fg="#666666",
        ).pack(pady=(0, 8))

        # Notebook (3 tabs)
        notebook = ttk.Notebook(dlg)
        notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        # 存储 PhotoImage 引用，防止被垃圾回收
        dlg._img_refs = []

        tab_configs = [
            (t("gui.wechat_pay"), "wechat_pay.jpg", None),
            (t("gui.alipay"), "alipay.jpg", None),
            (t("gui.buymeacoffee"), "bmc_qr.png", donate_url),
        ]

        for tab_name, img_file, link_url in tab_configs:
            tab = tk.Frame(notebook)
            notebook.add(tab, text=tab_name)

            img_path = os.path.join(assets_dir, img_file)
            if os.path.exists(img_path) and _HAS_PIL:
                try:
                    pil_img = Image.open(img_path)
                    # 缩放到合适大小
                    max_size = (300, 300)
                    pil_img.thumbnail(max_size, Image.LANCZOS)
                    tk_img = ImageTk.PhotoImage(pil_img)
                    dlg._img_refs.append(tk_img)  # 防止 GC

                    img_label = tk.Label(tab, image=tk_img)
                    img_label.pack(pady=10)
                except Exception:
                    tk.Label(tab, text=t("gui.qr_load_failed"), fg="red").pack(pady=20)
            elif os.path.exists(img_path) and not _HAS_PIL:
                # 没有 PIL，尝试用 tkinter 原生加载 PNG
                if img_file.endswith(".png"):
                    try:
                        tk_img = tk.PhotoImage(file=img_path)
                        # 简单缩放（tkinter 原生只能整数倍缩小）
                        w, h = tk_img.width(), tk_img.height()
                        if w > 300 or h > 300:
                            factor = max(w // 300, h // 300, 1)
                            tk_img = tk_img.subsample(factor, factor)
                        dlg._img_refs.append(tk_img)
                        tk.Label(tab, image=tk_img).pack(pady=10)
                    except Exception:
                        tk.Label(tab, text=t("gui.qr_load_failed"), fg="red").pack(pady=20)
                else:
                    tk.Label(
                        tab,
                        text=t("gui.install_pillow"),
                        fg="#888", wraplength=300,
                    ).pack(pady=20)
            else:
                tk.Label(tab, text=t("gui.qr_not_found"), fg="red").pack(pady=20)

            # BuyMeACoffee 额外显示链接
            if link_url:
                link = tk.Label(
                    tab, text=link_url, fg=THEMES[self._current_theme]["link_fg"],
                    font=("", 10, "underline"),
                )
                try:
                    link.configure(cursor="hand2")
                except tk.TclError:
                    pass
                link.pack(pady=(4, 0))
                link.bind("<Button-1>", lambda e, url=link_url: webbrowser.open(url))

        # 关闭按钮
        ttk.Button(
            dlg, text=t("gui.close"), command=dlg.destroy, width=12,
        ).pack(pady=(8, 12))

        # 应用当前主题
        c = THEMES[self._current_theme]
        self._apply_colors_recursive(dlg, c)
        # 恢复标题橙色和链接蓝色
        for child in dlg.winfo_children():
            if isinstance(child, tk.Label):
                try:
                    font = child.cget("font")
                    if "bold" in str(font):
                        child.configure(fg=c["donate_fg"])
                except tk.TclError:
                    pass

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _clear_results(self) -> None:
        # Clear treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        # Clear detail
        self.detail_text.configure(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.configure(state=tk.DISABLED)
        # Clear log
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
        # Clear scanner status labels
        for w in self._scanner_status_inner.winfo_children():
            w.destroy()
        self._scanner_status_labels.clear()

    def run(self) -> None:
        """Start the tkinter main loop."""
        self.root.mainloop()


def launch_gui(*, _skip_init: bool = False) -> None:
    """Entry point to launch the VulnScan GUI."""
    app = VulnScanGUI(_skip_init=_skip_init)
    app.run()


if __name__ == "__main__":
    launch_gui()
