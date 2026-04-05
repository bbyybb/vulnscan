# -*- coding: utf-8 -*-
"""vulnscan.gui 模块单元测试。

测试覆盖:
- 模块级常量 (SEVERITY_COLORS, THEMES)
- launch_gui 入口函数存在性
- VulnScanGUI 类的可独立测试的逻辑方法 (需要 tkinter 环境)
"""

from __future__ import annotations

import os
import platform
from unittest.mock import MagicMock, patch

import pytest


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


def _can_create_tk() -> bool:
    """检测当前环境是否能创建 Tk 窗口。CI 无头环境可能无法创建。"""
    try:
        import tkinter as tk
        root = tk.Tk()
        root.withdraw()
        root.destroy()
        return True
    except Exception:
        return False


# ==================================================================
# 模块级常量测试 (不依赖 tkinter)
# ==================================================================


class TestModuleConstants:
    """GUI 模块级常量测试。"""

    def test_severity_colors_keys(self):
        """SEVERITY_COLORS 应包含所有严重程度级别。"""
        from vulnscan.gui import SEVERITY_COLORS

        expected = {"critical", "high", "medium", "low", "info"}
        assert set(SEVERITY_COLORS.keys()) == expected

    def test_severity_colors_values_format(self):
        """SEVERITY_COLORS 的值应为合法的十六进制颜色字符串。"""
        from vulnscan.gui import SEVERITY_COLORS

        for key, color in SEVERITY_COLORS.items():
            assert color.startswith("#"), f"{key}: {color} 不以 # 开头"
            assert len(color) == 7, f"{key}: {color} 长度应为 7"

    def test_themes_keys(self):
        """THEMES 应包含 light 和 aqua 两个主题。"""
        from vulnscan.gui import THEMES

        assert set(THEMES.keys()) == {"light", "aqua"}

    def test_themes_have_same_keys(self):
        """两个主题应具有完全相同的颜色键集合。"""
        from vulnscan.gui import THEMES

        light_keys = set(THEMES["light"].keys())
        aqua_keys = set(THEMES["aqua"].keys())
        assert light_keys == aqua_keys, (
            f"主题颜色键不匹配。仅 light: {light_keys - aqua_keys}; "
            f"仅 aqua: {aqua_keys - light_keys}"
        )

    def test_themes_required_keys(self):
        """两个主题都应包含核心颜色键。"""
        from vulnscan.gui import THEMES

        required = {"bg", "fg", "entry_bg", "entry_fg", "btn_bg", "btn_fg",
                     "tree_bg", "tree_fg", "text_bg", "text_fg"}
        for name, theme in THEMES.items():
            missing = required - set(theme.keys())
            assert not missing, f"主题 {name} 缺少颜色键: {missing}"

    def test_themes_color_values(self):
        """所有主题颜色值应为合法的十六进制颜色字符串。"""
        from vulnscan.gui import THEMES

        for theme_name, colors in THEMES.items():
            for key, color in colors.items():
                assert color.startswith("#"), f"{theme_name}.{key}: {color}"
                assert len(color) == 7, f"{theme_name}.{key}: {color} 长度应为 7"


# ==================================================================
# launch_gui 测试
# ==================================================================


class TestLaunchGui:
    """launch_gui 入口函数测试。"""

    def test_launch_gui_callable(self):
        """launch_gui 应是可调用的函数。"""
        from vulnscan.gui import launch_gui

        assert callable(launch_gui)

    def test_vulnscan_gui_class_exists(self):
        """VulnScanGUI 类应存在于 gui 模块中。"""
        from vulnscan.gui import VulnScanGUI

        assert hasattr(VulnScanGUI, "run")
        assert hasattr(VulnScanGUI, "__init__")


# ==================================================================
# VulnScanGUI 功能测试 (需要 tkinter)
# ==================================================================


@pytest.mark.skipif(not _can_create_tk(), reason="No display / tkinter unavailable")
class TestVulnScanGUI:
    """VulnScanGUI 功能测试 (需要 tkinter 环境)。"""

    @pytest.fixture
    def gui(self):
        """创建 VulnScanGUI 实例 (不进入 mainloop)。"""
        from vulnscan.gui import VulnScanGUI

        try:
            app = VulnScanGUI(_skip_init=True)
        except Exception:
            pytest.skip("Cannot create tkinter window on this environment")
        app.root.withdraw()  # 隐藏窗口
        yield app
        app.root.destroy()

    # -- 初始化 --

    def test_init_creates_root(self, gui):
        """VulnScanGUI 初始化后应有有效的 root 窗口。"""
        assert gui.root is not None
        assert gui.root.winfo_exists()

    def test_init_default_theme(self, gui):
        """初始化后默认主题应为 light。"""
        assert gui._current_theme == "light"

    def test_init_scanner_vars(self, gui):
        """初始化后 scanner_vars 应包含扫描器列表。"""
        assert isinstance(gui.scanner_vars, list)
        assert len(gui.scanner_vars) > 0

    # -- 主题切换 --

    def test_toggle_theme(self, gui):
        """_toggle_theme 应在 light 和 aqua 之间切换。"""
        assert gui._current_theme == "light"
        gui._toggle_theme()
        assert gui._current_theme == "aqua"
        gui._toggle_theme()
        assert gui._current_theme == "light"

    # -- 语言切换 --

    def test_switch_language(self, gui):
        """_switch_language 应正确切换语言。"""
        from vulnscan.i18n import get_language

        gui._switch_language("zh")
        assert get_language() == "zh"
        gui._switch_language("en")
        assert get_language() == "en"

    # -- 扫描器选择逻辑 --

    def test_get_selected_scanners_all(self, gui):
        """全部选中时应返回 None。"""
        for name, var, avail in gui.scanner_vars:
            if avail:
                var.set(True)
        result = gui._get_selected_scanners()
        assert result is None

    def test_get_selected_scanners_none(self, gui):
        """全部取消选中时应返回 None (空列表回退)。"""
        for name, var, _ in gui.scanner_vars:
            var.set(False)
        result = gui._get_selected_scanners()
        assert result is None

    def test_get_selected_scanners_partial(self, gui):
        """部分选中时应返回选中的扫描器名称列表。"""
        # 取消所有
        for name, var, _ in gui.scanner_vars:
            var.set(False)
        # 只选中第一个
        if gui.scanner_vars:
            first_name, first_var, _ = gui.scanner_vars[0]
            first_var.set(True)
            result = gui._get_selected_scanners()
            assert result is not None
            assert first_name in result

    # -- 模式切换 --

    def test_on_mode_change(self, gui):
        """切换模式不应抛出异常。"""
        gui.scan_mode.set("code")
        gui._on_mode_change()
        assert gui.scan_mode.get() == "code"

        gui.scan_mode.set("web")
        gui._on_mode_change()
        assert gui.scan_mode.get() == "web"

    # -- 日志追加 --

    def test_append_log(self, gui):
        """_append_log 应正确追加文本到日志区域。"""
        import tkinter as tk

        gui._append_log("test log message\n")
        gui.log_text.configure(state=tk.NORMAL)
        content = gui.log_text.get("1.0", tk.END)
        gui.log_text.configure(state=tk.DISABLED)
        assert "test log message" in content

    # -- 结果清除 --

    def test_clear_results(self, gui):
        """_clear_results 不应抛出异常。"""
        gui._clear_results()

    # -- select_all / builtin_only --

    def test_select_all_scanners(self, gui):
        """_select_all_scanners 应选中所有可用的扫描器。"""
        gui._select_all_scanners()
        for name, var, available in gui.scanner_vars:
            if available:
                assert var.get() is True, f"可用扫描器 {name} 应被选中"

    def test_select_builtin_only(self, gui):
        """_select_builtin_only 应只选中内置扫描器。"""
        gui._select_builtin_only()
        from vulnscan.registry import ALL_SCANNERS

        builtin_names = {cls.name for cls in ALL_SCANNERS if cls.is_builtin}
        external_names = {cls.name for cls in ALL_SCANNERS if not cls.is_builtin}

        for name, var, _ in gui.scanner_vars:
            if name in builtin_names:
                assert var.get() is True, f"内置扫描器 {name} 应被选中"
            elif name in external_names:
                assert var.get() is False, f"外部扫描器 {name} 应未被选中"
