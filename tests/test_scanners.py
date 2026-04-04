# -*- coding: utf-8 -*-
"""扫描器基类和注册表测试。"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import pytest

from vulnscan.models import ScanResult, ScanType
from vulnscan.registry import ALL_SCANNERS, check_all_tools, get_scanners_for_mode
from vulnscan.scanners.base import ExternalScanner, Scanner, load_tool_paths, save_tool_path


class TestScannerBase:
    """Scanner 抽象基类测试。"""

    def test_scanner_base_interface(self):
        """Scanner 是抽象类，不能直接实例化。"""
        with pytest.raises(TypeError):
            Scanner()  # type: ignore[abstract]

    def test_scanner_subclass_must_implement_run(self):
        """子类必须实现 run 方法才能实例化。"""

        class IncompleteScanner(Scanner):
            name = "Incomplete"

        with pytest.raises(TypeError):
            IncompleteScanner()  # type: ignore[abstract]

    def test_scanner_subclass_with_run(self):
        """实现了 run 方法的子类可以正常实例化。"""

        class CompleteScanner(Scanner):
            name = "Complete"

            def run(self, target, callback=None):
                return ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    target=target,
                )

        scanner = CompleteScanner()
        assert scanner.name == "Complete"
        assert scanner.is_builtin is True

        available, reason = scanner.is_available()
        assert available is True
        assert reason == "builtin"


class TestExternalScanner:
    """ExternalScanner 基类测试。"""

    def test_external_scanner_not_available(self):
        """不存在的可执行文件应返回 (False, ...)。"""

        class FakeExternalScanner(ExternalScanner):
            name = "FakeExternal"
            executable = "nonexistent_tool_xyz_12345"
            install_hint = "Install it somehow"

            def run(self, target, callback=None):
                return ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    target=target,
                )

        scanner = FakeExternalScanner()
        available, reason = scanner.is_available()

        assert available is False
        assert "nonexistent_tool_xyz_12345" in reason
        assert scanner.is_builtin is False

    def test_external_scanner_repr(self):
        """验证 __repr__ 格式。"""

        class DummyExternal(ExternalScanner):
            name = "Dummy"
            executable = "dummy"

            def run(self, target, callback=None):
                return ScanResult(
                    scanner_name=self.name,
                    scan_type=self.scan_type,
                    target=target,
                )

        scanner = DummyExternal()
        r = repr(scanner)
        assert "DummyExternal" in r
        assert "Dummy" in r
        assert "builtin=False" in r


class TestRegistry:
    """扫描器注册表测试。"""

    def test_registry_all_scanners_count(self):
        """ALL_SCANNERS 应包含 16 个扫描器 (7 内置 + 9 外部)。"""
        assert len(ALL_SCANNERS) == 16

    def test_get_scanners_for_mode_web(self):
        """web 模式返回的扫描器的 target_mode 都是 'url' 或 'both'。"""
        web_scanners = get_scanners_for_mode("web")
        assert len(web_scanners) > 0
        for cls in web_scanners:
            assert cls.target_mode in ("url", "both"), (
                f"{cls.name} 的 target_mode={cls.target_mode} 不适用于 web 模式"
            )

    def test_get_scanners_for_mode_code(self):
        """code 模式返回的扫描器的 target_mode 都是 'file' 或 'both'。"""
        code_scanners = get_scanners_for_mode("code")
        assert len(code_scanners) > 0
        for cls in code_scanners:
            assert cls.target_mode in ("file", "both"), (
                f"{cls.name} 的 target_mode={cls.target_mode} 不适用于 code 模式"
            )

    def test_get_scanners_for_mode_full(self):
        """full 模式返回所有扫描器。"""
        full_scanners = get_scanners_for_mode("full")
        assert len(full_scanners) == len(ALL_SCANNERS)

    def test_check_all_tools(self):
        """验证 check_all_tools 返回列表长度和字段存在性。"""
        results = check_all_tools()
        assert len(results) == len(ALL_SCANNERS)

        for item in results:
            assert "name" in item
            assert "description" in item
            assert "builtin" in item
            assert "available" in item
            assert "reason" in item
            assert "target_mode" in item
            assert "scan_type" in item
            assert isinstance(item["available"], bool)
            assert isinstance(item["builtin"], bool)

    def test_check_all_tools_builtin_available(self):
        """所有内置扫描器应可用。"""
        results = check_all_tools()
        for item in results:
            if item["builtin"]:
                assert item["available"] is True, (
                    f"内置扫描器 {item['name']} 应始终可用"
                )


class TestLoadToolPaths:
    """load_tool_paths 函数测试。"""

    def test_load_tool_paths_file_not_exists(self, tmp_path):
        """配置文件不存在时应返回空字典。"""
        fake_path = str(tmp_path / "nonexistent" / "tool_paths.json")
        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", fake_path):
            result = load_tool_paths()
        assert result == {}

    def test_load_tool_paths_valid_json(self, tmp_path):
        """配置文件包含有效 JSON 时应正确加载。"""
        config_file = tmp_path / "tool_paths.json"
        data = {"nmap": "/usr/bin/nmap", "nikto": "/usr/bin/nikto"}
        config_file.write_text(json.dumps(data), encoding="utf-8")

        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", str(config_file)):
            result = load_tool_paths()
        assert result == data

    def test_load_tool_paths_invalid_json(self, tmp_path):
        """配置文件包含无效 JSON 时应返回空字典。"""
        config_file = tmp_path / "tool_paths.json"
        config_file.write_text("{invalid json!!!", encoding="utf-8")

        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", str(config_file)):
            result = load_tool_paths()
        assert result == {}

    def test_load_tool_paths_non_dict_json(self, tmp_path):
        """配置文件包含非 dict 类型的 JSON 时应返回空字典。"""
        config_file = tmp_path / "tool_paths.json"
        config_file.write_text('["not", "a", "dict"]', encoding="utf-8")

        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", str(config_file)):
            result = load_tool_paths()
        assert result == {}


class TestSaveToolPath:
    """save_tool_path 函数测试。"""

    def test_save_tool_path_creates_file_and_dir(self, tmp_path):
        """保存工具路径时应自动创建目录和文件。"""
        config_file = str(tmp_path / "subdir" / "tool_paths.json")
        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", config_file):
            save_tool_path("nmap", "/usr/local/bin/nmap")

        assert os.path.isfile(config_file)
        with open(config_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data == {"nmap": "/usr/local/bin/nmap"}

    def test_save_tool_path_updates_existing(self, tmp_path):
        """已有配置时应更新对应条目而不影响其他条目。"""
        config_file = str(tmp_path / "tool_paths.json")
        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", config_file):
            save_tool_path("nmap", "/usr/bin/nmap")
            save_tool_path("nikto", "/usr/bin/nikto")

        with open(config_file, encoding="utf-8") as f:
            data = json.load(f)
        assert data == {"nmap": "/usr/bin/nmap", "nikto": "/usr/bin/nikto"}

    def test_save_tool_path_empty_string_removes_entry(self, tmp_path):
        """传入空字符串应删除对应工具的配置。"""
        config_file = str(tmp_path / "tool_paths.json")
        with patch("vulnscan.scanners.base._TOOL_PATHS_FILE", config_file):
            save_tool_path("nmap", "/usr/bin/nmap")
            save_tool_path("nikto", "/usr/bin/nikto")
            # 用空字符串删除 nmap 条目
            save_tool_path("nmap", "")

        with open(config_file, encoding="utf-8") as f:
            data = json.load(f)
        assert "nmap" not in data
        assert data == {"nikto": "/usr/bin/nikto"}
