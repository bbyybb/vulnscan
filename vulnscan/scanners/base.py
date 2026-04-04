"""扫描器抽象基类

Scanner:         所有扫描器的公共接口
ExternalScanner: 依赖外部可执行文件的扫描器基类
"""

from __future__ import annotations

import json
import locale
import logging
import os
import platform
import shutil
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Optional

from vulnscan.models import HttpOptions, ScanResult, ScanType

_PLATFORM = platform.system()  # "Windows", "Darwin", "Linux"
_logger = logging.getLogger(__name__)

# 用户自定义工具路径配置文件
_TOOL_PATHS_FILE = os.path.join(
    os.path.expanduser("~"), ".vulnscan", "tool_paths.json"
)


def load_tool_paths() -> dict[str, str]:
    """加载用户自定义的工具路径配置。"""
    try:
        with open(_TOOL_PATHS_FILE, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_tool_path(tool_name: str, exe_path: str) -> None:
    """保存单个工具的自定义路径。传空字符串可删除配置。"""
    paths = load_tool_paths()
    if exe_path:
        paths[tool_name] = exe_path
    else:
        paths.pop(tool_name, None)
    os.makedirs(os.path.dirname(_TOOL_PATHS_FILE), exist_ok=True)
    with open(_TOOL_PATHS_FILE, "w", encoding="utf-8") as f:
        json.dump(paths, f, indent=2, ensure_ascii=False)


class Scanner(ABC):
    """所有扫描器的抽象基类"""

    name: str = "BaseScanner"
    description: str = ""
    scan_type: ScanType = ScanType.DAST
    is_builtin: bool = True
    target_mode: str = "url"  # "url" / "file" / "both"

    @abstractmethod
    def run(
        self,
        target: str,
        callback: Optional[Callable[[str], None]] = None,
        http_options: Optional[HttpOptions] = None,
    ) -> ScanResult:
        """执行扫描。

        Args:
            target:       扫描目标 (URL 或 文件/目录路径)
            callback:     进度回调 fn(message)
            http_options: 自定义 HTTP 请求选项 (仅 Web 扫描器使用)

        Returns:
            ScanResult
        """
        ...

    def is_available(self) -> tuple[bool, str]:
        """检查扫描器是否可用。"""
        if self.is_builtin:
            return True, "builtin"
        return False, "not implemented"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} builtin={self.is_builtin}>"


class ExternalScanner(Scanner):
    """依赖外部命令行工具的扫描器基类"""

    is_builtin: bool = False
    executable: str = ""
    install_hint: str = ""  # fallback; subclasses can override get_install_hint()

    def get_install_hint(self) -> str:
        """Return platform-specific installation instructions."""
        return self.install_hint

    def get_install_url(self) -> str:
        """Return platform-specific download URL. Subclasses should override."""
        return ""

    # 可作为工具的脚本扩展名
    _SCRIPT_EXTS = {".py", ".pl", ".rb", ".sh", ".bat", ".cmd", ".jar", ".ps1"}

    def is_available(self) -> tuple[bool, str]:
        # 优先使用用户配置的自定义路径
        custom_paths = load_tool_paths()
        custom = custom_paths.get(self.name, "")
        if custom and os.path.isfile(custom):
            # 安全校验: 路径必须是绝对路径，且不能包含可疑的目录遍历
            custom_path = Path(custom).resolve()
            if not custom_path.is_absolute() or ".." in Path(custom).parts:
                _logger.warning(
                    "自定义路径 %s 包含不安全的路径成分，已忽略: %s",
                    self.name, custom,
                )
            else:
                custom = str(custom_path)
                ext = os.path.splitext(custom)[1].lower()
                if shutil.which(custom):
                    self.executable = custom
                    return True, f"custom path: {custom}"
                elif ext in self._SCRIPT_EXTS:
                    # .py/.pl 等脚本文件视为有效
                    self.executable = custom
                    return True, f"custom path (script): {custom}"
                else:
                    _logger.warning(
                        "自定义路径 %s 不是有效的可执行文件，已忽略: %s",
                        self.name, custom,
                    )

        path = shutil.which(self.executable)
        if path:
            return True, f"found at {path}"
        return False, f"'{self.executable}' not found in PATH. {self.get_install_hint()}"

    # 脚本扩展名 -> 解释器映射
    _INTERPRETERS: dict[str, list[str]] = {
        ".py": [sys.executable],
        ".pl": ["perl"],
        ".rb": ["ruby"],
        ".jar": ["java", "-jar"],
        ".ps1": ["powershell", "-ExecutionPolicy", "Bypass", "-File"],
    }

    def _run_command(
        self, args: list[str], timeout: int = 300
    ) -> subprocess.CompletedProcess:
        """安全执行外部命令。自动为脚本文件加上解释器前缀。"""
        # 如果第一个参数是脚本文件, 自动加上解释器
        if args:
            ext = os.path.splitext(args[0])[1].lower()
            interpreter = self._INTERPRETERS.get(ext)
            if interpreter:
                args = interpreter + args

        # Windows 中文系统上外部工具可能输出 GBK 编码, 优先使用系统编码
        encoding = "utf-8"
        if _PLATFORM == "Windows":
            try:
                encoding = locale.getpreferredencoding(False) or "utf-8"
            except Exception:
                pass

        kwargs = dict(
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding=encoding,
            errors="replace",
        )
        if _PLATFORM == "Windows":
            kwargs["creationflags"] = getattr(
                subprocess, "CREATE_NO_WINDOW", 0
            )

        result = subprocess.run(args, **kwargs)

        # 记录 stderr 用于调试
        if result.stderr and result.stderr.strip():
            _logger.debug(
                "[%s] stderr: %s", args[0], result.stderr[:500]
            )

        return result
