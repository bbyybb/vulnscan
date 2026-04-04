"""通用工具函数"""

from __future__ import annotations

import os
import shlex
import sys
import re
from urllib.parse import urlparse


def get_base_dir() -> str:
    """获取项目基础目录。

    兼容 PyInstaller 打包后的 sys._MEIPASS 路径
    和源码直接运行时的 __file__ 路径。
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        # PyInstaller 解压目录下数据在 vulnscan/ 子目录
        # (因为 --add-data 的目标路径是 vulnscan/data 等)
        base = os.path.join(sys._MEIPASS, "vulnscan")
        if os.path.isdir(base):
            return base
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def parse_host_port(url: str) -> tuple[str, int]:
    """从 URL 提取 hostname 和 port。"""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port
    if not port:
        port = 443 if parsed.scheme == "https" else 80
    return host, port


def normalize_url(url: str) -> str:
    """确保 URL 有 scheme。"""
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url.rstrip("/")


def is_url(target: str) -> bool:
    """判断 target 是否为 URL。"""
    return bool(re.match(r"^https?://", target, re.I))


def parse_curl(curl_cmd: str) -> tuple[str, dict[str, str], str, str, str]:
    """解析 curl 命令，提取 URL 和 HTTP 选项。

    Returns:
        (url, headers_dict, cookies_str, data_str, method_str)
    """
    # 预处理: 去掉换行续行符
    cmd = curl_cmd.replace("\\\n", " ").replace("\\\r\n", " ").strip()
    # 去掉开头的 "curl" 词
    if cmd.lower().startswith("curl"):
        cmd = cmd[4:].strip()

    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        # shlex 解析失败时回退简单 split
        tokens = cmd.split()

    url = ""
    headers: dict[str, str] = {}
    cookies = ""
    data = ""
    method = "GET"

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok in ("-H", "--header") and i + 1 < len(tokens):
            i += 1
            val = tokens[i]
            if ":" in val:
                key, _, value = val.partition(":")
                key = key.strip()
                value = value.strip()
                if key.lower() == "cookie":
                    cookies = value
                else:
                    headers[key] = value
        elif tok in ("-b", "--cookie") and i + 1 < len(tokens):
            i += 1
            cookies = tokens[i]
        elif tok in ("-d", "--data", "--data-raw", "--data-binary") and i + 1 < len(tokens):
            i += 1
            data = tokens[i]
            if method == "GET":
                method = "POST"
        elif tok in ("-X", "--request") and i + 1 < len(tokens):
            i += 1
            method = tokens[i].upper()
        elif not tok.startswith("-") and not url:
            # 位置参数视为 URL
            url = tok
        # 跳过其他 curl 选项
        elif tok in ("-k", "--insecure", "-s", "--silent", "-v", "--verbose",
                      "-L", "--location", "--compressed"):
            pass  # 无参数选项, 直接跳过
        elif tok.startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            # 有参数的未知选项, 跳过参数 (但若下一个 token 像 URL 则不跳)
            next_tok = tokens[i + 1]
            if not re.match(r"^https?://", next_tok, re.I):
                i += 1

        i += 1

    return url, headers, cookies, data, method


_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".php",
    ".rb", ".go", ".c", ".cpp", ".h", ".cs", ".html",
    ".xml", ".yml", ".yaml", ".json", ".env", ".cfg",
    ".ini", ".conf", ".sh", ".bat", ".ps1",
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".idea", ".vscode", ".pytest_cache",
    "vendor", "target", "bin", "obj",
}


def walk_source_files(
    directory: str,
    extensions: set[str] | None = None,
    skip_dirs: set[str] | None = None,
    max_size: int = 1_048_576,
):
    """遍历目录，yield 所有符合条件的源码文件路径。"""
    if extensions is None:
        extensions = _SOURCE_EXTENSIONS
    if skip_dirs is None:
        skip_dirs = _SKIP_DIRS

    if os.path.isfile(directory):
        _, ext = os.path.splitext(directory)
        if ext.lower() in extensions:
            try:
                if os.path.getsize(directory) <= max_size:
                    yield directory
            except OSError:
                pass
        return

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            _, ext = os.path.splitext(fname)
            if ext.lower() in extensions:
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) <= max_size:
                        yield fpath
                except OSError:
                    continue
