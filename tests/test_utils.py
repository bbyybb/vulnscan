# -*- coding: utf-8 -*-
"""vulnscan.utils 工具函数单元测试。"""

from __future__ import annotations

import os
from unittest.mock import patch

from vulnscan.utils import get_base_dir, is_url, normalize_url, parse_curl, parse_host_port, walk_source_files


class TestGetBaseDir:
    """get_base_dir 测试。"""

    def test_get_base_dir_normal_mode(self):
        """非打包模式下应返回 vulnscan 包所在目录。"""
        base = get_base_dir()
        # 应该是 vulnscan 包的目录（包含 utils.py 等文件）
        assert os.path.isdir(base)
        assert os.path.isfile(os.path.join(base, "utils.py"))

    def test_get_base_dir_frozen_with_vulnscan_subdir(self, tmp_path):
        """PyInstaller 打包模式下，若 _MEIPASS/vulnscan 存在则返回该路径。"""
        meipass = str(tmp_path / "meipass")
        vulnscan_dir = os.path.join(meipass, "vulnscan")
        os.makedirs(vulnscan_dir)

        with patch("vulnscan.utils.sys") as mock_sys:
            mock_sys.frozen = True
            mock_sys._MEIPASS = meipass
            result = get_base_dir()

        assert result == vulnscan_dir

    def test_get_base_dir_frozen_without_vulnscan_subdir(self, tmp_path):
        """PyInstaller 打包模式下，若 _MEIPASS/vulnscan 不存在则返回 _MEIPASS。"""
        meipass = str(tmp_path / "meipass")
        os.makedirs(meipass)

        with patch("vulnscan.utils.sys") as mock_sys:
            mock_sys.frozen = True
            mock_sys._MEIPASS = meipass
            result = get_base_dir()

        assert result == meipass


class TestParseHostPort:
    """parse_host_port 测试。"""

    def test_parse_host_port_https(self):
        """HTTPS URL 应解析出 host 和默认端口 443。"""
        host, port = parse_host_port("https://example.com")
        assert host == "example.com"
        assert port == 443

    def test_parse_host_port_http(self):
        """带显式端口的 HTTP URL 应正确解析。"""
        host, port = parse_host_port("http://example.com:8080")
        assert host == "example.com"
        assert port == 8080

    def test_parse_host_port_no_port(self):
        """HTTP URL 无端口时应返回默认端口 80。"""
        host, port = parse_host_port("http://example.com")
        assert host == "example.com"
        assert port == 80

    def test_parse_host_port_https_custom_port(self):
        """HTTPS URL 带自定义端口。"""
        host, port = parse_host_port("https://example.com:8443")
        assert host == "example.com"
        assert port == 8443

    def test_parse_host_port_with_path(self):
        """带路径的 URL 仍能正确解析 host 和 port。"""
        host, port = parse_host_port("http://example.com:3000/api/v1")
        assert host == "example.com"
        assert port == 3000


class TestNormalizeUrl:
    """normalize_url 测试。"""

    def test_normalize_url_no_scheme(self):
        """无 scheme 时应添加 http://。"""
        assert normalize_url("example.com") == "http://example.com"

    def test_normalize_url_with_http(self):
        """已有 http:// 时不做修改。"""
        assert normalize_url("http://example.com") == "http://example.com"

    def test_normalize_url_with_https(self):
        """已有 https:// 时不做修改。"""
        assert normalize_url("https://example.com") == "https://example.com"

    def test_normalize_url_trailing_slash(self):
        """尾部斜杠应被移除。"""
        assert normalize_url("http://example.com/") == "http://example.com"

    def test_normalize_url_case_insensitive(self):
        """scheme 大小写不敏感。"""
        result = normalize_url("HTTP://Example.com")
        assert result == "HTTP://Example.com"


class TestIsUrl:
    """is_url 测试。"""

    def test_is_url_http(self):
        assert is_url("http://example.com") is True

    def test_is_url_https(self):
        assert is_url("https://example.com") is True

    def test_is_url_no_scheme(self):
        assert is_url("example.com") is False

    def test_is_url_file_path(self):
        assert is_url("/home/user/code") is False

    def test_is_url_ftp(self):
        assert is_url("ftp://example.com") is False

    def test_is_url_empty(self):
        assert is_url("") is False


class TestParseCurl:
    """parse_curl 测试。"""

    def test_parse_curl_simple_url(self):
        url, headers, cookies, data, method = parse_curl(
            "curl https://example.com"
        )
        assert url == "https://example.com"
        assert method == "GET"
        assert headers == {}
        assert cookies == ""
        assert data == ""

    def test_parse_curl_with_headers(self):
        url, headers, cookies, data, method = parse_curl(
            'curl -H "Authorization: Bearer token123" -H "Accept: application/json" https://api.example.com'
        )
        assert url == "https://api.example.com"
        assert headers["Authorization"] == "Bearer token123"
        assert headers["Accept"] == "application/json"

    def test_parse_curl_with_cookies(self):
        url, headers, cookies, data, method = parse_curl(
            'curl -b "session=abc; user=test" https://example.com'
        )
        assert cookies == "session=abc; user=test"

    def test_parse_curl_with_cookie_header(self):
        url, headers, cookies, data, method = parse_curl(
            'curl -H "Cookie: session=abc" https://example.com'
        )
        assert cookies == "session=abc"
        assert "Cookie" not in headers

    def test_parse_curl_post_with_data(self):
        url, headers, cookies, data, method = parse_curl(
            'curl -d "username=admin&password=123" https://example.com/login'
        )
        assert url == "https://example.com/login"
        assert data == "username=admin&password=123"
        assert method == "POST"  # -d 自动设置 POST

    def test_parse_curl_explicit_method(self):
        url, headers, cookies, data, method = parse_curl(
            "curl -X PUT https://example.com/api/resource"
        )
        assert method == "PUT"

    def test_parse_curl_multiline(self):
        cmd = """curl 'https://example.com/api' \\
        -H 'Content-Type: application/json' \\
        -d '{"key": "value"}'"""
        url, headers, cookies, data, method = parse_curl(cmd)
        assert url == "https://example.com/api"
        assert headers["Content-Type"] == "application/json"
        assert data == '{"key": "value"}'

    def test_parse_curl_empty(self):
        url, headers, cookies, data, method = parse_curl("")
        assert url == ""


class TestWalkSourceFiles:
    """walk_source_files 测试。"""

    def test_walk_source_files_filters_by_extension(self, tmp_path):
        """只 yield 符合扩展名的文件，忽略其他文件。"""
        # 创建 .py 文件
        py1 = tmp_path / "app.py"
        py1.write_text("print('hello')", encoding="utf-8")

        py2 = tmp_path / "utils.py"
        py2.write_text("x = 1", encoding="utf-8")

        # 创建 .txt 文件（不在默认 _SOURCE_EXTENSIONS 中）
        txt = tmp_path / "readme.txt"
        txt.write_text("readme", encoding="utf-8")

        # 创建 .md 文件
        md = tmp_path / "notes.md"
        md.write_text("notes", encoding="utf-8")

        results = list(walk_source_files(str(tmp_path)))
        result_names = {os.path.basename(f) for f in results}

        assert "app.py" in result_names
        assert "utils.py" in result_names
        # .txt 和 .md 不在默认源文件扩展名中
        assert "readme.txt" not in result_names
        assert "notes.md" not in result_names

    def test_walk_source_files_custom_extensions(self, tmp_path):
        """使用自定义 extensions 过滤。"""
        py = tmp_path / "test.py"
        py.write_text("pass", encoding="utf-8")

        txt = tmp_path / "data.txt"
        txt.write_text("data", encoding="utf-8")

        results = list(walk_source_files(str(tmp_path), extensions={".txt"}))
        result_names = {os.path.basename(f) for f in results}
        assert "data.txt" in result_names
        assert "test.py" not in result_names

    def test_walk_source_files_skips_dirs(self, tmp_path):
        """默认跳过 __pycache__、node_modules 等目录。"""
        # 正常目录
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("pass", encoding="utf-8")

        # 应被跳过的目录
        cache = tmp_path / "__pycache__"
        cache.mkdir()
        (cache / "cached.py").write_text("pass", encoding="utf-8")

        results = list(walk_source_files(str(tmp_path)))
        result_names = {os.path.basename(f) for f in results}

        assert "main.py" in result_names
        assert "cached.py" not in result_names

    def test_walk_source_files_single_file(self, tmp_path):
        """传入单文件路径时直接 yield 该文件。"""
        f = tmp_path / "single.py"
        f.write_text("pass", encoding="utf-8")

        results = list(walk_source_files(str(f)))
        assert len(results) == 1
        assert results[0] == str(f)

    def test_walk_source_files_empty_dir(self, tmp_path):
        """空目录返回空列表。"""
        results = list(walk_source_files(str(tmp_path)))
        assert results == []

    def test_walk_source_files_single_file_wrong_extension(self, tmp_path):
        """传入单文件路径但扩展名不匹配时不应 yield。"""
        f = tmp_path / "readme.txt"
        f.write_text("some text", encoding="utf-8")

        results = list(walk_source_files(str(f)))
        assert results == []

    def test_walk_source_files_single_file_exceeds_max_size(self, tmp_path):
        """传入单文件路径但文件超过 max_size 时不应 yield。"""
        f = tmp_path / "large.py"
        f.write_text("x" * 200, encoding="utf-8")

        results = list(walk_source_files(str(f), max_size=100))
        assert results == []


class TestParseCurlAdditional:
    """parse_curl 补充测试。"""

    def test_parse_curl_unknown_flag_does_not_skip_url(self):
        """未知选项不应导致 URL 被跳过。"""
        url, headers, cookies, data, method = parse_curl(
            "curl --unknown-flag https://example.com"
        )
        assert url == "https://example.com"
        assert method == "GET"
