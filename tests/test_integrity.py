# -*- coding: utf-8 -*-
"""vulnscan.integrity 模块的单元测试。"""

from __future__ import annotations

import hashlib
import sys
from unittest.mock import patch

import pytest

import vulnscan.integrity as integrity
from vulnscan.integrity import (
    _decode_fragment,
    _encode_fragment,
    _hash_file,
    _hash_string,
    _reassemble,
    deferred_asset_check,
    full_integrity_check,
    get_assets_dir,
    get_protected_author,
    get_protected_donate_url,
    get_seal,
    require_seal,
    startup_check,
    verify_assets,
    verify_author,
    verify_donate_url,
)


@pytest.fixture(autouse=True)
def reset_seal():
    """每个测试后重置 integrity 模块的全局状态。"""
    yield
    integrity._seal = None
    integrity._seal_timestamp = 0.0


# ------------------------------------------------------------------
# 1. test_get_protected_author
# ------------------------------------------------------------------
def test_get_protected_author():
    assert get_protected_author() == "白白LOVE尹尹"


# ------------------------------------------------------------------
# 2. test_get_protected_donate_url
# ------------------------------------------------------------------
def test_get_protected_donate_url():
    assert get_protected_donate_url() == "https://buymeacoffee.com/bbyybb"


# ------------------------------------------------------------------
# 3. test_get_assets_dir
# ------------------------------------------------------------------
def test_get_assets_dir():
    import os

    path = get_assets_dir()
    assert os.path.isdir(path)
    assert "assets" in path


# ------------------------------------------------------------------
# 4. test_verify_author_correct
# ------------------------------------------------------------------
def test_verify_author_correct():
    assert verify_author("白白LOVE尹尹") is True


# ------------------------------------------------------------------
# 5. test_verify_author_tampered
# ------------------------------------------------------------------
def test_verify_author_tampered():
    assert verify_author("hacker") is False


# ------------------------------------------------------------------
# 6. test_verify_donate_url_correct
# ------------------------------------------------------------------
def test_verify_donate_url_correct():
    assert verify_donate_url("https://buymeacoffee.com/bbyybb") is True


# ------------------------------------------------------------------
# 7. test_verify_donate_url_tampered
# ------------------------------------------------------------------
def test_verify_donate_url_tampered():
    assert verify_donate_url("https://evil.com") is False


# ------------------------------------------------------------------
# 8. test_verify_assets
# ------------------------------------------------------------------
def test_verify_assets():
    assert verify_assets() is True


# ------------------------------------------------------------------
# 9. test_verify_assets_tampered
# ------------------------------------------------------------------
def test_verify_assets_tampered():
    with patch.object(integrity, "_hash_file", return_value="0" * 64):
        assert verify_assets() is False


# ------------------------------------------------------------------
# 10. test_full_integrity_check
# ------------------------------------------------------------------
def test_full_integrity_check():
    assert full_integrity_check() is True


# ------------------------------------------------------------------
# 11. test_full_integrity_check_fail
# ------------------------------------------------------------------
def test_full_integrity_check_fail():
    with patch.object(integrity, "verify_author", return_value=False):
        assert full_integrity_check() is False


# ------------------------------------------------------------------
# 12. test_seal_after_check
# ------------------------------------------------------------------
def test_seal_after_check():
    full_integrity_check()
    assert get_seal() is not None


# ------------------------------------------------------------------
# 13. test_require_seal
# ------------------------------------------------------------------
def test_require_seal():
    result = require_seal()
    assert result != 0
    assert isinstance(result, int)


# ------------------------------------------------------------------
# 14. test_deferred_asset_check
# ------------------------------------------------------------------
def test_deferred_asset_check():
    assert deferred_asset_check() is True


# ------------------------------------------------------------------
# 15. test_encode_decode_roundtrip
# ------------------------------------------------------------------
def test_encode_decode_roundtrip():
    original = "hello_world_1234"
    encoded = _encode_fragment(original)
    decoded = _decode_fragment(encoded)
    assert decoded == original


# ------------------------------------------------------------------
# 16. test_reassemble
# ------------------------------------------------------------------
def test_reassemble():
    parts = [_encode_fragment("aaaa"), _encode_fragment("bbbb")]
    assert _reassemble(parts) == "aaaabbbb"


# ------------------------------------------------------------------
# 17. test_hash_string
# ------------------------------------------------------------------
def test_hash_string():
    expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert _hash_string("test") == expected


# ------------------------------------------------------------------
# 18. test_hash_file_nonexistent
# ------------------------------------------------------------------
def test_hash_file_nonexistent():
    assert _hash_file("nonexistent_file_that_does_not_exist.xyz") == ""


# ------------------------------------------------------------------
# 19. test_startup_check_pass
# ------------------------------------------------------------------
def test_startup_check_pass():
    # 资源完好时 startup_check 不应抛出异常
    startup_check()


# ------------------------------------------------------------------
# 20. test_startup_check_fail
# ------------------------------------------------------------------
def test_startup_check_fail():
    with patch.object(integrity, "full_integrity_check", return_value=False):
        with pytest.raises(SystemExit) as exc_info:
            startup_check()
        assert exc_info.value.code == 1
