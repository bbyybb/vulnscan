# -*- coding: utf-8 -*-
"""vulnscan.i18n 和 vulnscan.locale.messages 模块的单元测试。"""

from __future__ import annotations

import pytest

import vulnscan.i18n as i18n
from vulnscan.i18n import (
    SUPPORTED_LANGUAGES,
    auto_detect_language,
    get_language,
    register_translations,
    set_language,
    t,
)
from vulnscan.locale.messages import (
    CLI_MESSAGES,
    GUI_MESSAGES,
    register_all,
)


@pytest.fixture(autouse=True)
def reset_i18n():
    """重置 i18n 模块状态。"""
    old_lang = i18n._current_lang
    old_trans = i18n._translations.copy()
    yield
    i18n._current_lang = old_lang
    i18n._translations = old_trans


# ------------------------------------------------------------------
# 1. test_default_language
# ------------------------------------------------------------------
def test_default_language():
    """默认语言应为中文。"""
    set_language("zh")  # 重置为默认值
    assert get_language() == "zh"


# ------------------------------------------------------------------
# 2. test_set_language_zh
# ------------------------------------------------------------------
def test_set_language_zh():
    set_language("zh")
    assert get_language() == "zh"


# ------------------------------------------------------------------
# 3. test_set_language_invalid
# ------------------------------------------------------------------
def test_set_language_invalid():
    original = get_language()
    set_language("fr")
    assert get_language() == original


# ------------------------------------------------------------------
# 4. test_register_and_translate
# ------------------------------------------------------------------
def test_register_and_translate():
    register_translations({
        "test.greeting": {"en": "Hello", "zh": "你好"},
    })
    set_language("en")
    assert t("test.greeting") == "Hello"
    set_language("zh")
    assert t("test.greeting") == "你好"


# ------------------------------------------------------------------
# 5. test_translate_with_kwargs
# ------------------------------------------------------------------
def test_translate_with_kwargs():
    register_translations({
        "test.hello": {"en": "Hello {name}", "zh": "你好 {name}"},
    })
    set_language("en")
    assert t("test.hello", name="test") == "Hello test"


# ------------------------------------------------------------------
# 6. test_translate_missing_key
# ------------------------------------------------------------------
def test_translate_missing_key():
    assert t("nonexistent") == "nonexistent"


# ------------------------------------------------------------------
# 7. test_translate_fallback_to_en
# ------------------------------------------------------------------
def test_translate_fallback_to_en():
    register_translations({
        "test.only_en": {"en": "English only"},
    })
    set_language("zh")
    assert t("test.only_en") == "English only"


# ------------------------------------------------------------------
# 8. test_auto_detect_env_var
# ------------------------------------------------------------------
def test_auto_detect_env_var(monkeypatch):
    monkeypatch.setenv("VULNSCAN_LANG", "zh")
    assert auto_detect_language() == "zh"


# ------------------------------------------------------------------
# 9. test_auto_detect_env_var_en
# ------------------------------------------------------------------
def test_auto_detect_env_var_en(monkeypatch):
    monkeypatch.setenv("VULNSCAN_LANG", "en")
    assert auto_detect_language() == "en"


# ------------------------------------------------------------------
# 10. test_auto_detect_no_env
# ------------------------------------------------------------------
def test_auto_detect_no_env(monkeypatch):
    monkeypatch.delenv("VULNSCAN_LANG", raising=False)
    result = auto_detect_language()
    assert result in ("en", "zh")


# ------------------------------------------------------------------
# 11. test_register_all_messages
# ------------------------------------------------------------------
def test_register_all_messages():
    register_all()
    result = t("cli.desc")
    assert result != "cli.desc"


# ------------------------------------------------------------------
# 12. test_all_gui_messages_have_both_langs
# ------------------------------------------------------------------
def test_all_gui_messages_have_both_langs():
    register_all()
    for key, entry in GUI_MESSAGES.items():
        for lang in SUPPORTED_LANGUAGES:
            assert lang in entry, f"GUI_MESSAGES[{key!r}] 缺少语言 {lang!r}"
            assert entry[lang], f"GUI_MESSAGES[{key!r}][{lang!r}] 为空"


# ------------------------------------------------------------------
# 13. test_all_cli_messages_have_both_langs
# ------------------------------------------------------------------
def test_all_cli_messages_have_both_langs():
    register_all()
    for key, entry in CLI_MESSAGES.items():
        for lang in SUPPORTED_LANGUAGES:
            assert lang in entry, f"CLI_MESSAGES[{key!r}] 缺少语言 {lang!r}"
            assert entry[lang], f"CLI_MESSAGES[{key!r}][{lang!r}] 为空"


# ------------------------------------------------------------------
# 14. test_language_switch
# ------------------------------------------------------------------
def test_language_switch():
    register_all()
    set_language("en")
    en_text = t("gui.title")
    set_language("zh")
    zh_text = t("gui.title")
    assert en_text != zh_text
    assert en_text == "VulnScan - Vulnerability Scanner"
    assert zh_text == "VulnScan - 漏洞扫描器"
