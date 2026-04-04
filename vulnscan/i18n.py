"""国际化支持模块"""

from __future__ import annotations

import locale
import os

# 支持的语言
SUPPORTED_LANGUAGES = ("en", "zh")
_current_lang = "en"  # 默认英文 (启动时由 auto_detect_language 覆盖)

# 翻译字典: key -> {lang: text}
_translations: dict[str, dict[str, str]] = {}


def set_language(lang: str) -> None:
    """设置当前语言"""
    global _current_lang
    if lang in SUPPORTED_LANGUAGES:
        _current_lang = lang


def get_language() -> str:
    """获取当前语言"""
    return _current_lang


def auto_detect_language() -> str:
    """自动检测系统语言

    优先级:
    1. VULNSCAN_LANG 环境变量
    2. 系统 locale
    3. 默认英文
    """
    # 优先读取环境变量 VULNSCAN_LANG
    env_lang = os.environ.get("VULNSCAN_LANG", "")
    if env_lang in SUPPORTED_LANGUAGES:
        return env_lang
    # 其次读系统 locale
    try:
        sys_locale = locale.getlocale()[0] or ""
    except Exception:
        sys_locale = ""
    if sys_locale.startswith("zh"):
        return "zh"
    return "en"


def t(key: str, **kwargs: object) -> str:
    """翻译函数。支持 {placeholder} 替换。

    如果找不到翻译条目则返回 key 本身作为 fallback。
    """
    entry = _translations.get(key)
    if entry is None:
        return key  # fallback: 返回 key 本身
    text = entry.get(_current_lang, entry.get("en", key))
    if kwargs:
        text = text.format(**kwargs)
    return text


def register_translations(translations: dict[str, dict[str, str]]) -> None:
    """注册翻译条目"""
    _translations.update(translations)
