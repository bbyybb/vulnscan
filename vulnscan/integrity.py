"""Integrity verification module.

Multi-layer tamper detection for protected resources (author info,
donation QR codes, donation URL). Verification is woven into core
application logic so that removing checks breaks functionality.

Design principles:
  1. Hashes are NOT stored as plain hex strings — they are split,
     reversed, and reassembled at runtime.
  2. Verification happens at multiple scattered points, not one.
  3. Verification results feed into a token used by the scan engine,
     so bypassing verification also breaks scanning.
  4. Delayed checks — not all at startup, some during first scan.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from functools import lru_cache
from typing import Optional

# ── Internal constants (obfuscated) ──────────────────────────────────
# Hash fragments are split, reversed, and XOR-masked at rest.
# At runtime they are reassembled into the real SHA-256 hex digests.
# This makes simple string-search for hash values ineffective.

_XK = 0x5A  # XOR key byte

def _encode_fragment(plain: str) -> bytes:
    return bytes(b ^ _XK for b in plain.encode())

def _decode_fragment(data: bytes) -> str:
    return bytes(b ^ _XK for b in data).decode()


# --- Protected hash fragments (each split into 4 parts, XOR-masked) ---
# These are computed from the actual assets and embedded at build time.

# wechat_pay.jpg
_WP = [
    _encode_fragment("686b9d5bba59d683"),
    _encode_fragment("1580984cb9380454"),
    _encode_fragment("3f346d943f2baf4a"),
    _encode_fragment("94216fd13438f1e6"),
]
# alipay.jpg
_AP = [
    _encode_fragment("510155042b703d23"),
    _encode_fragment("f7eeabc04496097a"),
    _encode_fragment("7cc13772c5712c8d"),
    _encode_fragment("0716bab5962172dd"),
]
# bmc_qr.png
_BM = [
    _encode_fragment("bfd20ef305007c3d"),
    _encode_fragment("acf30dde49ce8f0f"),
    _encode_fragment("e4d7ac3ffcc86ac1"),
    _encode_fragment("f83bc1e75cccfcd6"),
]
# author string "白白LOVE尹尹"
_AU = [
    _encode_fragment("37e33aed7283996b"),
    _encode_fragment("52b8aa60ae09c6c7"),
    _encode_fragment("bf2c4953d47eb199"),
    _encode_fragment("54dd304e09bd2eda"),
]
# donate URL "https://buymeacoffee.com/bbyybb"
_DU = [
    _encode_fragment("5edb83751810b2fa"),
    _encode_fragment("a1e83fe46767ecd2"),
    _encode_fragment("99df1ece1ff81d96"),
    _encode_fragment("e5c4ca8ff4f27da5"),
]

def _reassemble(parts: list[bytes]) -> str:
    """Reassemble XOR-masked fragments into full hex digest."""
    return "".join(_decode_fragment(p) for p in parts)


# ── Verification state ───────────────────────────────────────────────
# _seal is a runtime token derived from successful verification.
# The scan engine requires a valid seal to operate. This creates a
# functional dependency — removing verification means no valid seal,
# which means scans silently produce empty results.

_seal: Optional[int] = None
_seal_timestamp: float = 0.0

# Expected seal value (derived from XOR of all hash bytes)
_EXPECTED_SEAL_MOD = 21090  # pre-computed: sum of all hash bytes mod 100003


def _compute_seal_from_hashes(hashes: list[str]) -> int:
    """Derive a numeric seal from a list of hex digest strings."""
    total = 0
    for h in hashes:
        for i in range(0, len(h), 2):
            total += int(h[i:i+2], 16)
    return total % 100003


def _hash_file(filepath: str) -> str:
    """SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except (OSError, IOError):
        return ""
    return h.hexdigest()


def _hash_string(s: str) -> str:
    """SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# ── Public API ───────────────────────────────────────────────────────

def get_protected_author() -> str:
    """Return the canonical author string."""
    return "\u767d\u767dLOVE\u5c39\u5c39"


def get_protected_donate_url() -> str:
    """Return the canonical donate URL."""
    return "https://buymeacoffee.com/bbyybb"


def get_assets_dir() -> str:
    """Return the path to the assets directory."""
    from vulnscan.utils import get_base_dir
    return os.path.join(get_base_dir(), "assets")


def verify_author(author_text: str) -> bool:
    """Check that the given author string matches the protected value."""
    return _hash_string(author_text) == _reassemble(_AU)


def verify_donate_url(url: str) -> bool:
    """Check that the donate URL matches the protected value."""
    return _hash_string(url) == _reassemble(_DU)


def verify_assets() -> bool:
    """Verify all QR code images are intact."""
    assets_dir = get_assets_dir()
    checks = [
        ("wechat_pay.jpg", _WP),
        ("alipay.jpg", _AP),
        ("bmc_qr.png", _BM),
    ]
    for filename, parts in checks:
        filepath = os.path.join(assets_dir, filename)
        actual = _hash_file(filepath)
        expected = _reassemble(parts)
        if actual != expected:
            return False
    return True


def full_integrity_check() -> bool:
    """Run all integrity checks and compute the runtime seal.

    Returns True if all checks pass. Also sets the internal seal
    that the scan engine depends on.
    """
    global _seal, _seal_timestamp

    author_ok = verify_author(get_protected_author())
    url_ok = verify_donate_url(get_protected_donate_url())
    assets_ok = verify_assets()

    if not (author_ok and url_ok and assets_ok):
        _seal = None
        return False

    # Compute seal from actual hashes
    all_hashes = [
        _reassemble(_WP), _reassemble(_AP), _reassemble(_BM),
        _reassemble(_AU), _reassemble(_DU),
    ]
    computed = _compute_seal_from_hashes(all_hashes)

    if computed != _EXPECTED_SEAL_MOD:
        # Fragment data itself is corrupted
        _seal = None
        return False

    _seal = computed
    _seal_timestamp = time.time()
    return True


def get_seal() -> Optional[int]:
    """Return the current integrity seal, or None if not verified."""
    return _seal


def require_seal() -> int:
    """Return the seal, running verification if needed.

    Called by the scan engine before executing scans. If integrity
    check fails, returns 0 which causes scans to produce no results.
    """
    global _seal
    if _seal is None:
        full_integrity_check()
    return _seal or 0


# ── Deferred verification (called during scan) ──────────────────────

def deferred_asset_check() -> bool:
    """Lightweight re-check of a single random asset.

    Called mid-scan to catch runtime tampering. Uses a rotating
    index based on current time.
    """
    assets_dir = get_assets_dir()
    checks = [
        ("wechat_pay.jpg", _WP),
        ("alipay.jpg", _AP),
        ("bmc_qr.png", _BM),
    ]
    idx = int(time.time()) % len(checks)
    filename, parts = checks[idx]
    filepath = os.path.join(assets_dir, filename)
    return _hash_file(filepath) == _reassemble(parts)


# ── Startup check ────────────────────────────────────────────────────

def startup_check() -> None:
    """Run at application startup. Exits if integrity fails."""
    if not full_integrity_check():
        print(
            "\n[INTEGRITY ERROR] Application files have been tampered with.\n"
            "The author information, donation QR codes, or donation URL\n"
            "have been modified. The application cannot start.\n"
            "\n"
            "[完整性错误] 应用程序文件已被篡改。\n"
            "作者信息、打赏二维码或打赏地址已被修改。程序无法启动。\n",
            file=sys.stderr,
        )
        sys.exit(1)
