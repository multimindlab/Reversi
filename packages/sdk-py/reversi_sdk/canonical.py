"""Canonical JSON and payload hashing, byte-compatible with the TypeScript implementation.

Supported values: None, bool, int, str, list/tuple, dict with str keys, and finite floats.
Floats that are whole numbers are written as integers (as JavaScript does). Non-whole floats
outside 1e-4 <= |x| < 1e16 are rejected, because Python and JavaScript format them differently.
"""
from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _num(x: float, path: str) -> str:
    if not math.isfinite(x):
        raise TypeError(f"cannot canonicalize a non-finite number at {path}")
    if x == int(x) and abs(x) < 1e21:
        return str(int(x))
    if not (1e-4 <= abs(x) < 1e16):
        raise TypeError(f"cannot canonicalize float {x!r} at {path}: pass it as a string or an integer")
    return repr(x)


def _utf16_key(k: str) -> bytes:
    # JavaScript sorts keys by UTF-16 code units.
    return k.encode("utf-16-be", "surrogatepass")


def _canon(v: Any, path: str) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return _num(v, path)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_canon(x, f"{path}[{i}]") for i, x in enumerate(v)) + "]"
    if isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise TypeError(f"cannot canonicalize a non-string key at {path}")
        items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canon(x, f"{path}.{k}") for k, x in items) + "}"
    raise TypeError(f"cannot canonicalize a value of type {type(v).__name__} at {path}")


def canonicalize(value: Any) -> str:
    return _canon(value, "$")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_payload(value: Any) -> str:
    """Hash of a payload as recorded in the ledger. Never raises: unhashable values get a fixed marker."""
    try:
        return sha256_hex(canonicalize(value))
    except TypeError:
        return sha256_hex("unhashable")
