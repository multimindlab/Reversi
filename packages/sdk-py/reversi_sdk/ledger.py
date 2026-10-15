"""Verify a Reversi ledger (JSON Lines). Depends only on the standard library."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .canonical import canonicalize, sha256_hex

GENESIS_HASH = "0" * 64

_FIELDS = [
    ("seq", "int"), ("ts_ms", "int"), ("run_id", "str"), ("step", "int|null"), ("actor", "str"), ("tool", "str"),
    ("payload_hash", "str"), ("reason", "str"), ("event", "str"), ("detail", "str"), ("prev_hash", "str"), ("hash", "str"),
]


@dataclass
class VerifyResult:
    ok: bool
    records: int = 0
    head: str = GENESIS_HASH
    seq: Optional[int] = None
    error: Optional[str] = None


def _type_ok(v: Any, kind: str) -> bool:
    if kind == "int":
        return isinstance(v, int) and not isinstance(v, bool)
    if kind == "int|null":
        return v is None or (isinstance(v, int) and not isinstance(v, bool))
    return isinstance(v, str)


def verify_records(records: List[Dict[str, Any]]) -> VerifyResult:
    prev = GENESIS_HASH
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            return VerifyResult(False, seq=i, error="record is not an object")
        for field, kind in _FIELDS:
            if field not in r or not _type_ok(r[field], kind):
                return VerifyResult(False, seq=i, error=f"field `{field}` is missing or has the wrong type")
        if r["seq"] != i:
            return VerifyResult(False, seq=r["seq"], error="sequence number out of order")
        if r["prev_hash"] != prev:
            return VerifyResult(False, seq=r["seq"], error="prev_hash does not match the previous record")
        body = {k: v for k, v in r.items() if k != "hash"}
        if sha256_hex(canonicalize(body)) != r["hash"]:
            return VerifyResult(False, seq=r["seq"], error="stored hash does not match the record's contents")
        prev = r["hash"]
    return VerifyResult(True, records=len(records), head=prev)


def parse_jsonl(text: str) -> List[Dict[str, Any]]:
    out = []
    for n, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise ValueError(f"line {n}: not valid JSON ({e.msg})") from None
    return out


def verify_file(path: str) -> VerifyResult:
    with open(path, "r", encoding="utf-8") as f:
        return verify_records(parse_jsonl(f.read()))
