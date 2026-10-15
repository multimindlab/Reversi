"""Tool manifests: validation that matches the TypeScript implementation and schemas/manifest.schema.json."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

EFFECTS = ("read_only", "idempotent", "reversible", "compensable", "irreversible")
_TOOL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,127}")
_PERM = re.compile(r"\S{1,128}")
_REF = re.compile(r"\$(args|result)(\.[A-Za-z0-9_-]+)+")
_TOP = {"tool", "description", "effect", "permission", "approval", "compensation", "requires"}
_COMP = {"tool", "argument_map", "requires_approval"}


class ManifestError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate_manifest(raw: Any) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Return (normalized manifest, []) or (None, errors). Does not check cross-references."""
    if not isinstance(raw, dict):
        return None, ["manifest must be an object"]
    errors: List[str] = []
    name = raw.get("tool")
    label = f"`{name}`" if isinstance(name, str) and name else "manifest"

    def err(m: str) -> None:
        errors.append(f"{label}: {m}")

    for k in raw:
        if k not in _TOP:
            err(f"unknown field `{k}`")
    if not isinstance(name, str) or not _TOOL.fullmatch(name):
        err("`tool` must be a name of letters, digits and _ . : / - (max 128 characters)")
    perm = raw.get("permission")
    if not isinstance(perm, str) or not _PERM.fullmatch(perm):
        err("`permission` must be a non-empty string without whitespace")
    if "description" in raw and not isinstance(raw["description"], str):
        err("`description` must be a string")
    effect = raw.get("effect")
    effect_ok = isinstance(effect, str) and effect in EFFECTS
    if not effect_ok:
        err(f"`effect` must be one of {', '.join(EFFECTS)}")

    approval = "never"
    if "approval" in raw:
        if raw["approval"] in ("never", "always") and isinstance(raw["approval"], str):
            approval = raw["approval"]
        else:
            err("`approval` must be `never` or `always`")
    if effect == "irreversible":
        if raw.get("approval") == "never":
            err("irreversible tools must require approval")
        approval = "always"

    requires: List[str] = []
    if "requires" in raw:
        r = raw["requires"]
        if not isinstance(r, list) or any(not isinstance(x, str) or not x for x in r):
            err("`requires` must be a list of tool names")
        else:
            requires = list(r)
            if len(set(requires)) != len(requires):
                err("`requires` contains duplicates")
            if name in requires:
                err("a tool cannot require itself")

    compensation: Optional[Dict[str, Any]] = None
    if "compensation" in raw:
        c = raw["compensation"]
        if not isinstance(c, dict):
            err("`compensation` must be an object")
        else:
            for k in c:
                if k not in _COMP:
                    err(f"unknown compensation field `{k}`")
            ctool = c.get("tool")
            if not isinstance(ctool, str) or not _TOOL.fullmatch(ctool):
                err("`compensation.tool` must be a tool name")
            elif ctool == name:
                err("a tool cannot compensate itself")
            amap: Dict[str, str] = {}
            if "argument_map" in c:
                if not isinstance(c["argument_map"], dict):
                    err("`compensation.argument_map` must be an object")
                else:
                    for k, v in c["argument_map"].items():
                        if not isinstance(v, str) or not _REF.fullmatch(v):
                            err(f"argument_map.{k} must be a reference like `$args.id` or `$result.charge_id`")
                        else:
                            amap[k] = v
            if "requires_approval" in c and not isinstance(c["requires_approval"], bool):
                err("`compensation.requires_approval` must be a boolean")
            if isinstance(ctool, str):
                compensation = {"tool": ctool, "argument_map": amap, "requires_approval": c.get("requires_approval") is True}

    if effect in ("reversible", "compensable"):
        if "compensation" not in raw:
            err(f"{effect} tools must declare a compensation")
    elif effect_ok and "compensation" in raw:
        err(f"{effect} tools must not declare a compensation")

    if errors:
        return None, errors
    out: Dict[str, Any] = {"tool": name, "effect": effect, "permission": perm, "approval": approval, "requires": requires}
    if isinstance(raw.get("description"), str):
        out["description"] = raw["description"]
    if compensation:
        out["compensation"] = compensation
    return out, []


class Registry:
    def __init__(self) -> None:
        self._tools: Dict[str, Dict[str, Any]] = {}

    def register(self, raw: Any) -> Dict[str, Any]:
        m, errors = validate_manifest(raw)
        if m is None:
            raise ManifestError(errors)
        if m["tool"] in self._tools:
            raise ManifestError([f"`{m['tool']}`: tool is already registered"])
        self._tools[m["tool"]] = m
        return m

    def get(self, tool: str) -> Optional[Dict[str, Any]]:
        return self._tools.get(tool)

    def __len__(self) -> int:
        return len(self._tools)

    def validate(self) -> List[str]:
        """Cross-reference check, run after every manifest is registered."""
        out: List[str] = []
        for m in self._tools.values():
            c = m.get("compensation")
            if c and c["tool"] not in self._tools:
                out.append(f"`{m['tool']}`: compensation tool `{c['tool']}` is not registered")
            for r in m["requires"]:
                if r not in self._tools:
                    out.append(f"`{m['tool']}`: required tool `{r}` is not registered")
        return out

    @classmethod
    def from_json_file(cls, path: str) -> "Registry":
        """Load a JSON file holding one manifest or a list of them. (YAML needs a third-party parser; convert first.)"""
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        reg = cls()
        errors: List[str] = []
        for m in doc if isinstance(doc, list) else [doc]:
            try:
                reg.register(m)
            except ManifestError as e:
                errors.extend(e.errors)
        errors.extend(reg.validate())
        if errors:
            raise ManifestError(errors)
        return reg
