"""Tool manifests: validation that matches the TypeScript implementation and schemas/manifest.schema.json."""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

EFFECTS = ("read_only", "idempotent", "reversible", "compensable", "irreversible")
_TOOL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,127}")
_PERM = re.compile(r"\S{1,128}")
_REF = re.compile(r"\$(args|result)(\.[A-Za-z0-9_-]+)+")
_TOP = {"tool", "description", "effect", "permission", "approval", "compensation", "requires", "version", "status",
        "replaced_by", "owner", "oncall", "risk", "timeout_ms", "retry", "idempotency", "audit", "schema_hash"}
_COMP = {"tool", "argument_map", "requires_approval", "kind", "residue", "verification", "timeout_ms"}
_VERIFY = {"tool", "arguments", "expect", "retries", "backoff_ms"}
BLAST_RADII = ("low", "medium", "high", "critical")
_DURATION = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d)")
_MULT = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}
_IDEM = re.compile(r"\{\{\s*args(\.[A-Za-z0-9_-]+)+\s*\}\}")
_REDACT = re.compile(r"\$(args|result)(\.[A-Za-z0-9_-]+)+")


def parse_duration(v: Any) -> Optional[int]:
    """'15m', '30s', '2h', '500ms', '1d' or a number of milliseconds. None if invalid."""
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return int(v) if v == v and v not in (float("inf"), float("-inf")) and v > 0 else None
    if not isinstance(v, str):
        return None
    m = _DURATION.fullmatch(v.strip())
    return int(float(m.group(1)) * _MULT[m.group(2)]) if m else None


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


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
    approval_rules: Optional[Dict[str, Any]] = None
    if "approval" in raw:
        ap = raw["approval"]
        if isinstance(ap, str) and ap in ("never", "always"):
            approval = ap
        elif isinstance(ap, dict):
            for k in ap:
                if k not in ("required", "roles", "quorum", "timeout", "on_timeout", "escalate_to"):
                    err(f"unknown approval field `{k}`")
            if "required" in ap and not isinstance(ap["required"], bool):
                err("`approval.required` must be a boolean")
            approval = "never" if ap.get("required") is False else "always"
            roles = ap.get("roles", [])
            if not isinstance(roles, list) or any(not isinstance(r, str) or not r for r in roles):
                err("`approval.roles` must be a list of role or group names")
            quorum = ap.get("quorum", 1)
            if not _is_int(quorum) or quorum < 1 or quorum > 10:
                err("`approval.quorum` must be an integer from 1 to 10")
            timeout_ms = None
            if "timeout" in ap:
                timeout_ms = parse_duration(ap["timeout"])
                if timeout_ms is None:
                    err("`approval.timeout` must be a duration like 15m, 30s or 2h")
            if "on_timeout" in ap and ap["on_timeout"] not in ("deny", "escalate"):
                err("`approval.on_timeout` must be deny or escalate")
            if isinstance(roles, list) and _is_int(quorum) and quorum > 1 and len(roles) == 0:
                err("a quorum needs `approval.roles` to draw approvers from")
            approval_rules = {
                "roles": list(roles) if isinstance(roles, list) else [],
                "quorum": quorum if _is_int(quorum) else 1,
                "on_timeout": "escalate" if ap.get("on_timeout") == "escalate" else "deny",
            }
            if timeout_ms is not None:
                approval_rules["timeout_ms"] = timeout_ms
            if isinstance(ap.get("escalate_to"), list):
                approval_rules["escalate_to"] = ap["escalate_to"]
        else:
            err("`approval` must be `never`, `always` or an object with roles, quorum and timeout")
    if effect == "irreversible":
        if raw.get("approval") == "never":
            err("irreversible tools must require approval")
        approval = "always"

    requires: List[str] = []
    if "requires" in raw:
        r = raw["requires"]
        normalized = []
        if isinstance(r, list):
            for x in r:
                if isinstance(x, str):
                    normalized.append(x)
                elif isinstance(x, dict) and isinstance(x.get("tool"), str) and x.get("status", "succeeded") == "succeeded":
                    normalized.append(x["tool"])
                else:
                    normalized.append("")
        if not isinstance(r, list) or any(not x for x in normalized):
            err("`requires` must be a list of tool names (or { tool, status: succeeded })")
        else:
            requires = normalized
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
            if "kind" in c and c["kind"] not in ("inverse", "compensation"):
                err("`compensation.kind` must be inverse or compensation")
            residue: List[str] = []
            if "residue" in c:
                if not isinstance(c["residue"], list) or any(not isinstance(x, str) or not x for x in c["residue"]):
                    err("`compensation.residue` must be a list of strings")
                else:
                    residue = list(c["residue"])
            if c.get("kind") == "inverse" and residue:
                err("an `inverse` compensation restores exact state, so it cannot declare residue; use kind: compensation")
            comp_timeout = None
            if "timeout_ms" in c:
                comp_timeout = parse_duration(c["timeout_ms"])
                if comp_timeout is None:
                    err("`compensation.timeout_ms` must be a positive number or a duration")
            verification = None
            if "verification" in c:
                v = c["verification"]
                if not isinstance(v, dict):
                    err("`compensation.verification` must be an object")
                else:
                    for k in v:
                        if k not in _VERIFY:
                            err(f"unknown verification field `{k}`")
                    vtool = v.get("tool")
                    if not isinstance(vtool, str) or not _TOOL.fullmatch(vtool):
                        err("`verification.tool` must be a tool name")
                    vargs: Dict[str, str] = {}
                    if "arguments" in v:
                        if not isinstance(v["arguments"], dict):
                            err("`verification.arguments` must be an object")
                        else:
                            for k, ref in v["arguments"].items():
                                if not isinstance(ref, str) or not _REF.fullmatch(ref):
                                    err(f"verification.arguments.{k} must be a reference like `$result.id`")
                                else:
                                    vargs[k] = ref
                    if not isinstance(v.get("expect"), dict) or len(v["expect"]) == 0:
                        err("`verification.expect` must name at least one path and its expected value")
                    retries = v.get("retries", 3)
                    if not _is_int(retries) or retries < 1 or retries > 10:
                        err("`verification.retries` must be 1..10")
                    backoff = 1000 if "backoff_ms" not in v else parse_duration(v["backoff_ms"])
                    if backoff is None:
                        err("`verification.backoff_ms` must be a positive number or a duration like 2s")
                    if isinstance(vtool, str) and isinstance(v.get("expect"), dict) and _is_int(retries) and backoff is not None:
                        verification = {"tool": vtool, "arguments": vargs, "expect": v["expect"], "retries": retries, "backoff_ms": backoff}
            if isinstance(ctool, str):
                compensation = {"tool": ctool, "argument_map": amap, "requires_approval": c.get("requires_approval") is True,
                                "kind": "inverse" if c.get("kind") == "inverse" else "compensation", "residue": residue}
                if verification:
                    compensation["verification"] = verification
                if comp_timeout is not None:
                    compensation["timeout_ms"] = comp_timeout

    if effect in ("reversible", "compensable"):
        if "compensation" not in raw:
            err(f"{effect} tools must declare a compensation")
    elif effect_ok and "compensation" in raw:
        err(f"{effect} tools must not declare a compensation")

    version = raw.get("version", 1)
    if not _is_int(version) or version < 1:
        err("`version` must be a positive integer")
    status = raw.get("status", "approved")
    if status not in ("draft", "approved", "deprecated"):
        err("`status` must be draft, approved or deprecated")
    for k in ("replaced_by", "owner", "oncall", "schema_hash"):
        if k in raw and (not isinstance(raw[k], str) or not raw[k]):
            err(f"`{k}` must be a non-empty string")
    risk = None
    if "risk" in raw:
        r = raw["risk"]
        if not isinstance(r, dict):
            err("`risk` must be an object")
        else:
            for k in r:
                if k not in ("data_class", "blast_radius", "environment"):
                    err(f"unknown risk field `{k}`")
            if "data_class" in r and (not isinstance(r["data_class"], str) or not r["data_class"]):
                err("`risk.data_class` must be a non-empty string")
            if "blast_radius" in r and r["blast_radius"] not in BLAST_RADII:
                err(f"`risk.blast_radius` must be one of {', '.join(BLAST_RADII)}")
            if "environment" in r and not isinstance(r["environment"], str):
                err("`risk.environment` must be a string")
            risk = r
    timeout_ms = None
    if "timeout_ms" in raw:
        timeout_ms = parse_duration(raw["timeout_ms"])
        if timeout_ms is None:
            err("`timeout_ms` must be a positive number or a duration like 30s")
    retry = None
    if "retry" in raw:
        r = raw["retry"]
        if not isinstance(r, dict):
            err("`retry` must be an object")
        else:
            for k in r:
                if k not in ("attempts", "base_ms", "max_ms"):
                    err(f"unknown retry field `{k}`")
            attempts = r.get("attempts", 3)
            base = 200 if "base_ms" not in r else parse_duration(r["base_ms"])
            mx = 5000 if "max_ms" not in r else parse_duration(r["max_ms"])
            if not _is_int(attempts) or attempts < 1 or attempts > 10:
                err("`retry.attempts` must be 1..10")
            if base is None or mx is None:
                err("`retry.base_ms` and `retry.max_ms` must be positive durations")
            elif _is_int(attempts):
                retry = {"attempts": attempts, "base_ms": base, "max_ms": mx}
        if effect not in ("read_only", "idempotent"):
            err("forward retry is only allowed for read_only and idempotent tools: retrying anything else could repeat its effect")
    idempotency = None
    if "idempotency" in raw:
        i = raw["idempotency"]
        if not isinstance(i, dict):
            err("`idempotency` must be an object")
        else:
            for k in i:
                if k not in ("key", "scope"):
                    err(f"unknown idempotency field `{k}`")
            if not isinstance(i.get("key"), str) or not _IDEM.search(i["key"]):
                err("`idempotency.key` must be a template using at least one `{{args.field}}`")
            if "scope" in i and i["scope"] not in ("run", "actor", "global"):
                err("`idempotency.scope` must be run, actor or global")
            if isinstance(i.get("key"), str):
                idempotency = {"key": i["key"], "scope": i.get("scope", "run")}
    audit = None
    if "audit" in raw:
        a = raw["audit"]
        if not isinstance(a, dict):
            err("`audit` must be an object")
        else:
            for k in a:
                if k not in ("retention_days", "evidence_export", "redaction"):
                    err(f"unknown audit field `{k}`")
            if "retention_days" in a and (not _is_int(a["retention_days"]) or a["retention_days"] < 1):
                err("`audit.retention_days` must be a positive integer")
            if "evidence_export" in a and a["evidence_export"] not in ("required", "optional"):
                err("`audit.evidence_export` must be required or optional")
            if "redaction" in a and (not isinstance(a["redaction"], list) or any(not isinstance(p, str) or not _REDACT.fullmatch(p) for p in a["redaction"])):
                err("`audit.redaction` must be a list of paths like `$args.client_secret`")
            audit = a
    if status == "deprecated" and raw.get("replaced_by") == name:
        err("a manifest cannot be replaced by itself")

    if errors:
        return None, errors
    out: Dict[str, Any] = {"tool": name, "effect": effect, "permission": perm, "approval": approval, "requires": requires,
                           "version": version, "status": status}
    if approval_rules:
        out["approval_rules"] = approval_rules
    for k in ("replaced_by", "owner", "oncall", "schema_hash"):
        if isinstance(raw.get(k), str):
            out[k] = raw[k]
    if risk:
        out["risk"] = risk
    if timeout_ms is not None:
        out["timeout_ms"] = timeout_ms
    if retry:
        out["retry"] = retry
    if idempotency:
        out["idempotency"] = idempotency
    if audit:
        out["audit"] = audit
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
            v = (c or {}).get("verification")
            if v and v["tool"] not in self._tools:
                out.append(f"`{m['tool']}`: verification tool `{v['tool']}` is not registered")
            if v and v["tool"] in self._tools and self._tools[v["tool"]]["effect"] != "read_only":
                out.append(f"`{m['tool']}`: verification tool `{v['tool']}` must be read_only: a check must not change anything")
            if m.get("replaced_by") and m["replaced_by"] not in self._tools:
                out.append(f"`{m['tool']}`: replaced_by `{m['replaced_by']}` is not registered")
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
