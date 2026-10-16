"""Optional pydantic v2 bindings for the manifest. Import this module only if pydantic is installed.

The stdlib validator in `manifest.py` stays the single authority on what a valid manifest is: every model runs it first
and reports its errors, so the typed models and the validator cannot disagree. The models add IDE types and
`model_dump()` / JSON Schema generation on top.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, ConfigDict, model_validator
except ImportError as e:  # pragma: no cover
    raise ImportError("reversi_sdk.pydantic_models needs pydantic v2: pip install 'reversi-sdk[pydantic]'") from e

from .manifest import validate_manifest


def _plain(v: Any) -> Any:
    """Models nested in the input become plain dicts, so the stdlib validator sees what the caller meant."""
    if isinstance(v, BaseModel):
        return _plain(v.model_dump(exclude_unset=True))
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


class Verification(BaseModel):
    """Read back state after a compensation and require it to match `expect` before the undo counts as done."""
    model_config = ConfigDict(extra="forbid")

    tool: str
    arguments: Dict[str, str] = {}
    expect: Dict[str, Any]
    retries: int = 3
    backoff_ms: int = 1000


class Compensation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    argument_map: Dict[str, str] = {}
    requires_approval: bool = False
    kind: str = "compensation"
    residue: List[str] = []
    verification: Optional[Verification] = None
    timeout_ms: Optional[int] = None


class ToolManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    effect: str
    permission: str
    description: Optional[str] = None
    approval: str = "never"
    approval_rules: Optional[Dict[str, Any]] = None
    requires: List[str] = []
    compensation: Optional[Compensation] = None
    version: int = 1
    status: str = "approved"
    replaced_by: Optional[str] = None
    owner: Optional[str] = None
    oncall: Optional[str] = None
    risk: Optional[Dict[str, Any]] = None
    timeout_ms: Optional[int] = None
    retry: Optional[Dict[str, int]] = None
    idempotency: Optional[Dict[str, str]] = None
    audit: Optional[Dict[str, Any]] = None
    schema_hash: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _authoritative(cls, data: Any) -> Any:
        raw = _plain(data)
        normalized, errors = validate_manifest(raw)
        if normalized is None:
            raise ValueError("; ".join(errors))
        return normalized

    def normalized(self) -> Dict[str, Any]:
        """The same dict `validate_manifest` returns."""
        return self.model_dump(exclude_none=True)


def validate_with_pydantic(raw: Any) -> Optional[Dict[str, Any]]:
    """Normalized manifest, or None if invalid (use ToolManifest.model_validate for the error details)."""
    try:
        return ToolManifest.model_validate(raw).normalized()
    except ValueError:  # pydantic.ValidationError subclasses ValueError
        return None
