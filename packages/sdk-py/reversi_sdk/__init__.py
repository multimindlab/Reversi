"""Reversi Python SDK."""
from .canonical import canonicalize, hash_payload, sha256_hex
from .client import Blocked, EffectUncertain, ReversiClient, ReversiError, RunHandle, verify_webhook_signature
from .ledger import GENESIS_HASH, VerifyResult, parse_jsonl, verify_file, verify_records
from .manifest import EFFECTS, ManifestError, Registry, validate_manifest

__version__ = "0.1.0"
__all__ = [
    "Blocked", "EFFECTS", "EffectUncertain", "GENESIS_HASH", "ManifestError", "Registry", "ReversiClient",
    "ReversiError", "RunHandle", "VerifyResult", "canonicalize", "hash_payload", "parse_jsonl", "sha256_hex",
    "validate_manifest", "verify_file", "verify_records", "verify_webhook_signature",
]
