"""Shared contracts for language-neutral error-signal parser adapters."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from aira.parser_health import ParserHealth

SIGNAL_SCHEMA_VERSION = "aira-error-signal-v1"


@dataclass
class ParserOutput:
    signals: List[Dict[str, Any]] = field(default_factory=list)
    health: ParserHealth = field(
        default_factory=lambda: ParserHealth(
            parser="unknown",
            parser_version="unknown",
            status="failed",
            structural=False,
        )
    )


def normalize_evidence(value: str) -> str:
    """Normalize evidence for content comparison without using source lines."""
    return re.sub(r"\s+", " ", value.strip())


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def stable_signal_id(
    *,
    artifact: str,
    language: str,
    symbol_id: str,
    kind: str,
    structural_path: str,
    normalized_statement: str,
) -> str:
    identity = {
        "artifact": artifact,
        "kind": kind,
        "language": language,
        "statement": normalized_statement,
        "structural_path": structural_path,
        "symbol_id": symbol_id,
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return f"sig-{digest(encoded)[:24]}"


def build_signal(
    *,
    artifact: str,
    language: str,
    kind: str,
    region: Dict[str, int],
    symbol: Dict[str, str],
    structural_path: str,
    normalized_statement: str,
    evidence_text: str,
    parser: Dict[str, Any],
    confidence: str,
    enclosing_blocks: Optional[List[str]] = None,
    error_identity: Optional[Dict[str, Any]] = None,
    outcome: Optional[Dict[str, Any]] = None,
    side_effects: Optional[List[str]] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    symbol_id = symbol.get("id", "<module>")
    evidence_normalized = normalize_evidence(normalized_statement or evidence_text)
    return {
        "schema_version": SIGNAL_SCHEMA_VERSION,
        "signal_id": stable_signal_id(
            artifact=artifact,
            language=language,
            symbol_id=symbol_id,
            kind=kind,
            structural_path=structural_path,
            normalized_statement=evidence_normalized,
        ),
        "artifact": artifact,
        "language": language,
        "kind": kind,
        "region": region,
        "symbol": symbol,
        "structural_path": structural_path,
        "enclosing_blocks": list(enclosing_blocks or []),
        "error_identity": dict(error_identity or {}),
        "outcome": dict(outcome or {}),
        "side_effects": list(side_effects or []),
        "parser": dict(parser),
        "confidence": confidence,
        "evidence": {
            "text": evidence_text.strip(),
            "normalized": evidence_normalized,
            "hash": digest(evidence_normalized),
        },
        "attributes": dict(attributes or {}),
    }
