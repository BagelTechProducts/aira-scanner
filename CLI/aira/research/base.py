"""
AIRA research — core types, constants, and configuration helpers.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Optional

from aira.scanner import CHECKS

BASELINE_FIELD_ORDER = (
    "Submitted At",
    "Checks JSON",
    "High Count",
    "Medium Count",
    "Low Count",
    "Total Findings",
    "Checks Failed",
    "Engine",
    "Source",
)

OPTIONAL_FIELD_ORDER = (
    "Check Count JSON",
    "Check Severity JSON",
    "Checks Passed",
    "Checks Unknown",
    "Files Scanned",
    "Scan Mode",
    "Provider",
    "Model",
    "Target Kind",
    "CI Workflow",
    "CI Run ID",
    "CI Ref",
)

UNKNOWN_FIELD_RE = re.compile(r'Unknown field name:\s*"?(?P<field>[^"]+)"?')
VALID_RESEARCH_BACKENDS = {"supabase", "jsonl", "airtable", "none"}
DEFAULT_HOSTED_RESEARCH_BACKEND = "supabase"
RESEARCH_BACKEND_ORDER = ("supabase", "jsonl", "airtable")
VALID_ATTRIBUTION_CLASSES = {"explicit_ai", "suspected_ai", "human_baseline", "unknown"}
VALID_SOURCE_KINDS = {"repo", "directory", "dataset_file", "dataset_repo", "ci_run", "manual"}
VALID_CHECK_STATUSES = {"PASS", "FAIL", "UNKNOWN"}
DEFAULT_SCORING_VERSION = "fti-v1"
CHECK_IDS = tuple(CHECKS.keys())
FTI_V1_WEIGHTS_BY_KEY = {
    "success_integrity": 3,
    "audit_integrity": 3,
    "exception_handling": 3,
    "confidence_representation": 3,
    "fallback_control": 2,
    "bypass_controls": 2,
    "return_contracts": 2,
    "determinism": 2,
    "idempotency_safety": 2,
    "logic_consistency": 1,
    "background_tasks": 1,
    "environment_safety": 1,
    "startup_integrity": 1,
    "lineage": 1,
    "test_coverage_symmetry": 1,
}
FTI_V1_TOTAL_WEIGHT = sum(FTI_V1_WEIGHTS_BY_KEY.values())


class ResearchSubmissionError(RuntimeError):
    """Raised when aggregate research submission fails."""

    def __init__(self, message: str, *, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def _env(*names: str) -> Optional[str]:
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return None


def _non_empty_str(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed or None


def _normalize_int(value: Any) -> int:
    try:
        return max(0, int(float(value or 0)))
    except (TypeError, ValueError):
        return 0


def _normalize_status(value: Any) -> str:
    normalized = str(value or "UNKNOWN").upper()
    return normalized if normalized in VALID_CHECK_STATUSES else "UNKNOWN"


def _canonicalize(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def infer_research_backend(explicit_backend: Optional[str] = None) -> str:
    requested = (explicit_backend or _env("AIRA_RESEARCH_BACKEND", "RESEARCH_BACKEND") or "").strip().lower()
    if requested:
        return requested
    if _env("SUPABASE_URL") and _env("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY"):
        return "supabase"
    if _env("AIRA_RESEARCH_JSONL", "RESEARCH_JSONL"):
        return "jsonl"
    if _env("AIRTABLE_BASE_ID") and _env("AIRTABLE_TOKEN"):
        return "airtable"
    return "none"


def _is_valid_backend(name: str) -> bool:
    return name in VALID_RESEARCH_BACKENDS