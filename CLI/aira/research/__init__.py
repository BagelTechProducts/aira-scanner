"""
AIRA research sub-package — public API for research submission.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from aira.research.airtable import (
    airtable_config_snapshot,
    check_airtable_connection,
)
from aira.research.base import (
    BASELINE_FIELD_ORDER,
    CHECK_IDS,
    DEFAULT_HOSTED_RESEARCH_BACKEND,
    DEFAULT_SCORING_VERSION,
    FTI_V1_TOTAL_WEIGHT,
    FTI_V1_WEIGHTS_BY_KEY,
    OPTIONAL_FIELD_ORDER,
    RESEARCH_BACKEND_ORDER,
    UNKNOWN_FIELD_RE,
    VALID_ATTRIBUTION_CLASSES,
    VALID_CHECK_STATUSES,
    VALID_RESEARCH_BACKENDS,
    VALID_SOURCE_KINDS,
    ResearchSubmissionError,
    _canonicalize,
    _env,
    _sha256_hex,
    infer_research_backend,
)
from aira.research.helpers import (
    build_aggregate_submission_fields,
    build_baseline_submission_fields,
    build_check_finding_counts,
    build_check_severity_counts,
    build_optional_submission_fields,
    build_structured_submission_record,
    build_submission_bundle,
    build_submission_check_rows,
    compute_fti_v1,
    finalize_submission_bundle,
    infer_research_source,
    normalize_checks_json,
    risk_level_for_fti,
)
from aira.research.jsonl_backend import (
    check_jsonl_connection,
    jsonl_config_snapshot,
)
from aira.research.supabase import (
    _supabase_request_json,
    _supabase_target,
    check_supabase_connection,
    supabase_config_snapshot,
)


def research_backend_snapshot(explicit_backend: Optional[str] = None) -> Dict[str, Any]:
    backend = infer_research_backend(explicit_backend)
    snapshot: Dict[str, Any] = {
        "backend": backend,
        "preferred_backend": DEFAULT_HOSTED_RESEARCH_BACKEND,
        "backend_order": list(RESEARCH_BACKEND_ORDER),
        "legacy_fallback_backend": "airtable",
    }
    from aira.research.base import _is_valid_backend
    if not _is_valid_backend(backend):
        snapshot.update({"configured": False, "invalid_backend": True})
        return snapshot
    if backend == "supabase":
        snapshot.update(supabase_config_snapshot())
    elif backend == "jsonl":
        snapshot.update(jsonl_config_snapshot())
    elif backend == "airtable":
        snapshot.update(airtable_config_snapshot())
        snapshot["legacy_fallback"] = True
    else:
        snapshot.update({"configured": False})
    return snapshot


def check_research_connection(timeout_seconds: int = 10, backend: Optional[str] = None) -> Dict[str, Any]:
    selected = infer_research_backend(backend)
    from aira.research.base import _is_valid_backend
    if not _is_valid_backend(selected):
        return {
            "backend": selected,
            "preferred_backend": DEFAULT_HOSTED_RESEARCH_BACKEND,
            "backend_order": list(RESEARCH_BACKEND_ORDER),
            "legacy_fallback_backend": "airtable",
            "configured": False,
            "ok": False,
            "reachable": False,
            "invalid_backend": True,
            "message": f"Unknown research backend '{selected}'. Use one of: supabase, jsonl, airtable.",
        }
    if selected == "supabase":
        return {
            "backend": "supabase",
            "preferred_backend": DEFAULT_HOSTED_RESEARCH_BACKEND,
            "backend_order": list(RESEARCH_BACKEND_ORDER),
            "legacy_fallback_backend": "airtable",
            **check_supabase_connection(timeout_seconds=timeout_seconds),
        }
    if selected == "jsonl":
        return {
            "backend": "jsonl",
            "preferred_backend": DEFAULT_HOSTED_RESEARCH_BACKEND,
            "backend_order": list(RESEARCH_BACKEND_ORDER),
            "legacy_fallback_backend": "airtable",
            **check_jsonl_connection(),
        }
    if selected == "airtable":
        snapshot = check_airtable_connection(timeout_seconds=timeout_seconds)
        if snapshot.get("ok"):
            snapshot["message"] = "Airtable connection verified. This backend is supported only as a legacy compatibility fallback."
        return {
            "backend": "airtable",
            "preferred_backend": DEFAULT_HOSTED_RESEARCH_BACKEND,
            "backend_order": list(RESEARCH_BACKEND_ORDER),
            "legacy_fallback_backend": "airtable",
            "legacy_fallback": True,
            **snapshot,
        }
    return {
        "backend": "none",
        "preferred_backend": DEFAULT_HOSTED_RESEARCH_BACKEND,
        "backend_order": list(RESEARCH_BACKEND_ORDER),
        "legacy_fallback_backend": "airtable",
        "configured": False,
        "ok": False,
        "reachable": False,
        "message": "No research backend is configured. Supabase is the preferred hosted backend.",
    }


def submit_aggregate_research(
    result: Any,
    source: Optional[str] = None,
    timeout_seconds: int = 15,
    backend: Optional[str] = None,
    submission_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    selected = infer_research_backend(backend)
    from aira.research.base import _is_valid_backend
    if not _is_valid_backend(selected):
        raise ResearchSubmissionError(
            f"Unknown research backend '{selected}'. Use one of: supabase, jsonl, airtable."
        )
    if selected == "supabase":
        from aira.research.supabase import _submit_aggregate_research_supabase
        return _submit_aggregate_research_supabase(
            result,
            source=source,
            timeout_seconds=timeout_seconds,
            submission_options=submission_options,
        )
    if selected == "jsonl":
        from aira.research.jsonl_backend import _submit_aggregate_research_jsonl
        return _submit_aggregate_research_jsonl(result, source=source, submission_options=submission_options)
    if selected == "airtable":
        from aira.research.airtable import _submit_aggregate_research_airtable
        response = _submit_aggregate_research_airtable(result, source=source, timeout_seconds=timeout_seconds)
        response["backend"] = "airtable"
        response["legacy_fallback"] = True
        return response
    raise ResearchSubmissionError(
        "No research backend is configured. Set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY, "
        "AIRA_RESEARCH_JSONL, or AIRTABLE_BASE_ID + AIRTABLE_TOKEN. Supabase is the preferred hosted backend."
    )


__all__ = [
    # base
    "BASELINE_FIELD_ORDER",
    "CHECK_IDS",
    "DEFAULT_HOSTED_RESEARCH_BACKEND",
    "DEFAULT_SCORING_VERSION",
    "FTI_V1_TOTAL_WEIGHT",
    "FTI_V1_WEIGHTS_BY_KEY",
    "OPTIONAL_FIELD_ORDER",
    "RESEARCH_BACKEND_ORDER",
    "ResearchSubmissionError",
    "UNKNOWN_FIELD_RE",
    "VALID_ATTRIBUTION_CLASSES",
    "VALID_CHECK_STATUSES",
    "VALID_RESEARCH_BACKENDS",
    "VALID_SOURCE_KINDS",
    "_canonicalize",
    "_env",
    "_sha256_hex",
    "infer_research_backend",
    # helpers
    "build_aggregate_submission_fields",
    "build_baseline_submission_fields",
    "build_check_finding_counts",
    "build_check_severity_counts",
    "build_optional_submission_fields",
    "build_structured_submission_record",
    "build_submission_bundle",
    "build_submission_check_rows",
    "compute_fti_v1",
    "finalize_submission_bundle",
    "infer_research_source",
    "normalize_checks_json",
    "risk_level_for_fti",
    # supabase
    "_supabase_request_json",
    "_supabase_target",
    "check_supabase_connection",
    "supabase_config_snapshot",
    # airtable
    "airtable_config_snapshot",
    "check_airtable_connection",
    # jsonl
    "check_jsonl_connection",
    "jsonl_config_snapshot",
    # __init__
    "check_research_connection",
    "research_backend_snapshot",
    "submit_aggregate_research",
]