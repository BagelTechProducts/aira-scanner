"""
AIRA research — shared utility functions for building submission payloads.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib import error as urllib_error

from aira import __version__ as AIRA_VERSION
from aira.research.base import (
    CHECK_IDS,
    DEFAULT_SCORING_VERSION,
    FTI_V1_TOTAL_WEIGHT,
    FTI_V1_WEIGHTS_BY_KEY,
    VALID_ATTRIBUTION_CLASSES,
    VALID_SOURCE_KINDS,
    ResearchSubmissionError,
    _canonicalize,
    _env,
    _non_empty_str,
    _normalize_int,
    _normalize_status,
    _sha256_hex,
)
from aira.scanner import CHECKS, ScanResult


def _submission_option(submission_options: Optional[Dict[str, Any]], key: str, *env_names: str) -> Optional[str]:
    if submission_options:
        direct = submission_options.get(key)
        direct_str = _non_empty_str(str(direct)) if direct is not None else None
        if direct_str:
            return direct_str
    return _env(*env_names)


def _normalize_attribution_class(value: Optional[str]) -> str:
    normalized = _non_empty_str(value) or "unknown"
    if normalized not in VALID_ATTRIBUTION_CLASSES:
        raise ResearchSubmissionError(
            "Invalid attribution_class "
            f"'{normalized}'. Use one of: explicit_ai, suspected_ai, human_baseline, unknown."
        )
    return normalized


def _normalize_source_kind(value: Optional[str]) -> Optional[str]:
    normalized = _non_empty_str(value)
    if not normalized:
        return None
    if normalized not in VALID_SOURCE_KINDS:
        raise ResearchSubmissionError(
            "Invalid source_kind "
            f"'{normalized}'. Use one of: repo, directory, dataset_file, dataset_repo, ci_run, manual."
        )
    return normalized


def _normalize_scoring_version(value: Optional[str]) -> str:
    normalized = _non_empty_str(value) or DEFAULT_SCORING_VERSION
    if normalized != DEFAULT_SCORING_VERSION:
        raise ResearchSubmissionError(
            f"Unsupported scoring_version '{normalized}'. Only fti-v1 is currently supported."
        )
    return normalized


def infer_research_source(explicit_source: Optional[str] = None) -> str:
    if explicit_source:
        return explicit_source
    if _env("GITHUB_REPOSITORY"):
        return f"github:{_env('GITHUB_REPOSITORY')}"
    if _env("CI"):
        return "ci"
    return "aira-cli"


def _engine_label(result: ScanResult) -> str:
    metadata = result.metadata or {}
    provider = metadata.get("provider") or metadata.get("engine")
    model = metadata.get("model")
    if provider and model:
        return f"{provider}:{model}"
    if provider:
        return str(provider)
    return str(metadata.get("mode", "static"))


def normalize_checks_json(raw: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    data = raw or {}
    normalized: Dict[str, str] = {}
    for check_id, (key, _) in CHECKS.items():
        normalized[key] = _normalize_status(data.get(key, data.get(check_id)))
    return normalized


def build_check_finding_counts(result: ScanResult) -> Dict[str, int]:
    counts: Dict[str, int] = {check_id: 0 for check_id in CHECK_IDS}
    for finding in result.findings or []:
        check_id = str(finding.get("check_id") or "UNSPECIFIED").upper()
        counts[check_id] = counts.get(check_id, 0) + 1
    return counts


def build_check_severity_counts(result: ScanResult) -> Dict[str, Dict[str, int]]:
    severity_counts: Dict[str, Dict[str, int]] = {
        check_id: {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0}
        for check_id in CHECK_IDS
    }
    for finding in result.findings or []:
        check_id = str(finding.get("check_id") or "UNSPECIFIED").upper()
        if check_id not in severity_counts:
            severity_counts[check_id] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "TOTAL": 0}
        severity = str(finding.get("severity") or "LOW").upper()
        if severity not in {"HIGH", "MEDIUM", "LOW"}:
            severity = "LOW"
        severity_counts[check_id][severity] += 1
        severity_counts[check_id]["TOTAL"] += 1
    return severity_counts


def build_submission_check_rows(
    checks_json: Dict[str, str],
    check_count_json: Dict[str, int],
    check_severity_json: Dict[str, Dict[str, int]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for check_id, (key, label) in CHECKS.items():
        severity = check_severity_json.get(check_id, {})
        rows.append(
            {
                "check_id": check_id,
                "check_key": key,
                "check_name": label,
                "status": _normalize_status(checks_json.get(key)),
                "weight": FTI_V1_WEIGHTS_BY_KEY[key],
                "finding_count": _normalize_int(check_count_json.get(check_id)),
                "high_count": _normalize_int(severity.get("HIGH")),
                "medium_count": _normalize_int(severity.get("MEDIUM")),
                "low_count": _normalize_int(severity.get("LOW")),
            }
        )
    return rows


def compute_fti_v1(checks_or_rows: Any) -> float:
    rows: List[Dict[str, Any]]
    if isinstance(checks_or_rows, list):
        rows = checks_or_rows
    else:
        rows = build_submission_check_rows(normalize_checks_json(checks_or_rows), {}, {})
    failed_weight = sum(row["weight"] for row in rows if row.get("status") == "FAIL")
    score = 100 - ((failed_weight / FTI_V1_TOTAL_WEIGHT) * 100)
    return round(score, 2)


def risk_level_for_fti(score: float) -> str:
    if score >= 85.0:
        return "LOW_RISK"
    if score >= 65.0:
        return "MODERATE_RISK"
    if score >= 40.0:
        return "HIGH_RISK"
    return "CRITICAL_RISK"


def _infer_source_kind(
    explicit_source_kind: Optional[str],
    source_id: Optional[str],
    source: str,
    target_kind: str,
) -> str:
    explicit = _normalize_source_kind(explicit_source_kind)
    if explicit:
        return explicit
    if _env("GITHUB_RUN_ID") or _env("GITHUB_WORKFLOW"):
        return "ci_run"
    if source.startswith("github:"):
        return "repo"
    if source_id and "/" in source_id:
        return "repo"
    if target_kind == "directory":
        return "directory"
    if target_kind == "file":
        return "dataset_file"
    return "manual"


def _resolve_sample_name(
    requested_sample_name: Optional[str],
    source_kind: str,
    source_id: Optional[str],
    source: str,
    target_name: Optional[str],
    fallback_seed: str,
) -> str:
    explicit = _non_empty_str(requested_sample_name)
    if explicit:
        return explicit
    if source_id:
        return source_id
    if source.startswith("github:"):
        return source.split("github:", 1)[1]
    if source_kind in {"repo", "dataset_repo"} and _non_empty_str(source):
        return source
    if target_name:
        return target_name
    return f"adhoc:{_sha256_hex(fallback_seed)[:16]}"


def _build_fingerprint_payload(record: Dict[str, Any], submission_checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "attribution_class": record["attribution_class"],
        "checks_failed": record["checks_failed"],
        "checks_json": record["checks_json"],
        "checks_passed": record["checks_passed"],
        "checks_unknown": record["checks_unknown"],
        "ci_ref": record["ci_ref"],
        "ci_run_id": record["ci_run_id"],
        "ci_workflow": record["ci_workflow"],
        "engine": record["engine"],
        "files_scanned": record["files_scanned"],
        "high_count": record["high_count"],
        "language": record["language"],
        "low_count": record["low_count"],
        "medium_count": record["medium_count"],
        "metadata_json": record["metadata_json"],
        "model": record["model"],
        "provider": record["provider"],
        "ruleset_version": record["ruleset_version"],
        "sample_name": record["sample_name"],
        "sample_version": record["sample_version"],
        "scanner_name": record["scanner_name"],
        "scanner_version": record["scanner_version"],
        "scan_mode": record["scan_mode"],
        "scoring_version": record["scoring_version"],
        "source": record["source"],
        "source_id": record["source_id"],
        "source_kind": record["source_kind"],
        "submission_checks": [
            {
                "check_id": row["check_id"],
                "status": row["status"],
                "weight": row["weight"],
                "finding_count": row["finding_count"],
                "high_count": row["high_count"],
                "medium_count": row["medium_count"],
                "low_count": row["low_count"],
            }
            for row in submission_checks
        ],
        "target_kind": record["target_kind"],
        "total_findings": record["total_findings"],
    }


def _build_persisted_payload(record: Dict[str, Any], submission_checks: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "attribution_class": record["attribution_class"],
        "check_count_json": record["check_count_json"],
        "check_severity_json": record["check_severity_json"],
        "checks_failed": record["checks_failed"],
        "checks_json": record["checks_json"],
        "checks_passed": record["checks_passed"],
        "checks_unknown": record["checks_unknown"],
        "ci_ref": record["ci_ref"],
        "ci_run_id": record["ci_run_id"],
        "ci_workflow": record["ci_workflow"],
        "engine": record["engine"],
        "files_scanned": record["files_scanned"],
        "fti_score": record["fti_score"],
        "high_count": record["high_count"],
        "language": record["language"],
        "low_count": record["low_count"],
        "medium_count": record["medium_count"],
        "metadata_json": record["metadata_json"],
        "model": record["model"],
        "parent_record_sha256": record["parent_record_sha256"],
        "provider": record["provider"],
        "risk_level": record["risk_level"],
        "ruleset_version": record["ruleset_version"],
        "sample_name": record["sample_name"],
        "sample_version": record["sample_version"],
        "scanner_name": record["scanner_name"],
        "scanner_version": record["scanner_version"],
        "scan_mode": record["scan_mode"],
        "scoring_version": record["scoring_version"],
        "source": record["source"],
        "source_id": record["source_id"],
        "source_kind": record["source_kind"],
        "submission_checks": [
            {
                "check_id": row["check_id"],
                "check_name": row["check_name"],
                "status": row["status"],
                "weight": row["weight"],
                "finding_count": row["finding_count"],
                "high_count": row["high_count"],
                "medium_count": row["medium_count"],
                "low_count": row["low_count"],
            }
            for row in submission_checks
        ],
        "submission_fingerprint": record["submission_fingerprint"],
        "submitted_at": record["submitted_at"],
        "target_kind": record["target_kind"],
        "total_findings": record["total_findings"],
    }


def build_baseline_submission_fields(result: ScanResult, source: Optional[str] = None) -> Dict[str, Any]:
    summary = result.summary or {}
    checks = result.check_results or {}
    return {
        "Submitted At": datetime.now(timezone.utc).isoformat(),
        "Checks JSON": json.dumps(checks, sort_keys=True),
        "High Count": int((summary.get("by_severity") or {}).get("HIGH", 0)),
        "Medium Count": int((summary.get("by_severity") or {}).get("MEDIUM", 0)),
        "Low Count": int((summary.get("by_severity") or {}).get("LOW", 0)),
        "Total Findings": int(summary.get("findings_total", 0)),
        "Checks Failed": int(summary.get("checks_failed", 0)),
        "Engine": _engine_label(result),
        "Source": infer_research_source(source),
    }


def build_optional_submission_fields(result: ScanResult) -> Dict[str, Any]:
    summary = result.summary or {}
    metadata = result.metadata or {}
    target_kind = "directory"
    try:
        target_kind = "file" if Path(result.target).is_file() else "directory"
    except OSError:
        pass

    fields = {
        "Check Count JSON": json.dumps(build_check_finding_counts(result), sort_keys=True),
        "Check Severity JSON": json.dumps(build_check_severity_counts(result), sort_keys=True),
        "Checks Passed": int(summary.get("checks_passed", 0)),
        "Checks Unknown": int(summary.get("checks_unknown", 0)),
        "Files Scanned": int(summary.get("files_scanned", 0)),
        "Scan Mode": str(metadata.get("mode", "static")),
        "Provider": str(metadata.get("provider") or metadata.get("engine") or "static"),
        "Model": str(metadata.get("model") or ""),
        "Target Kind": target_kind,
    }

    if _env("GITHUB_WORKFLOW"):
        fields["CI Workflow"] = _env("GITHUB_WORKFLOW")
    if _env("GITHUB_RUN_ID"):
        fields["CI Run ID"] = _env("GITHUB_RUN_ID")
    if _env("GITHUB_REF_NAME"):
        fields["CI Ref"] = _env("GITHUB_REF_NAME")

    return fields


def build_aggregate_submission_fields(result: ScanResult, source: Optional[str] = None) -> Dict[str, Any]:
    return {
        **build_baseline_submission_fields(result, source=source),
        **build_optional_submission_fields(result),
    }


def build_submission_bundle(
    result: ScanResult,
    source: Optional[str] = None,
    submission_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    summary = result.summary or {}
    metadata = result.metadata or {}
    target_kind = "directory"
    try:
        target_kind = "file" if Path(result.target).is_file() else "directory"
    except OSError:
        pass
    source_label = infer_research_source(source)
    source_id = _submission_option(submission_options, "source_id", "AIRA_SOURCE_ID", "RESEARCH_SOURCE_ID")
    source_kind = _infer_source_kind(
        _submission_option(submission_options, "source_kind", "AIRA_SOURCE_KIND", "RESEARCH_SOURCE_KIND"),
        source_id,
        source_label,
        target_kind,
    )
    scanner_version = (
        _submission_option(submission_options, "scanner_version", "AIRA_SCANNER_VERSION", "RESEARCH_SCANNER_VERSION")
        or AIRA_VERSION
    )
    ruleset_version = (
        _submission_option(submission_options, "ruleset_version", "AIRA_RULESET_VERSION", "RESEARCH_RULESET_VERSION")
        or scanner_version
    )
    scoring_version = _normalize_scoring_version(
        _submission_option(submission_options, "scoring_version", "AIRA_SCORING_VERSION")
    )
    checks_json = normalize_checks_json(result.check_results or {})
    check_count_json = build_check_finding_counts(result)
    check_severity_json = build_check_severity_counts(result)
    submission_checks = build_submission_check_rows(checks_json, check_count_json, check_severity_json)
    fti_score = compute_fti_v1(submission_checks)
    fingerprint_seed = _canonicalize(
        {
            "checks_json": checks_json,
            "ci_ref": _env("GITHUB_REF_NAME"),
            "ci_run_id": _env("GITHUB_RUN_ID"),
            "ci_workflow": _env("GITHUB_WORKFLOW"),
            "metadata_json": metadata,
            "source": source_label,
            "source_id": source_id,
            "source_kind": source_kind,
            "target_kind": target_kind,
        }
    )
    sample_name = _resolve_sample_name(
        _submission_option(submission_options, "sample_name", "AIRA_SAMPLE_NAME", "RESEARCH_SAMPLE_NAME"),
        source_kind,
        source_id,
        source_label,
        _non_empty_str(Path(result.target).name),
        fingerprint_seed,
    )
    sample_version = _submission_option(
        submission_options, "sample_version", "AIRA_SAMPLE_VERSION", "RESEARCH_SAMPLE_VERSION"
    ) or "v1"
    record = {
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "source": source_label,
        "language": metadata.get("language"),
        "engine": _engine_label(result),
        "scan_mode": metadata.get("mode", "static"),
        "provider": metadata.get("provider") or metadata.get("engine"),
        "model": metadata.get("model"),
        "target_kind": target_kind,
        "files_scanned": int(summary.get("files_scanned", 0)),
        "high_count": int((summary.get("by_severity") or {}).get("HIGH", 0)),
        "medium_count": int((summary.get("by_severity") or {}).get("MEDIUM", 0)),
        "low_count": int((summary.get("by_severity") or {}).get("LOW", 0)),
        "total_findings": int(summary.get("findings_total", 0)),
        "checks_failed": sum(1 for row in submission_checks if row["status"] == "FAIL"),
        "checks_passed": sum(1 for row in submission_checks if row["status"] == "PASS"),
        "checks_unknown": sum(1 for row in submission_checks if row["status"] == "UNKNOWN"),
        "checks_json": checks_json,
        "check_count_json": check_count_json,
        "check_severity_json": check_severity_json,
        "ci_workflow": _env("GITHUB_WORKFLOW"),
        "ci_run_id": _env("GITHUB_RUN_ID"),
        "ci_ref": _env("GITHUB_REF_NAME"),
        "metadata_json": metadata,
        "sample_name": sample_name,
        "sample_version": sample_version,
        "attribution_class": _normalize_attribution_class(
            _submission_option(
                submission_options, "attribution_class", "AIRA_ATTRIBUTION_CLASS", "RESEARCH_ATTRIBUTION_CLASS"
            )
        ),
        "source_id": source_id,
        "source_kind": source_kind,
        "scanner_name": _submission_option(submission_options, "scanner_name", "AIRA_SCANNER_NAME") or "aira",
        "scanner_version": scanner_version,
        "ruleset_version": ruleset_version,
        "scoring_version": scoring_version,
        "fti_score": fti_score,
        "risk_level": risk_level_for_fti(fti_score),
        "parent_record_sha256": None,
    }
    record["submission_fingerprint"] = _sha256_hex(_canonicalize(_build_fingerprint_payload(record, submission_checks)))
    return {
        "record": record,
        "submission_checks": submission_checks,
    }


def finalize_submission_bundle(
    bundle: Dict[str, Any],
    parent_record_sha256: Optional[str] = None,
) -> Dict[str, Any]:
    record = {
        **bundle["record"],
        "parent_record_sha256": parent_record_sha256,
    }
    record["record_sha256"] = _sha256_hex(_canonicalize(_build_persisted_payload(record, bundle["submission_checks"])))
    return {
        "record": record,
        "submission_checks": bundle["submission_checks"],
    }


def build_structured_submission_record(
    result: ScanResult,
    source: Optional[str] = None,
    submission_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return finalize_submission_bundle(
        build_submission_bundle(result, source=source, submission_options=submission_options)
    )["record"]


def _decode_error_message(raw: str, exc: urllib_error.HTTPError) -> str:
    try:
        parsed = json.loads(raw or "{}")
        err = parsed.get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err.get("type") or raw or exc)
        if err:
            return str(err)
    except (json.JSONDecodeError, ValueError, KeyError):
        # C03: Broad error parsing - fall back to raw message on any parse failure
        pass
    return raw or str(exc)