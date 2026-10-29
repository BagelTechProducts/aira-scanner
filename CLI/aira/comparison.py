"""
Compare deterministic and model-assisted AIRA outputs.

The comparison is intentionally conservative: exact semantic fingerprints match
first, then same-file/same-check line windows, then same-file/same-boundary line
windows. That gives study code a stable suppression matrix without pretending
that nearby-but-different findings are identical.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from aira.scanner import CHECKS

COMPARISON_VERSION = "aira-comparison-v2"


def _read_json_or_jsonl(path: Path) -> Dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        first_line = next((line for line in text.splitlines() if line.strip()), "")
        if not first_line:
            raise ValueError(f"No JSON records found in {path}")
        return json.loads(first_line)
    return json.loads(text)


def extract_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract an ``aira_scan`` object from supported result wrappers."""
    if "aira_scan" in payload and isinstance(payload["aira_scan"], dict):
        return payload["aira_scan"]
    aira_result = payload.get("aira_result")
    if isinstance(aira_result, dict) and isinstance(aira_result.get("aira_scan"), dict):
        return aira_result["aira_scan"]
    if "ai_failure_audit" in payload or "findings" in payload:
        return payload
    raise ValueError("Input does not look like an AIRA scan result.")


def load_scan(path: Union[str, Path]) -> Dict[str, Any]:
    return extract_scan(_read_json_or_jsonl(Path(path)))


def _findings(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = scan.get("findings") or []
    return [finding for finding in findings if isinstance(finding, dict)]


def _checks(scan: Dict[str, Any]) -> Dict[str, str]:
    checks = scan.get("ai_failure_audit") or scan.get("checks") or {}
    return checks if isinstance(checks, dict) else {}


def _file_key(value: Any) -> str:
    """Return a canonical repository-relative artifact identity or an empty key."""
    raw = str(value or "").strip().replace("\\", "/")
    if not raw or re.match(r"^[A-Za-z]:/", raw):
        return ""
    path = PurePosixPath(raw)
    if path.is_absolute() or ".." in path.parts:
        return ""
    parts = [part for part in path.parts if part not in {"", "."}]
    if not parts:
        return ""
    return PurePosixPath(*parts).as_posix()


def _same_file(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    left_file = _file_key(left.get("file"))
    right_file = _file_key(right.get("file"))
    return bool(left_file and right_file and left_file == right_file)


def _line(value: Dict[str, Any]) -> int:
    try:
        return int(value.get("line") or 0)
    except (TypeError, ValueError):
        return 0


def _line_distance(left: Dict[str, Any], right: Dict[str, Any]) -> Optional[int]:
    left_line = _line(left)
    right_line = _line(right)
    if left_line <= 0 or right_line <= 0:
        return None
    return abs(left_line - right_line)


def _same_check(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return str(left.get("check_id") or "").upper() == str(right.get("check_id") or "").upper()


def _same_boundary(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    return bool(left.get("boundary_type") and left.get("boundary_type") == right.get("boundary_type"))


def _match_static_finding(
    static_finding: Dict[str, Any],
    model_findings: Iterable[Tuple[int, Dict[str, Any]]],
    *,
    line_window: int,
) -> Tuple[Optional[int], str]:
    same_file_candidates = [
        (index, model_finding)
        for index, model_finding in model_findings
        if _same_file(static_finding, model_finding)
    ]
    semantic = static_finding.get("semantic_fingerprint")
    if semantic:
        for index, model_finding in same_file_candidates:
            if semantic == model_finding.get("semantic_fingerprint"):
                return index, "semantic_fingerprint"

    nearest_candidates = sorted(
        same_file_candidates,
        key=lambda item: (
            _line_distance(static_finding, item[1])
            if _line_distance(static_finding, item[1]) is not None
            else float("inf"),
            item[0],
        ),
    )
    for index, model_finding in nearest_candidates:
        distance = _line_distance(static_finding, model_finding)
        if distance is not None and distance <= line_window and _same_check(static_finding, model_finding):
            return index, "same_check_line_window"

    for index, model_finding in nearest_candidates:
        distance = _line_distance(static_finding, model_finding)
        if distance is not None and distance <= line_window and _same_boundary(static_finding, model_finding):
            return index, "same_boundary_line_window"

    return None, "missed"


def _compact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "check_id": finding.get("check_id"),
        "severity": finding.get("severity"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "boundary_type": finding.get("boundary_type", "unknown"),
        "fingerprint": finding.get("fingerprint", ""),
        "fingerprint_version": finding.get("fingerprint_version", ""),
        "description": finding.get("description", ""),
    }


def _ratio(static_count: int, model_count: int) -> Any:
    if model_count == 0:
        return "inf" if static_count else 0
    return round(static_count / model_count, 4)


def _status_category(static_status: str, model_status: str) -> str:
    if static_status == "FAIL" and model_status == "PASS":
        return "static_fail_model_pass"
    if static_status == "FAIL" and model_status == "UNKNOWN":
        return "static_fail_model_unknown"
    if static_status == "FAIL" and model_status == "FAIL":
        return "both_fail"
    if static_status == "PASS" and model_status == "FAIL":
        return "model_only_fail"
    return "no_static_failure"


def build_suppression_matrix(
    static_scan: Dict[str, Any],
    model_scan: Dict[str, Any],
    *,
    line_window: int = 5,
) -> Dict[str, Any]:
    """Build a suppression matrix from two AIRA scan payloads."""
    static_findings = _findings(static_scan)
    model_findings = _findings(model_scan)
    indexed_model_findings = list(enumerate(model_findings))
    used_model_indexes = set()

    by_check: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    by_boundary: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    missed_findings = []
    matched_findings = []

    for finding in static_findings:
        check_id = str(finding.get("check_id") or "UNSPECIFIED").upper()
        boundary_type = str(finding.get("boundary_type") or "unknown")
        by_check[check_id]["static_findings"] += 1
        by_boundary[boundary_type]["static_findings"] += 1
        available_model_findings = [
            item for item in indexed_model_findings
            if item[0] not in used_model_indexes
        ]
        match_index, match_type = _match_static_finding(
            finding,
            available_model_findings,
            line_window=line_window,
        )
        if match_index is None:
            by_check[check_id]["missed_by_model"] += 1
            by_boundary[boundary_type]["missed_by_model"] += 1
            missed_findings.append(_compact_finding(finding))
            continue
        used_model_indexes.add(match_index)
        by_check[check_id]["matched_by_model"] += 1
        by_check[check_id][match_type] += 1
        by_boundary[boundary_type]["matched_by_model"] += 1
        by_boundary[boundary_type][match_type] += 1
        matched_findings.append({
            "static": _compact_finding(finding),
            "model": _compact_finding(model_findings[match_index]),
            "match_type": match_type,
        })

    model_only_findings = []
    for index, finding in indexed_model_findings:
        check_id = str(finding.get("check_id") or "UNSPECIFIED").upper()
        boundary_type = str(finding.get("boundary_type") or "unknown")
        by_check[check_id]["model_findings"] += 1
        by_boundary[boundary_type]["model_findings"] += 1
        if index not in used_model_indexes:
            by_check[check_id]["model_only_findings"] += 1
            by_boundary[boundary_type]["model_only_findings"] += 1
            model_only_findings.append(_compact_finding(finding))

    static_checks = _checks(static_scan)
    model_checks = _checks(model_scan)
    check_status_matrix = []
    status_counts: Dict[str, int] = defaultdict(int)
    for _, (check_key, _) in CHECKS.items():
        static_status = str(static_checks.get(check_key, "UNKNOWN")).upper()
        model_status = str(model_checks.get(check_key, "UNKNOWN")).upper()
        category = _status_category(static_status, model_status)
        status_counts[category] += 1
        check_status_matrix.append({
            "check_key": check_key,
            "static_status": static_status,
            "model_status": model_status,
            "category": category,
        })

    summary = {
        "comparison_version": COMPARISON_VERSION,
        "line_window": line_window,
        "static_findings": len(static_findings),
        "model_findings": len(model_findings),
        "static_to_model_finding_ratio": _ratio(len(static_findings), len(model_findings)),
        "matched_by_model": len(matched_findings),
        "missed_by_model": len(missed_findings),
        "model_only_findings": len(model_only_findings),
        **dict(status_counts),
    }
    invariants = {
        "one_to_one_model_matching": len(matched_findings) <= len(model_findings),
        "static_partition_complete": len(matched_findings) + len(missed_findings) == len(static_findings),
        "model_partition_complete": len(matched_findings) + len(model_only_findings) == len(model_findings),
    }
    if not all(invariants.values()):
        raise AssertionError(f"Comparison invariant violation: {invariants}")
    return {
        "comparison_version": COMPARISON_VERSION,
        "summary": summary,
        "invariants": invariants,
        "check_status_matrix": check_status_matrix,
        "by_check": {key: dict(value) for key, value in sorted(by_check.items())},
        "by_boundary_type": {key: dict(value) for key, value in sorted(by_boundary.items())},
        "matched_findings": matched_findings,
        "missed_findings": missed_findings,
        "model_only_findings": model_only_findings,
    }
