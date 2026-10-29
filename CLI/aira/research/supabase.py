"""
AIRA research — Supabase backend.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from urllib import error, parse, request

from aira.research.base import (
    ResearchSubmissionError,
    _env,
)
from aira.research.helpers import (
    build_submission_bundle,
    finalize_submission_bundle,
)


def _supabase_target() -> tuple[Optional[str], str, Optional[str]]:
    return (
        (_env("SUPABASE_URL") or "").rstrip("/") or None,
        _env("SUPABASE_TABLE") or "aira_submissions",
        _env("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_KEY"),
    )


def _supabase_checks_table() -> str:
    return _env("SUPABASE_CHECKS_TABLE") or "aira_submission_checks"


def supabase_config_snapshot() -> Dict[str, Any]:
    url, table, key = _supabase_target()
    return {
        "configured": bool(url and key),
        "url_configured": bool(url),
        "table": table,
        "checks_table": _supabase_checks_table(),
        "key_configured": bool(key),
    }


def _supabase_url(base_url: str, table: str, query: str = "") -> str:
    url = f"{base_url}/rest/v1/{parse.quote(table)}"
    if query:
        return f"{url}?{query}"
    return url


def _supabase_request_json(
    method: str,
    url: str,
    key: str,
    *,
    payload: Optional[Any] = None,
    prefer: str = "return=representation",
    timeout_seconds: int = 15,
) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={
            "apikey": key,
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Prefer": prefer,
        },
        method=method,
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw or "[]")
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw or "{}")
            message = parsed.get("message") or parsed.get("error_description") or parsed.get("error") or raw
        except Exception:
            message = raw or str(exc)
        raise ResearchSubmissionError(f"Supabase request failed: {message}", status_code=exc.code) from exc
    except error.URLError as exc:
        raise ResearchSubmissionError(f"Supabase request failed: {exc.reason}") from exc


def _supabase_fetch_submission_by_fingerprint(
    base_url: str,
    table: str,
    key: str,
    fingerprint: str,
    *,
    timeout_seconds: int = 15,
) -> Optional[Dict[str, Any]]:
    url = _supabase_url(
        base_url,
        table,
        query=parse.urlencode({"select": "*", "submission_fingerprint": f"eq.{fingerprint}", "limit": 1}),
    )
    data = _supabase_request_json("GET", url, key, timeout_seconds=timeout_seconds)
    if isinstance(data, list):
        return data[0] if data else None
    return data or None


def _supabase_fetch_latest_parent(
    base_url: str,
    table: str,
    key: str,
    *,
    sample_name: str,
    sample_version: str,
    timeout_seconds: int = 15,
) -> Optional[Dict[str, Any]]:
    url = _supabase_url(
        base_url,
        table,
        query=parse.urlencode(
            {
                "select": "id,record_sha256",
                "sample_name": f"eq.{sample_name}",
                "sample_version": f"eq.{sample_version}",
                "order": "submitted_at.desc,created_at.desc",
                "limit": 1,
            }
        ),
    )
    data = _supabase_request_json("GET", url, key, timeout_seconds=timeout_seconds)
    if isinstance(data, list):
        return data[0] if data else None
    return data or None


def _supabase_insert_submission_checks(
    base_url: str,
    key: str,
    *,
    submission_id: str,
    submission_checks: List[Dict[str, Any]],
    timeout_seconds: int = 15,
) -> Any:
    if not submission_checks:
        return []
    payload = [
        {
            "submission_id": submission_id,
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
    ]
    url = _supabase_url(
        base_url,
        _supabase_checks_table(),
        query=parse.urlencode({"on_conflict": "submission_id,check_id"}),
    )
    return _supabase_request_json(
        "POST",
        url,
        key,
        payload=payload,
        prefer="resolution=ignore-duplicates,return=representation",
        timeout_seconds=timeout_seconds,
    )


def check_supabase_connection(timeout_seconds: int = 10) -> Dict[str, Any]:
    snapshot = supabase_config_snapshot()
    if not snapshot["configured"]:
        return {
            **snapshot,
            "ok": False,
            "reachable": False,
            "message": "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are not configured.",
        }

    base_url, table, key = _supabase_target()
    assert base_url is not None and key is not None
    url = _supabase_url(base_url, table, query=parse.urlencode({"select": "submitted_at", "limit": 1}))

    try:
        _supabase_request_json("GET", url, key, timeout_seconds=timeout_seconds)
        return {
            **snapshot,
            "ok": True,
            "reachable": True,
            "message": "Supabase connection verified.",
        }
    except ResearchSubmissionError as exc:
        return {
            **snapshot,
            "ok": False,
            "reachable": False,
            "message": str(exc),
            "status_code": exc.status_code,
        }


def _submit_aggregate_research_supabase(
    result: Any,
    source: Optional[str] = None,
    timeout_seconds: int = 15,
    submission_options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    base_url, table, key = _supabase_target()
    if not base_url or not key:
        raise ResearchSubmissionError(
            "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured for research submission."
        )

    bundle = build_submission_bundle(result, source=source, submission_options=submission_options)
    existing = _supabase_fetch_submission_by_fingerprint(
        base_url,
        table,
        key,
        bundle["record"]["submission_fingerprint"],
        timeout_seconds=timeout_seconds,
    )
    if existing and existing.get("id"):
        _supabase_insert_submission_checks(
            base_url,
            key,
            submission_id=existing["id"],
            submission_checks=bundle["submission_checks"],
            timeout_seconds=timeout_seconds,
        )
        return {
            "backend": "supabase",
            "id": existing.get("id"),
            "duplicate": True,
            "record": existing,
        }

    parent = _supabase_fetch_latest_parent(
        base_url,
        table,
        key,
        sample_name=bundle["record"]["sample_name"],
        sample_version=bundle["record"]["sample_version"],
        timeout_seconds=timeout_seconds,
    )
    finalized = finalize_submission_bundle(bundle, parent_record_sha256=(parent or {}).get("record_sha256"))
    response = _supabase_request_json(
        "POST",
        _supabase_url(base_url, table, query=parse.urlencode({"on_conflict": "submission_fingerprint"})),
        key,
        payload=[finalized["record"]],
        prefer="resolution=ignore-duplicates,return=representation",
        timeout_seconds=timeout_seconds,
    )
    inserted = response[0] if isinstance(response, list) and response else None
    if not inserted:
        inserted = _supabase_fetch_submission_by_fingerprint(
            base_url,
            table,
            key,
            finalized["record"]["submission_fingerprint"],
            timeout_seconds=timeout_seconds,
        )
    if not inserted or not inserted.get("id"):
        raise ResearchSubmissionError("Supabase submission did not return a persisted record.")
    _supabase_insert_submission_checks(
        base_url,
        key,
        submission_id=inserted["id"],
        submission_checks=finalized["submission_checks"],
        timeout_seconds=timeout_seconds,
    )
    return {
        "backend": "supabase",
        "id": inserted.get("id"),
        "duplicate": False,
        "record": inserted,
    }