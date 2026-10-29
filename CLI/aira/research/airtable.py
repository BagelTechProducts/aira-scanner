"""
AIRA research — Airtable backend (legacy fallback).
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib import error, parse, request

from aira.research.base import (
    UNKNOWN_FIELD_RE,
    ResearchSubmissionError,
    _env,
)
from aira.research.helpers import (
    _decode_error_message,
    build_baseline_submission_fields,
    build_optional_submission_fields,
)


def _airtable_target() -> tuple[Optional[str], str, Optional[str]]:
    return (
        _env("AIRTABLE_BASE_ID"),
        _env("AIRTABLE_TABLE") or "Submissions",
        _env("AIRTABLE_TOKEN"),
    )


def airtable_config_snapshot() -> Dict[str, Any]:
    base_id, table, token = _airtable_target()
    return {
        "configured": bool(base_id and token),
        "base_id_configured": bool(base_id),
        "table": table,
        "token_configured": bool(token),
    }


def _airtable_url(base_id: str, table: str, query: str = "") -> str:
    url = f"https://api.airtable.com/v0/{parse.quote(base_id)}/{parse.quote(table)}"
    if query:
        return f"{url}?{query}"
    return url


def _airtable_request_json(
    method: str,
    url: str,
    token: str,
    *,
    payload: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = 15,
) -> Dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with request.urlopen(req, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return json.loads(raw or "{}")
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise ResearchSubmissionError(_decode_error_message(raw, exc), status_code=exc.code) from exc
    except error.URLError as exc:
        raise ResearchSubmissionError(f"Airtable request failed: {exc.reason}") from exc


def _extract_unknown_field(message: str) -> Optional[str]:
    match = UNKNOWN_FIELD_RE.search(message)
    if not match:
        return None
    return match.group("field")


def check_airtable_connection(timeout_seconds: int = 10) -> Dict[str, Any]:
    snapshot = airtable_config_snapshot()
    if not snapshot["configured"]:
        return {
            **snapshot,
            "ok": False,
            "reachable": False,
            "message": "AIRTABLE_BASE_ID and AIRTABLE_TOKEN are not configured.",
        }

    base_id, table, token = _airtable_target()
    assert base_id is not None and token is not None
    url = _airtable_url(base_id, table, query=parse.urlencode({"maxRecords": 1}))

    try:
        _airtable_request_json("GET", url, token, timeout_seconds=timeout_seconds)
        return {
            **snapshot,
            "ok": True,
            "reachable": True,
            "message": "Airtable connection verified.",
        }
    except ResearchSubmissionError as exc:
        return {
            **snapshot,
            "ok": False,
            "reachable": False,
            "message": str(exc),
            "status_code": exc.status_code,
        }


def _submit_aggregate_research_airtable(result: Any, source: Optional[str] = None, timeout_seconds: int = 15) -> Dict[str, Any]:
    base_id, table, token = _airtable_target()
    if not base_id or not token:
        raise ResearchSubmissionError(
            "AIRTABLE_BASE_ID and AIRTABLE_TOKEN must be configured for research submission."
        )

    baseline_fields = build_baseline_submission_fields(result, source=source)
    optional_fields = build_optional_submission_fields(result)
    dropped_optional_fields = []
    url = _airtable_url(base_id, table)

    while True:
        fields = {**baseline_fields, **optional_fields}
        try:
            response = _airtable_request_json(
                "POST",
                url,
                token,
                payload={"fields": fields},
                timeout_seconds=timeout_seconds,
            )
            response["submitted_fields"] = sorted(fields)
            response["dropped_optional_fields"] = dropped_optional_fields
            return response
        except ResearchSubmissionError as exc:
            unknown_field = _extract_unknown_field(str(exc))
            if exc.status_code != 422 or not unknown_field:
                raise ResearchSubmissionError(f"Airtable submission failed: {exc}", status_code=exc.status_code) from exc
            if unknown_field not in optional_fields:
                raise ResearchSubmissionError(
                    f"Airtable submission failed: required field '{unknown_field}' is missing from the table.",
                    status_code=exc.status_code,
                ) from exc

            optional_fields.pop(unknown_field, None)
            dropped_optional_fields.append(unknown_field)