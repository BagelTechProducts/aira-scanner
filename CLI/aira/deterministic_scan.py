"""
Deterministic inline scan helpers for server-side fallback routes.
"""

from __future__ import annotations

import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Mapping, Sequence

from aira.scanner import SUPPORTED_EXTENSIONS, AIRAScanner, ScanResult

try:
    import esprima  # type: ignore
except ImportError:  # pragma: no cover - optional parser dependency
    esprima = None


LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "py": ".py",
    "javascript": ".js",
    "js": ".js",
    "jsx": ".jsx",
    "mjs": ".mjs",
    "cjs": ".cjs",
    "typescript": ".ts",
    "ts": ".ts",
    "tsx": ".tsx",
}

LANGUAGE_CANONICAL = {
    "python": "python",
    "py": "python",
    "javascript": "javascript",
    "js": "javascript",
    "jsx": "javascript",
    "mjs": "javascript",
    "cjs": "javascript",
    "typescript": "typescript",
    "ts": "typescript",
    "tsx": "typescript",
}


def _canonical_language(lang: str) -> str:
    return LANGUAGE_CANONICAL.get((lang or "").lower(), (lang or "").lower())


def _metadata_for_languages(languages: Sequence[str]) -> Dict[str, Any]:
    normalized = sorted({LANGUAGE_CANONICAL.get((lang or "").lower(), (lang or "").lower()) for lang in languages if lang})
    if normalized == ["python"]:
        return {
            "engine": "deterministic-static",
            "engine_label": "Deterministic parser-backed scan",
            "note": "Server-side deterministic scan using Python AST-backed rules.",
            "parser_backed": True,
        }
    if normalized == ["javascript"]:
        return {
            "engine": "deterministic-static",
            "engine_label": "Deterministic parser-backed scan" if esprima is not None else "Deterministic static scan",
            "note": "Server-side deterministic scan using JavaScript AST-backed rules." if esprima is not None else "Server-side deterministic scan using structured JavaScript checks.",
            "parser_backed": esprima is not None,
        }
    if normalized == ["typescript"]:
        return {
            "engine": "deterministic-static",
            "engine_label": "Deterministic static scan",
            "note": "Server-side deterministic scan using structured TypeScript checks.",
            "parser_backed": False,
        }

    parser_backed = bool(normalized) and all(lang == "python" or (lang == "javascript" and esprima is not None) for lang in normalized)
    return {
        "engine": "deterministic-static",
        "engine_label": "Deterministic parser-backed scan" if parser_backed else "Deterministic static scan",
        "note": "Server-side deterministic scan over selected files using shared CLI static rules.",
        "parser_backed": parser_backed,
    }


def _build_summary(result: ScanResult) -> Dict[str, Any]:
    by_severity = result.summary.get("by_severity") or {}
    return {
        "high": int(by_severity.get("HIGH", 0)),
        "medium": int(by_severity.get("MEDIUM", 0)),
        "low": int(by_severity.get("LOW", 0)),
        "total": int(result.summary.get("findings_total", 0)),
        "files_scanned": int(result.summary.get("files_scanned", 0)),
        "files_discovered": int(result.summary.get("files_discovered", result.summary.get("files_scanned", 0))),
        "files_analyzed": int(result.summary.get("files_analyzed", result.summary.get("files_scanned", 0))),
        "files_partial": int(result.summary.get("files_partial", 0)),
        "files_failed": int(result.summary.get("files_failed", 0)),
        "files_omitted": int(result.summary.get("files_omitted", 0)),
        "scan_completeness": str(result.summary.get("scan_completeness", "unavailable")),
        "checks_failed": int(result.summary.get("checks_failed", 0)),
        "checks_passed": int(result.summary.get("checks_passed", 0)),
        "checks_unknown": int(result.summary.get("checks_unknown", 0)),
        "requires_human_review": list(result.summary.get("requires_human_review") or []),
    }


def _resolved_output_path(raw_path: str, index: int, default_lang: str | None) -> Path:
    candidate = PurePosixPath((raw_path or "").replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"Invalid file path for deterministic scan: {raw_path}")

    parts = [part for part in candidate.parts if part not in {"", "."}]
    relative_path = Path(*parts) if parts else Path(f"snippet-{index}")
    suffix = relative_path.suffix.lower()
    if suffix in SUPPORTED_EXTENSIONS:
        return relative_path

    extension = LANGUAGE_EXTENSIONS.get(_canonical_language(default_lang or ""))
    if not extension:
        raise ValueError(f"Unsupported language for deterministic scan: {default_lang or raw_path}")
    return relative_path.with_suffix(extension)


def scan_inline_sources(sources: Sequence[Mapping[str, Any]], default_lang: str | None = None) -> Dict[str, Any]:
    if not sources:
        raise ValueError("No code supplied for deterministic scan.")

    detected_languages: List[str] = []
    canonical_default_lang = _canonical_language(default_lang or "")
    with tempfile.TemporaryDirectory(prefix="aira-static-") as tmpdir:
        root = Path(tmpdir)
        for index, source in enumerate(sources, start=1):
            if not isinstance(source, Mapping):
                raise ValueError("Deterministic scan files must be objects with path and code.")

            code = str(source.get("code") or "")
            raw_path = str(source.get("path") or "")
            output_path = _resolved_output_path(raw_path, index, canonical_default_lang)
            detected_languages.append(SUPPORTED_EXTENSIONS[output_path.suffix.lower()])

            full_path = root / output_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(code, encoding="utf-8")

        result = AIRAScanner(str(root)).scan(mode="static")

    canonical_languages = sorted({_canonical_language(lang) for lang in detected_languages})
    return {
        "checks": result.check_results,
        "findings": [
            {
                "check_id": finding["check_id"],
                "check_name": finding["check_name"],
                "severity": finding["severity"],
                "file": finding["file"],
                "line": finding["line"],
                "description": finding["description"],
                "snippet": finding["snippet"],
                "boundary_type": finding.get("boundary_type", "unknown"),
                "context": finding.get("context", {}),
                "evidence": finding.get("evidence", {}),
                "fingerprint_version": finding.get("fingerprint_version", ""),
                "fingerprint": finding.get("fingerprint", ""),
                "semantic_fingerprint": finding.get("semantic_fingerprint", ""),
                "location_fingerprint": finding.get("location_fingerprint", ""),
            }
            for finding in result.findings
        ],
        "summary": _build_summary(result),
        "meta": {
            **_metadata_for_languages(canonical_languages),
            "language": canonical_languages[0] if len(canonical_languages) == 1 else "mixed",
            "languages": canonical_languages,
            "source_count": int(result.summary.get("files_discovered", result.summary.get("files_scanned", 0))),
            "scan_completeness": str(result.summary.get("scan_completeness", "unavailable")),
            "capability_gaps": dict(result.metadata.get("capability_gaps") or {}),
            "artifact_manifest": list(result.metadata.get("artifacts") or []),
        },
    }


def scan_inline_source(code: str, lang: str) -> Dict[str, Any]:
    normalized_lang = _canonical_language(lang)
    extension = LANGUAGE_EXTENSIONS.get(normalized_lang)
    if not extension:
        raise ValueError(f"Unsupported language for deterministic scan: {lang}")

    return scan_inline_sources(
        [{"path": f"snippet{extension}", "code": code}],
        default_lang=normalized_lang,
    )
