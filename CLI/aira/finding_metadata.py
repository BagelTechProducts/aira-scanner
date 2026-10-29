"""
Location-aware finding metadata for AIRA scan output.

This module is intentionally deterministic. It adds stable identifiers and
boundary/context fields without changing whether a rule passes or fails.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

FINGERPRINT_VERSION = "aira-finding-v1"


CHECK_BOUNDARY_DEFAULTS = {
    "C01": "success_signal",
    "C02": "audit_boundary",
    "C03": "exception_handler",
    "C04": "fallback_branch",
    "C05": "bypass_override",
    "C06": "return_contract",
    "C08": "async_task",
    "C09": "environment_gate",
    "C10": "startup_boundary",
    "C11": "nondeterministic_call",
    "C13": "confidence_surface",
    "C14": "test_surface",
    "C15": "retry_write_boundary",
    "SCANNER": "scanner_error",
}

MEANINGFUL_PYTHON_NODES = {
    "AsyncFunctionDef",
    "Assign",
    "Await",
    "Call",
    "ClassDef",
    "ExceptHandler",
    "Expr",
    "For",
    "FunctionDef",
    "If",
    "Return",
    "Try",
    "While",
    "With",
}


def _sha256_short(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def normalize_snippet(snippet: Any) -> str:
    """Collapse whitespace so snippet-derived fingerprints survive formatting drift."""
    if snippet is None:
        return ""
    return re.sub(r"\s+", " ", str(snippet).strip())


def _line_position(line: int, total_lines: int) -> Optional[float]:
    if line <= 0 or total_lines <= 0:
        return None
    return round(min(line, total_lines) / total_lines, 6)


def _node_name(node: ast.AST) -> str:
    return type(node).__name__


def _node_start(node: ast.AST) -> int:
    return int(getattr(node, "lineno", 0) or 0)


def _node_end(node: ast.AST) -> int:
    return int(getattr(node, "end_lineno", 0) or _node_start(node) or 0)


def _contains_line(node: ast.AST, line: int) -> bool:
    start = _node_start(node)
    end = _node_end(node)
    return start > 0 and start <= line <= end


def _python_context(source: str, line: int, total_lines: int) -> Dict[str, Any]:
    context: Dict[str, Any] = {
        "parser": "python_ast",
        "line_count": total_lines,
        "normalized_line_position": _line_position(line, total_lines),
        "enclosing_function": "",
        "enclosing_class": "",
        "enclosing_block": "",
        "ast_path": [],
    }
    if line <= 0:
        return context

    try:
        tree = ast.parse(source)
    except SyntaxError:
        context["parser"] = "python_ast_unavailable"
        return context

    candidates = [
        node for node in ast.walk(tree)
        if _contains_line(node, line) and _node_name(node) in MEANINGFUL_PYTHON_NODES
    ]
    candidates.sort(key=lambda node: (_node_start(node), -(_node_end(node) - _node_start(node))))
    context["ast_path"] = [_node_name(node) for node in candidates]
    if candidates:
        context["enclosing_block"] = _node_name(candidates[-1])

    functions = [
        node for node in candidates
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    classes = [node for node in candidates if isinstance(node, ast.ClassDef)]
    if functions:
        context["enclosing_function"] = functions[-1].name
    if classes:
        context["enclosing_class"] = classes[-1].name
    return context


_JS_FUNCTION_PATTERNS = (
    re.compile(r"\b(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\b"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"),
    re.compile(r"^\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"),
)
_JS_CLASS_PATTERN = re.compile(r"\bclass\s+([A-Za-z_$][\w$]*)\b")


def _latest_match(lines: List[str], patterns: Iterable[re.Pattern[str]]) -> str:
    for line in reversed(lines):
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                return match.group(1)
    return ""


def _javascript_context(source: str, line: int, total_lines: int) -> Dict[str, Any]:
    context: Dict[str, Any] = {
        "parser": "javascript_heuristic",
        "line_count": total_lines,
        "normalized_line_position": _line_position(line, total_lines),
        "enclosing_function": "",
        "enclosing_class": "",
        "enclosing_block": "",
        "ast_path": [],
    }
    if line <= 0:
        return context

    lines = source.splitlines()
    prefix = lines[:line]
    window = "\n".join(lines[max(0, line - 6): min(len(lines), line + 4)])
    context["enclosing_function"] = _latest_match(prefix, _JS_FUNCTION_PATTERNS)
    context["enclosing_class"] = _latest_match(prefix, (_JS_CLASS_PATTERN,))

    ast_path: List[str] = []
    if re.search(r"\bcatch\s*(?:\(|\{)", window):
        ast_path.append("CatchClause")
    if re.search(r"\btry\s*\{", window):
        ast_path.append("TryStatement")
    if re.search(r"\breturn\b", window):
        ast_path.append("ReturnStatement")
    if context["enclosing_function"]:
        ast_path.insert(0, "Function")
    if context["enclosing_class"]:
        ast_path.insert(0, "Class")
    context["ast_path"] = ast_path
    context["enclosing_block"] = ast_path[-1] if ast_path else ""
    return context


def _generic_context(source: Optional[str], line: int) -> Dict[str, Any]:
    lines = source.splitlines() if source else []
    total_lines = len(lines)
    return {
        "parser": "unavailable",
        "line_count": total_lines,
        "normalized_line_position": _line_position(line, total_lines),
        "enclosing_function": "",
        "enclosing_class": "",
        "enclosing_block": "",
        "ast_path": [],
    }


def build_context(
    *,
    source: Optional[str],
    line: int,
    language: Optional[str] = None,
    source_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Build deterministic location context for a finding line."""
    if source is None and source_path is not None and source_path.exists():
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            source = None

    if not source:
        return _generic_context(source, line)

    total_lines = len(source.splitlines())
    suffix = source_path.suffix.lower() if source_path else ""
    inferred_language = (language or "").lower()
    if inferred_language == "python" or suffix == ".py":
        return _python_context(source, line, total_lines)
    if inferred_language in {"javascript", "typescript"} or suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return _javascript_context(source, line, total_lines)
    return _generic_context(source, line)


def infer_boundary_type(finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> str:
    """Classify the code boundary where the finding occurs."""
    check_id = str(finding.get("check_id") or "").upper()
    text = " ".join(
        str(finding.get(key) or "")
        for key in ("description", "snippet", "check_name")
    ).lower()
    ast_path = set((context or {}).get("ast_path") or [])
    function_name = str((context or {}).get("enclosing_function") or "").lower()

    if "ExceptHandler" in ast_path or "CatchClause" in ast_path or "except" in text or "catch" in text:
        if check_id in {"C01", "C02", "C03", "C10"}:
            return "exception_handler"
    if check_id == "C10" or any(term in function_name for term in ("startup", "init", "setup", "bootstrap")):
        return "startup_boundary"
    if "fallback" in text or "degraded" in text or "best_effort" in text:
        return "fallback_branch"
    if "bypass" in text or "skip" in text or "force" in text or "disable" in text:
        return "bypass_override"
    if "environment" in text or "debug" in text or "staging" in text or "dev" in text:
        return "environment_gate"
    if "return" in text or "Return" in ast_path:
        if check_id in {"C01", "C06", "C13"}:
            return "return_contract"
    return CHECK_BOUNDARY_DEFAULTS.get(check_id, "unknown")


def _fingerprint_payload(finding: Dict[str, Any], context: Dict[str, Any], boundary_type: str) -> Dict[str, Any]:
    return {
        "boundary_type": boundary_type,
        "check_id": str(finding.get("check_id") or ""),
        "file": str(finding.get("file") or ""),
        "line": int(finding.get("line") or 0),
        "snippet": normalize_snippet(finding.get("snippet"))[:500],
        "enclosing_class": context.get("enclosing_class") or "",
        "enclosing_function": context.get("enclosing_function") or "",
    }


def enrich_finding(
    finding: Dict[str, Any],
    *,
    source: Optional[str] = None,
    source_path: Optional[Path] = None,
    language: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a finding with deterministic identity and boundary metadata."""
    enriched = dict(finding)
    try:
        line = int(enriched.get("line") or 0)
    except (TypeError, ValueError):
        line = 0
    context = dict(enriched.get("context") or {})
    if not context:
        context = build_context(source=source, source_path=source_path, line=line, language=language)

    boundary_type = str(enriched.get("boundary_type") or infer_boundary_type(enriched, context))
    payload = _fingerprint_payload(enriched, context, boundary_type)
    semantic_payload = {
        key: payload[key]
        for key in ("boundary_type", "check_id", "snippet", "enclosing_class", "enclosing_function")
    }
    location_payload = {
        key: payload[key]
        for key in ("boundary_type", "check_id", "file", "line")
    }

    enriched["boundary_type"] = boundary_type
    enriched["context"] = context
    enriched["fingerprint_version"] = enriched.get("fingerprint_version") or FINGERPRINT_VERSION
    enriched["fingerprint"] = enriched.get("fingerprint") or _sha256_short(payload)
    enriched["semantic_fingerprint"] = enriched.get("semantic_fingerprint") or _sha256_short(semantic_payload)
    enriched["location_fingerprint"] = enriched.get("location_fingerprint") or _sha256_short(location_payload)
    enriched["evidence"] = {
        **(enriched.get("evidence") or {}),
        "snippet_normalized": normalize_snippet(enriched.get("snippet")),
        "classification": "structural" if str(context.get("parser", "")).endswith("_ast") else "heuristic",
    }
    return enriched
