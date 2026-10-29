"""Versioned, non-scoring ErrorSignal inventory orchestration."""

from __future__ import annotations

import fnmatch
import os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Union

from aira.parsers import JavaScriptTypeScriptSignalParser, PythonSignalParser

INVENTORY_SCHEMA_VERSION = "aira-error-inventory-v1"
SIGNAL_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}
SKIP_DIRECTORIES = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", "dist", "build", ".tox", "coverage", ".mypy_cache"}


def _matches_exclude(path: Path, root: Path, patterns: Iterable[str]) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.name
    for raw_pattern in patterns:
        pattern = raw_pattern.strip().replace("\\", "/").rstrip("/")
        if not pattern:
            continue
        if path.name == pattern or relative == pattern:
            return True
        if fnmatch.fnmatchcase(path.name, pattern) or fnmatch.fnmatchcase(relative, pattern):
            return True
        if "/" not in pattern and not any(char in pattern for char in "*?[]") and pattern in path.parts:
            return True
    return False


def _discover_files(target: Path, exclude_patterns: Iterable[str]) -> List[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() in SIGNAL_EXTENSIONS else []
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(target):
        current = Path(dirpath)
        dirnames[:] = [
            name for name in dirnames
            if name not in SKIP_DIRECTORIES and not _matches_exclude(current / name, target, exclude_patterns)
        ]
        for filename in filenames:
            path = current / filename
            if path.suffix.lower() in SIGNAL_EXTENSIONS and not _matches_exclude(path, target, exclude_patterns):
                files.append(path)
    return sorted(files)


def _artifact_path(target: Path, path: Path) -> str:
    return path.name if target.is_file() else path.relative_to(target).as_posix()


def inventory_errors(
    target: Union[str, Path],
    *,
    exclude_patterns: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Inventory error-related observations without changing canonical checks."""
    resolved = Path(target).expanduser().resolve(strict=False)
    if not resolved.exists():
        raise ValueError(f"Inventory target does not exist: {resolved}")
    patterns = tuple(exclude_patterns or ())
    files = _discover_files(resolved, patterns)
    if not files:
        raise ValueError(f"No supported source files found for error inventory: {resolved}")

    signals: List[Dict[str, Any]] = []
    artifacts: List[Dict[str, Any]] = []
    for path in files:
        artifact = _artifact_path(resolved, path)
        language = SIGNAL_EXTENSIONS[path.suffix.lower()]
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            if language == "python":
                output = PythonSignalParser(path, artifact, source).parse()
            else:
                output = JavaScriptTypeScriptSignalParser(path, artifact, source, language).parse()
            signals.extend(output.signals)
            artifacts.append({
                "path": artifact,
                "language": language,
                **output.health.to_dict(),
            })
        except OSError as exc:
            artifacts.append({
                "path": artifact,
                "language": language,
                "parser": "unavailable",
                "parser_version": "unknown",
                "status": "failed",
                "structural": False,
                "limitations": ["artifact could not be read"],
                "error": {"type": exc.__class__.__name__, "message": str(exc)},
            })

    signals.sort(key=lambda item: (
        item["artifact"],
        item["region"]["start_line"],
        item["region"]["start_column"],
        item["kind"],
        item["signal_id"],
    ))
    artifacts.sort(key=lambda item: item["path"])
    kind_counts = Counter(signal["kind"] for signal in signals)
    status_counts = Counter(artifact["status"] for artifact in artifacts)
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "target": str(resolved),
        "summary": {
            "artifacts_discovered": len(artifacts),
            "artifacts_analyzed": status_counts["analyzed"],
            "artifacts_partial": status_counts["partial"],
            "artifacts_failed": status_counts["failed"],
            "signals_total": len(signals),
            "signals_by_kind": dict(sorted(kind_counts.items())),
        },
        "artifacts": artifacts,
        "signals": signals,
    }
