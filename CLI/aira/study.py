"""
Manifest-driven AIRA study runs.

This module keeps raw scan output for every sample/engine/model combination so
follow-up studies can analyze locations, boundaries, and model misses without
depending on aggregate-only research submissions.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import yaml

from aira import __version__
from aira.comparison import build_suppression_matrix, extract_scan
from aira.llm import LLMConfig
from aira.scanner import AIRAScanner, ScanResult

VALID_STUDY_ENGINES = {"static", "llm", "hybrid"}


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scan_result_payload(result: ScanResult) -> Dict[str, Any]:
    return {
        "aira_scan": {
            "version": __version__,
            "target": result.target,
            "scanned_at": result.scanned_at,
            "summary": result.summary,
            "metadata": result.metadata,
            "ai_failure_audit": result.check_results,
            "findings": result.findings,
        }
    }


def _non_empty_string(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def load_study_manifest(path: Union[str, Path]) -> Dict[str, Any]:
    manifest_path = Path(path).expanduser()
    raw = manifest_path.read_text(encoding="utf-8")
    if manifest_path.suffix.lower() == ".json":
        manifest = json.loads(raw)
    else:
        manifest = yaml.safe_load(raw)
    if not isinstance(manifest, dict):
        raise ValueError("Study manifest must be a JSON/YAML object.")
    samples = manifest.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("Study manifest must contain a non-empty 'samples' list.")
    return manifest


def parse_engines(value: Union[str, Iterable[str]]) -> List[str]:
    if isinstance(value, str):
        raw_engines = [item.strip() for item in value.split(",") if item.strip()]
    else:
        raw_engines = [str(item).strip() for item in value if str(item).strip()]
    engines = raw_engines or ["static"]
    invalid = [engine for engine in engines if engine not in VALID_STUDY_ENGINES]
    if invalid:
        raise ValueError(f"Unsupported study engine(s): {', '.join(invalid)}")
    return list(dict.fromkeys(engines))


def parse_model_specs(value: Optional[str]) -> List[Dict[str, str]]:
    if not value:
        return []
    specs = []
    for raw in value.split(","):
        item = raw.strip()
        if not item:
            continue
        provider, sep, model = item.partition(":")
        provider = provider.strip()
        if not provider:
            raise ValueError("Study model specs must include a provider name.")
        if not sep:
            specs.append({"provider": provider, "model": ""})
            continue
        specs.append({"provider": provider, "model": model.strip()})
    return specs


def _sample_target_path(manifest_path: Path, sample: Dict[str, Any]) -> Path:
    raw_path = _non_empty_string(sample.get("path") or sample.get("target") or sample.get("file"))
    if not raw_path:
        raise ValueError("Study sample is missing 'path'.")
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = manifest_path.parent / path
    return path.resolve(strict=False)


def _sample_id(index: int, sample: Dict[str, Any], target_path: Path) -> str:
    explicit = _non_empty_string(sample.get("sample_id") or sample.get("id") or sample.get("sample_name"))
    if explicit:
        return explicit
    return f"sample_{index:04d}_{target_path.stem}"


def _sample_metadata(sample: Dict[str, Any], target_path: Path) -> Dict[str, Any]:
    excluded = {"path", "target", "file"}
    metadata = {key: value for key, value in sample.items() if key not in excluded}
    metadata["resolved_path"] = str(target_path)
    metadata["target_kind"] = "file" if target_path.is_file() else "directory"
    return metadata


def _engine_runs(
    engines: List[str],
    model_specs: List[Dict[str, str]],
    llm_config: Optional[LLMConfig],
) -> List[Tuple[str, LLMConfig]]:
    runs: List[Tuple[str, LLMConfig]] = []
    default_llm = llm_config or LLMConfig()
    for engine in engines:
        if engine == "static":
            runs.append(("static", LLMConfig(provider="auto")))
            continue
        if model_specs:
            for spec in model_specs:
                runs.append((
                    engine,
                    LLMConfig(
                        provider=spec.get("provider") or default_llm.provider,
                        model=spec.get("model") or None,
                        base_url=default_llm.base_url,
                        timeout_seconds=default_llm.timeout_seconds,
                        max_context_chars=default_llm.max_context_chars,
                    ),
                ))
        else:
            runs.append((engine, default_llm))
    return runs


def _run_identity(engine: str, config: LLMConfig, result: Optional[ScanResult] = None) -> Dict[str, str]:
    metadata = result.metadata if result else {}
    provider = str(metadata.get("provider") or metadata.get("engine") or (config.provider if engine != "static" else "static"))
    model = str(metadata.get("model") or config.model or "")
    return {
        "engine": engine,
        "provider": provider,
        "model": model,
        "model_key": ":".join(part for part in (engine, provider, model) if part),
    }


def _result_row(
    *,
    study_id: str,
    run_id: str,
    sample_id: str,
    sample_index: int,
    sample_metadata: Dict[str, Any],
    target_path: Path,
    engine: str,
    config: LLMConfig,
    result: Optional[ScanResult] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    identity = _run_identity(engine, config, result)
    row = {
        "record_type": "aira_study_result",
        "study_id": study_id,
        "run_id": run_id,
        "created_at": _utc_timestamp(),
        "sample_id": sample_id,
        "sample_index": sample_index,
        "sample": sample_metadata,
        "target_path": str(target_path),
        "target_kind": "file" if target_path.is_file() else "directory",
        "status": "error" if error else "ok",
        "error": error,
        **identity,
    }
    if result is not None:
        row["aira_result"] = _scan_result_payload(result)
        row["summary"] = result.summary
    return row


def run_study_manifest(
    manifest_path: Union[str, Path],
    *,
    engines: Union[str, Iterable[str]] = "static",
    model_specs: Optional[str] = None,
    llm_config: Optional[LLMConfig] = None,
    exclude_dirs: Optional[List[str]] = None,
    fail_fast: bool = False,
) -> Dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve(strict=False)
    manifest = load_study_manifest(manifest_file)
    study_id = str(manifest.get("study_id") or manifest_file.stem)
    run_id = f"{study_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    parsed_engines = parse_engines(engines)
    parsed_models = parse_model_specs(model_specs)
    runs = _engine_runs(parsed_engines, parsed_models, llm_config)
    rows: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for index, raw_sample in enumerate(manifest["samples"], start=1):
        sample = dict(raw_sample or {})
        try:
            target_path = _sample_target_path(manifest_file, sample)
            sample_id = _sample_id(index, sample, target_path)
            metadata = _sample_metadata(sample, target_path)
        except Exception as exc:
            if fail_fast:
                raise
            sample_id = str(sample.get("sample_id") or sample.get("id") or f"sample_{index:04d}")
            target_path = manifest_file.parent
            metadata = dict(sample)
            error = str(exc)
            errors.append({"sample_id": sample_id, "error": error})
            rows.append(_result_row(
                study_id=study_id,
                run_id=run_id,
                sample_id=sample_id,
                sample_index=index,
                sample_metadata=metadata,
                target_path=target_path,
                engine="static",
                config=LLMConfig(provider="auto"),
                error=error,
            ))
            continue

        for engine, config in runs:
            try:
                scanner = AIRAScanner(str(target_path), exclude_dirs=exclude_dirs or [])
                result = scanner.scan(mode=engine, llm_config=config)
                rows.append(_result_row(
                    study_id=study_id,
                    run_id=run_id,
                    sample_id=sample_id,
                    sample_index=index,
                    sample_metadata=metadata,
                    target_path=target_path,
                    engine=engine,
                    config=config,
                    result=result,
                ))
            except Exception as exc:
                if fail_fast:
                    raise
                error = str(exc)
                errors.append({"sample_id": sample_id, "engine": engine, "error": error})
                rows.append(_result_row(
                    study_id=study_id,
                    run_id=run_id,
                    sample_id=sample_id,
                    sample_index=index,
                    sample_metadata=metadata,
                    target_path=target_path,
                    engine=engine,
                    config=config,
                    error=error,
                ))

    summary = summarize_study_rows(rows, study_id=study_id, run_id=run_id)
    summary["manifest_path"] = str(manifest_file)
    summary["errors"] = errors
    return {"summary": summary, "rows": rows}


def summarize_study_rows(rows: List[Dict[str, Any]], *, study_id: str, run_id: str) -> Dict[str, Any]:
    by_run: Dict[str, Dict[str, int]] = defaultdict(lambda: {"rows": 0, "ok": 0, "error": 0})
    samples = set()
    for row in rows:
        samples.add(row.get("sample_id"))
        key = str(row.get("model_key") or row.get("engine") or "unknown")
        by_run[key]["rows"] += 1
        if row.get("status") == "ok":
            by_run[key]["ok"] += 1
        else:
            by_run[key]["error"] += 1
    return {
        "study_id": study_id,
        "run_id": run_id,
        "sample_count": len(samples),
        "row_count": len(rows),
        "ok_count": sum(1 for row in rows if row.get("status") == "ok"),
        "error_count": sum(1 for row in rows if row.get("status") != "ok"),
        "by_run": dict(sorted(by_run.items())),
    }


def write_study_jsonl(path: Union[str, Path], rows: Iterable[Dict[str, Any]]) -> Path:
    output_path = Path(path).expanduser()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True))
            handle.write("\n")
    return output_path


def load_study_jsonl(path: Union[str, Path]) -> List[Dict[str, Any]]:
    rows = []
    with Path(path).expanduser().open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            payload = json.loads(line)
            if not isinstance(payload, dict):
                raise ValueError(f"Study JSONL line {line_number} is not an object.")
            rows.append(payload)
    return rows


def _scan_from_row(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if row.get("status") != "ok":
        return None
    aira_result = row.get("aira_result")
    if not isinstance(aira_result, dict):
        return None
    try:
        return extract_scan(aira_result)
    except ValueError:
        return None


def _aggregate_counts(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    for key, value in source.items():
        if isinstance(value, int):
            target[key] = int(target.get(key, 0)) + value


def _aggregate_nested_counts(target: Dict[str, Dict[str, int]], source: Dict[str, Dict[str, int]]) -> None:
    for key, counts in source.items():
        bucket = target.setdefault(key, {})
        _aggregate_counts(bucket, counts)


def _ratio(static_count: int, model_count: int) -> Any:
    if model_count == 0:
        return "inf" if static_count else 0
    return round(static_count / model_count, 4)


def _compare_key(row: Dict[str, Any]) -> str:
    return str(row.get("model_key") or row.get("engine") or "unknown")


def compare_study_results(
    rows: List[Dict[str, Any]],
    *,
    baseline_engine: str = "static",
    line_window: int = 5,
) -> Dict[str, Any]:
    baselines: Dict[str, Dict[str, Any]] = {}
    candidates: List[Dict[str, Any]] = []
    for row in rows:
        if row.get("engine") == baseline_engine and row.get("status") == "ok":
            baselines[str(row.get("sample_id"))] = row
        elif row.get("status") == "ok":
            candidates.append(row)

    by_model: Dict[str, Dict[str, Any]] = {}
    skipped = []
    for row in candidates:
        sample_id = str(row.get("sample_id"))
        baseline = baselines.get(sample_id)
        if not baseline:
            skipped.append({"sample_id": sample_id, "model_key": _compare_key(row), "reason": "missing_baseline"})
            continue
        static_scan = _scan_from_row(baseline)
        model_scan = _scan_from_row(row)
        if not static_scan or not model_scan:
            skipped.append({"sample_id": sample_id, "model_key": _compare_key(row), "reason": "missing_scan_payload"})
            continue

        matrix = build_suppression_matrix(static_scan, model_scan, line_window=line_window)
        model_key = _compare_key(row)
        aggregate = by_model.setdefault(model_key, {
            "model_key": model_key,
            "engine": row.get("engine"),
            "provider": row.get("provider"),
            "model": row.get("model"),
            "samples_compared": 0,
            "summary": {
                "line_window": line_window,
                "static_findings": 0,
                "model_findings": 0,
                "matched_by_model": 0,
                "missed_by_model": 0,
                "model_only_findings": 0,
            },
            "by_check": {},
            "by_boundary_type": {},
            "check_status_counts": {},
            "missed_findings": [],
            "model_only_findings": [],
        })
        aggregate["samples_compared"] += 1
        _aggregate_counts(aggregate["summary"], matrix.get("summary", {}))
        _aggregate_nested_counts(aggregate["by_check"], matrix.get("by_check", {}))
        _aggregate_nested_counts(aggregate["by_boundary_type"], matrix.get("by_boundary_type", {}))
        for check_row in matrix.get("check_status_matrix", []):
            check_key = str(check_row.get("check_key") or "unknown")
            category = str(check_row.get("category") or "unknown")
            bucket = aggregate["check_status_counts"].setdefault(check_key, {})
            bucket[category] = int(bucket.get(category, 0)) + 1
        for finding in matrix.get("missed_findings", []):
            aggregate["missed_findings"].append({"sample_id": sample_id, **finding})
        for finding in matrix.get("model_only_findings", []):
            aggregate["model_only_findings"].append({"sample_id": sample_id, **finding})

    for aggregate in by_model.values():
        summary = aggregate["summary"]
        summary["static_to_model_finding_ratio"] = _ratio(
            int(summary.get("static_findings", 0)),
            int(summary.get("model_findings", 0)),
        )

    return {
        "baseline_engine": baseline_engine,
        "line_window": line_window,
        "baseline_samples": len(baselines),
        "candidate_rows": len(candidates),
        "skipped": skipped,
        "by_model": dict(sorted(by_model.items())),
    }
