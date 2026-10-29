"""
Manifest-driven collection of public repository samples for curated AIRA research datasets.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from aira import __version__ as AIRA_VERSION
from aira.llm import LLMConfig
from aira.research import (
    DEFAULT_SCORING_VERSION,
    ResearchSubmissionError,
    _canonicalize,
    _env,
    _sha256_hex,
    _supabase_request_json,
    _supabase_target,
    submit_aggregate_research,
)
from aira.scanner import AIRAScanner, ScanResult, result_to_json

DEFAULT_MANIFESTS_TABLE = "aira_sample_manifests"


@dataclass
class CollectionSummary:
    sample_name: str
    sample_version: str
    repo: str
    commit_sha: str
    findings_total: int
    checks_failed: int
    research_submission_id: Optional[str] = None
    duplicate: bool = False
    manifest_written: bool = False
    error: Optional[str] = None
    result_path: Optional[str] = None
    engine: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None


def _safe_result_filename(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value.strip())
    return safe.strip("._") or "sample"


def _write_scan_result(
    result: ScanResult,
    results_dir: str | Path,
    *,
    sample_name: str,
    sample_version: str,
) -> str:
    output_dir = Path(results_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{_safe_result_filename(sample_name)}--{_safe_result_filename(sample_version)}.json"
    output_path = output_dir / filename
    output_path.write_text(result_to_json(result) + "\n", encoding="utf-8")
    return str(output_path)


def _result_metadata_value(result: ScanResult, key: str) -> Optional[str]:
    value = result.metadata.get(key) if result.metadata else None
    if value:
        return str(value)
    for source in result.metadata.get("sources", []) if result.metadata else []:
        if isinstance(source, dict) and source.get(key):
            return str(source[key])
    return None


def _normalize_repo_url(repo: str) -> str:
    text = repo.strip()
    if text.startswith("https://") or text.startswith("http://") or text.startswith("git@"):
        return text
    if text.count("/") == 1:
        return f"https://github.com/{text}.git"
    raise ValueError(f"Unsupported repo reference '{repo}'. Use owner/repo or a git URL.")


def _infer_repo_slug(repo: str) -> str:
    text = repo.strip()
    if text.count("/") == 1 and not text.startswith("http"):
        return text.removesuffix(".git")
    if text.startswith("git@github.com:"):
        text = text.split("git@github.com:", 1)[1]
    if text.startswith("https://github.com/"):
        text = text.split("https://github.com/", 1)[1]
    elif text.startswith("http://github.com/"):
        text = text.split("http://github.com/", 1)[1]
    return text.removesuffix(".git").strip("/")


def _repo_checkout_dirname(repo: str) -> str:
    try:
        return _infer_repo_slug(repo).replace("/", "__")
    except ValueError:
        return _sha256_hex(repo)[:16]


def _run_git(args: List[str], *, cwd: Optional[Path] = None) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def load_collection_manifest(path: str | Path) -> Dict[str, Any]:
    manifest_path = Path(path)
    raw = manifest_path.read_text(encoding="utf-8")
    if manifest_path.suffix.lower() == ".json":
        data = json.loads(raw)
    else:
        data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("Collection manifest must be a JSON/YAML object.")
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("Collection manifest must contain a non-empty 'samples' list.")
    for required in ("sampling_method", "sampling_frame", "attribution_policy"):
        if not data.get(required):
            raise ValueError(f"Collection manifest must define '{required}'.")
    return data


def _resolve_sample_name(sample: Dict[str, Any]) -> str:
    explicit = sample.get("sample_name")
    if explicit:
        return str(explicit)
    return f"github:{_infer_repo_slug(str(sample['repo']))}"


def _resolve_sample_version(sample: Dict[str, Any], commit_sha: str) -> str:
    explicit = sample.get("sample_version")
    if explicit:
        return str(explicit)
    return commit_sha


def _submission_options_for_sample(sample: Dict[str, Any], commit_sha: str, defaults: Dict[str, Any]) -> Dict[str, Any]:
    repo_slug = _infer_repo_slug(str(sample["repo"]))
    return {
        "sample_name": _resolve_sample_name(sample),
        "sample_version": _resolve_sample_version(sample, commit_sha),
        "attribution_class": str(sample.get("attribution_class") or defaults.get("attribution_class") or "unknown"),
        "source_id": str(sample.get("source_id") or repo_slug),
        "source_kind": str(sample.get("source_kind") or defaults.get("source_kind") or "repo"),
        "scanner_version": str(defaults.get("scanner_version") or _env("AIRA_SCANNER_VERSION") or AIRA_VERSION),
        "ruleset_version": str(
            defaults.get("ruleset_version")
            or _env("AIRA_RULESET_VERSION")
            or defaults.get("scanner_version")
            or _env("AIRA_SCANNER_VERSION")
            or AIRA_VERSION
        ),
        "scoring_version": str(defaults.get("scoring_version") or DEFAULT_SCORING_VERSION),
    }


def build_sample_manifest_record(
    manifest: Dict[str, Any],
    sample: Dict[str, Any],
    *,
    commit_sha: str,
    submission_options: Dict[str, Any],
) -> Dict[str, Any]:
    record = {
        "sample_name": submission_options["sample_name"],
        "sample_version": submission_options["sample_version"],
        "sampling_method": str(manifest["sampling_method"]),
        "sampling_frame": str(manifest["sampling_frame"]),
        "inclusion_criteria": manifest.get("inclusion_criteria") or {},
        "exclusion_criteria": manifest.get("exclusion_criteria") or {},
        "attribution_policy": str(manifest["attribution_policy"]),
        "random_seed": manifest.get("random_seed"),
        "scanner_version": submission_options["scanner_version"],
        "ruleset_version": submission_options["ruleset_version"],
        "scoring_version": submission_options["scoring_version"],
        "notes": sample.get("notes") or manifest.get("notes"),
        "repo": str(sample["repo"]),
        "ref": sample.get("ref"),
        "commit_sha": commit_sha,
        "attribution_class": submission_options["attribution_class"],
        "source_id": submission_options["source_id"],
        "source_kind": submission_options["source_kind"],
    }
    manifest_sha256 = _sha256_hex(_canonicalize(record))
    return {
        "sample_name": record["sample_name"],
        "sample_version": record["sample_version"],
        "sampling_method": record["sampling_method"],
        "sampling_frame": record["sampling_frame"],
        "inclusion_criteria": record["inclusion_criteria"],
        "exclusion_criteria": record["exclusion_criteria"],
        "attribution_policy": record["attribution_policy"],
        "random_seed": record["random_seed"],
        "scanner_version": record["scanner_version"],
        "ruleset_version": record["ruleset_version"],
        "scoring_version": record["scoring_version"],
        "manifest_sha256": manifest_sha256,
        "notes": record["notes"],
    }


def submit_sample_manifest(record: Dict[str, Any], *, timeout_seconds: int = 15) -> bool:
    base_url, _, key = _supabase_target()
    if not base_url or not key:
        raise ResearchSubmissionError(
            "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured for manifest submission."
        )
    table = _env("SUPABASE_MANIFESTS_TABLE") or DEFAULT_MANIFESTS_TABLE
    query = "on_conflict=sample_name,sample_version"
    url = f"{base_url}/rest/v1/{table}?{query}"
    _supabase_request_json(
        "POST",
        url,
        key,
        payload=[record],
        prefer="resolution=merge-duplicates,return=representation",
        timeout_seconds=timeout_seconds,
    )
    return True


def _clone_sample_repo(sample: Dict[str, Any], destination: Path) -> Tuple[Path, str]:
    repo_url = _normalize_repo_url(str(sample["repo"]))
    repo_dir = destination / _repo_checkout_dirname(str(sample["repo"]))
    _run_git(["clone", "--depth", "1", repo_url, str(repo_dir)])
    ref = sample.get("ref")
    if ref:
        _run_git(["fetch", "--depth", "1", "origin", str(ref)], cwd=repo_dir)
        _run_git(["checkout", "FETCH_HEAD"], cwd=repo_dir)
    commit_sha = _run_git(["rev-parse", "HEAD"], cwd=repo_dir)
    return repo_dir, commit_sha


def collect_public_repos(
    manifest_path: str | Path,
    *,
    engine: str = "static",
    llm_config: Optional[LLMConfig] = None,
    exclude_dirs: Optional[List[str]] = None,
    submit_research_aggregate_flag: bool = False,
    timeout_seconds: int = 15,
    keep_repos: bool = False,
    checkout_root: Optional[str | Path] = None,
    results_dir: Optional[str | Path] = None,
) -> Dict[str, Any]:
    manifest = load_collection_manifest(manifest_path)
    defaults = manifest.get("defaults") or {}
    summaries: List[CollectionSummary] = []
    errors: List[Dict[str, Any]] = []

    if checkout_root:
        root_path = Path(checkout_root)
        root_path.mkdir(parents=True, exist_ok=True)
        cleanup = None
    else:
        tempdir = tempfile.TemporaryDirectory(prefix="aira-collect-")
        root_path = Path(tempdir.name)
        cleanup = tempdir

    try:
        for raw_sample in manifest["samples"]:
            sample = dict(raw_sample or {})
            repo_label = str(sample.get("repo") or "").strip()
            if not repo_label:
                errors.append({"repo": repo_label, "error": "Sample is missing 'repo'."})
                continue
            try:
                repo_dir, commit_sha = _clone_sample_repo(sample, root_path)
                scanner = AIRAScanner(str(repo_dir), exclude_dirs=exclude_dirs or [])
                result = scanner.scan(mode=engine, llm_config=llm_config or LLMConfig())
                submission_options = _submission_options_for_sample(sample, commit_sha, defaults)
                result_path = None
                if results_dir:
                    result_path = _write_scan_result(
                        result,
                        results_dir,
                        sample_name=submission_options["sample_name"],
                        sample_version=submission_options["sample_version"],
                    )

                response = None
                manifest_written = False
                if submit_research_aggregate_flag:
                    response = submit_aggregate_research(
                        result,
                        source=f"github:{_infer_repo_slug(repo_label)}",
                        timeout_seconds=timeout_seconds,
                        submission_options=submission_options,
                    )
                    if response.get("backend") == "supabase":
                        manifest_record = build_sample_manifest_record(
                            manifest,
                            sample,
                            commit_sha=commit_sha,
                            submission_options=submission_options,
                        )
                        manifest_written = submit_sample_manifest(
                            manifest_record,
                            timeout_seconds=timeout_seconds,
                        )

                summaries.append(
                    CollectionSummary(
                        sample_name=submission_options["sample_name"],
                        sample_version=submission_options["sample_version"],
                        repo=repo_label,
                        commit_sha=commit_sha,
                        findings_total=result.findings_total,
                        checks_failed=int(result.summary.get("checks_failed", 0)),
                        research_submission_id=(response or {}).get("id"),
                        duplicate=bool((response or {}).get("duplicate")),
                        manifest_written=manifest_written,
                        result_path=result_path,
                        engine=str(result.metadata.get("mode") or result.metadata.get("engine") or engine),
                        provider=_result_metadata_value(result, "provider") or result.metadata.get("engine"),
                        model=_result_metadata_value(result, "model"),
                    )
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                try:
                    fallback_sample_name = sample.get("sample_name") or f"github:{_infer_repo_slug(repo_label)}"
                except (KeyboardInterrupt, SystemExit):
                    raise
                except Exception:
                    fallback_sample_name = str(sample.get("sample_name") or repo_label or "unresolved-sample")
                submission_options = {
                    "sample_name": fallback_sample_name,
                    "sample_version": str(sample.get("sample_version") or sample.get("ref") or "unresolved"),
                }
                summaries.append(
                    CollectionSummary(
                        sample_name=str(submission_options["sample_name"]),
                        sample_version=str(submission_options["sample_version"]),
                        repo=repo_label,
                        commit_sha="",
                        findings_total=0,
                        checks_failed=0,
                        error=str(exc),
                        engine=engine,
                    )
                )
                errors.append({"repo": repo_label, "error": str(exc)})
            finally:
                if not keep_repos:
                    repo_dir_candidate = root_path / _repo_checkout_dirname(repo_label)
                    if repo_dir_candidate.exists():
                        shutil.rmtree(repo_dir_candidate, ignore_errors=True)
    finally:
        if cleanup is not None:
            cleanup.cleanup()

    return {
        "ok": not errors,
        "sampling_method": manifest["sampling_method"],
        "sampling_frame": manifest["sampling_frame"],
        "submitted": submit_research_aggregate_flag,
        "samples": [summary.__dict__ for summary in summaries],
        "errors": errors,
    }
