"""Tests for public repository collection functionality."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from aira.cli import main
from aira.collector import (
    build_sample_manifest_record,
    collect_public_repos,
    load_collection_manifest,
)
from aira.scanner import ScanResult


def _sample_scan_result(target: str) -> ScanResult:
    return ScanResult(
        target=target,
        scanned_at="2026-03-29T00:00:00+00:00",
        files_scanned=4,
        findings_total=2,
        check_results={
            "success_integrity": "FAIL",
            "audit_integrity": "PASS",
            "exception_handling": "PASS",
            "fallback_control": "PASS",
            "bypass_controls": "PASS",
            "return_contracts": "PASS",
            "logic_consistency": "UNKNOWN",
            "background_tasks": "PASS",
            "environment_safety": "PASS",
            "startup_integrity": "PASS",
            "determinism": "PASS",
            "lineage": "UNKNOWN",
            "confidence_representation": "PASS",
            "test_coverage_symmetry": "PASS",
            "idempotency_safety": "PASS",
        },
        findings=[],
        summary={"checks_failed": 1, "files_scanned": 4, "findings_total": 2},
        metadata={"mode": "static", "engine": "static"},
    )


class CollectorTests(unittest.TestCase):
    def test_load_collection_manifest_reads_yaml(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.yaml"
            manifest_path.write_text(
                "sampling_method: curated_public_repos\n"
                "sampling_frame: github-public\n"
                "attribution_policy: manual-review-v1\n"
                "samples:\n"
                "  - repo: openai/openai-python\n",
                encoding="utf-8",
            )

            manifest = load_collection_manifest(manifest_path)

        self.assertEqual(manifest["sampling_method"], "curated_public_repos")
        self.assertEqual(manifest["samples"][0]["repo"], "openai/openai-python")

    def test_build_sample_manifest_record_hashes_curated_metadata(self):
        manifest = {
            "sampling_method": "curated_public_repos",
            "sampling_frame": "github-public",
            "inclusion_criteria": {"stars_gte": 100},
            "exclusion_criteria": {"fork": True},
            "attribution_policy": "manual-review-v1",
            "random_seed": "seed-1",
            "notes": "public baseline",
        }
        sample = {"repo": "openai/openai-python", "ref": "main"}
        submission_options = {
            "sample_name": "github:openai/openai-python",
            "sample_version": "abc123",
            "attribution_class": "suspected_ai",
            "source_id": "openai/openai-python",
            "source_kind": "repo",
            "scanner_version": "1.2.1",
            "ruleset_version": "1.2.1",
            "scoring_version": "fti-v1",
        }

        record = build_sample_manifest_record(
            manifest,
            sample,
            commit_sha="abc123",
            submission_options=submission_options,
        )

        self.assertEqual(record["sample_name"], "github:openai/openai-python")
        self.assertEqual(record["sample_version"], "abc123")
        self.assertEqual(record["sampling_method"], "curated_public_repos")
        self.assertEqual(len(record["manifest_sha256"]), 64)

    def test_collect_public_repos_scans_and_submits_curated_samples(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.yaml"
            manifest_path.write_text(
                "sampling_method: curated_public_repos\n"
                "sampling_frame: github-public\n"
                "attribution_policy: manual-review-v1\n"
                "defaults:\n"
                "  attribution_class: suspected_ai\n"
                "samples:\n"
                "  - repo: openai/openai-python\n",
                encoding="utf-8",
            )
            checkout_dir = Path(tmpdir) / "repos"
            repo_dir = checkout_dir / "openai__openai-python"
            repo_dir.mkdir(parents=True, exist_ok=True)

            with mock.patch("aira.collector._clone_sample_repo", return_value=(repo_dir, "abc123")):
                with mock.patch("aira.collector.AIRAScanner") as scanner_cls:
                    scanner_cls.return_value.scan.return_value = _sample_scan_result(str(repo_dir))
                    with mock.patch(
                        "aira.collector.submit_aggregate_research",
                        return_value={"backend": "supabase", "id": "row123", "duplicate": False},
                    ) as submit_mock:
                        with mock.patch("aira.collector.submit_sample_manifest", return_value=True) as manifest_mock:
                            results_dir = Path(tmpdir) / "results"
                            summary = collect_public_repos(
                                manifest_path,
                                submit_research_aggregate_flag=True,
                                checkout_root=checkout_dir,
                                results_dir=results_dir,
                            )
                            result_file = results_dir / "github_openai_openai-python--abc123.json"
                            result_file_exists = result_file.exists()
                            result_file_text = result_file.read_text(encoding="utf-8")

        self.assertTrue(summary["ok"])
        self.assertEqual(summary["samples"][0]["sample_name"], "github:openai/openai-python")
        self.assertEqual(summary["samples"][0]["sample_version"], "abc123")
        self.assertEqual(summary["samples"][0]["research_submission_id"], "row123")
        self.assertTrue(summary["samples"][0]["manifest_written"])
        self.assertEqual(summary["samples"][0]["engine"], "static")
        self.assertTrue(summary["samples"][0]["result_path"].endswith("github_openai_openai-python--abc123.json"))
        self.assertTrue(result_file_exists)
        self.assertIn('"aira_scan"', result_file_text)
        submit_mock.assert_called_once()
        _, kwargs = submit_mock.call_args
        self.assertEqual(kwargs["source"], "github:openai/openai-python")
        self.assertEqual(kwargs["submission_options"]["sample_name"], "github:openai/openai-python")
        self.assertEqual(kwargs["submission_options"]["attribution_class"], "suspected_ai")
        manifest_mock.assert_called_once()

    def test_collect_command_emits_json_summary(self):
        summary = {
            "ok": True,
            "sampling_method": "curated_public_repos",
            "sampling_frame": "github-public",
            "submitted": False,
            "samples": [],
            "errors": [],
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch("aira.cli.collect_public_repos", return_value=summary) as collect_mock:
            with mock.patch("sys.argv", ["aira", "collect", "manifest.yaml", "--output", "json", "--results-dir", "results"]):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as exit_ctx:
                        main()

        self.assertEqual(exit_ctx.exception.code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(collect_mock.call_args.kwargs["results_dir"], "results")


if __name__ == "__main__":
    unittest.main()
