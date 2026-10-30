import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
from urllib import error

from aira.cli import main
from aira.research import (
    build_aggregate_submission_fields,
    build_structured_submission_record,
    build_submission_bundle,
    check_airtable_connection,
    check_research_connection,
    compute_fti_v1,
    infer_research_backend,
    risk_level_for_fti,
    submit_aggregate_research,
)
from aira.scanner import ScanResult


class _FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.payload


def _sample_result() -> ScanResult:
    return ScanResult(
        target="/tmp/project",
        scanned_at="2026-03-28T00:00:00+00:00",
        files_scanned=3,
        findings_total=3,
        check_results={
            "success_integrity": "FAIL",
            "audit_integrity": "PASS",
            "exception_handling": "FAIL",
            "fallback_control": "FAIL",
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
        findings=[
            {
                "check_id": "C03",
                "check_name": "BROAD EXCEPTION SUPPRESSION",
                "severity": "HIGH",
                "file": "src/a.py",
                "line": 10,
                "description": "Broad except.",
                "snippet": "except Exception:",
            },
            {
                "check_id": "C03",
                "check_name": "BROAD EXCEPTION SUPPRESSION",
                "severity": "MEDIUM",
                "file": "src/b.py",
                "line": 22,
                "description": "Broad except.",
                "snippet": "except Exception:",
            },
            {
                "check_id": "C04",
                "check_name": "DISTRIBUTED FALLBACK / DEGRADED EXECUTION",
                "severity": "LOW",
                "file": "src/c.py",
                "line": 30,
                "description": "Silent fallback.",
                "snippet": "return cached_value",
            },
        ],
        summary={
            "files_scanned": 3,
            "findings_total": 3,
            "by_severity": {"HIGH": 1, "MEDIUM": 1, "LOW": 1},
            "checks_failed": 3,
            "checks_passed": 10,
            "checks_unknown": 2,
            "requires_human_review": ["logic_consistency (C07)", "lineage (C12)"],
        },
        metadata={"mode": "hybrid", "provider": "groq", "model": "gpt-oss-120b", "engine": "llm"},
    )


class ResearchHelpersTests(unittest.TestCase):
    def test_build_aggregate_submission_fields_include_per_check_counts_only(self):
        result = _sample_result()

        fields = build_aggregate_submission_fields(result, source="github:bageltech/aira")
        count_json = json.loads(fields["Check Count JSON"])
        severity_json = json.loads(fields["Check Severity JSON"])

        self.assertEqual(fields["Source"], "github:bageltech/aira")
        self.assertEqual(count_json["C03"], 2)
        self.assertEqual(count_json["C04"], 1)
        self.assertEqual(count_json["C01"], 0)
        self.assertEqual(severity_json["C03"]["HIGH"], 1)
        self.assertEqual(severity_json["C03"]["MEDIUM"], 1)
        self.assertEqual(severity_json["C03"]["TOTAL"], 2)
        self.assertEqual(severity_json["C04"]["LOW"], 1)
        serialized = json.dumps(fields, sort_keys=True)
        self.assertNotIn("src/a.py", serialized)
        self.assertNotIn("except Exception:", serialized)

    def test_check_airtable_connection_reports_missing_config(self):
        with mock.patch.dict(os.environ, {"AIRTABLE_BASE_ID": "", "AIRTABLE_TOKEN": ""}, clear=False):
            snapshot = check_airtable_connection()

        self.assertFalse(snapshot["configured"])
        self.assertFalse(snapshot["ok"])
        self.assertIn("not configured", snapshot["message"])

    def test_check_research_connection_reports_missing_backend(self):
        with mock.patch.dict(os.environ, {
            "SUPABASE_URL": "", "SUPABASE_SERVICE_ROLE_KEY": "",
            "AIRTABLE_BASE_ID": "", "AIRTABLE_TOKEN": "",
            "AIRA_RESEARCH_JSONL": "", "RESEARCH_BACKEND": "",
        }, clear=False):
            snapshot = check_research_connection()

        self.assertEqual(snapshot["backend"], "none")
        self.assertFalse(snapshot["ok"])
        self.assertEqual(snapshot["preferred_backend"], "supabase")

    def test_infer_research_backend_prefers_supabase_over_airtable(self):
        with mock.patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "secret",
                "AIRTABLE_BASE_ID": "app123",
                "AIRTABLE_TOKEN": "token123",
            },
            clear=False,
        ):
            backend = infer_research_backend()

        self.assertEqual(backend, "supabase")

    def test_check_research_connection_reports_invalid_backend(self):
        with mock.patch.dict(os.environ, {"RESEARCH_BACKEND": "bogus"}, clear=False):
            snapshot = check_research_connection()

        self.assertEqual(snapshot["backend"], "bogus")
        self.assertTrue(snapshot["invalid_backend"])
        self.assertIn("Unknown research backend", snapshot["message"])

    def test_submit_aggregate_research_drops_unknown_optional_fields(self):
        bodies = []

        def fake_urlopen(req, timeout=0):  # noqa: ANN001
            bodies.append(json.loads(req.data.decode("utf-8")))
            if len(bodies) == 1:
                raise error.HTTPError(
                    req.full_url,
                    422,
                    "Unprocessable Entity",
                    hdrs=None,
                    fp=io.BytesIO(b'{"error":{"message":"Unknown field name: \\"Check Count JSON\\""}}'),
                )
            return _FakeResponse({"id": "rec123"})

        with mock.patch.dict(
            os.environ,
            {
                "AIRTABLE_BASE_ID": "app123",
                "AIRTABLE_TABLE": "Submissions",
                "AIRTABLE_TOKEN": "token123",
            },
            clear=False,
        ):
            with mock.patch("aira.research.airtable.request.urlopen", side_effect=fake_urlopen):
                response = submit_aggregate_research(_sample_result())

        self.assertEqual(response["id"], "rec123")
        self.assertEqual(response["dropped_optional_fields"], ["Check Count JSON"])
        self.assertIn("Check Count JSON", bodies[0]["fields"])
        self.assertNotIn("Check Count JSON", bodies[1]["fields"])
        self.assertIn("Checks JSON", bodies[1]["fields"])

    def test_submit_aggregate_research_can_use_jsonl_backend(self):
        result = _sample_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            sink = Path(tmpdir) / "research.jsonl"
            with mock.patch.dict(os.environ, {"AIRA_RESEARCH_JSONL": str(sink)}, clear=False):
                response = submit_aggregate_research(result)

            lines = sink.read_text(encoding="utf-8").splitlines()

        self.assertEqual(response["backend"], "jsonl")
        self.assertEqual(len(lines), 1)
        payload = json.loads(lines[0])
        self.assertEqual(payload["source"], "aira-cli")
        self.assertEqual(payload["check_severity_json"]["C03"]["HIGH"], 1)
        self.assertEqual(payload["scoring_version"], "fti-v1")
        self.assertEqual(payload["risk_level"], "MODERATE_RISK")
        self.assertEqual(len(payload["submission_checks"]), 15)

    def test_submit_aggregate_research_can_use_supabase_backend(self):
        with mock.patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "secret",
                "SUPABASE_TABLE": "aira_submissions",
            },
            clear=False,
        ):
            with mock.patch(
                "aira.research.supabase._supabase_request_json",
                side_effect=[
                    [],
                    [],
                    [{"id": "row123"}],
                    [],
                ],
            ) as request_mock:
                response = submit_aggregate_research(
                    _sample_result(),
                    submission_options={
                        "sample_name": "benchmarks/repo-a",
                        "sample_version": "2026-03",
                        "attribution_class": "suspected_ai",
                    },
                )

        self.assertEqual(response["backend"], "supabase")
        self.assertEqual(response["id"], "row123")
        self.assertEqual(request_mock.call_count, 4)

    def test_structured_submission_record_contains_v2_fields(self):
        record = build_structured_submission_record(
            _sample_result(),
            source="github:test/repo",
            submission_options={
                "sample_name": "github:test/repo",
                "sample_version": "v2",
                "attribution_class": "suspected_ai",
            },
        )

        self.assertEqual(record["source"], "github:test/repo")
        self.assertEqual(record["checks_json"]["success_integrity"], "FAIL")
        self.assertEqual(record["check_count_json"]["C03"], 2)
        self.assertEqual(record["check_severity_json"]["C03"]["MEDIUM"], 1)
        self.assertEqual(record["sample_name"], "github:test/repo")
        self.assertEqual(record["sample_version"], "v2")
        self.assertEqual(record["attribution_class"], "suspected_ai")
        self.assertEqual(record["fti_score"], 71.43)
        self.assertEqual(record["risk_level"], "MODERATE_RISK")
        self.assertEqual(record["scoring_version"], "fti-v1")
        self.assertEqual(len(record["submission_fingerprint"]), 64)
        self.assertEqual(len(record["record_sha256"]), 64)

    def test_fti_v1_scoring_and_risk_mapping_are_stable(self):
        bundle = build_submission_bundle(
            _sample_result(),
            source="github:test/repo",
            submission_options={
                "sample_name": "github:test/repo",
                "attribution_class": "suspected_ai",
            },
        )

        self.assertAlmostEqual(compute_fti_v1(bundle["submission_checks"]), 71.43, places=2)
        self.assertEqual(risk_level_for_fti(85.0), "LOW_RISK")
        self.assertEqual(risk_level_for_fti(84.99), "MODERATE_RISK")
        self.assertEqual(risk_level_for_fti(64.99), "HIGH_RISK")
        self.assertEqual(risk_level_for_fti(39.99), "CRITICAL_RISK")

    def test_supabase_submission_returns_duplicate_when_fingerprint_exists(self):
        existing = {"id": "row123", "submission_fingerprint": "abc", "record_sha256": "def"}
        with mock.patch.dict(
            os.environ,
            {
                "SUPABASE_URL": "https://example.supabase.co",
                "SUPABASE_SERVICE_ROLE_KEY": "secret",
                "SUPABASE_TABLE": "aira_submissions",
            },
            clear=False,
        ):
            with mock.patch(
                "aira.research.supabase._supabase_request_json",
                side_effect=[
                    [existing],
                    [],
                ],
            ) as request_mock:
                response = submit_aggregate_research(
                    _sample_result(),
                    submission_options={
                        "sample_name": "benchmarks/repo-a",
                        "attribution_class": "suspected_ai",
                    },
                )

        self.assertTrue(response["duplicate"])
        self.assertEqual(response["id"], "row123")
        self.assertEqual(request_mock.call_count, 2)

    def test_scan_command_can_submit_aggregate_research(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text("print('safe')\n", encoding="utf-8")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch("aira.cli.submit_aggregate_research", return_value={"id": "rec123", "dropped_optional_fields": []}) as submit_mock:
                with mock.patch(
                    "sys.argv",
                    ["aira", "scan", str(target), "--output", "json", "--engine", "static", "--submit-research-aggregate"],
                ):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exit_ctx:
                            main()

        self.assertEqual(exit_ctx.exception.code, 0)
        submit_mock.assert_called_once()
        self.assertIn("Research submission succeeded", stderr.getvalue())

    def test_scan_command_reports_backend_name_for_research_submission(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text("print('safe')\n", encoding="utf-8")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch(
                "aira.cli.submit_aggregate_research",
                return_value={"backend": "supabase", "id": "row123", "dropped_optional_fields": []},
            ):
                with mock.patch(
                    "sys.argv",
                    ["aira", "scan", str(target), "--output", "json", "--engine", "static", "--submit-research-aggregate"],
                ):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exit_ctx:
                            main()

        self.assertEqual(exit_ctx.exception.code, 0)
        self.assertIn("supabase record row123", stderr.getvalue())

    def test_health_command_reports_research_backend_json(self):
        stdout = io.StringIO()
        with mock.patch("aira.cli.check_research_connection", return_value={"backend": "jsonl", "configured": True, "ok": True, "reachable": True, "message": "ok", "path": "/tmp/research.jsonl"}):
            with mock.patch("sys.argv", ["aira", "health", "--check-research", "--json"]):
                with redirect_stdout(stdout):
                    with self.assertRaises(SystemExit) as exit_ctx:
                        main()

        self.assertEqual(exit_ctx.exception.code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["research"]["backend"], "jsonl")


if __name__ == "__main__":
    unittest.main()
