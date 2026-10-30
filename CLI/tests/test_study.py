import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from aira.cli import main
from aira.study import (
    compare_study_results,
    load_study_jsonl,
    run_study_manifest,
    write_study_jsonl,
)


def _write_python_sample(path: Path) -> None:
    path.write_text(
        "def save_record(db, record):\n"
        "    try:\n"
        "        db.insert(record)\n"
        "    except Exception:\n"
        "        return True\n",
        encoding="utf-8",
    )


class StudyRunnerTests(unittest.TestCase):
    def test_run_study_manifest_preserves_raw_static_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sample = root / "sample.py"
            manifest = root / "study.yaml"
            _write_python_sample(sample)
            manifest.write_text(
                "study_id: local-study\n"
                "samples:\n"
                "  - sample_id: sample-1\n"
                "    path: sample.py\n"
                "    attribution_class: suspected_ai\n",
                encoding="utf-8",
            )

            result = run_study_manifest(manifest, engines="static")

        self.assertEqual(result["summary"]["study_id"], "local-study")
        self.assertEqual(result["summary"]["sample_count"], 1)
        self.assertEqual(result["summary"]["row_count"], 1)
        self.assertEqual(result["summary"]["error_count"], 0)
        row = result["rows"][0]
        self.assertEqual(row["sample_id"], "sample-1")
        self.assertEqual(row["engine"], "static")
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["sample"]["attribution_class"], "suspected_ai")
        findings = row["aira_result"]["aira_scan"]["findings"]
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(findings[0]["fingerprint"])
        self.assertTrue(findings[0]["semantic_fingerprint"])
        self.assertTrue(findings[0]["location_fingerprint"])

    def test_study_jsonl_round_trip(self):
        rows = [
            {
                "record_type": "aira_study_result",
                "study_id": "s",
                "run_id": "r",
                "sample_id": "one",
                "status": "ok",
            }
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "nested" / "study.jsonl"
            write_study_jsonl(path, rows)
            loaded = load_study_jsonl(path)

        self.assertEqual(loaded, rows)

    def test_compare_study_results_aggregates_by_model_and_boundary(self):
        static_scan = {
            "ai_failure_audit": {"exception_handling": "FAIL", "fallback_control": "FAIL"},
            "findings": [
                {
                    "check_id": "C03",
                    "severity": "HIGH",
                    "file": "service.py",
                    "line": 10,
                    "boundary_type": "exception_handler",
                    "semantic_fingerprint": "static-exception",
                    "fingerprint": "static-1",
                    "description": "Broad exception handler",
                },
                {
                    "check_id": "C04",
                    "severity": "LOW",
                    "file": "service.py",
                    "line": 40,
                    "boundary_type": "fallback_branch",
                    "semantic_fingerprint": "static-fallback",
                    "fingerprint": "static-2",
                    "description": "Fallback branch",
                },
            ],
        }
        model_scan = {
            "ai_failure_audit": {"exception_handling": "PASS", "fallback_control": "UNKNOWN"},
            "findings": [
                {
                    "check_id": "C03",
                    "severity": "MEDIUM",
                    "file": "service.py",
                    "line": 12,
                    "boundary_type": "exception_handler",
                    "semantic_fingerprint": "model-exception",
                    "fingerprint": "model-1",
                    "description": "Nearby exception concern",
                }
            ],
        }
        rows = [
            {
                "status": "ok",
                "sample_id": "sample-1",
                "engine": "static",
                "model_key": "static:static",
                "aira_result": {"aira_scan": static_scan},
            },
            {
                "status": "ok",
                "sample_id": "sample-1",
                "engine": "llm",
                "provider": "ollama",
                "model": "minimax-m2:cloud",
                "model_key": "llm:ollama:minimax-m2:cloud",
                "aira_result": {"aira_scan": model_scan},
            },
        ]

        report = compare_study_results(rows, line_window=3)

        aggregate = report["by_model"]["llm:ollama:minimax-m2:cloud"]
        self.assertEqual(aggregate["samples_compared"], 1)
        self.assertEqual(aggregate["summary"]["static_findings"], 2)
        self.assertEqual(aggregate["summary"]["model_findings"], 1)
        self.assertEqual(aggregate["summary"]["matched_by_model"], 1)
        self.assertEqual(aggregate["summary"]["missed_by_model"], 1)
        self.assertEqual(aggregate["summary"]["static_to_model_finding_ratio"], 2.0)
        self.assertEqual(aggregate["by_boundary_type"]["fallback_branch"]["missed_by_model"], 1)
        self.assertEqual(aggregate["missed_findings"][0]["sample_id"], "sample-1")


class StudyCliTests(unittest.TestCase):
    def test_study_run_writes_jsonl_and_compare_reads_it(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            sample = root / "sample.py"
            manifest = root / "study.yaml"
            results = root / "results.jsonl"
            _write_python_sample(sample)
            manifest.write_text(
                "study_id: cli-study\n"
                "samples:\n"
                "  - sample_id: sample-1\n"
                "    path: sample.py\n",
                encoding="utf-8",
            )

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch(
                "sys.argv",
                ["aira", "study", "run", str(manifest), "--engines", "static", "--out-file", str(results)],
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()

            self.assertEqual(ex.exception.code, 0)
            self.assertTrue(results.exists())
            self.assertIn("AIRA STUDY RUN", stdout.getvalue())
            rows = load_study_jsonl(results)
            self.assertEqual(len(rows), 1)

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch("sys.argv", ["aira", "study", "compare", str(results), "--output", "json"]):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()

            self.assertEqual(ex.exception.code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["baseline_samples"], 1)
            self.assertEqual(payload["candidate_rows"], 0)


if __name__ == "__main__":
    unittest.main()
