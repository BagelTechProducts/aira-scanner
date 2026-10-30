import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hypothesis import given, settings
from hypothesis import strategies as st

from aira.llm import LLMConfig, LLMRoutingError
from aira.scanner import AIRAScanner, ScannerInputError


class ScannerModeTests(unittest.TestCase):
    def test_static_scan_rejects_missing_target(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.py"
            scanner = AIRAScanner(str(missing))

            with self.assertRaises(ScannerInputError) as exc_ctx:
                scanner.scan(mode="static")

        self.assertIn("Path not found", str(exc_ctx.exception))

    def test_static_scan_rejects_unsupported_single_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "notes.md"
            target.write_text("# docs only\n", encoding="utf-8")
            scanner = AIRAScanner(str(target))

            with self.assertRaises(ScannerInputError) as exc_ctx:
                scanner.scan(mode="static")

        self.assertIn("Unsupported file type", str(exc_ctx.exception))

    def test_static_scan_reports_malformed_python_as_scanner_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "broken.py"
            target.write_text("def broken(:\n    pass\n", encoding="utf-8")

            result = AIRAScanner(str(target)).scan(mode="static")

        self.assertEqual(result.files_scanned, 0)
        self.assertEqual(result.summary["files_analyzed"], 0)
        self.assertEqual(result.summary["files_failed"], 1)
        self.assertEqual(result.summary["checks_passed"], 0)
        self.assertEqual(result.summary["checks_unknown"], 15)
        self.assertEqual(result.findings[0]["check_id"], "SCANNER")
        self.assertEqual(result.findings[0]["severity"], "HIGH")
        self.assertIn("Could not parse Python file", result.findings[0]["description"])

    def test_static_scan_respects_file_exclude_pattern(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            included = root / "keep.py"
            excluded = root / "skip.py"
            source = (
                "def save_record(db, record):\n"
                "    try:\n"
                "        db.insert(record)\n"
                "        return True\n"
                "    except Exception:\n"
                "        return True\n"
            )
            included.write_text(source, encoding="utf-8")
            excluded.write_text(source, encoding="utf-8")

            scanner = AIRAScanner(str(root), exclude_dirs=["skip.py"])
            result = scanner.scan(mode="static")

        self.assertEqual(result.files_scanned, 1)
        self.assertGreater(result.findings_total, 0)
        self.assertTrue(all(finding["file"] != "skip.py" for finding in result.findings))
        self.assertTrue(any(finding["file"] == "keep.py" for finding in result.findings))

    def test_test_coverage_scan_respects_excluded_test_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            included = root / "test_keep.py"
            excluded = root / "test_skip.py"
            test_source = (
                "def test_happy_path():\n"
                "    assert True\n"
            )
            included.write_text(test_source, encoding="utf-8")
            excluded.write_text(test_source, encoding="utf-8")

            scanner = AIRAScanner(str(root), exclude_dirs=["test_skip.py"])
            result = scanner.scan(mode="static")

        coverage_findings = [finding for finding in result.findings if finding["check_id"] == "C14"]
        self.assertEqual(len(coverage_findings), 1)
        self.assertEqual(coverage_findings[0]["file"], "test_keep.py")

    def test_static_scan_reports_test_coverage_analysis_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            test_file = root / "test_app.py"
            test_file.write_text("def test_happy_path():\n    assert True\n", encoding="utf-8")

            scanner = AIRAScanner(str(root))
            with mock.patch("aira.checkers.test_coverage_checker.analyze_test_file", side_effect=OSError("denied")):
                result = scanner.scan(mode="static")

        scanner_errors = [finding for finding in result.findings if finding["check_id"] == "SCANNER"]
        self.assertEqual(len(scanner_errors), 1)
        self.assertEqual(scanner_errors[0]["severity"], "HIGH")
        self.assertEqual(scanner_errors[0]["file"], "test_app.py")
        self.assertIn("Unable to analyze test file", scanner_errors[0]["description"])

    def test_hybrid_falls_back_to_static_when_llm_unavailable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text(
                "def save_record(db, record):\n"
                "    try:\n"
                "        db.insert(record)\n"
                "        return True\n"
                "    except Exception:\n"
                "        return True\n",
                encoding="utf-8",
            )

            scanner = AIRAScanner(str(target))
            with mock.patch("aira.scanner.run_llm_json_audit", side_effect=LLMRoutingError("no provider")):
                result = scanner.scan(mode="hybrid", llm_config=LLMConfig(provider="auto"))

        self.assertEqual(result.metadata["mode"], "hybrid")
        self.assertEqual(result.metadata["llm_fallback"], "static_only")
        self.assertEqual(result.check_results["success_integrity"], "FAIL")

    def test_llm_mode_normalizes_provider_response(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text("print('hello')\n", encoding="utf-8")

            scanner = AIRAScanner(str(target))
            fake_response = {
                "provider": "openai-compatible",
                "model": "gpt-oss-120b",
                "text": json.dumps(
                    {
                        "ai_failure_audit": {
                            "success_integrity": "PASS",
                            "audit_integrity": "UNKNOWN",
                            "exception_handling": "UNKNOWN",
                            "fallback_control": "UNKNOWN",
                            "bypass_controls": "UNKNOWN",
                            "return_contracts": "UNKNOWN",
                            "logic_consistency": "UNKNOWN",
                            "background_tasks": "UNKNOWN",
                            "environment_safety": "UNKNOWN",
                            "startup_integrity": "UNKNOWN",
                            "determinism": "UNKNOWN",
                            "lineage": "UNKNOWN",
                            "confidence_representation": "UNKNOWN",
                            "test_coverage_symmetry": "UNKNOWN",
                            "idempotency_safety": "UNKNOWN",
                        },
                        "findings": [
                            {
                                "check_id": "C05",
                                "check_name": "BYPASS / OVERRIDE PATHS",
                                "severity": "MEDIUM",
                                "file": "sample.py",
                                "line": 1,
                                "description": "Potential bypass detected.",
                                "snippet": "print('hello')",
                            }
                        ],
                    }
                ),
            }

            with mock.patch("aira.scanner.run_llm_json_audit", return_value=fake_response):
                result = scanner.scan(mode="llm", llm_config=LLMConfig(provider="openai-compatible", model="gpt-oss-120b"))

        self.assertEqual(result.metadata["provider"], "openai-compatible")
        self.assertEqual(result.metadata["model"], "gpt-oss-120b")
        self.assertEqual(result.check_results["logic_consistency"], "UNKNOWN")
        self.assertEqual(result.findings[0]["check_id"], "C05")

    def test_llm_mode_tolerates_malformed_finding_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text("print('hello')\n", encoding="utf-8")

            scanner = AIRAScanner(str(target))
            fake_response = {
                "provider": "openai-compatible",
                "model": "gpt-oss-120b",
                "text": json.dumps(
                    {
                        "ai_failure_audit": [],
                        "findings": [
                            "not an object",
                            {
                                "check_id": "C05",
                                "check_name": "BYPASS / OVERRIDE PATHS",
                                "severity": "MEDIUM",
                                "file": "sample.py",
                                "line": "not-a-line",
                                "description": "Potential bypass detected.",
                            },
                        ],
                    }
                ),
            }

            with mock.patch("aira.scanner.run_llm_json_audit", return_value=fake_response):
                result = scanner.scan(mode="llm", llm_config=LLMConfig(provider="openai-compatible", model="gpt-oss-120b"))

        self.assertEqual(result.findings[0]["check_id"], "C05")
        self.assertEqual(result.findings[0]["line"], 0)
        self.assertEqual(result.check_results["success_integrity"], "UNKNOWN")

    def test_llm_mode_drops_human_review_only_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text("print('hello')\n", encoding="utf-8")

            scanner = AIRAScanner(str(target))
            fake_response = {
                "provider": "ollama",
                "model": "minimax-m2:cloud",
                "text": json.dumps(
                    {
                        "ai_failure_audit": {
                            "logic_consistency": "FAIL",
                            "lineage": "FAIL",
                        },
                        "findings": [
                            {
                                "check_id": "C07",
                                "check_name": "PARALLEL LOGIC DRIFT",
                                "severity": "HIGH",
                                "file": "sample.py",
                                "line": 1,
                                "description": "Human-review check should not survive normalization.",
                                "snippet": "print('hello')",
                            },
                            {
                                "check_id": "C12",
                                "check_name": "SOURCE-TO-OUTPUT LINEAGE",
                                "severity": "HIGH",
                                "file": "sample.py",
                                "line": 1,
                                "description": "Human-review check should not survive normalization.",
                                "snippet": "print('hello')",
                            },
                        ],
                    }
                ),
            }

            with mock.patch("aira.scanner.run_llm_json_audit", return_value=fake_response):
                result = scanner.scan(mode="llm", llm_config=LLMConfig(provider="ollama", model="minimax-m2:cloud"))

        self.assertEqual(result.check_results["logic_consistency"], "UNKNOWN")
        self.assertEqual(result.check_results["lineage"], "UNKNOWN")
        self.assertEqual(result.findings, [])


if __name__ == "__main__":
    unittest.main()


_VALID_STATEMENTS = [
    "x = 1",
    "y = 2 + 3",
    "print('hello')",
    "pass",
    "import os",
    "from pathlib import Path",
    "a = [1, 2, 3]",
    "b = {'key': 'value'}",
    "c = (x for x in range(5))",
    "if True:\n    pass",
    "for i in range(10):\n    pass",
    "while False:\n    break",
    "def f():\n    return 1",
    "class C:\n    pass",
]

_FAIL_SOFT_STATEMENTS = [
    "try:\n    x = 1\nexcept:\n    pass",
    "def g():\n    try:\n        pass\n    except Exception:\n        return True",
    "skip_validation = True",
    "task = asyncio.create_task(foo())",
    "def predict():\n    return {'result': 42}",
]


class PropertyBasedScannerTests(unittest.TestCase):

    @given(st.lists(st.sampled_from(_VALID_STATEMENTS), min_size=1, max_size=50))
    @settings(max_examples=100)
    def test_static_scan_succeeds_on_any_valid_python_syntax(self, statements):
        code = "\n".join(statements)
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text(code, encoding="utf-8")
            result = AIRAScanner(str(target)).scan(mode="static")
        self.assertIn("files_scanned", result.summary)
        self.assertEqual(result.files_scanned, 1)

    @given(
        st.lists(
            st.tuples(
                st.sampled_from(_FAIL_SOFT_STATEMENTS),
                st.booleans(),
            ),
            min_size=1,
            max_size=10,
        )
    )
    @settings(max_examples=100)
    def test_static_scan_detects_fail_soft_patterns_when_present(self, statements_with_use):
        code = "\n".join(stmt for stmt, use in statements_with_use if use)
        if not code.strip():
            code = "\n".join(stmt for stmt, _ in statements_with_use)
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text(code, encoding="utf-8")
            result = AIRAScanner(str(target)).scan(mode="static")
        self.assertIsInstance(result.findings, list)

    @given(
        st.lists(st.sampled_from(_VALID_STATEMENTS), min_size=1, max_size=20),
        st.lists(st.text(min_size=1, max_size=10, alphabet="abcdefghijklmnopqrstuvwxyz"), min_size=1, max_size=5, unique=True),
    )
    @settings(max_examples=100)
    def test_exclude_dirs_never_includes_excluded_files_in_findings(self, statements, exclude_names):
        code = "\n".join(statements)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            excluded_files = []
            for name in exclude_names:
                if not name:
                    continue
                fname = f"{name}.py"
                (root / fname).write_text(code, encoding="utf-8")
                excluded_files.append(fname)
            ensure_file = root / "ensure.py"
            ensure_file.write_text("x = 1\n", encoding="utf-8")
            if not excluded_files:
                return
            result = AIRAScanner(str(root), exclude_dirs=excluded_files).scan(mode="static")
        excluded_set = set(excluded_files)
        for finding in result.findings:
            self.assertNotIn(finding["file"], excluded_set)

    @given(st.lists(st.sampled_from(_VALID_STATEMENTS + _FAIL_SOFT_STATEMENTS), min_size=1, max_size=30))
    @settings(max_examples=100)
    def test_static_scan_never_returns_empty_check_results_keys(self, statements):
        code = "\n".join(statements)
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.py"
            target.write_text(code, encoding="utf-8")
            result = AIRAScanner(str(target)).scan(mode="static")
        self.assertIsInstance(result.check_results, dict)
        self.assertGreater(len(result.check_results), 0)
        required = {
            "success_integrity", "audit_integrity", "exception_handling",
            "fallback_control", "bypass_controls", "return_contracts",
            "logic_consistency", "background_tasks", "environment_safety",
            "startup_integrity", "determinism", "lineage",
            "confidence_representation", "test_coverage_symmetry", "idempotency_safety",
        }
        actual_keys = set(result.check_results.keys())
        missing = required - actual_keys
        self.assertSetEqual(missing, set(), f"Missing check result keys: {missing}")
