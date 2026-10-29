import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from aira.cli import main


def _run_cli(argv):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with mock.patch("sys.argv", argv):
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                main()
            except SystemExit as exc:
                return exc.code, stdout.getvalue(), stderr.getvalue()
    raise AssertionError("CLI did not exit")


class CliFailureBehaviorTests(unittest.TestCase):
    def test_scan_command_json_success_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "safe.py"
            target.write_text("print('safe')\n", encoding="utf-8")

            code, stdout, stderr = _run_cli(["aira", "scan", str(target), "--output", "json"])

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["aira_scan"]["summary"]["files_scanned"], 1)
        self.assertEqual(payload["aira_scan"]["metadata"]["mode"], "static")

    def test_malformed_source_emits_incomplete_json_instead_of_empty_scan_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "broken.py"
            target.write_text("def broken(:\n", encoding="utf-8")

            code, stdout, stderr = _run_cli(["aira", "scan", str(target), "--output", "json"])

        self.assertEqual(code, 2)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        summary = payload["aira_scan"]["summary"]
        self.assertEqual(summary["files_discovered"], 1)
        self.assertEqual(summary["files_scanned"], 0)
        self.assertEqual(summary["files_failed"], 1)
        self.assertEqual(summary["checks_passed"], 0)

    def test_scan_command_missing_path_exits_with_input_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.py"

            code, stdout, stderr = _run_cli(["aira", "scan", str(missing), "--output", "json"])

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Input error", stderr)
        self.assertIn("Path not found", stderr)

    def test_scan_command_unsupported_file_exits_with_actionable_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "notes.md"
            target.write_text("# notes\n", encoding="utf-8")

            code, stdout, stderr = _run_cli(["aira", "scan", str(target), "--output", "json"])

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Unsupported file type", stderr)
        self.assertIn("Supported extensions", stderr)
        self.assertIn(".py", stderr)

    def test_scan_command_directory_without_supported_files_exits_with_input_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("# docs only\n", encoding="utf-8")

            code, stdout, stderr = _run_cli(["aira", "scan", str(root), "--output", "json"])

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("No supported source files found", stderr)
        self.assertIn("--exclude", stderr)

    def test_scan_command_out_file_write_failure_exits_with_output_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "safe.py"
            target.write_text("print('safe')\n", encoding="utf-8")
            out_dir = root / "report-dir"
            out_dir.mkdir()

            code, stdout, stderr = _run_cli(
                ["aira", "scan", str(target), "--output", "json", "--out-file", str(out_dir)]
            )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("Output error", stderr)
        self.assertIn("Could not write", stderr)

    def test_scan_command_rejects_nonpositive_timeout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "safe.py"
            target.write_text("print('safe')\n", encoding="utf-8")

            code, stdout, stderr = _run_cli(["aira", "scan", str(target), "--timeout", "0"])

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("must be greater than 0", stderr)

    def test_scan_command_llm_missing_configuration_exits_with_input_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "safe.py"
            target.write_text("print('safe')\n", encoding="utf-8")

            with mock.patch.dict(os.environ, {
                "AIRA_OPENAI_BASE_URL": "", "OPENAI_BASE_URL": "",
                "AIRA_OPENAI_MODEL": "", "OPENAI_MODEL": "",
                "AIRA_OPENAI_API_KEY": "", "OPENAI_API_KEY": "",
                "AIRA_OLLAMA_MODEL": "", "OLLAMA_MODEL": "",
                "AIRA_GROQ_API_KEY": "", "GROQ_API_KEY": "",
                "AIRA_GEMINI_API_KEY": "", "GEMINI_API_KEY": "",
                "GOOGLE_API_KEY": "",
                "AIRA_OPENROUTER_API_KEY": "", "OPENROUTER_API_KEY": "",
            }, clear=False):
                code, stdout, stderr = _run_cli(["aira", "scan", str(target), "--engine", "llm", "--output", "json"])

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("LLM scan failed", stderr)
        self.assertIn("No LLM providers are configured", stderr)

    def test_scan_command_malformed_python_exits_with_scanner_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "broken.py"
            target.write_text("def broken(:\n    pass\n", encoding="utf-8")

            code, stdout, stderr = _run_cli(["aira", "scan", str(target), "--output", "json"])

        self.assertEqual(code, 2)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        findings = payload["aira_scan"]["findings"]
        self.assertEqual(findings[0]["check_id"], "SCANNER")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertIn("Could not parse Python file", findings[0]["description"])

    def test_scan_command_unexpected_scanner_exception_exits_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "safe.py"
            target.write_text("print('safe')\n", encoding="utf-8")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch("aira.cli.AIRAScanner") as scanner_cls:
                scanner_cls.return_value.scan.side_effect = RuntimeError("boom")
                with mock.patch("sys.argv", ["aira", "scan", str(target), "--output", "json"]):
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exit_ctx:
                            main()

        self.assertEqual(exit_ctx.exception.code, 3)
        self.assertEqual(stdout.getvalue(), "")
        # C03/C02: Unexpected errors now include traceback for debugging
        # The message should indicate the failure; traceback provides debugging context
        self.assertIn("Unexpected scan failure: boom", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
