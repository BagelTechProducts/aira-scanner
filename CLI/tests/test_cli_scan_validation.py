import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from aira.cli import EXIT_INPUT_OR_USAGE, EXIT_OPERATIONAL_FAILURE, main
from aira.scanner import (
    AIRAScanner,
    ScanTargetError,
    describe_empty_scan_result,
    validate_scan_target,
)


class ValidateScanTargetTests(unittest.TestCase):
    def test_rejects_missing_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "nope.py"
            with self.assertRaises(ScanTargetError) as ctx:
                validate_scan_target(missing)
            self.assertIn("does not exist", str(ctx.exception).lower())

    def test_rejects_unsupported_single_file_extension(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = Path(tmpdir) / "notes.txt"
            bad.write_text("hello", encoding="utf-8")
            with self.assertRaises(ScanTargetError) as ctx:
                validate_scan_target(bad)
            self.assertIn("unsupported file type", str(ctx.exception).lower())

    def test_accepts_supported_file_and_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "m.py"
            py_file.write_text("x = 1\n", encoding="utf-8")
            validate_scan_target(py_file)
            validate_scan_target(Path(tmpdir))


class DescribeEmptyScanTests(unittest.TestCase):
    def test_directory_with_no_sources_explained(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner = AIRAScanner(tmpdir)
            msg = describe_empty_scan_result(scanner, 0)
            self.assertIsNotNone(msg)
            self.assertIn("No scannable source files", msg)

    def test_single_file_excluded_explained(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            py_file = Path(tmpdir) / "skip_me.py"
            py_file.write_text("x = 1\n", encoding="utf-8")
            scanner = AIRAScanner(str(py_file), exclude_dirs=["skip_me.py"])
            msg = describe_empty_scan_result(scanner, 0)
            self.assertIsNotNone(msg)
            self.assertIn("--exclude", msg)


class CliScanIntegrationTests(unittest.TestCase):
    def test_scan_json_success_on_clean_py_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "clean.py"
            target.write_text("def f():\n    return True\n", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with mock.patch(
                "sys.argv",
                ["aira", "scan", str(target), "--output", "json", "--engine", "static"],
            ):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()
            self.assertEqual(ex.exception.code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertIn("aira_scan", payload)
            self.assertGreaterEqual(payload["aira_scan"]["summary"]["files_scanned"], 1)

    def test_scan_missing_target_exits_input_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "missing.py"
            stderr = io.StringIO()
            with mock.patch("sys.argv", ["aira", "scan", str(missing), "--output", "json", "--engine", "static"]):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()
            self.assertEqual(ex.exception.code, EXIT_INPUT_OR_USAGE)
            self.assertIn("invalid scan target", stderr.getvalue().lower())

    def test_scan_unsupported_single_file_exits_input_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "data.toml"
            target.write_text("k = 1\n", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch("sys.argv", ["aira", "scan", str(target), "--output", "json", "--engine", "static"]):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()
            self.assertEqual(ex.exception.code, EXIT_INPUT_OR_USAGE)

    def test_scan_empty_directory_exits_input_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stderr = io.StringIO()
            with mock.patch("sys.argv", ["aira", "scan", str(tmpdir), "--output", "json", "--engine", "static"]):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()
            self.assertEqual(ex.exception.code, EXIT_INPUT_OR_USAGE)
            self.assertIn("cannot complete scan", stderr.getvalue().lower())

    def test_scan_exclude_matches_only_file_exits_input_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "alone.py"
            target.write_text("x = 1\n", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch(
                "sys.argv",
                ["aira", "scan", str(target), "--exclude", "alone.py", "--output", "json", "--engine", "static"],
            ):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()
            self.assertEqual(ex.exception.code, EXIT_INPUT_OR_USAGE)

    def test_scan_out_file_missing_parent_exits_input_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "alone.py"
            target.write_text("x = 1\n", encoding="utf-8")
            out_file = Path(tmpdir) / "no_such_dir" / "out.json"
            stderr = io.StringIO()
            with mock.patch(
                "sys.argv",
                [
                    "aira",
                    "scan",
                    str(target),
                    "--output",
                    "json",
                    "--engine",
                    "static",
                    "--out-file",
                    str(out_file),
                ],
            ):
                with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as ex:
                        main()
            self.assertEqual(ex.exception.code, EXIT_INPUT_OR_USAGE)
            self.assertIn("output directory does not exist", stderr.getvalue().lower())

    def test_scan_unexpected_exception_exits_operational_code(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "alone.py"
            target.write_text("x = 1\n", encoding="utf-8")
            stderr = io.StringIO()
            with mock.patch("aira.cli.AIRAScanner") as scanner_cls:
                scanner_cls.return_value.scan.side_effect = RuntimeError("boom")
                with mock.patch(
                    "sys.argv",
                    ["aira", "scan", str(target), "--output", "json", "--engine", "static"],
                ):
                    with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as ex:
                            main()
            self.assertEqual(ex.exception.code, EXIT_OPERATIONAL_FAILURE)

    def test_main_requires_subcommand(self):
        stderr = io.StringIO()
        with mock.patch("sys.argv", ["aira"]):
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ex:
                    main()
        self.assertEqual(ex.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
