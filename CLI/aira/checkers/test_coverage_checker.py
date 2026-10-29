"""
AIRA Test Coverage Asymmetry Analyzer (Check 14)
Analyzes test files to measure happy-path vs failure-path coverage ratio.
Works for both Python and JavaScript/TypeScript test files.
"""

import ast
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple


@dataclass
class TestCoverageReport:
    file: str
    total_tests: int
    happy_path_tests: int
    failure_path_tests: int
    unclassified_tests: int
    asymmetry_ratio: float  # happy/failure — higher = worse
    flagged_findings: List[dict]
    test_cases: List[dict]


# Patterns that indicate happy-path tests
HAPPY_PATH_PATTERNS = [
    r'(?:test|it|describe)\s*\(["\'].*(?:success|happy|works|correct|valid|pass|ok|return|resolv|complet)',
    r'expect\s*\(.*\)\s*\.\s*(?:toBe|toEqual|toReturn|toResolve|toBeTruthy|toMatchObject)',
    r'assert\s+\w+\s*==',
    r'assertEqual\s*\(',
    r'assertTrue\s*\(',
]

# Patterns that indicate failure/edge-case tests
FAILURE_PATH_PATTERNS = [
    r'(?:test|it|describe)\s*\(["\'].*(?:fail|error|invalid|reject|throw|exception|edge|missing|null|undefined|timeout|bad|wrong|corrupt|empty)',
    r'expect\s*\(.*\)\s*\.\s*(?:toThrow|toReject|toFail|toBeFalsy|toBeNull|toBeUndefined|toRaise)',
    r'assertRaises\s*\(',
    r'pytest\.raises\s*\(',
    r'with\s+(?:self\.)?assertRaises\s*\(',
    r'\.rejects\s*\.',
    r'expect\s*\(\s*\w+\s*\)\s*\.\s*rejects',
]

# Test file detection
TEST_FILE_PATTERNS = [
    r'test_.*\.py$',
    r'.*_test\.py$',
    r'.*\.test\.[jt]sx?$',
    r'.*\.spec\.[jt]sx?$',
    r'__tests__',
]


def is_test_file(filepath: str) -> bool:
    path_str = str(filepath)
    return any(re.search(p, path_str, re.IGNORECASE) for p in TEST_FILE_PATTERNS)


FAILURE_TEST_TERMS = {
    "fail", "failure", "error", "invalid", "reject", "throw", "exception",
    "missing", "timeout", "corrupt", "empty", "denied", "unauthorized",
}
HAPPY_TEST_TERMS = {"success", "happy", "valid", "works", "correct", "ok", "complete"}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        prefix = ""
        if isinstance(func.value, ast.Name):
            prefix = func.value.id
        return ".".join(part for part in (prefix, func.attr) if part)
    return ""


def _classify_python_test(node: ast.AST) -> str:
    name = str(getattr(node, "name", "")).lower()
    if any(term in name for term in FAILURE_TEST_TERMS):
        return "failure"
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            call_name = _call_name(child).lower()
            if any(term in call_name for term in ("raises", "assertraises", "tothrow", "rejects")):
                return "failure"
    if any(term in name for term in HAPPY_TEST_TERMS):
        return "happy"
    if any(isinstance(child, ast.Assert) for child in ast.walk(node)):
        return "happy"
    if any(
        isinstance(child, ast.Call)
        and any(term in _call_name(child).lower() for term in ("assertequal", "asserttrue", "assertis", "tobe", "toequal"))
        for child in ast.walk(node)
    ):
        return "happy"
    return "unclassified"


def _python_test_cases(source: str) -> List[dict]:
    tree = ast.parse(source)
    cases = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or not node.name.startswith("test_"):
            continue
        cases.append({
            "name": node.name,
            "line": int(getattr(node, "lineno", 0) or 0),
            "classification": _classify_python_test(node),
            "parser": "python_ast",
        })
    return sorted(cases, key=lambda item: (item["line"], item["name"]))


def _javascript_test_cases(source: str) -> List[dict]:
    lines = source.splitlines()
    starts = []
    pattern = re.compile(r"\b(?:it|test)\s*\(\s*(['\"])(.*?)\1")
    for index, line in enumerate(lines):
        match = pattern.search(line)
        if match:
            starts.append((index, match.group(2)))

    cases = []
    for position, (start, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        body = "\n".join(lines[start:end])
        lowered = f"{name}\n{body}".lower()
        if any(term in lowered for term in FAILURE_TEST_TERMS) or re.search(
            r"\b(toThrow|rejects|toReject|toFail)\b", body, re.IGNORECASE
        ):
            classification = "failure"
        elif any(term in name.lower() for term in HAPPY_TEST_TERMS) or re.search(
            r"\b(expect|assert)\b", body, re.IGNORECASE
        ):
            classification = "happy"
        else:
            classification = "unclassified"
        cases.append({
            "name": name,
            "line": start + 1,
            "classification": classification,
            "parser": "javascript_test_structure",
        })
    return cases


def analyze_test_file(filepath: str) -> TestCoverageReport:
    source = Path(filepath).read_text(encoding="utf-8", errors="replace")
    suffix = Path(filepath).suffix.lower()
    cases = _python_test_cases(source) if suffix == ".py" else _javascript_test_cases(source)
    happy = sum(1 for case in cases if case["classification"] == "happy")
    failure = sum(1 for case in cases if case["classification"] == "failure")
    unclassified = sum(1 for case in cases if case["classification"] == "unclassified")
    total = len(cases)
    ratio = (happy / failure) if failure > 0 else (999.0 if happy > 0 else 0.0)
    findings = []

    if happy > 0 and (ratio > 3.0 or failure == 0):
        first_happy_line = next(
            (case["line"] for case in cases if case["classification"] == "happy"),
            1,
        )
        findings.append({
            "check_id": "C14",
            "check_name": "TEST COVERAGE ASYMMETRY",
            "severity": "HIGH" if (failure == 0 or ratio > 5.0) else "MEDIUM",
            "file": filepath,
            "line": first_happy_line,
            "description": (
                "Observed test-surface asymmetry. "
                f"Happy-path test cases: {happy}, Failure-path test cases: {failure}, "
                f"Unclassified test cases: {unclassified}, "
                f"Ratio: {'∞' if failure == 0 else f'{ratio:.1f}:1'}. "
                "Review whether production failure branches have corresponding tests."
            ),
        })

    return TestCoverageReport(
        file=filepath,
        total_tests=total,
        happy_path_tests=happy,
        failure_path_tests=failure,
        unclassified_tests=unclassified,
        asymmetry_ratio=ratio,
        flagged_findings=findings,
        test_cases=cases,
    )


def _scanner_error_finding(filepath: str, exc: Exception) -> dict:
    return {
        "check_id": "SCANNER",
        "check_name": "SCANNER ERROR",
        "severity": "HIGH",
        "file": filepath,
        "line": 0,
        "description": (
            f"Unable to analyze test file: {exc}. "
            "Fix this file or exclude it before relying on scan results."
        ),
        "snippet": "",
    }


def scan_test_files(root: str, *, is_excluded: Optional[Callable[[Path], bool]] = None) -> Tuple[List[TestCoverageReport], List[dict]]:
    """Scan all test files under root and return reports + findings."""
    reports = []
    all_findings = []

    root_path = Path(root)
    if root_path.is_file():
        if not (is_excluded and is_excluded(root_path)) and is_test_file(str(root_path)):
            try:
                report = analyze_test_file(str(root_path))
                reports.append(report)
                all_findings.extend(report.flagged_findings)
            except Exception as exc:
                all_findings.append(_scanner_error_finding(str(root_path), exc))
        return reports, all_findings

    for dirpath, dirnames, filenames in os.walk(root_path):
        current_dir = Path(dirpath)
        dirnames[:] = [name for name in dirnames if not (is_excluded and is_excluded(current_dir / name))]
        for filename in filenames:
            path = current_dir / filename
            if is_excluded and is_excluded(path):
                continue
            if path.is_file() and is_test_file(str(path)):
                try:
                    report = analyze_test_file(str(path))
                    reports.append(report)
                    all_findings.extend(report.flagged_findings)
                except Exception as exc:
                    all_findings.append(_scanner_error_finding(str(path), exc))

    return reports, all_findings
