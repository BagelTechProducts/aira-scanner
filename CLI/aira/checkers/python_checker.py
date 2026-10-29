"""
AIRA Python Checker
Performs static analysis of Python source files for AI-induced failure patterns.
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Finding:
    check_id: str
    check_name: str
    severity: str  # HIGH | MEDIUM | LOW
    file: str
    line: int
    description: str
    snippet: Optional[str] = None


class PythonChecker:
    """
    Analyzes Python source files for all 15 AIRA checks.
    Returns a list of Finding objects.
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        self.lines = self.source.splitlines()
        # Parse initialization: gracefully handle syntax errors and report via SCANNER finding
        self.tree, self.parse_ok, self.parse_error = self._parse_source()
        self.parents = self._build_parents() if self.tree else {}
        self.findings: List[Finding] = []

    def _parse_source(self) -> Tuple[Any, bool, Optional[SyntaxError]]:
        """
        Attempt to parse Python source.
        Returns (tree, parse_ok, parse_error) tuple - never raises.
        Parse failures are reported as SCANNER findings on run().
        """
        try:
            return ast.parse(self.source), True, None
        except SyntaxError as exc:
            return None, False, exc

    def _build_parents(self) -> Dict:
        """Build parent node mapping for AST traversal."""
        return {
            child: parent
            for parent in ast.walk(self.tree)
            for child in ast.iter_child_nodes(parent)
        }

    def run(self) -> List[Finding]:
        if not self.parse_ok:
            line = getattr(self.parse_error, "lineno", 1) or 1
            message = getattr(self.parse_error, "msg", "invalid syntax")
            self._add(
                "SCANNER",
                "SCANNER ERROR",
                "HIGH",
                line,
                f"Could not parse Python file: {message}. Fix syntax before relying on scan results.",
            )
            return self.findings
        self._check_broad_exception_suppression()
        self._check_success_integrity()
        self._check_audit_integrity()
        self._check_bypass_paths()
        self._check_ambiguous_returns()
        self._check_background_tasks()
        self._check_environment_safety()
        self._check_startup_integrity()
        self._check_determinism()
        self._check_confidence_misrepresentation()
        self._check_idempotency()
        self._check_fallback_scatter()
        return self.findings

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        return self.lines[idx].strip() if 0 <= idx < len(self.lines) else ""

    def _add(self, check_id, check_name, severity, line, description):
        self.findings.append(Finding(
            check_id=check_id,
            check_name=check_name,
            severity=severity,
            file=self.filepath,
            line=line,
            description=description,
            snippet=self._snippet(line)
        ))

    # ── CHECK 3: Broad Exception Suppression ─────────────────────
    def _check_broad_exception_suppression(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            # Bare except or except Exception
            is_broad = (
                node.type is None or
                (isinstance(node.type, ast.Name) and node.type.id == "Exception") or
                (isinstance(node.type, ast.Attribute) and node.type.attr == "Exception")
            )
            if not is_broad:
                continue

            # Check if handler re-raises or just logs/passes
            body_types = [type(s).__name__ for s in node.body]
            has_raise = any(isinstance(s, ast.Raise) for s in ast.walk(ast.Module(body=node.body, type_ignores=[])))
            has_only_pass = body_types == ["Pass"]
            has_only_log = all(
                isinstance(s, (ast.Expr, ast.Pass)) for s in node.body
            ) and not has_raise

            if has_only_pass:
                self._add("C03", "BROAD EXCEPTION SUPPRESSION", "HIGH",
                          node.lineno,
                          "Bare except/Exception handler with only 'pass' — failure silently swallowed")
            elif has_only_log and not has_raise:
                self._add("C03", "BROAD EXCEPTION SUPPRESSION", "HIGH",
                          node.lineno,
                          "Broad exception handler that logs but does not re-raise — failure semantics lost")
            elif is_broad and not has_raise:
                self._add("C03", "BROAD EXCEPTION SUPPRESSION", "MEDIUM",
                          node.lineno,
                          "Broad exception handler does not re-raise — verify failure is intentionally absorbed")

    # ── CHECK 1: Success Integrity ────────────────────────────────
    @staticmethod
    def _constant_value(node):
        return node.value if isinstance(node, ast.Constant) else None

    @classmethod
    def _dict_returns_success(cls, value: ast.Dict) -> bool:
        pairs = []
        for key, item_value in zip(value.keys, value.values):
            key_value = cls._constant_value(key)
            if key_value is None:
                continue
            pairs.append((str(key_value).lower(), cls._constant_value(item_value)))

        explicit_failure = any(
            (key in {"success", "ok"} and item_value is False)
            or (key == "status" and str(item_value).lower() in {"error", "failed", "failure", "invalid"})
            for key, item_value in pairs
        )
        if explicit_failure:
            return False
        return any(
            (key in {"success", "ok"} and item_value is True)
            or (
                key == "status"
                and str(item_value).lower() in {"ok", "success", "succeeded", "complete", "completed", "ready"}
            )
            for key, item_value in pairs
        )

    def _check_success_integrity(self):
        """Flag try blocks in functions that return success-like values after catching errors."""
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Try):
                continue
            for handler in node.handlers:
                # Look for return True / return {"status": "ok"} / return success_obj inside handler
                handler_scope = ast.Module(body=handler.body, type_ignores=[])
                for child in self._iter_returns_in_scope(handler_scope):
                    val = child.value
                    if isinstance(val, ast.Constant) and val.value is True:
                        self._add("C01", "SUCCESS INTEGRITY", "HIGH",
                                  getattr(child, 'lineno', node.lineno),
                                  "Exception handler returns True — may misrepresent success after failure")
                    elif isinstance(val, ast.Dict) and self._dict_returns_success(val):
                        self._add("C01", "SUCCESS INTEGRITY", "HIGH",
                                  getattr(child, 'lineno', node.lineno),
                                  "Exception handler returns an explicit success result after failure")

    # ── CHECK 2: Audit / Evidence Integrity ──────────────────────
    def _check_audit_integrity(self):
        """Flag audit/log writes inside try/except that only log on failure."""
        audit_keywords = {"audit", "evidence", "log_event", "write_audit", "record_event",
                          "audit_write", "flush", "persist_audit", "commit_audit"}
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Try):
                continue
            # Check if try body contains audit-related calls
            try_calls = []
            for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(child, ast.Call):
                    func = child.func
                    name = ""
                    if isinstance(func, ast.Attribute):
                        name = func.attr
                    elif isinstance(func, ast.Name):
                        name = func.id
                    if any(kw in name.lower() for kw in audit_keywords):
                        try_calls.append((name, getattr(child, 'lineno', node.lineno)))

            if not try_calls:
                continue

            # Check handlers — do they swallow?
            for handler in node.handlers:
                has_raise = any(isinstance(s, ast.Raise)
                                for s in ast.walk(ast.Module(body=handler.body, type_ignores=[])))
                if not has_raise:
                    for call_name, call_line in try_calls:
                        self._add("C02", "AUDIT / EVIDENCE INTEGRITY", "HIGH",
                                  call_line,
                                  f"Audit operation '{call_name}' inside try/except that does not re-raise — evidence loss possible")

    # ── CHECK 5: Bypass / Override Paths ─────────────────────────
    def _check_bypass_paths(self):
        bypass_names = {"testing_bypass", "skip_router", "force_model_output",
                        "allow_degraded", "bypass_governance", "skip_validation",
                        "skip_audit", "disable_checks", "force_pass"}
        for node in ast.walk(self.tree):
            name = None
            lineno = 0
            if isinstance(node, ast.Name) and node.id in bypass_names:
                name = node.id
                lineno = node.lineno
            elif isinstance(node, ast.Attribute) and node.attr in bypass_names:
                name = node.attr
                lineno = node.lineno
            if name:
                self._add("C05", "BYPASS / OVERRIDE PATHS", "HIGH",
                          lineno, f"Potential governance bypass flag detected: '{name}'")

    @staticmethod
    def _iter_returns_in_scope(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(child, ast.Return):
                yield child
            yield from PythonChecker._iter_returns_in_scope(child)

    # ── CHECK 6: Ambiguous Return Contracts ───────────────────────
    def _check_ambiguous_returns(self):
        """Flag functions that return None in multiple semantically different contexts."""
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            none_returns = []
            for ret in self._iter_returns_in_scope(node):
                val = ret.value
                if val is None or (isinstance(val, ast.Constant) and val.value is None):
                    none_returns.append(ret.lineno)
            if len(none_returns) >= 2:
                self._add("C06", "AMBIGUOUS RETURN CONTRACTS", "MEDIUM",
                          node.lineno,
                          f"Function '{node.name}' returns None in {len(none_returns)} locations — "
                          f"caller may not distinguish failure vs absence vs disabled (lines: {none_returns})")

    # ── CHECK 8: Unsupervised Background Tasks ────────────────────
    def _ancestor(self, node, node_types):
        current = self.parents.get(node)
        while current is not None:
            if isinstance(current, node_types):
                return current
            current = self.parents.get(current)
        return None

    @staticmethod
    def _assigned_names(parent) -> set:
        targets = []
        if isinstance(parent, ast.Assign):
            targets = parent.targets
        elif isinstance(parent, ast.AnnAssign):
            targets = [parent.target]
        elif isinstance(parent, ast.NamedExpr):
            targets = [parent.target]
        return {
            child.id
            for target in targets
            for child in ast.walk(target)
            if isinstance(child, ast.Name)
        }

    @staticmethod
    def _task_group_names(scope) -> set:
        names = set()
        if scope is None:
            return names
        for node in ast.walk(scope):
            if not isinstance(node, ast.AsyncWith):
                continue
            for item in node.items:
                context = item.context_expr
                if not isinstance(context, ast.Call):
                    continue
                func = context.func
                func_name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
                if func_name == "TaskGroup" and isinstance(item.optional_vars, ast.Name):
                    names.add(item.optional_vars.id)
        return names

    def _task_is_supervised(self, node: ast.Call) -> bool:
        if self._ancestor(node, ast.Await) is not None:
            return True

        scope = self._ancestor(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id in self._task_group_names(scope):
                return True

        assigned_names = self._assigned_names(self.parents.get(node))
        if not assigned_names or scope is None:
            return False
        for child in ast.walk(scope):
            if isinstance(child, ast.Await):
                awaited_names = {item.id for item in ast.walk(child.value) if isinstance(item, ast.Name)}
                if assigned_names & awaited_names:
                    return True
            if not isinstance(child, ast.Call):
                continue
            func = child.func
            name = func.attr if isinstance(func, ast.Attribute) else func.id if isinstance(func, ast.Name) else ""
            if name not in {"gather", "wait", "as_completed"}:
                continue
            consumed_names = {
                item.id
                for argument in child.args
                for item in ast.walk(argument)
                if isinstance(item, ast.Name)
            }
            if assigned_names & consumed_names:
                return True
        return False

    def _check_background_tasks(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = ""
            if isinstance(func, ast.Attribute):
                name = func.attr
            elif isinstance(func, ast.Name):
                name = func.id
            if name in ("create_task", "ensure_future"):
                if self._task_is_supervised(node):
                    continue
                lineno = getattr(node, 'lineno', 0)
                self._add("C08", "UNSUPERVISED BACKGROUND TASKS", "MEDIUM",
                          lineno,
                          f"'{name}()' call — verify task result is supervised and failure surfaces to health monitoring")

    # ── CHECK 9: Environment-Dependent Safety ─────────────────────
    def _check_environment_safety(self):
        # Pattern terms used to detect dangerous environment checks
        env_check_terms = ("debug", "dev", "development", "staging", "test", "environment", "node_env")
        dangerous_effect_terms = ("skip", "disable", "bypass", "relax", "valid", "check", "auth", "security", "guard")
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.If):
                continue
            condition = ast.unparse(node.test).lower()
            body = " ".join(ast.unparse(statement).lower() for statement in node.body)
            has_env_check = any(term in condition for term in env_check_terms)
            has_dangerous_effect = any(term in f"{condition} {body}" for term in dangerous_effect_terms)
            if has_env_check and has_dangerous_effect:
                self._add(
                    "C09",
                    "ENVIRONMENT-DEPENDENT SAFETY",
                    "HIGH",
                    node.lineno,
                    "Environment-dependent branch appears to alter validation, authorization, or safety behavior",
                )

    # ── CHECK 10: Startup Integrity ───────────────────────────────
    def _check_startup_integrity(self):
        startup_keywords = {"startup", "initialize", "init", "setup", "bootstrap", "on_startup"}
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(kw in node.name.lower() for kw in startup_keywords):
                continue
            # Look for try/except that logs but continues
            for child in ast.walk(node):
                if isinstance(child, ast.ExceptHandler):
                    has_raise = any(isinstance(s, ast.Raise)
                                    for s in ast.walk(ast.Module(body=child.body, type_ignores=[])))
                    has_sys_exit = any(
                        isinstance(s, ast.Call) and
                        isinstance(getattr(s, 'func', None), ast.Attribute) and
                        s.func.attr in ("exit", "_exit")
                        for s in ast.walk(ast.Module(body=child.body, type_ignores=[]))
                    )
                    if not has_raise and not has_sys_exit:
                        self._add("C10", "STARTUP INTEGRITY", "HIGH",
                                  child.lineno,
                                  f"Startup function '{node.name}' catches exception without halting — "
                                  "system may run in partially invalid state")

    # ── CHECK 11: Deterministic Reasoning Drift ───────────────────
    def _check_determinism(self):
        candidates = []
        for node in ast.walk(self.tree):
            if isinstance(node, ast.keyword) and node.arg == "temperature":
                candidates.append((node.value, getattr(node, "lineno", 0)))
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and str(key.value).lower() == "temperature":
                        candidates.append((value, getattr(value, "lineno", getattr(node, "lineno", 0))))

        seen_lines = set()
        for value, line in candidates:
            numeric = value.value if isinstance(value, ast.Constant) else None
            if not isinstance(numeric, (int, float)) or isinstance(numeric, bool) or numeric == 0 or line in seen_lines:
                continue
            seen_lines.add(line)
            self._add(
                "C11",
                "DETERMINISTIC REASONING DRIFT",
                "HIGH",
                line,
                "Non-zero temperature detected in model call or model configuration",
            )

    # ── CHECK 13: Confidence Misrepresentation ────────────────────
    def _check_confidence_misrepresentation(self):
        """Flag functions returning results without confidence/certainty metadata."""
        confidence_terms = {"confidence", "is_confident", "certainty", "is_verified",
                            "score", "probability", "is_cached", "is_default", "is_estimated"}
        for node in ast.walk(self.tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            result_names = {"predict", "assess", "evaluate", "score", "classify",
                            "recommend", "decide", "infer", "generate", "resolve"}
            if not any(kw in node.name.lower() for kw in result_names):
                continue
            returns = list(self._iter_returns_in_scope(node))
            has_confidence = False
            for ret in returns:
                src = ast.unparse(ret)
                if any(term in src.lower() for term in confidence_terms):
                    has_confidence = True
                    break
            if not has_confidence and returns:
                self._add("C13", "CONFIDENCE MISREPRESENTATION", "MEDIUM",
                          node.lineno,
                          f"Function '{node.name}' returns result without confidence/certainty metadata — "
                          "caller cannot distinguish verified result from estimate or default")

    # ── CHECK 15: Retry / Idempotency Assumption Drift ───────────
    def _check_idempotency(self):
        retry_patterns = [
            r'\bretry\b', r'\bbackoff\b', r'\btenacity\b',
            r'for\s+\w+\s+in\s+range\s*\(.*attempt',
            r'while.*attempt', r'@retry', r'@backoff'
        ]
        write_patterns = [
            r'\b(?:insert|create|write|commit|publish|send|post|charge|submit)\b'
        ]
        idempotency_patterns = [
            r'\bidempotency_key\b', r'\bidempotent\b', r'\bdedup\b',
            r'\bdeduplicate\b', r'\bif_not_exists\b'
        ]

        for i, line in enumerate(self.lines, start=1):
            is_retry = any(re.search(p, line, re.IGNORECASE) for p in retry_patterns)
            if not is_retry:
                continue
            # Look at surrounding 10 lines for write ops without idempotency
            window_start = max(0, i - 5)
            window_end = min(len(self.lines), i + 10)
            window = "\n".join(self.lines[window_start:window_end])
            # Strip string literals and comments before scanning the window
            clean_window = self._strip_comments_and_strings(window)
            has_write = any(re.search(p, clean_window, re.IGNORECASE) for p in write_patterns)
            has_idempotency = any(re.search(p, clean_window, re.IGNORECASE) for p in idempotency_patterns)
            if has_write and not has_idempotency:
                self._add("C15", "RETRY / IDEMPOTENCY ASSUMPTION DRIFT", "HIGH",
                          i,
                          f"Retry logic near write operation without idempotency key — "
                          f"double-write/commit risk: '{line.strip()}'")

    @staticmethod
    def _strip_comments_and_strings(source: str) -> str:
        """Remove comments and string literals so idempotency regexes don't miscount."""
        result: list[str] = []
        i = 0
        n = len(source)
        while i < n:
            c = source[i]
            if c == '#':
                i += 1
                while i < n and source[i] != '\n':
                    i += 1
                continue
            if c in ('"', "'"):
                # Check for triple quotes
                if source[i:i+3] in ('"""', "'''"):
                    quote = source[i:i+3]
                    i += 3
                    while i < n and source[i:i+3] != quote:
                        i += 1
                    i += 3
                    result.append(' ')
                    continue
                # Regular string
                quote = c
                i += 1
                while i < n and source[i] != quote:
                    if source[i] == '\\':
                        i += 1
                    i += 1
                i += 1  # skip closing quote
                result.append(' ')
                continue
            if c == 'f' and i + 1 < n and source[i+1] in ('"', "'"):
                # f-string
                i += 1
                c = source[i]
                if source[i:i+3] in ('"""', "'''"):
                    quote = source[i:i+3]
                    i += 3
                    brace_depth = 0
                    while i < n:
                        if brace_depth == 0 and source[i:i+3] == quote:
                            i += 3
                            break
                        if source[i] == '{':
                            brace_depth += 1
                        elif source[i] == '}':
                            brace_depth -= 1
                        i += 1
                else:
                    quote = c
                    i += 1
                    brace_depth = 0
                    while i < n:
                        if brace_depth == 0 and source[i] == quote:
                            i += 1
                            break
                        if source[i] == '{':
                            brace_depth += 1
                        elif source[i] == '}':
                            brace_depth -= 1
                        i += 1
                result.append(' ')
                continue
            result.append(c)
            i += 1
        return ''.join(result)

    # ── CHECK 4: Fallback Scatter ─────────────────────────────────
    def _check_fallback_scatter(self):
        fallback_names = {"fallback", "degraded", "best_effort", "best_effort",
                          "fallback_mode", "use_fallback", "fail_open"}
        for node in ast.walk(self.tree):
            name = None
            lineno = 0
            if isinstance(node, ast.Name) and node.id in fallback_names:
                name = node.id
                lineno = node.lineno
            elif isinstance(node, ast.Attribute) and node.attr in fallback_names:
                name = node.attr
                lineno = node.lineno
            if name:
                self._add("C04", "DISTRIBUTED FALLBACK / DEGRADED EXECUTION", "LOW",
                          lineno, f"Fallback/degraded logic detected — verify centralized governance: '{name}'")
