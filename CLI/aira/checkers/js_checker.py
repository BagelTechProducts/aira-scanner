"""
AIRA JavaScript/TypeScript Checker
Regex and heuristic-based analysis for JS/TS source files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional, Tuple

try:
    import esprima
except ImportError:  # pragma: no cover - optional parser dependency
    esprima = None


@dataclass
class Finding:
    check_id: str
    check_name: str
    severity: str
    file: str
    line: int
    description: str
    snippet: Optional[str] = None


class JSChecker:
    """
    Analyzes JavaScript/TypeScript source files for AIRA failure patterns.
    Uses regex and structural heuristics (no full AST parse required).
    """

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        self.lines = self.source.splitlines()
        self.code_lines = self._strip_comments_strings_and_regexes(self.source).splitlines()
        self.findings: List[Finding] = []
        self._seen = set()
        # Parser parsing: gracefully degrade to heuristic-only on parse failure
        self.tree, self.parse_ok = self._try_parse()

    def _try_parse(self) -> Tuple[Optional[Any], bool]:
        """
        Attempt to parse source with esprima.
        Returns (tree, parse_ok) tuple - never raises, always returns usable state.
        Parse failures are handled silently with fallback to heuristic analysis.
        """
        if esprima is None:
            return None, False
        try:
            return esprima.parseModule(self.source, loc=True, tolerant=True), True
        except Exception:
            try:
                return esprima.parseScript(self.source, loc=True, tolerant=True), True
            except Exception:
                # Both module and script parsing failed - use heuristic mode
                return None, False

    @staticmethod
    def _strip_comments_strings_and_regexes(source: str) -> str:
        """Blank lexical literals while preserving newlines and executable identifiers."""
        result = []
        index = 0
        length = len(source)
        block_comment = False
        while index < length:
            char = source[index]
            next_char = source[index + 1] if index + 1 < length else ""
            if block_comment:
                if char == "*" and next_char == "/":
                    result.extend((" ", " "))
                    index += 2
                    block_comment = False
                else:
                    result.append("\n" if char == "\n" else " ")
                    index += 1
                continue
            if char == "/" and next_char == "/":
                while index < length and source[index] != "\n":
                    result.append(" ")
                    index += 1
                continue
            if char == "/" and next_char == "*":
                result.extend((" ", " "))
                index += 2
                block_comment = True
                continue
            if char in {"'", '"', "`"}:
                quote = char
                result.append(" ")
                index += 1
                while index < length:
                    current = source[index]
                    result.append("\n" if current == "\n" else " ")
                    index += 1
                    if current == "\\" and index < length:
                        escaped = source[index]
                        result.append("\n" if escaped == "\n" else " ")
                        index += 1
                        continue
                    if current == quote:
                        break
                continue
            if char == "/":
                previous = next((item for item in reversed(result) if not item.isspace()), "")
                if previous in {"", "=", "(", ":", ",", "!", "[", "{", ";"}:
                    result.append(" ")
                    index += 1
                    in_class = False
                    while index < length:
                        current = source[index]
                        result.append("\n" if current == "\n" else " ")
                        index += 1
                        if current == "\\" and index < length:
                            escaped = source[index]
                            result.append("\n" if escaped == "\n" else " ")
                            index += 1
                            continue
                        if current == "[":
                            in_class = True
                        elif current == "]":
                            in_class = False
                        elif current == "/" and not in_class:
                            while index < length and source[index].isalpha():
                                result.append(" ")
                                index += 1
                            break
                    continue
            result.append(char)
            index += 1
        return "".join(result)

    def _code_window(self, lineno: int, before: int = 3, after: int = 8) -> str:
        start = max(0, lineno - 1 - before)
        end = min(len(self.code_lines), lineno + after)
        return "\n".join(self.code_lines[start:end])

    def run(self) -> List[Finding]:
        if self.parse_ok:
            self._check_broad_exception_suppression_ast()
            self._check_success_integrity_ast()
            self._check_audit_integrity_ast()
            self._check_ambiguous_returns_ast()
            self._check_startup_integrity_ast()
        self._check_broad_exception_suppression()
        if not self.parse_ok:
            self._check_success_integrity()
        self._check_background_tasks()
        self._check_bypass_paths()
        self._check_environment_safety()
        self._check_determinism()
        self._check_confidence_misrepresentation()
        self._check_idempotency()
        self._check_fallback_scatter()
        self._check_audit_integrity()
        self._check_startup_integrity()
        self._check_ambiguous_returns()
        return self.findings

    def _snippet(self, lineno: int) -> str:
        idx = lineno - 1
        return self.lines[idx].strip() if 0 <= idx < len(self.lines) else ""

    def _add(self, check_id, check_name, severity, line, description):
        dedupe_key = (check_id, line, description)
        if dedupe_key in self._seen:
            return
        self._seen.add(dedupe_key)
        self.findings.append(Finding(
            check_id=check_id,
            check_name=check_name,
            severity=severity,
            file=self.filepath,
            line=line,
            description=description,
            snippet=self._snippet(line)
        ))

    def _window(self, lineno: int, before: int = 3, after: int = 8) -> str:
        start = max(0, lineno - 1 - before)
        end = min(len(self.lines), lineno + after)
        return "\n".join(self.lines[start:end])

    def _iter_nodes(self, node):
        if node is None:
            return
        if isinstance(node, list):
            for item in node:
                yield from self._iter_nodes(item)
            return
        if hasattr(node, "type"):
            yield node
            for value in vars(node).values():
                if isinstance(value, (str, int, float, bool, type(None))):
                    continue
                yield from self._iter_nodes(value)

    def _loc(self, node) -> int:
        return getattr(getattr(node, "loc", None), "start", None).line if getattr(getattr(node, "loc", None), "start", None) else 0

    def _member_name(self, node) -> str:
        if node is None:
            return ""
        if getattr(node, "type", None) == "Identifier":
            return node.name
        if getattr(node, "type", None) == "MemberExpression":
            object_name = self._member_name(getattr(node, "object", None))
            property_name = self._member_name(getattr(node, "property", None))
            return ".".join(part for part in (object_name, property_name) if part)
        return ""

    def _has_throw(self, node) -> bool:
        return any(getattr(child, "type", None) == "ThrowStatement" for child in self._iter_nodes(node))

    def _returns_success_like(self, node) -> bool:
        for child in self._iter_nodes(node):
            child_type = getattr(child, "type", None)
            if child_type == "ReturnStatement":
                argument = getattr(child, "argument", None)
                if getattr(argument, "type", None) == "Literal" and argument.value is True:
                    return True
                if getattr(argument, "type", None) == "ObjectExpression":
                    pairs = []
                    for prop in getattr(argument, "properties", []):
                        key = getattr(getattr(prop, "key", None), "name", None)
                        if key is None and hasattr(getattr(prop, "key", None), "value"):
                            key = str(prop.key.value)
                        value = getattr(prop, "value", None)
                        pairs.append((str(key).lower(), getattr(value, "value", None)))
                    if any(
                        (key in {"success", "ok"} and value is False)
                        or (key == "status" and str(value).lower() in {"error", "failed", "failure", "invalid"})
                        for key, value in pairs
                    ):
                        continue
                    if any(
                        (key in {"success", "ok"} and value is True)
                        or (
                            key == "status"
                            and str(value).lower() in {"ok", "success", "succeeded", "complete", "completed", "ready"}
                        )
                        for key, value in pairs
                    ):
                        return True
            if child_type == "CallExpression":
                callee_name = self._member_name(getattr(child, "callee", None))
                if callee_name.endswith("resolve"):
                    first_arg = (getattr(child, "arguments", None) or [None])[0]
                    if getattr(first_arg, "type", None) == "Literal" and first_arg.value is True:
                        return True
        return False

    def _is_console_only(self, statements) -> bool:
        if not statements:
            return True
        for statement in statements:
            st_type = getattr(statement, "type", None)
            if st_type == "EmptyStatement":
                continue
            if st_type != "ExpressionStatement":
                return False
            expression = getattr(statement, "expression", None)
            if getattr(expression, "type", None) != "CallExpression":
                return False
            callee_name = self._member_name(getattr(expression, "callee", None))
            if not callee_name.startswith("console."):
                return False
        return True

    def _audit_calls_in_try(self, node):
        audit_terms = ("audit", "evidence", "logevent", "writeaudit", "recordevent", "flushaudit")
        calls = []
        for child in self._iter_nodes(node):
            if getattr(child, "type", None) != "CallExpression":
                continue
            callee_name = self._member_name(getattr(child, "callee", None))
            if any(term in callee_name.replace(".", "").lower() for term in audit_terms):
                calls.append((callee_name, self._loc(child)))
        return calls

    def _function_name(self, node) -> str:
        node_type = getattr(node, "type", None)
        if node_type == "FunctionDeclaration":
            return getattr(getattr(node, "id", None), "name", "") or ""
        return ""

    def _iter_function_returns(self, node):
        for child in self._iter_nodes(getattr(node, "body", None)):
            if child is node:
                continue
            if getattr(child, "type", None) in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
                continue
            if getattr(child, "type", None) == "ReturnStatement":
                yield child

    def _check_broad_exception_suppression_ast(self):
        for node in self._iter_nodes(self.tree):
            if getattr(node, "type", None) != "TryStatement" or getattr(node, "handler", None) is None:
                continue
            handler = node.handler
            statements = getattr(getattr(handler, "body", None), "body", []) or []
            line = self._loc(handler) or self._loc(node)
            if not statements:
                self._add("C03", "BROAD EXCEPTION SUPPRESSION", "HIGH", line, "Empty catch block — exception silently swallowed")
                continue
            if self._has_throw(handler):
                continue
            if self._is_console_only(statements):
                self._add("C03", "BROAD EXCEPTION SUPPRESSION", "HIGH", line, "Catch block only logs — failure semantics lost, no re-throw")
            else:
                self._add("C03", "BROAD EXCEPTION SUPPRESSION", "MEDIUM", line, "Catch block does not throw or reject — verify failure is intentionally absorbed")

    def _check_success_integrity_ast(self):
        for node in self._iter_nodes(self.tree):
            if getattr(node, "type", None) != "TryStatement" or getattr(node, "handler", None) is None:
                continue
            handler = node.handler
            if self._returns_success_like(handler):
                self._add("C01", "SUCCESS INTEGRITY", "HIGH", self._loc(handler) or self._loc(node), "Catch block returns success-like data after an exception path")

    def _check_audit_integrity_ast(self):
        for node in self._iter_nodes(self.tree):
            if getattr(node, "type", None) != "TryStatement" or getattr(node, "handler", None) is None:
                continue
            if self._has_throw(node.handler):
                continue
            for call_name, line in self._audit_calls_in_try(node.block):
                self._add("C02", "AUDIT / EVIDENCE INTEGRITY", "HIGH", line or self._loc(node), f"Audit operation '{call_name}' is inside a try/catch that does not re-throw — evidence loss possible")

    def _check_ambiguous_returns_ast(self):
        for node in self._iter_nodes(self.tree):
            if getattr(node, "type", None) not in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
                continue
            null_like_lines = []
            for ret in self._iter_function_returns(node):
                argument = getattr(ret, "argument", None)
                if getattr(argument, "type", None) == "Literal" and argument.value in {None, False}:
                    null_like_lines.append(self._loc(ret))
                elif getattr(argument, "type", None) == "Identifier" and getattr(argument, "name", "") == "undefined":
                    null_like_lines.append(self._loc(ret))
            if len(null_like_lines) >= 2:
                fn_name = self._function_name(node) or "anonymous function"
                self._add("C06", "AMBIGUOUS RETURN CONTRACTS", "MEDIUM", self._loc(node), f"{fn_name} returns null/undefined/false in {len(null_like_lines)} locations — caller may not distinguish failure vs absence vs disabled")

    def _check_startup_integrity_ast(self):
        startup_keywords = ("init", "startup", "bootstrap", "setup", "onstart")
        for node in self._iter_nodes(self.tree):
            if getattr(node, "type", None) != "FunctionDeclaration":
                continue
            fn_name = self._function_name(node).lower()
            if not any(keyword in fn_name for keyword in startup_keywords):
                continue
            for child in self._iter_nodes(getattr(node, "body", None)):
                if getattr(child, "type", None) != "TryStatement" or getattr(child, "handler", None) is None:
                    continue
                if self._has_throw(child.handler):
                    continue
                handler_statements = getattr(getattr(child.handler, "body", None), "body", []) or []
                has_process_exit = any(
                    getattr(statement, "type", None) == "ExpressionStatement"
                    and self._member_name(getattr(getattr(statement, "expression", None), "callee", None)) == "process.exit"
                    for statement in handler_statements
                    if getattr(getattr(statement, "expression", None), "type", None) == "CallExpression"
                )
                if not has_process_exit:
                    self._add("C10", "STARTUP INTEGRITY", "HIGH", self._loc(child.handler) or self._loc(child), f"Startup function '{fn_name}' catches exception without halting")

    # ── CHECK 3: Broad Exception Suppression ─────────────────────
    def _check_broad_exception_suppression(self):
        """
        Detects catch blocks that are empty, only console.log, or only comment.
        """
        in_catch = False
        catch_line = 0
        brace_depth = 0
        catch_body_lines = []

        i = 0
        while i < len(self.lines):
            line = self.lines[i]
            stripped = line.strip()

            # Detect catch block start
            catch_match = re.search(r'\bcatch\s*\(', line)
            if catch_match and '{' in line:
                in_catch = True
                catch_line = i + 1
                brace_depth = line.count('{') - line.count('}')
                catch_body_lines = []
                i += 1
                continue

            if in_catch:
                brace_depth += line.count('{') - line.count('}')
                catch_body_lines.append(stripped)
                if brace_depth <= 0:
                    in_catch = False
                    body = " ".join(catch_body_lines)
                    # Empty catch
                    if re.match(r'^\s*\}?\s*$', body) or body.strip() in ("}", ""):
                        self._add("C03", "BROAD EXCEPTION SUPPRESSION", "HIGH",
                                  catch_line, "Empty catch block — exception silently swallowed")
                    # Only console.log / console.error
                    elif re.match(r'^[\s\}]*console\.(log|error|warn)\(.*\)[\s;]*\}?\s*$', body):
                        self._add("C03", "BROAD EXCEPTION SUPPRESSION", "HIGH",
                                  catch_line,
                                  "Catch block only logs — failure semantics lost, no re-throw")
                    # No throw/reject/return error
                    elif not re.search(r'\b(throw|reject|return.*[Ee]rr|return false)\b', body):
                        self._add("C03", "BROAD EXCEPTION SUPPRESSION", "MEDIUM",
                                  catch_line,
                                  "Catch block does not throw or reject — verify failure is intentionally absorbed")
            i += 1

    # ── CHECK 1: Success Integrity ────────────────────────────────
    def _check_success_integrity(self):
        """Detect catch blocks that return success-like values."""
        patterns = [
            (r'return\s+true\s*;', "Catch block returns true — may misrepresent success after failure"),
            (r'return\s+\{\s*(?:success|status|ok)\s*:\s*true', "Catch block returns success object after error"),
            (r'resolve\s*\(\s*(?:true|null|\{\s*(?:success|ok)\s*:\s*true)', "Promise resolved with success value inside catch"),
        ]
        in_catch = False
        catch_line = 0
        brace_depth = 0
        catch_body = []

        for i, line in enumerate(self.lines):
            if re.search(r'\bcatch\s*\(', line) and '{' in line:
                in_catch = True
                catch_line = i + 1
                brace_depth = line.count('{') - line.count('}')
                catch_body = [line]
                continue
            if in_catch:
                brace_depth += line.count('{') - line.count('}')
                catch_body.append(line)
                if brace_depth <= 0:
                    in_catch = False
                    body = "\n".join(catch_body)
                    for pattern, msg in patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            self._add("C01", "SUCCESS INTEGRITY", "HIGH", catch_line, msg)

    # ── CHECK 8: Unsupervised Background Tasks ────────────────────
    def _check_background_tasks(self):
        patterns = [
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'new\s+Worker\s*\(',
            r'\.then\s*\([^)]*\)\s*(?:;|$)',  # .then() without .catch()
        ]
        for i, line in enumerate(self.code_lines, start=1):
            for pattern in patterns:
                if re.search(pattern, line):
                    window = self._code_window(i)
                    # Flag if no .catch() or try/catch in vicinity
                    if not re.search(r'\.catch\s*\(|try\s*\{', window):
                        self._add("C08", "UNSUPERVISED BACKGROUND TASKS", "MEDIUM",
                                  i, f"Async operation without visible error handler: '{line.strip()}'")
                    break

    # ── CHECK 5: Bypass / Override Paths ─────────────────────────
    def _check_bypass_paths(self):
        bypass_patterns = [
            r'\btestingBypass\b', r'\bskipRouter\b', r'\bforceModelOutput\b',
            r'\ballowDegraded\b', r'\bbypassGovernance\b', r'\bskipValidation\b',
            r'\bskipAudit\b', r'\bdisableChecks\b', r'\bforcePass\b',
            r'\btesting_bypass\b', r'\bskip_validation\b'
        ]
        for i, line in enumerate(self.code_lines, start=1):
            for pattern in bypass_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add("C05", "BYPASS / OVERRIDE PATHS", "HIGH",
                              i, f"Potential governance bypass flag: '{line.strip()}'")

    # ── CHECK 9: Environment-Dependent Safety ─────────────────────
    def _check_environment_safety(self):
        patterns = [
            r'process\.env\.NODE_ENV\s*[!=]==?',
            r'if\s*\(\s*(?:isDev|isTest|isStaging|debugMode)\b',
            r'(?:skip|disable|bypass)\w*\s*[=:]\s*(?:true|process\.env)',
        ]
        for i, line in enumerate(self.code_lines, start=1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add("C09", "ENVIRONMENT-DEPENDENT SAFETY", "HIGH",
                              i, f"Environment-conditional safety logic: '{line.strip()}'")

    # ── CHECK 11: Deterministic Reasoning Drift ───────────────────
    def _check_determinism(self):
        patterns = [
            r'\btemperature\s*[:=]\s*(?:0?\.\d*[1-9]\d*|[1-9]\d*(?:\.\d+)?)',
            r'"temperature"\s*:\s*(?:0?\.\d*[1-9]\d*|[1-9]\d*(?:\.\d+)?)',
        ]
        for i, line in enumerate(self.code_lines, start=1):
            for pattern in patterns:
                if re.search(pattern, line):
                    self._add("C11", "DETERMINISTIC REASONING DRIFT", "HIGH",
                              i, f"Non-zero temperature in model call — verify not a commit path: '{line.strip()}'")

    # ── CHECK 13: Confidence Misrepresentation ────────────────────
    def _check_confidence_misrepresentation(self):
        result_fn_pattern = r'(?:function|const|let|var)\s+(\w*(?:predict|assess|evaluate|score|classify|recommend|decide|infer|generate|resolve)\w*)\s*[=(]'
        confidence_terms = r'(?:confidence|isConfident|certainty|isVerified|probability|isCached|isDefault|isEstimated)'

        for i, line in enumerate(self.code_lines, start=1):
            match = re.search(result_fn_pattern, line, re.IGNORECASE)
            if match:
                fn_name = match.group(1)
                # Look at next 30 lines for confidence metadata
                window_end = min(len(self.code_lines), i + 30)
                fn_body = "\n".join(self.code_lines[i:window_end])
                if not re.search(confidence_terms, fn_body, re.IGNORECASE):
                    self._add("C13", "CONFIDENCE MISREPRESENTATION", "MEDIUM",
                              i, f"Function '{fn_name}' appears to return results without confidence metadata")

    # ── CHECK 15: Retry / Idempotency Assumption Drift ───────────
    def _check_idempotency(self):
        retry_patterns = [r'\bretry\b', r'\bbackoff\b', r'for\s*\(.*attempt', r'\.retry\s*\(']
        write_patterns = [r'\b(?:insert|create|write|commit|publish|send|post|charge|submit)\b']
        idempotency_patterns = [r'\bidempotency[_-]?[Kk]ey\b', r'\bidempotent\b', r'\bdedup\b']

        for i, line in enumerate(self.code_lines, start=1):
            is_retry = any(re.search(p, line, re.IGNORECASE) for p in retry_patterns)
            if not is_retry:
                continue
            window = self._code_window(i, before=3, after=12)
            has_write = any(re.search(p, window, re.IGNORECASE) for p in write_patterns)
            has_idem = any(re.search(p, window, re.IGNORECASE) for p in idempotency_patterns)
            if has_write and not has_idem:
                self._add("C15", "RETRY / IDEMPOTENCY ASSUMPTION DRIFT", "HIGH",
                          i, f"Retry near write op without idempotency key: '{line.strip()}'")

    # ── CHECK 4: Fallback Scatter ─────────────────────────────────
    def _check_fallback_scatter(self):
        patterns = [r'\bfallback\b', r'\bdegraded\b', r'\bbestEffort\b', r'\bbest_effort\b']
        for i, line in enumerate(self.code_lines, start=1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self._add("C04", "DISTRIBUTED FALLBACK / DEGRADED EXECUTION", "LOW",
                              i, f"Fallback/degraded logic — verify centralized governance: '{line.strip()}'")

    # ── CHECK 2: Audit / Evidence Integrity ──────────────────────
    def _check_audit_integrity(self):
        audit_terms = r'(?:audit|evidence|logEvent|writeAudit|recordEvent|flushAudit)'
        for i, line in enumerate(self.lines, start=1):
            if re.search(audit_terms, line, re.IGNORECASE):
                window = self._window(i, before=2, after=6)
                if re.search(r'\bcatch\b', window) and not re.search(r'\bthrow\b', window):
                    self._add("C02", "AUDIT / EVIDENCE INTEGRITY", "HIGH",
                              i, f"Audit operation in try block with non-throwing catch — evidence loss possible: '{line.strip()}'")

    # ── CHECK 10: Startup Integrity ───────────────────────────────
    def _check_startup_integrity(self):
        startup_pattern = r'(?:function|const|async function)\s+\w*(?:init|startup|bootstrap|setup|onStart)\w*'
        for i, line in enumerate(self.lines, start=1):
            if re.search(startup_pattern, line, re.IGNORECASE):
                window_end = min(len(self.lines), i + 30)
                fn_body = "\n".join(self.lines[i:window_end])
                if re.search(r'\bcatch\b', fn_body) and not re.search(r'\b(?:throw|process\.exit)\b', fn_body):
                    self._add("C10", "STARTUP INTEGRITY", "HIGH",
                              i, f"Startup function catches exception without halting: '{line.strip()}'")

    # ── CHECK 6: Ambiguous Return Contracts ───────────────────────
    def _check_ambiguous_returns(self):
        """Flag functions with multiple return null/undefined/false in different contexts."""
        fn_pattern = r'(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))'
        null_return = r'\breturn\s+(?:null|undefined|false)\s*;'

        for i, line in enumerate(self.lines, start=1):
            if re.search(fn_pattern, line):
                window_end = min(len(self.lines), i + 40)
                fn_body = "\n".join(self.lines[i:window_end])
                null_returns = re.findall(null_return, fn_body)
                if len(null_returns) >= 2:
                    self._add("C06", "AMBIGUOUS RETURN CONTRACTS", "MEDIUM",
                              i, f"Function returns null/undefined/false in {len(null_returns)} locations — "
                                 "caller may not distinguish failure vs absence vs disabled")
