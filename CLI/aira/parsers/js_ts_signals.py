"""JavaScript/TypeScript ErrorSignal adapter with labeled lexical recovery."""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from aira.parser_health import ParserHealth
from aira.parsers.base import ParserOutput, build_signal, normalize_evidence

try:
    import esprima
except ImportError:  # pragma: no cover - environment dependent
    esprima = None

try:
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - labeled fallback covers broken installs
    Language = None
    Parser = None
    tree_sitter_javascript = None
    tree_sitter_typescript = None


LOG_RE = re.compile(r"\b(?:console|logger|log)\.(debug|info|warn|warning|error|fatal)\s*\(")
CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
SIDE_EFFECT_NAMES = {"write", "save", "insert", "update", "delete", "remove", "commit", "publish", "send", "charge", "upload", "persist", "flush", "execute", "put", "post", "patch", "rollback", "revert", "compensate", "abort_transaction"}
RETRY_NAMES = {"retry", "backoff"}
SPAWN_NAMES = {"settimeout", "setinterval", "queuemicrotask", "create_task", "spawn", "submit"}
JOIN_NAMES = {"all", "allsettled", "race", "any", "wait", "join"}


def _member_name(node: Any) -> str:
    node_type = getattr(node, "type", None)
    if node_type == "Identifier":
        return str(getattr(node, "name", ""))
    if node_type in {"Literal", "StringLiteral"}:
        return str(getattr(node, "value", ""))
    if node_type in {"MemberExpression", "OptionalMemberExpression"}:
        left = _member_name(getattr(node, "object", None))
        right = _member_name(getattr(node, "property", None))
        return ".".join(part for part in (left, right) if part)
    if node_type in {"CallExpression", "NewExpression"}:
        return _member_name(getattr(node, "callee", None))
    return ""


def _children(node: Any) -> Iterable[Tuple[str, Any]]:
    if node is None:
        return
    for key, value in vars(node).items():
        if key in {"loc", "range", "tokens", "comments", "errors"}:
            continue
        if isinstance(value, list):
            for index, item in enumerate(value):
                if hasattr(item, "type"):
                    yield f"{key}[{index}]", item
        elif hasattr(value, "type"):
            yield key, value


class JavaScriptTypeScriptSignalParser:
    def __init__(self, path: Path, artifact: str, source: str, language: str):
        self.path = path
        self.artifact = artifact
        self.source = source
        self.language = language
        self.lines = source.splitlines()
        self.signals: List[Dict[str, Any]] = []
        self._logical_ordinal = 0
        version = str(getattr(esprima, "__version__", "optional-missing"))
        self._parser = {"name": "esprima", "version": version}

    def parse(self) -> ParserOutput:
        tree_sitter_output = self._parse_tree_sitter()
        if tree_sitter_output is not None:
            return tree_sitter_output

        tree = None
        parse_error: Optional[Exception] = None
        if esprima is not None:
            for method_name in ("parseModule", "parseScript"):
                try:
                    tree = getattr(esprima, method_name)(self.source, loc=True, tolerant=True)
                    break
                except Exception as exc:  # pragma: no cover - syntax-dependent
                    parse_error = exc
        if tree is not None:
            self._walk(tree, "Program", [], ["<module>"])
            return ParserOutput(
                signals=self.signals,
                health=ParserHealth(
                    parser="esprima",
                    parser_version=self._parser["version"],
                    status="analyzed",
                    structural=True,
                    capabilities=["handlers", "throws", "returns", "logs", "retries", "side_effects", "async_ownership"],
                ),
            )

        limitation = "optional esprima parser is not installed" if esprima is None else "syntax unsupported by esprima; lexical recovery used"
        self._lexical_recovery()
        error = None
        if parse_error is not None:
            error = {"type": parse_error.__class__.__name__, "message": str(parse_error)}
        self.signals.append(self._lexical_signal(
            kind="parser_missing" if esprima is None else "parser_unsupported",
            line=1,
            text=limitation,
            outcome={"kind": "parser_capability", "success_state": "unknown"},
            attributes={"limitation": limitation},
        ))
        return ParserOutput(
            signals=self.signals,
            health=ParserHealth(
                parser="lexical_fallback",
                parser_version="aira-lexical-v1",
                status="partial",
                structural=False,
                capabilities=["lexical_error_signals"],
                limitations=[limitation, "absence of lexical signals is not evidence of absence"],
                error=error,
            ),
        )

    @staticmethod
    def _package_version(package: str, fallback: str) -> str:
        try:
            return version(package)
        except PackageNotFoundError:  # pragma: no cover - editable/source edge case
            return fallback

    def _parse_tree_sitter(self) -> Optional[ParserOutput]:
        if Parser is None or Language is None or tree_sitter_javascript is None or tree_sitter_typescript is None:
            return None
        try:
            if self.path.suffix.lower() == ".tsx":
                capsule = tree_sitter_typescript.language_tsx()
                grammar_package = "tree-sitter-typescript"
            elif self.language == "typescript":
                capsule = tree_sitter_typescript.language_typescript()
                grammar_package = "tree-sitter-typescript"
            else:
                capsule = tree_sitter_javascript.language()
                grammar_package = "tree-sitter-javascript"
            parser = Parser(Language(capsule))
            source_bytes = self.source.encode("utf-8")
            tree = parser.parse(source_bytes)
        except Exception:
            return None

        core_version = self._package_version("tree-sitter", "0.23.2")
        grammar_version = self._package_version(grammar_package, "unknown")
        self._parser = {
            "name": "tree_sitter",
            "version": core_version,
            "grammar": grammar_package,
            "grammar_version": grammar_version,
        }
        diagnostics: List[Any] = []
        self._collect_tree_sitter_diagnostics(tree.root_node, diagnostics)
        self._walk_tree_sitter(tree.root_node, "program", [], ["<module>"], source_bytes)
        for index, node in enumerate(diagnostics):
            kind = "parser_error" if node.is_error else "parser_missing"
            region = self._tree_sitter_region(node)
            evidence = self._tree_sitter_text(node, source_bytes)
            self.signals.append(build_signal(
                artifact=self.artifact,
                language=self.language,
                kind=kind,
                region=region,
                symbol={
                    "id": f"{self.language}:{self.artifact}:<module>",
                    "name": "<module>",
                    "kind": "module",
                },
                structural_path=f"program.diagnostic[{index}]",
                normalized_statement=f"{kind}:{node.type}:{evidence}",
                evidence_text=evidence,
                parser=self._parser,
                confidence="structural",
                error_identity={"type": node.type},
                outcome={"kind": "parser_capability", "success_state": "unknown"},
                attributes={"missing": bool(node.is_missing), "error": bool(node.is_error)},
            ))

        has_recovery = bool(diagnostics or tree.root_node.has_error)
        limitations = []
        if has_recovery:
            limitations.append("Tree-sitter recovered syntax errors or missing nodes; affected regions are partial")
        return ParserOutput(
            signals=self.signals,
            health=ParserHealth(
                parser="tree_sitter",
                parser_version=core_version,
                status="partial" if has_recovery else "analyzed",
                structural=True,
                capabilities=[
                    "handlers", "throws", "returns", "logs", "retries", "side_effects",
                    "async_ownership", "error_recovery",
                ],
                limitations=limitations,
            ),
        )

    @staticmethod
    def _tree_sitter_region(node: Any) -> Dict[str, int]:
        start = node.start_point
        end = node.end_point
        start_line = int(start.row) + 1
        start_column = int(start.column) + 1
        end_line = int(end.row) + 1
        end_column = int(end.column) + 1
        if end_line == start_line and end_column <= start_column:
            end_column = start_column + 1
        return {
            "start_line": start_line,
            "start_column": start_column,
            "end_line": end_line,
            "end_column": end_column,
        }

    @staticmethod
    def _tree_sitter_text(node: Any, source_bytes: bytes) -> str:
        return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    @staticmethod
    def _tree_sitter_named_child(node: Any, field: str) -> Any:
        return node.child_by_field_name(field)

    def _collect_tree_sitter_diagnostics(self, node: Any, diagnostics: List[Any]) -> None:
        if node.is_error or node.is_missing:
            diagnostics.append(node)
        for child in node.children:
            self._collect_tree_sitter_diagnostics(child, diagnostics)

    def _tree_sitter_outcome(self, node: Any, source_bytes: bytes) -> Dict[str, Any]:
        named = list(node.named_children)
        value = named[0] if named else None
        text = self._tree_sitter_text(value, source_bytes).strip() if value is not None else ""
        lowered = text.lower()
        if lowered in {"false", "null", "undefined"}:
            return {"kind": "failure" if lowered == "false" else "sentinel", "value": lowered, "success_state": "failure" if lowered == "false" else "unknown"}
        if lowered == "true":
            return {"kind": "success", "value": True, "success_state": "success"}
        if lowered.isdigit() and 100 <= int(lowered) <= 599:
            code = int(lowered)
            return {"kind": "status_code", "value": code, "success_state": "failure" if code >= 400 else "success" if code < 300 else "unknown"}
        failure = bool(re.search(r"(?:status\s*:\s*['\"]?(?:error|failed|failure)|success\s*:\s*false|ok\s*:\s*false|status_code\s*:\s*[45]\d\d)", lowered))
        success = bool(re.search(r"(?:status\s*:\s*['\"]?(?:ok|success|ready)|success\s*:\s*true|ok\s*:\s*true|status_code\s*:\s*2\d\d)", lowered))
        return {"kind": "error_object" if failure else "success_object" if success else "value", "text": text, "success_state": "failure" if failure else "success" if success else "unknown"}

    def _emit_tree_sitter(
        self,
        node: Any,
        path: str,
        symbols: List[str],
        blocks: List[str],
        source_bytes: bytes,
        kind: str,
        *,
        error_identity: Optional[Dict[str, Any]] = None,
        outcome: Optional[Dict[str, Any]] = None,
        side_effects: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        symbol_name = ".".join(symbols)
        evidence = self._tree_sitter_text(node, source_bytes)
        self.signals.append(build_signal(
            artifact=self.artifact,
            language=self.language,
            kind=kind,
            region=self._tree_sitter_region(node),
            symbol={
                "id": f"{self.language}:{self.artifact}:{symbol_name}",
                "name": symbol_name,
                "kind": "function" if symbol_name != "<module>" else "module",
            },
            structural_path=path,
            normalized_statement=f"{node.type}:{normalize_evidence(evidence)}",
            evidence_text=evidence,
            parser=self._parser,
            confidence="structural",
            enclosing_blocks=blocks,
            error_identity=error_identity,
            outcome=outcome,
            side_effects=side_effects,
            attributes=attributes,
        ))

    def _walk_tree_sitter(
        self,
        node: Any,
        path: str,
        blocks: List[str],
        symbols: List[str],
        source_bytes: bytes,
    ) -> None:
        node_type = node.type
        next_blocks = list(blocks)
        next_symbols = list(symbols)
        if node_type in {
            "function_declaration", "function_expression", "arrow_function", "generator_function_declaration",
            "generator_function", "method_definition",
        }:
            name_node = self._tree_sitter_named_child(node, "name")
            name = self._tree_sitter_text(name_node, source_bytes) if name_node is not None else f"<anonymous@{path}>"
            next_symbols = symbols + [name] if symbols != ["<module>"] else [name]
            next_blocks.append("function")
        elif node_type == "catch_clause":
            parameter = self._tree_sitter_named_child(node, "parameter")
            binding = self._tree_sitter_text(parameter, source_bytes) if parameter is not None else ""
            self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "handler", error_identity={"binding": binding}, outcome={"kind": "handler", "success_state": "unknown"})
            next_blocks.append("catch")
        elif node_type == "try_statement":
            next_blocks.append("try")
        elif node_type == "throw_statement":
            named = list(node.named_children)
            argument = named[0] if named else None
            error_type = self._tree_sitter_text(argument, source_bytes).split("(", 1)[0].strip() if argument is not None else "unknown"
            self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "throw", error_identity={"type": error_type}, outcome={"kind": "abort", "success_state": "failure"})
        elif node_type == "return_statement":
            self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "return", outcome=self._tree_sitter_outcome(node, source_bytes))
        elif node_type == "await_expression":
            named = list(node.named_children)
            operation = self._tree_sitter_text(named[0], source_bytes) if named else ""
            self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "async_join", outcome={"kind": "await", "operation": operation, "success_state": "unknown"})
        elif node_type in {"call_expression", "new_expression"}:
            function = self._tree_sitter_named_child(node, "function") or self._tree_sitter_named_child(node, "constructor")
            callee = self._tree_sitter_text(function, source_bytes) if function is not None else ""
            leaf = callee.rsplit(".", 1)[-1].lower()
            owner = callee.rsplit(".", 2)[-2].lower() if "." in callee else ""
            if owner in {"console", "logger", "log"} and leaf in {"debug", "info", "warn", "warning", "error", "fatal"}:
                self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "log", outcome={"kind": "evidence", "level": leaf, "success_state": "unknown"}, attributes={"callee": callee})
            elif any(token in leaf for token in RETRY_NAMES):
                self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "retry", outcome={"kind": "retry", "operation": callee, "success_state": "unknown"})
            elif leaf in SPAWN_NAMES:
                self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "async_spawn", outcome={"kind": "spawn", "operation": callee, "success_state": "unknown"})
            elif leaf in JOIN_NAMES and owner == "promise":
                self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "async_join", outcome={"kind": "join", "operation": callee, "success_state": "unknown"})
            elif leaf in SIDE_EFFECT_NAMES or any(leaf.startswith(f"{name}_") for name in SIDE_EFFECT_NAMES):
                self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "side_effect", side_effects=[callee], outcome={"kind": "side_effect", "operation": callee, "success_state": "unknown"})
            if any(token in leaf for token in {"fallback", "default", "degraded", "besteffort"}):
                self._emit_tree_sitter(node, path, next_symbols, blocks, source_bytes, "fallback", outcome={"kind": "fallback", "operation": callee, "success_state": "unknown"})

        for index, child in enumerate(node.named_children):
            self._walk_tree_sitter(child, f"{path}.{child.type}[{index}]", next_blocks, next_symbols, source_bytes)

    def _region(self, node: Any) -> Dict[str, int]:
        loc = getattr(node, "loc", None)
        start = getattr(loc, "start", None)
        end = getattr(loc, "end", None)
        return {
            "start_line": int(getattr(start, "line", 1) or 1),
            "start_column": int(getattr(start, "column", 0) or 0) + 1,
            "end_line": int(getattr(end, "line", getattr(start, "line", 1)) or 1),
            "end_column": int(getattr(end, "column", getattr(start, "column", 0)) or 0) + 1,
        }

    def _evidence(self, region: Dict[str, int]) -> str:
        start = region["start_line"] - 1
        end = region["end_line"]
        return "\n".join(self.lines[start:end])

    def _emit(
        self,
        node: Any,
        path: str,
        symbols: List[str],
        blocks: List[str],
        kind: str,
        *,
        error_identity: Optional[Dict[str, Any]] = None,
        outcome: Optional[Dict[str, Any]] = None,
        side_effects: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        region = self._region(node)
        symbol_name = ".".join(symbols)
        evidence = self._evidence(region)
        normalized = f"{getattr(node, 'type', 'Node')}:{normalize_evidence(evidence)}"
        self.signals.append(build_signal(
            artifact=self.artifact,
            language=self.language,
            kind=kind,
            region=region,
            symbol={"id": f"{self.language}:{self.artifact}:{symbol_name}", "name": symbol_name, "kind": "function" if symbol_name != "<module>" else "module"},
            structural_path=path,
            normalized_statement=normalized,
            evidence_text=evidence,
            parser=self._parser,
            confidence="structural",
            enclosing_blocks=blocks,
            error_identity=error_identity,
            outcome=outcome,
            side_effects=side_effects,
            attributes=attributes,
        ))

    def _walk(self, node: Any, path: str, blocks: List[str], symbols: List[str]) -> None:
        node_type = getattr(node, "type", "")
        next_blocks = list(blocks)
        next_symbols = list(symbols)
        if node_type in {"FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"}:
            identifier = _member_name(getattr(node, "id", None)) or f"<anonymous@{path}>"
            next_symbols = symbols + [identifier] if symbols != ["<module>"] else [identifier]
            next_blocks.append("function")
        elif node_type == "CatchClause":
            caught = _member_name(getattr(node, "param", None))
            self._emit(node, path, next_symbols, blocks, "handler", error_identity={"binding": caught}, outcome={"kind": "handler", "success_state": "unknown"})
            next_blocks.append("catch")
        elif node_type == "TryStatement":
            next_blocks.append("try")
        elif node_type in {"ThrowStatement"}:
            argument = getattr(node, "argument", None)
            self._emit(node, path, next_symbols, blocks, "throw", error_identity={"type": _member_name(argument) or getattr(argument, "type", "unknown")}, outcome={"kind": "abort", "success_state": "failure"})
        elif node_type == "ReturnStatement":
            argument = getattr(node, "argument", None)
            value = getattr(argument, "value", None)
            success_state = "failure" if value is False else "success" if value is True else "unknown"
            self._emit(node, path, next_symbols, blocks, "return", outcome={"kind": "value", "value": value, "success_state": success_state})
        elif node_type == "AwaitExpression":
            self._emit(node, path, next_symbols, blocks, "async_join", outcome={"kind": "await", "operation": _member_name(getattr(node, "argument", None)), "success_state": "unknown"})
        elif node_type == "CallExpression":
            callee = _member_name(getattr(node, "callee", None))
            leaf = callee.rsplit(".", 1)[-1].lower()
            owner = callee.rsplit(".", 2)[-2].lower() if "." in callee else ""
            if owner in {"console", "logger", "log"} and leaf in {"debug", "info", "warn", "warning", "error", "fatal"}:
                self._emit(node, path, next_symbols, blocks, "log", outcome={"kind": "evidence", "level": leaf, "success_state": "unknown"}, attributes={"callee": callee})
            elif any(token in leaf for token in RETRY_NAMES):
                self._emit(node, path, next_symbols, blocks, "retry", outcome={"kind": "retry", "operation": callee, "success_state": "unknown"})
            elif leaf in SPAWN_NAMES:
                self._emit(node, path, next_symbols, blocks, "async_spawn", outcome={"kind": "spawn", "operation": callee, "success_state": "unknown"})
            elif leaf in JOIN_NAMES and owner == "promise":
                self._emit(node, path, next_symbols, blocks, "async_join", outcome={"kind": "join", "operation": callee, "success_state": "unknown"})
            elif leaf in SIDE_EFFECT_NAMES or any(leaf.startswith(f"{name}_") for name in SIDE_EFFECT_NAMES):
                self._emit(node, path, next_symbols, blocks, "side_effect", side_effects=[callee], outcome={"kind": "side_effect", "operation": callee, "success_state": "unknown"})
            if any(token in leaf for token in {"fallback", "default", "degraded", "besteffort"}):
                self._emit(node, path, next_symbols, blocks, "fallback", outcome={"kind": "fallback", "operation": callee, "success_state": "unknown"})

        for child_name, child in _children(node):
            self._walk(child, f"{path}.{child_name}", next_blocks, next_symbols)

    def _lexical_signal(
        self,
        *,
        kind: str,
        line: int,
        text: str,
        outcome: Optional[Dict[str, Any]] = None,
        error_identity: Optional[Dict[str, Any]] = None,
        side_effects: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._logical_ordinal += 1
        normalized = normalize_evidence(text)
        return build_signal(
            artifact=self.artifact,
            language=self.language,
            kind=kind,
            region={"start_line": line, "start_column": 1, "end_line": line, "end_column": len(text) + 1},
            symbol={"id": f"{self.language}:{self.artifact}:<module>", "name": "<module>", "kind": "module"},
            structural_path=f"lexical[{self._logical_ordinal}]",
            normalized_statement=normalized,
            evidence_text=text,
            parser={"name": "lexical_fallback", "version": "aira-lexical-v1"},
            confidence="lexical",
            error_identity=error_identity,
            outcome=outcome,
            side_effects=side_effects,
            attributes=attributes,
        )

    def _lexical_recovery(self) -> None:
        in_block_comment = False
        for line_number, raw_line in enumerate(self.lines, start=1):
            line = raw_line
            if in_block_comment:
                if "*/" in line:
                    line = line.split("*/", 1)[1]
                    in_block_comment = False
                else:
                    continue
            if "/*" in line:
                before, after = line.split("/*", 1)
                line = before
                if "*/" not in after:
                    in_block_comment = True
            line = line.split("//", 1)[0]
            stripped = line.strip()
            if not stripped:
                continue
            if re.search(r"\bcatch\s*\(", stripped):
                self.signals.append(self._lexical_signal(kind="handler", line=line_number, text=stripped, outcome={"kind": "handler", "success_state": "unknown"}))
            if re.search(r"\bthrow\b", stripped):
                self.signals.append(self._lexical_signal(kind="throw", line=line_number, text=stripped, outcome={"kind": "abort", "success_state": "failure"}))
            if re.search(r"\breturn\b", stripped):
                failure = bool(re.search(r"\b(?:false|null|error|failed|failure)\b", stripped, re.IGNORECASE))
                success = bool(re.search(r"\b(?:true|ok|success|ready)\b", stripped, re.IGNORECASE))
                self.signals.append(self._lexical_signal(kind="return", line=line_number, text=stripped, outcome={"kind": "lexical_value", "success_state": "failure" if failure else "success" if success else "unknown"}))
            log_match = LOG_RE.search(stripped)
            if log_match:
                self.signals.append(self._lexical_signal(kind="log", line=line_number, text=stripped, outcome={"kind": "evidence", "level": log_match.group(1), "success_state": "unknown"}))
            for match in CALL_RE.finditer(stripped):
                callee = match.group(1)
                leaf = callee.rsplit(".", 1)[-1].lower()
                if any(token in leaf for token in RETRY_NAMES):
                    self.signals.append(self._lexical_signal(kind="retry", line=line_number, text=stripped, outcome={"kind": "retry", "operation": callee, "success_state": "unknown"}))
                elif leaf in SIDE_EFFECT_NAMES or any(leaf.startswith(f"{name}_") for name in SIDE_EFFECT_NAMES):
                    self.signals.append(self._lexical_signal(kind="side_effect", line=line_number, text=stripped, side_effects=[callee], outcome={"kind": "side_effect", "operation": callee, "success_state": "unknown"}))
