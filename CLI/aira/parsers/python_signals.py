"""Python AST adapter for the language-neutral ErrorSignal inventory."""

from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aira.parser_health import ParserHealth
from aira.parsers.base import ParserOutput, build_signal

LOG_LEVELS = {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "audit"}
RETRY_NAMES = {"retry", "retrying", "backoff", "sleep"}
SPAWN_NAMES = {"create_task", "ensure_future", "submit", "start", "spawn"}
JOIN_NAMES = {"gather", "wait", "as_completed", "join", "result"}
SIDE_EFFECT_NAMES = {
    "write", "save", "insert", "update", "delete", "remove", "commit", "publish", "send",
    "charge", "upload", "persist", "flush", "execute", "put", "post", "patch",
    "rollback", "revert", "compensate", "abort_transaction",
}


def _call_name(node: Optional[ast.AST]) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return ".".join(part for part in (prefix, node.attr) if part)
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    return ""


def _constant(node: Optional[ast.AST]) -> Any:
    return node.value if isinstance(node, ast.Constant) else None


def _outcome_from_return(value: Optional[ast.AST]) -> Dict[str, Any]:
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        return {"kind": "sentinel", "value": None, "success_state": "unknown"}
    if isinstance(value, ast.Constant):
        item = value.value
        if item is True:
            return {"kind": "success", "value": True, "success_state": "success"}
        if item is False:
            return {"kind": "failure", "value": False, "success_state": "failure"}
        if isinstance(item, int) and 100 <= item <= 599:
            return {
                "kind": "status_code",
                "value": item,
                "success_state": "failure" if item >= 400 else "success" if item < 300 else "unknown",
            }
        if isinstance(item, str):
            lowered = item.lower()
            if lowered in {"error", "failed", "failure", "invalid", "denied"}:
                return {"kind": "error", "value": item, "success_state": "failure"}
            if lowered in {"ok", "success", "succeeded", "complete", "completed", "ready"}:
                return {"kind": "success", "value": item, "success_state": "success"}
    if isinstance(value, ast.Dict):
        fields: Dict[str, Any] = {}
        for key, item in zip(value.keys, value.values):
            constant_key = _constant(key)
            if constant_key is not None:
                fields[str(constant_key)] = _constant(item)
        lowered = {key.lower(): item for key, item in fields.items()}
        status = str(lowered.get("status", "")).lower()
        code = lowered.get("status_code", lowered.get("code"))
        explicit_failure = (
            lowered.get("success") is False
            or lowered.get("ok") is False
            or bool(lowered.get("error"))
            or status in {"error", "failed", "failure", "invalid", "denied"}
            or isinstance(code, int) and code >= 400
        )
        explicit_success = (
            lowered.get("success") is True
            or lowered.get("ok") is True
            or status in {"ok", "success", "succeeded", "complete", "completed", "ready"}
            or isinstance(code, int) and 200 <= code < 300
        )
        return {
            "kind": "error_object" if explicit_failure else "success_object" if explicit_success else "result_object",
            "fields": fields,
            "success_state": "failure" if explicit_failure else "success" if explicit_success else "unknown",
        }
    if isinstance(value, (ast.Tuple, ast.List)):
        return {"kind": "result_sequence", "success_state": "unknown"}
    return {"kind": "value", "success_state": "unknown"}


class PythonSignalParser(ast.NodeVisitor):
    """Emit observations from Python AST without assigning canonical risk checks."""

    def __init__(self, path: Path, artifact: str, source: str):
        self.path = path
        self.artifact = artifact
        self.source = source
        self.lines = source.splitlines()
        self.tree: Optional[ast.AST] = None
        self.signals: List[Dict[str, Any]] = []
        self.parents: Dict[ast.AST, ast.AST] = {}
        self.paths: Dict[ast.AST, str] = {}
        self.symbol_stack: List[str] = []
        self.block_stack: List[str] = []
        self._parser = {"name": "python_ast", "version": f"stdlib-{sys.version_info.major}.{sys.version_info.minor}"}

    def parse(self) -> ParserOutput:
        try:
            self.tree = ast.parse(self.source, filename=str(self.path))
        except SyntaxError as exc:
            line = int(exc.lineno or 1)
            column = int(exc.offset or 1)
            error = {"type": "SyntaxError", "message": exc.msg, "line": line, "column": column}
            signal = build_signal(
                artifact=self.artifact,
                language="python",
                kind="parser_error",
                region={"start_line": line, "start_column": column, "end_line": line, "end_column": column},
                symbol={"id": "<module>", "name": "<module>", "kind": "module"},
                structural_path="parser",
                normalized_statement=f"SyntaxError:{exc.msg}",
                evidence_text=(exc.text or "").strip(),
                parser=self._parser,
                confidence="exact",
                error_identity={"type": "SyntaxError"},
                attributes={"message": exc.msg},
            )
            return ParserOutput(
                signals=[signal],
                health=ParserHealth(
                    parser="python_ast",
                    parser_version=self._parser["version"],
                    status="failed",
                    structural=False,
                    capabilities=[],
                    limitations=["source did not parse; no structural absence claims are valid"],
                    error=error,
                ),
            )

        self._index_paths(self.tree, "Module")
        self.visit(self.tree)
        return ParserOutput(
            signals=self.signals,
            health=ParserHealth(
                parser="python_ast",
                parser_version=self._parser["version"],
                status="analyzed",
                structural=True,
                capabilities=[
                    "handlers", "raises", "returns", "logs", "retries", "side_effects",
                    "async_ownership", "cleanup", "fallbacks",
                ],
            ),
        )

    def _index_paths(self, node: ast.AST, path: str) -> None:
        self.paths[node] = path
        for field_name, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                self.parents[value] = node
                self._index_paths(value, f"{path}.{field_name}")
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        self.parents[item] = node
                        self._index_paths(item, f"{path}.{field_name}[{index}]")

    def _symbol(self) -> Dict[str, str]:
        name = ".".join(self.symbol_stack) if self.symbol_stack else "<module>"
        kind = "function" if self.symbol_stack else "module"
        return {"id": f"python:{self.artifact}:{name}", "name": name, "kind": kind}

    def _region(self, node: ast.AST) -> Dict[str, int]:
        start_line = int(getattr(node, "lineno", 1) or 1)
        start_column = int(getattr(node, "col_offset", 0) or 0) + 1
        end_line = int(getattr(node, "end_lineno", start_line) or start_line)
        end_column = int(getattr(node, "end_col_offset", start_column) or start_column) + 1
        return {
            "start_line": start_line,
            "start_column": start_column,
            "end_line": end_line,
            "end_column": end_column,
        }

    def _evidence(self, node: ast.AST) -> str:
        segment = ast.get_source_segment(self.source, node)
        if segment:
            return segment
        line = int(getattr(node, "lineno", 1) or 1)
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ""

    @staticmethod
    def _normalized(node: ast.AST) -> str:
        return ast.dump(node, annotate_fields=True, include_attributes=False)

    def _emit(
        self,
        node: ast.AST,
        kind: str,
        *,
        error_identity: Optional[Dict[str, Any]] = None,
        outcome: Optional[Dict[str, Any]] = None,
        side_effects: Optional[List[str]] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.signals.append(build_signal(
            artifact=self.artifact,
            language="python",
            kind=kind,
            region=self._region(node),
            symbol=self._symbol(),
            structural_path=self.paths.get(node, node.__class__.__name__),
            normalized_statement=self._normalized(node),
            evidence_text=self._evidence(node),
            parser=self._parser,
            confidence="structural",
            enclosing_blocks=self.block_stack,
            error_identity=error_identity,
            outcome=outcome,
            side_effects=side_effects,
            attributes=attributes,
        ))

    def _visit_block(self, label: str, nodes: Iterable[ast.AST]) -> None:
        self.block_stack.append(label)
        for item in nodes:
            self.visit(item)
        self.block_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.symbol_stack.append(node.name)
        self._visit_block("class", node.body)
        self.symbol_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.symbol_stack.append(node.name)
        self._visit_block("function", node.body)
        self.symbol_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.symbol_stack.append(node.name)
        self._visit_block("async_function", node.body)
        self.symbol_stack.pop()

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_block("try", node.body)
        for handler in node.handlers:
            self.visit(handler)
        if node.orelse:
            self._visit_block("try_else", node.orelse)
        if node.finalbody:
            self._emit(node, "cleanup", attributes={"construct": "finally"})
            self._visit_block("finally", node.finalbody)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        caught = _call_name(node.type) if node.type is not None else "BaseException"
        self._emit(
            node,
            "handler",
            error_identity={"caught_type": caught, "binding": node.name or ""},
            outcome={"kind": "handler", "success_state": "unknown"},
        )
        self._visit_block("except", node.body)

    def visit_Raise(self, node: ast.Raise) -> None:
        error_type = _call_name(node.exc) or ("rethrow" if node.exc is None else node.exc.__class__.__name__)
        self._emit(
            node,
            "raise",
            error_identity={"type": error_type, "preserves_cause": node.cause is not None, "bare_rethrow": node.exc is None},
            outcome={"kind": "abort", "success_state": "failure"},
        )
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        self._emit(node, "return", outcome=_outcome_from_return(node.value))
        self.generic_visit(node)

    def visit_Await(self, node: ast.Await) -> None:
        operation = _call_name(node.value)
        self._emit(node, "async_join", outcome={"kind": "await", "operation": operation, "success_state": "unknown"})
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = _call_name(node.func)
        leaf = callee.rsplit(".", 1)[-1].lower()
        owner = callee.rsplit(".", 2)[-2].lower() if "." in callee else ""
        if leaf in LOG_LEVELS or owner in {"logger", "logging", "log"} and leaf in LOG_LEVELS:
            self._emit(
                node,
                "log",
                outcome={"kind": "evidence", "level": leaf, "success_state": "unknown"},
                attributes={"callee": callee},
            )
        elif any(token in leaf for token in RETRY_NAMES):
            self._emit(node, "retry", outcome={"kind": "retry", "operation": callee, "success_state": "unknown"})
        elif leaf in SPAWN_NAMES:
            self._emit(node, "async_spawn", outcome={"kind": "spawn", "operation": callee, "success_state": "unknown"})
        elif leaf in JOIN_NAMES:
            self._emit(node, "async_join", outcome={"kind": "join", "operation": callee, "success_state": "unknown"})
        elif leaf in SIDE_EFFECT_NAMES or any(leaf.startswith(f"{name}_") for name in SIDE_EFFECT_NAMES):
            self._emit(
                node,
                "side_effect",
                side_effects=[callee],
                outcome={"kind": "side_effect", "operation": callee, "success_state": "unknown"},
            )
        if any(token in leaf for token in {"fallback", "default", "degraded", "best_effort"}):
            self._emit(node, "fallback", outcome={"kind": "fallback", "operation": callee, "success_state": "unknown"})
        self.generic_visit(node)
