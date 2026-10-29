"""Conservative symbol and call index for ErrorSignal graph construction."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aira.parsers.base import digest, normalize_evidence

try:
    import tree_sitter_javascript
    import tree_sitter_typescript
    from tree_sitter import Language, Parser
except ImportError:  # pragma: no cover - package dependencies should provide these
    Language = None
    Parser = None
    tree_sitter_javascript = None
    tree_sitter_typescript = None


def _region_from_ast(node: ast.AST) -> Dict[str, int]:
    start_line = int(getattr(node, "lineno", 1) or 1)
    start_column = int(getattr(node, "col_offset", 0) or 0) + 1
    end_line = int(getattr(node, "end_lineno", start_line) or start_line)
    end_column = int(getattr(node, "end_col_offset", start_column) or start_column) + 1
    return {"start_line": start_line, "start_column": start_column, "end_line": end_line, "end_column": end_column}


def _ast_name(node: Optional[ast.AST]) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_name(node.value)
        return ".".join(part for part in (prefix, node.attr) if part)
    return ""


class _PythonIndex(ast.NodeVisitor):
    def __init__(self, artifact: str, source: str):
        self.artifact = artifact
        self.source = source
        self.paths: Dict[ast.AST, str] = {}
        self.stack: List[Tuple[str, str]] = []
        self.symbols: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []

    def build(self, tree: ast.AST) -> None:
        self._index_paths(tree, "Module")
        line_count = max(1, len(self.source.splitlines()))
        self.symbols.append({
            "id": f"python:{self.artifact}:<module>",
            "type": "symbol",
            "artifact": self.artifact,
            "language": "python",
            "name": "<module>",
            "kind": "module",
            "region": {"start_line": 1, "start_column": 1, "end_line": line_count, "end_column": 1},
            "confidence": "structural",
        })
        self.visit(tree)

    def _index_paths(self, node: ast.AST, path: str) -> None:
        self.paths[node] = path
        for field, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                self._index_paths(value, f"{path}.{field}")
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        self._index_paths(item, f"{path}.{field}[{index}]")

    def _qualified_name(self) -> str:
        return ".".join(name for name, _ in self.stack) if self.stack else "<module>"

    def _current_symbol(self) -> str:
        return f"python:{self.artifact}:{self._qualified_name()}"

    def _visit_definition(self, node: ast.AST, name: str, kind: str) -> None:
        self.stack.append((name, kind))
        qualified = self._qualified_name()
        self.symbols.append({
            "id": f"python:{self.artifact}:{qualified}",
            "type": "symbol",
            "artifact": self.artifact,
            "language": "python",
            "name": qualified,
            "kind": kind,
            "region": _region_from_ast(node),
            "confidence": "structural",
        })
        for statement in getattr(node, "body", []):
            self.visit(statement)
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_definition(node, node.name, "class")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_definition(node, node.name, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_definition(node, node.name, "async_function")

    def visit_Call(self, node: ast.Call) -> None:
        callee = _ast_name(node.func)
        path = self.paths.get(node, "Call")
        statement = ast.dump(node, annotate_fields=True, include_attributes=False)
        call_id = f"call-{digest('|'.join((self.artifact, self._current_symbol(), path, callee, statement)))[:24]}"
        evidence = ast.get_source_segment(self.source, node) or callee
        self.calls.append({
            "call_id": call_id,
            "artifact": self.artifact,
            "language": "python",
            "caller_symbol": self._current_symbol(),
            "callee": callee,
            "region": _region_from_ast(node),
            "structural_path": path,
            "confidence": "structural",
            "evidence": {"text": evidence, "hash": digest(normalize_evidence(statement))},
        })
        self.generic_visit(node)


class _TreeSitterIndex:
    FUNCTION_TYPES = {
        "function_declaration", "function_expression", "arrow_function", "generator_function_declaration",
        "generator_function", "method_definition",
    }

    def __init__(self, artifact: str, language: str, source: str, suffix: str):
        self.artifact = artifact
        self.language = language
        self.source = source
        self.source_bytes = source.encode("utf-8")
        self.suffix = suffix
        self.symbols: List[Dict[str, Any]] = []
        self.calls: List[Dict[str, Any]] = []

    @staticmethod
    def _region(node: Any) -> Dict[str, int]:
        return {
            "start_line": int(node.start_point.row) + 1,
            "start_column": int(node.start_point.column) + 1,
            "end_line": int(node.end_point.row) + 1,
            "end_column": max(int(node.end_point.column) + 1, int(node.start_point.column) + 2),
        }

    def _text(self, node: Any) -> str:
        return self.source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def build(self) -> bool:
        if Parser is None or Language is None or tree_sitter_javascript is None or tree_sitter_typescript is None:
            return False
        if self.suffix == ".tsx":
            capsule = tree_sitter_typescript.language_tsx()
        elif self.language == "typescript":
            capsule = tree_sitter_typescript.language_typescript()
        else:
            capsule = tree_sitter_javascript.language()
        tree = Parser(Language(capsule)).parse(self.source_bytes)
        line_count = max(1, len(self.source.splitlines()))
        self.symbols.append({
            "id": f"{self.language}:{self.artifact}:<module>",
            "type": "symbol",
            "artifact": self.artifact,
            "language": self.language,
            "name": "<module>",
            "kind": "module",
            "region": {"start_line": 1, "start_column": 1, "end_line": line_count, "end_column": 1},
            "confidence": "structural",
        })
        self._walk(tree.root_node, "program", ["<module>"])
        return True

    def _walk(self, node: Any, path: str, symbols: List[str]) -> None:
        next_symbols = list(symbols)
        if node.type in self.FUNCTION_TYPES:
            name_node = node.child_by_field_name("name")
            name = self._text(name_node) if name_node is not None else f"<anonymous@{path}>"
            next_symbols = symbols + [name] if symbols != ["<module>"] else [name]
            qualified = ".".join(next_symbols)
            self.symbols.append({
                "id": f"{self.language}:{self.artifact}:{qualified}",
                "type": "symbol",
                "artifact": self.artifact,
                "language": self.language,
                "name": qualified,
                "kind": "function",
                "region": self._region(node),
                "confidence": "structural",
            })
        if node.type in {"call_expression", "new_expression"}:
            function = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            callee = self._text(function) if function is not None else ""
            caller = f"{self.language}:{self.artifact}:{'.'.join(next_symbols)}"
            statement = normalize_evidence(self._text(node))
            call_id = f"call-{digest('|'.join((self.artifact, caller, path, callee, statement)))[:24]}"
            self.calls.append({
                "call_id": call_id,
                "artifact": self.artifact,
                "language": self.language,
                "caller_symbol": caller,
                "callee": callee,
                "region": self._region(node),
                "structural_path": path,
                "confidence": "structural",
                "evidence": {"text": self._text(node), "hash": digest(statement)},
            })
        for index, child in enumerate(node.named_children):
            self._walk(child, f"{path}.{child.type}[{index}]", next_symbols)


def _resolve_calls(symbols: List[Dict[str, Any]], calls: List[Dict[str, Any]]) -> None:
    by_leaf: Dict[str, List[Dict[str, Any]]] = {}
    for symbol in symbols:
        if symbol["kind"] == "module":
            continue
        by_leaf.setdefault(symbol["name"].rsplit(".", 1)[-1], []).append(symbol)
    for call in calls:
        leaf = call["callee"].rsplit(".", 1)[-1]
        candidates = by_leaf.get(leaf, [])
        same_artifact = [item for item in candidates if item["artifact"] == call["artifact"]]
        selected = same_artifact if same_artifact else candidates
        if len(selected) == 1:
            call["resolution"] = {
                "status": "resolved",
                "target_symbol": selected[0]["id"],
                "confidence": "exact" if same_artifact else "structural",
                "reason": "unique artifact-local symbol" if same_artifact else "unique repository symbol",
            }
        else:
            call["resolution"] = {
                "status": "unresolved",
                "reason": "ambiguous local symbols" if selected else "external, builtin, or dynamic call",
                "candidate_symbols": sorted(item["id"] for item in selected),
            }


def build_symbol_index(inventory: Dict[str, Any]) -> Dict[str, Any]:
    target = Path(inventory["target"])
    root = target.parent if target.is_file() else target
    symbols: List[Dict[str, Any]] = []
    calls: List[Dict[str, Any]] = []
    diagnostics: List[Dict[str, Any]] = []
    for artifact in inventory.get("artifacts", []):
        path = target if target.is_file() else root / artifact["path"]
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            if artifact["language"] == "python":
                tree = ast.parse(source, filename=str(path))
                index = _PythonIndex(artifact["path"], source)
                index.build(tree)
            else:
                index = _TreeSitterIndex(artifact["path"], artifact["language"], source, path.suffix.lower())
                if not index.build():
                    diagnostics.append({"artifact": artifact["path"], "reason": "Tree-sitter unavailable for symbol indexing"})
                    continue
            symbols.extend(index.symbols)
            calls.extend(index.calls)
        except (OSError, SyntaxError, ValueError) as exc:
            diagnostics.append({"artifact": artifact["path"], "reason": str(exc), "type": exc.__class__.__name__})
    unique_symbols = {symbol["id"]: symbol for symbol in symbols}
    symbols = sorted(unique_symbols.values(), key=lambda item: item["id"])
    calls.sort(key=lambda item: (item["artifact"], item["region"]["start_line"], item["region"]["start_column"], item["call_id"]))
    _resolve_calls(symbols, calls)
    return {"symbols": symbols, "calls": calls, "diagnostics": sorted(diagnostics, key=lambda item: (item["artifact"], item.get("reason", "")))}
