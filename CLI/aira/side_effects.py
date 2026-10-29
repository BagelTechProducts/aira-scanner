"""Side-effect ordering projections for the deterministic error-flow graph."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional

ROLLBACK_NAMES = {"rollback", "revert", "compensate", "abort_transaction"}
COMMIT_NAMES = {"commit", "flush", "publish"}


def side_effect_role(signal: Dict[str, Any]) -> str:
    operations = signal.get("side_effects") or []
    operation = str(operations[0] if operations else (signal.get("outcome") or {}).get("operation", ""))
    leaf = operation.rsplit(".", 1)[-1].lower()
    if leaf in ROLLBACK_NAMES:
        return "rollback"
    if leaf in COMMIT_NAMES:
        return "commit"
    return "write"


def _structural_container(signal: Dict[str, Any]) -> Optional[str]:
    path = str(signal.get("structural_path") or "")
    python_matches = list(re.finditer(r"\.(?:body|orelse|finalbody)\[\d+\]", path))
    if python_matches:
        match = python_matches[-1]
        return re.sub(r"\[\d+\]$", "", path[:match.end()])
    tree_matches = list(re.finditer(r"\.statement_block\[\d+\]", path))
    if tree_matches:
        return path[:tree_matches[-1].end()]
    return None


def side_effect_edges(
    signals: Iterable[Dict[str, Any]],
    make_edge: Callable[..., Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Connect ordered writes/rollback/commit observations to terminal outcomes."""
    ordered = sorted(
        signals,
        key=lambda item: (
            item["region"]["start_line"],
            item["region"]["start_column"],
            item["signal_id"],
        ),
    )
    effects = [item for item in ordered if item.get("kind") == "side_effect"]
    terminals = [
        item for item in ordered
        if item.get("kind") in {"raise", "throw"}
        or item.get("kind") == "return" and (item.get("outcome") or {}).get("success_state") == "failure"
    ]
    edges: List[Dict[str, Any]] = []
    for effect in effects:
        role = side_effect_role(effect)
        if role != "write":
            continue
        container = _structural_container(effect)
        if not container:
            continue
        effect_position = (effect["region"]["start_line"], effect["region"]["start_column"])
        for terminal in terminals:
            terminal_position = (terminal["region"]["start_line"], terminal["region"]["start_column"])
            if _structural_container(terminal) == container and effect_position < terminal_position:
                edges.append(make_edge(
                    "writes_before",
                    effect["signal_id"],
                    terminal["signal_id"],
                    [effect, terminal],
                    confidence="structural",
                    attributes={
                        "operation": (effect.get("outcome") or {}).get("operation", ""),
                        "ordering": "same_structural_block_source_order",
                    },
                ))
                break
    return edges
