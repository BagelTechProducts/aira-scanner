"""Deterministic, evidence-backed graph over AIRA ErrorSignal inventories."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional

from aira.parsers.base import digest
from aira.side_effects import side_effect_edges, side_effect_role
from aira.signals import inventory_errors
from aira.status_mapping import status_mapping
from aira.symbol_index import build_symbol_index

GRAPH_SCHEMA_VERSION = "aira-error-graph-v1"


def _evidence_record(item: Dict[str, Any]) -> Dict[str, Any]:
    if "signal_id" in item:
        return {
            "artifact": item["artifact"],
            "region": item["region"],
            "signal_id": item["signal_id"],
            "evidence_hash": (item.get("evidence") or {}).get("hash", ""),
        }
    return {
        "artifact": item["artifact"],
        "region": item["region"],
        "call_id": item["call_id"],
        "evidence_hash": (item.get("evidence") or {}).get("hash", ""),
    }


def _make_edge(
    kind: str,
    source: str,
    target: str,
    evidence_items: Iterable[Dict[str, Any]],
    *,
    confidence: str,
    resolved: bool = True,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    evidence = [_evidence_record(item) for item in evidence_items]
    identity = json.dumps(
        {"kind": kind, "source": source, "target": target, "evidence": evidence, "attributes": attributes or {}},
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "edge_id": f"edge-{digest(identity)[:24]}",
        "kind": kind,
        "source": source,
        "target": target,
        "resolved": resolved,
        "confidence": confidence,
        "evidence": evidence,
        "attributes": dict(attributes or {}),
    }


def _contains(outer: Dict[str, Any], inner: Dict[str, Any]) -> bool:
    if outer["artifact"] != inner["artifact"] or outer["symbol"]["id"] != inner["symbol"]["id"]:
        return False
    left = outer["region"]
    right = inner["region"]
    return (
        (left["start_line"], left["start_column"])
        <= (right["start_line"], right["start_column"])
        <= (left["end_line"], left["end_column"])
    )


def _handler_edge_kind(handler: Dict[str, Any], child: Dict[str, Any]) -> Optional[str]:
    kind = child["kind"]
    if kind in {"raise", "throw"}:
        identity = child.get("error_identity") or {}
        if identity.get("bare_rethrow"):
            return "rethrows"
        binding = str((handler.get("error_identity") or {}).get("binding", "")).strip("() ")
        thrown = str(identity.get("type", "")).strip()
        if binding and thrown == binding:
            return "rethrows"
        if identity.get("preserves_cause"):
            return "wraps"
        return "drops_cause"
    return {
        "return": "returns_status" if status_mapping(child) else "handles_as_return",
        "log": "logs",
        "retry": "retries",
        "fallback": "falls_back",
        "side_effect": {
            "rollback": "rolls_back",
            "commit": "commits_after",
            "write": "writes_in_handler",
        }[side_effect_role(child)],
        "async_spawn": "spawns",
        "async_join": "awaits",
        "cleanup": "cleans_up",
    }.get(kind)


def build_error_graph(inventory: Dict[str, Any]) -> Dict[str, Any]:
    """Build a deterministic graph; no edge is emitted without source evidence."""
    index = build_symbol_index(inventory)
    signals = list(inventory.get("signals", []))
    signal_by_id = {signal["signal_id"]: signal for signal in signals}
    symbol_nodes = {symbol["id"]: symbol for symbol in index["symbols"]}
    for signal in signals:
        symbol = signal["symbol"]
        symbol_nodes.setdefault(symbol["id"], {
            "id": symbol["id"],
            "type": "symbol",
            "artifact": signal["artifact"],
            "language": signal["language"],
            "name": symbol.get("name", "<module>"),
            "kind": symbol.get("kind", "module"),
            "region": signal["region"],
            "confidence": signal["confidence"],
        })

    nodes: Dict[str, Dict[str, Any]] = dict(symbol_nodes)
    for signal in signals:
        nodes[signal["signal_id"]] = {
            "id": signal["signal_id"],
            "type": "signal",
            "artifact": signal["artifact"],
            "language": signal["language"],
            "kind": signal["kind"],
            "region": signal["region"],
            "symbol_id": signal["symbol"]["id"],
            "confidence": signal["confidence"],
            "error_identity": signal.get("error_identity") or {},
            "outcome": signal.get("outcome") or {},
            "evidence_hash": (signal.get("evidence") or {}).get("hash", ""),
        }

    edges: List[Dict[str, Any]] = []
    for signal in signals:
        symbol_id = signal["symbol"]["id"]
        relation = "catches" if signal["kind"] == "handler" else "contains"
        edges.append(_make_edge(relation, symbol_id, signal["signal_id"], [signal], confidence=signal["confidence"]))

    by_symbol: Dict[str, List[Dict[str, Any]]] = {}
    for signal in signals:
        by_symbol.setdefault(signal["symbol"]["id"], []).append(signal)
    for symbol_signals in by_symbol.values():
        ordered = sorted(symbol_signals, key=lambda item: (item["region"]["start_line"], item["region"]["start_column"], item["signal_id"]))
        for left, right in zip(ordered, ordered[1:]):
            edges.append(_make_edge("sequence", left["signal_id"], right["signal_id"], [left, right], confidence="structural"))
        handlers = [item for item in ordered if item["kind"] == "handler"]
        for handler in handlers:
            for child in ordered:
                if child["signal_id"] == handler["signal_id"] or not _contains(handler, child):
                    continue
                edge_kind = _handler_edge_kind(handler, child)
                if edge_kind:
                    attributes = status_mapping(child) or {}
                    edges.append(_make_edge(edge_kind, handler["signal_id"], child["signal_id"], [handler, child], confidence="structural", attributes=attributes))
        edges.extend(side_effect_edges(ordered, _make_edge))

    for call in index["calls"]:
        resolution = call["resolution"]
        if resolution["status"] == "resolved":
            target = resolution["target_symbol"]
            edges.append(_make_edge(
                "calls",
                call["caller_symbol"],
                target,
                [call],
                confidence=resolution["confidence"],
                attributes={"callee": call["callee"], "call_id": call["call_id"]},
            ))
            for raised in by_symbol.get(target, []):
                if raised["kind"] in {"raise", "throw"}:
                    edges.append(_make_edge(
                        "may_raise",
                        call["caller_symbol"],
                        raised["signal_id"],
                        [call, raised],
                        confidence=resolution["confidence"],
                        attributes={"callee": call["callee"], "call_id": call["call_id"]},
                    ))
        else:
            unresolved_id = f"unresolved:{call['call_id']}"
            nodes[unresolved_id] = {
                "id": unresolved_id,
                "type": "unresolved_call",
                "artifact": call["artifact"],
                "language": call["language"],
                "kind": "call",
                "region": call["region"],
                "callee": call["callee"],
                "reason": resolution["reason"],
                "candidate_symbols": resolution.get("candidate_symbols", []),
                "confidence": call["confidence"],
            }
            edges.append(_make_edge(
                "calls",
                call["caller_symbol"],
                unresolved_id,
                [call],
                confidence=call["confidence"],
                resolved=False,
                attributes={"callee": call["callee"], "call_id": call["call_id"], "reason": resolution["reason"]},
            ))

    unique_edges = {edge["edge_id"]: edge for edge in edges}
    sorted_nodes = sorted(nodes.values(), key=lambda item: item["id"])
    sorted_edges = sorted(unique_edges.values(), key=lambda item: (item["kind"], item["source"], item["target"], item["edge_id"]))
    node_ids = {node["id"] for node in sorted_nodes}
    if any(edge["source"] not in node_ids or edge["target"] not in node_ids for edge in sorted_edges):
        raise ValueError("Error graph invariant failed: every edge endpoint must reference a graph node")
    if any(not edge["evidence"] for edge in sorted_edges):
        raise ValueError("Error graph invariant failed: every edge must include source evidence")
    edge_counts = Counter(edge["kind"] for edge in sorted_edges)
    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "inventory_schema_version": inventory.get("schema_version"),
        "target": inventory["target"],
        "summary": {
            "nodes_total": len(sorted_nodes),
            "signal_nodes": len(signal_by_id),
            "symbol_nodes": len(symbol_nodes),
            "unresolved_call_nodes": sum(1 for node in sorted_nodes if node["type"] == "unresolved_call"),
            "edges_total": len(sorted_edges),
            "edges_by_kind": dict(sorted(edge_counts.items())),
        },
        "parser_diagnostics": index["diagnostics"],
        "nodes": sorted_nodes,
        "edges": sorted_edges,
    }


def error_graph_for_target(target: str, *, exclude_patterns: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    return build_error_graph(inventory_errors(target, exclude_patterns=exclude_patterns))
