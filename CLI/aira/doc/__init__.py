"""
AIRA Pattern Documentation Module

Provides machine-readable documentation for fail-soft patterns (C01-C15).
This helps prevent these errors by understanding the patterns before they occur.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PatternDefinition:
    """Machine-readable definition of a fail-soft pattern."""
    check_id: str
    name: str
    description: str
    category: str  # "success", "audit", "exception", "fallback", "bypass", "return", "background", "environment", "determinism", "lineage", "confidence", "test", "idempotency"
    severity: str  # HIGH, MEDIUM, LOW
    root_causes: List[str]
    prevention_strategies: List[str]
    bad_examples: List[str]
    good_examples: List[str]
    related_checks: List[str]


# Comprehensive pattern definitions
PATTERNS = {
    "C01": PatternDefinition(
        check_id="C01",
        name="SUCCESS INTEGRITY VIOLATIONS",
        description="System returns success code despite operation failure",
        category="success",
        severity="HIGH",
        root_causes=[
            "Developer unfamiliar with error handling best practices",
            "Over-eager optimization to avoid propagating errors",
            "Misunderstanding of what constitutes 'success'",
        ],
        prevention_strategies=[
            "Always propagate exceptions or return explicit error indicators",
            "Use Result/Either types or similar patterns for explicit success/failure",
            "Test error paths in addition to happy paths",
            "Log and monitor failed operations",
        ],
        bad_examples=[
            '''def save_record(db, record):
    try:
        db.insert(record)
        return True  # FAIL-SOFT: Returns success even on exception
    except Exception:
        return True  # FAIL-SOFT: Explicit success return after failure''',
        ],
        good_examples=[
            '''def save_record(db, record):
    try:
        db.insert(record)
        return True  # Success: operation completed
    except Exception as e:
        logger.error(f"Save failed: {e}")
        return False  # Explicit failure indication''',
            '''def save_record(db, record):
    try:
        db.insert(record)
        return Result(success=True)
    except Exception as e:
        logger.error(f"Save failed: {e}")
        return Result(success=False, error=str(e))''',
        ],
        related_checks=["C03", "C06"],
    ),
    "C02": PatternDefinition(
        check_id="C02",
        name="AUDIT & EVIDENCE INTEGRITY GAPS",
        description="System fails to record evidence of decision or operation outcome",
        category="audit",
        severity="HIGH",
        root_causes=[
            "Assuming audit writes cannot fail",
            "Prioritizing functionality over observability",
            "Missing error handling around audit/logging calls",
        ],
        prevention_strategies=[
            "Treat audit writes as critical operations with error handling",
            "Implement audit write retry logic with backoff",
            "Monitor and alert on audit system failures",
            "Use structured logging that persists even during failures",
        ],
        bad_examples=[
            '''def audit_write(event):
    try:
        audit_db.insert(event)
    except Exception:
        pass  # FAIL-SOFT: Evidence silently lost''',
        ],
        good_examples=[
            '''def audit_write(event):
    try:
        audit_db.insert(event)
    except Exception as e:
        logger.error(f"Audit write failed: {e}")
        # Write to file backup or raise
        backup_audit_log(event)
        raise  # Or: return False''',
        ],
        related_checks=["C03", "C10"],
    ),
    "C03": PatternDefinition(
        check_id="C03",
        name="BROAD EXCEPTION SUPPRESSION",
        description="Catch-all exceptions swallowed without re-raising or proper handling",
        category="exception",
        severity="HIGH",
        root_causes=[
            "Copy-pasted exception handling code",
            "Fear of runtime errors from exception handling",
            "Misunderstanding that 'it works' is sufficient",
        ],
        prevention_strategies=[
            "Catch specific exceptions, not broad Exception",
            "Always log exceptions with context before handling",
            "Re-raise unexpected exceptions or convert to meaningful errors",
            "Use structured exception handling with explicit paths",
        ],
        bad_examples=[
            '''def fetch_data(url):
    try:
        response = http.get(url)
        return response.json()
    except:
        pass  # FAIL-SOFT: Any error returns None silently''',
        ],
        good_examples=[
            '''def fetch_data(url):
    try:
        response = http.get(url, timeout=30)
        return response.json()
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON response: {e}")
        raise DataParseError(f"Invalid response from {url}") from e
    except http.TimeoutError as e:
        logger.error(f"Request timeout: {e}")
        raise NetworkError(f"Request to {url} timed out") from e
    except Exception as e:
        logger.error(f"Unexpected error fetching {url}: {e}")
        raise  # Re-raise unexpected errors''',
        ],
        related_checks=["C01", "C02"],
    ),
}


def get_all_patterns() -> List[PatternDefinition]:
    """Get all pattern definitions."""
    return list(PATTERNS.values())


def get_pattern(check_id: str) -> Optional[PatternDefinition]:
    """Get a specific pattern by check ID."""
    return PATTERNS.get(check_id.upper())


def to_machine_readable() -> Dict[str, Any]:
    """
    Generate comprehensive machine-readable documentation.
    This is the primary output for automated tools and learning systems.
    """
    return {
        "version": "1.0.0",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "schema": "aira-patterns-v1",
        "patterns": [asdict(p) for p in PATTERNS.values()],
        "prevention_guidelines": {
            "general": [
                "Make error handling explicit and purposeful",
                "Log failures with context before handling",
                "Fail fast or fail safely - never silent failure",
                "Distinguish between expected and unexpected errors",
                "Write tests for error paths, not just happy paths",
            ],
            "design_principles": [
                "Use explicit result types (Result, Option, etc.)",
                "Separate concerns: validation, processing, and error handling",
                "Monitor and alert on systemic failures",
                "Document why specific error handlers exist",
                "Review exception handling in code reviews",
            ],
        },
    }


def to_markdown() -> str:
    """Generate human-readable markdown documentation."""
    lines = [
        "# AIRA Fail-Soft Pattern Documentation",
        "",
        "This document explains the 15 fail-soft patterns detected by AIRA Scanner.",
        "Understanding these patterns helps prevent them in code design.",
        "",
        "---",
        "",
    ]
    
    for check_id in sorted(PATTERNS.keys()):
        p = PATTERNS[check_id]
        lines.extend([
            f"## {check_id} — {p.name}",
            "",
            f"**Description:** {p.description}",
            "",
            f"**Severity:** {p.severity}",
            "",
            "### Root Causes",
            "",
        ])
        for cause in p.root_causes:
            lines.append(f"- {cause}")
        lines.extend([
            "",
            "### Prevention Strategies",
            "",
        ])
        for strategy in p.prevention_strategies:
            lines.append(f"- {strategy}")
        lines.extend([
            "",
            "### Bad Example (What to Avoid)",
            "",
            "```python",
            *p.bad_examples,
            "```",
            "",
            "### Good Example (Correct Implementation)",
            "",
            "```python",
            *p.good_examples,
            "```",
            "",
        ])
    
    lines.extend([
        "# Prevention Guidelines",
        "",
        "## General Principles",
        "",
    ])
    for guideline in to_machine_readable()["prevention_guidelines"]["general"]:
        lines.append(f"- {guideline}")
    
    lines.extend([
        "",
        "## Design Principles",
        "",
    ])
    for principle in to_machine_readable()["prevention_guidelines"]["design_principles"]:
        lines.append(f"- {principle}")
    
    lines.append("")
    return "\n".join(lines)


def save_documentation(
    output_dir: str = ".",
    include_markdown: bool = True,
    include_json: bool = True,
) -> Dict[str, str]:
    """
    Save documentation to files.
    
    Returns mapping of file paths to their contents.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    
    if include_json:
        json_path = output_dir / "patterns.json"
        json_content = json.dumps(to_machine_readable(), indent=2)
        json_path.write_text(json_content)
        results["json"] = str(json_path)
    
    if include_markdown:
        md_path = output_dir / "PATTERNS.md"
        md_content = to_markdown()
        md_path.write_text(md_content)
        results["markdown"] = str(md_path)
    
    return results