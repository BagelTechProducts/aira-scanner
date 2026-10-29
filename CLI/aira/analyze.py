"""
AIRA Analyzer — Unified Engine for fail-soft pattern detection.

This module provides a single, authoritative Engine class that consolidates
the scanning logic for static, LLM, and hybrid modes. All other entry points
(scanner.py, cli.py) delegate to this engine.

Change Policy:
- All scans MUST go through Engine.execute()
- Exit codes derived from EngineResult
- Findings normalized via normalize_finding() before return
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# ============================================================================
# Configuration & Constants
# ============================================================================

class ScanMode(str, Enum):
    STATIC = "static"
    LLM = "llm"
    HYBRID = "hybrid"


class FailOn(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class EngineConfig:
    """Configuration for the AIRA Engine."""
    target: str
    mode: ScanMode = ScanMode.STATIC
    exclude_dirs: Optional[List[str]] = None
    fail_on: FailOn = FailOn.NONE
    provider: Optional[str] = None
    model: Optional[str] = None
    base_url: Optional[str] = None
    timeout_seconds: int = 45
    max_context_chars: int = 120_000
    output_format: str = "json"
    out_file: Optional[str] = None

    @classmethod
    def from_env(cls, target: str, mode: str = "static") -> "EngineConfig":
        """Build config from CLI args and environment."""
        mode = ScanMode(mode.lower() if isinstance(mode, str) else mode)
        provider = os.getenv("AIRA_PROVIDER", "auto")
        return cls(
            target=target,
            mode=mode,
            provider=provider,
            model=os.getenv("NVIDIA_MODEL") or os.getenv("AIRA_NVIDIA_MODEL"),
            base_url=os.getenv("NVIDIA_BASE_URL") or "https://integrate.api.nvidia.com/v1",
        )


# ============================================================================
# Result Types
# ============================================================================

@dataclass
class EngineResult:
    """Unified result from an AIRA scan."""
    scan_id: str
    target: str
    scanned_at: str
    files_discovered: int = 0
    files_scanned: int = 0
    files_partial: int = 0
    files_failed: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    check_results: Dict[str, str] = field(default_factory=dict)
    exit_code: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def findings_total(self) -> int:
        return len(self.findings)

    @property
    def high_findings_count(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "HIGH")

    @property
    def medium_findings_count(self) -> int:
        return sum(1 for f in self.findings if f.get("severity") == "MEDIUM")


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a finding to canonical structure (aira-finding-v1)."""
    return {
        "check_id": finding.get("check_id", "C00"),
        "check_name": finding.get("check_name", "UNSPECIFIED"),
        "severity": finding.get("severity", "LOW"),
        "file": finding.get("file", ""),
        "line": max(0, int(finding.get("line", 0))),
        "description": str(finding.get("description", ""))[:500],
        "snippet": str(finding.get("snippet", "") or "")[:200],
        "fingerprint_version": "aira-finding-v1",
        "fingerprint": hashlib.sha256(
            json.dumps({
                "check_id": finding.get("check_id"),
                "file": finding.get("file"),
                "line": finding.get("line"),
                "description": finding.get("description"),
            }, sort_keys=True).encode()
        ).hexdigest()[:16],
    }


# ============================================================================
# The Engine
# ============================================================================

class Engine:
    """
    Unified scan engine for AIRA.

    Single entry point for all scanning modes:
    - Static: AST/tree-sitter analysis
    - LLM: provider-based reasoning
    - Hybrid: static + LLM with deduplication

    Example:
        config = EngineConfig.from_env("/path/to/project")
        result = Engine(config).execute()
        if result.exit_code != 0:
            print(f"Found {result.findings_total} issues")
    """

    def __init__(self, config: EngineConfig):
        self.config = config
        self.target = Path(config.target).resolve()
        self._findings: List[Dict[str, Any]] = []

    def execute(self) -> EngineResult:
        """
        Execute the scan according to config.

        Returns EngineResult with all findings and exit code based on fail_on threshold.
        """
        from aira.scanner import AIRAScanner

        # Build scanner and execute
        exclude = self.config.exclude_dirs or []
        scanner = AIRAScanner(str(self.config.target), exclude_dirs=exclude)
        result = scanner.scan(mode=self.config.mode.value, max_context_chars=self.config.max_context_chars)

        # Normalize findings
        normalized = [normalize_finding(f) for f in result.findings]

        # Compute check results
        check_results: Dict[str, str] = {}
        for check_id in ["C01", "C02", "C03", "C04", "C05", "C06",
                         "C07", "C08", "C09", "C10", "C11", "C12",
                         "C13", "C14", "C15"]:
            if any(f["check_id"] == check_id for f in normalized):
                check_results[check_id.lower()] = "FAIL"
            else:
                check_results[check_id.lower()] = "PASS"

        # C07 and C12 are always UNKNOWN (human review)
        check_results["logic_consistency"] = "UNKNOWN"
        check_results["lineage"] = "UNKNOWN"

        # Compute exit code
        exit_code = 0
        if self.config.fail_on != FailOn.NONE:
            severity_order = {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "PASS": 1}
            threshold = severity_order.get(self.config.fail_on.value.upper(), 0)

            for finding in normalized:
                if severity_order.get(finding.get("severity", "LOW"), 0) >= threshold:
                    exit_code = 1
                    break

        return EngineResult(
            scan_id="scan-" + hashlib.md5(str(self.config.target).encode()).hexdigest()[:8],
            target=str(self.config.target),
            scanned_at=datetime.now(timezone.utc).isoformat(),
            files_scanned=result.files_scanned,
            findings=normalized,
            check_results=check_results,
            exit_code=exit_code,
            metadata={
                "mode": self.config.mode.value,
                "config": {
                    "target": str(self.config.target),
                    "mode": self.config.mode.value,
                    "fail_on": self.config.fail_on.value,
                },
            },
        )


# ============================================================================
# Convenience Functions
# ============================================================================

def analyze_path(
    path: str,
    mode: str = "static",
    fail_on: str = "none",
    **kwargs,
) -> EngineResult:
    """
    One-shot analysis function.

    Usage:
        result = analyze_path("/my/project", mode="hybrid", fail_on="high")
    """
    config = EngineConfig(
        target=path,
        mode=ScanMode(mode),
        fail_on=FailOn(fail_on),
        **kwargs,
    )
    return Engine(config).execute()