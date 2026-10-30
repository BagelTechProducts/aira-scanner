"""
AIRA Fix Suggestions Module

Provides fix recommendations for detected fail-soft patterns.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Fix suggestion templates for each check
FIX_TEMPLATES = {
    "C01": {
        "title": "Success Integrity Violation",
        "problem": "Exception handler returns True/success despite failure",
        "suggestion": "Log the error and re-raise, or return False/error indicator",
        "code_example": '''# Before (fail-soft):
    try:
        db.insert(record)
        return True
    except Exception as e:
        return True

# After (explicit failure):
    try:
        db.insert(record)
        return True
    except Exception as e:
        logger.error(f"Insert failed: {e}")
        raise  # Re-raise to fail explicitly
        # Or: return False
''',
    },
    "C02": {
        "title": "Audit Evidence Gap",
        "problem": "Audit/write operations fail silently without evidence",
        "suggestion": "Ensure audit writes are recorded or failures are logged",
        "code_example": '''# Before (evidence lost):
    try:
        audit_write(event)
    except Exception:
        pass  # Evidence lost!

# After (evidence preserved):
    try:
        audit_write(event)
    except Exception as e:
        logger.error(f"Audit write failed: {e}")
        # Consider: raise or record failure in audit trail
''',
    },
    "C03": {
        "title": "Broad Exception Suppression",
        "problem": "Catch-all exception handler swallows failures",
        "suggestion": "Catch specific exceptions, log details, and re-raise or handle appropriately",
        "code_example": '''# Before (silent failure):
    try:
        important_operation()
    except:
        pass

# After (explicit handling):
    try:
        important_operation()
    except SpecificError as e:
        logger.error(f"Operation failed: {e}")
        raise  # Fail explicitly
    except AnotherError:
        # Handle specific case
        return fallback
''',
    },
    "C04": {
        "title": "Fallback/Degraded Execution",
        "problem": "Safety degrades based on debug/staging variables",
        "suggestion": "Log when degraded mode is active, ensure it's intentional",
        "code_example": '''# Before (silent degradation):
    if os.environ.get("DEBUG") or os.environ.get("TESTING"):
        skip_validation = True

# After (explicit and logged):
    is_debug = os.environ.get("DEBUG") or os.environ.get("TESTING")
    if is_debug:
        logger.warning("Running in degraded mode - validation skipped")
        skip_validation = True
''',
    },
    "C05": {
        "title": "Bypass Path Detected",
        "problem": "Force/skip bypass paths weaken guarantees",
        "suggestion": "Document bypass reasons and add audit logging",
        "code_example": '''# Before (untracked bypass):
    if force:
        return True

# After (auditable bypass):
    if force:
        logger.warning(f"Bypass activated by force flag")
        # Consider adding audit record
        return True
''',
    },
    "C10": {
        "title": "Startup Integrity Weakness",
        "problem": "Initialization catches exceptions without halting",
        "suggestion": "Ensure initialization failures fail fast or are explicitly handled",
        "code_example": '''# Before (silent failure):
    def __init__(self, config):
        try:
            self.validate(config)
        except ConfigError:
            pass  # System starts in broken state

# After (explicit):
    def __init__(self, config):
        try:
            self.validate(config)
        except ConfigError as e:
            logger.critical(f"Startup validation failed: {e}")
            raise RuntimeError(f"Invalid configuration: {e}")
''',
    },
    "C15": {
        "title": "Retry Without Idempotency",
        "problem": "Retry near write operations without idempotency safeguard",
        "suggestion": "Add idempotency keys or ensure operations are idempotent",
        "code_example": '''# Before (unsafe retry):
    for attempt in range(3):
        try:
            write_data(payload)
            break
        except:
            continue

# After (idempotent):
    idempotency_key = hashlib.md5(payload).hexdigest()
    for attempt in range(3):
        try:
            write_data(payload, idempotency_key=idempotency_key)
            break
        except:
            continue
''',
    },
}


def get_fix_suggestion(check_id: str) -> Optional[Dict[str, str]]:
    """Get fix suggestion for a given check ID."""
    return FIX_TEMPLATES.get(check_id.upper())


def generate_fix_report(findings: List[Dict[str, Any]]) -> str:
    """Generate a human-readable fix report for all findings."""
    lines = ["\n=== AIRA Fix Suggestions ===", ""]

    for finding in findings:
        check_id = finding.get("check_id")
        suggestion = get_fix_suggestion(check_id)

        if suggestion:
            lines.append(f"[{finding['severity']}] {finding['file']}:{finding['line']}")
            lines.append(f"  Problem: {suggestion['problem']}")
            lines.append(f"  Fix: {suggestion['suggestion']}")
            lines.append("  Suggestion:")
            for line in suggestion['code_example'].strip().split('\n'):
                lines.append(f"    {line}")
            lines.append("")
        else:
            lines.append(f"[{finding['severity']}] {finding['file']}:{finding['line']}")
            lines.append(f"  Issue: {check_id} - See AIRA documentation for pattern definition")
            lines.append("")

    return '\n'.join(lines)
