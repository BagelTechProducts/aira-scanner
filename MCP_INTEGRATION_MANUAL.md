# NVIDIAReview Integration Manual

## Overview

This document explains the AIRA Scanner enhancements and how to leverage them across different AI modes for cross-model review.

---

## What We've Built

### 1. Fix Suggestions Module (`aira/fix/`)
Intelligent suggestions for fixing fail-soft patterns:
- C01: Success Integrity Violations
- C02: Audit & Evidence Integrity Gaps  
- C03: Broad Exception Suppression
- C04: Fallback & Degradation
- C05: Bypass & Override Paths
- C10: Startup Integrity Weaknesses

Each fix template includes:
- Problem description
- Root cause analysis
- Prevention strategies
- Bad/good code examples

### 2. Documentation Module (`aira/doc/`)
Machine-readable pattern documentation:
- JSON schema: `aira-patterns-v1`
- Markdown format for human consumption
- Root causes, prevention strategies, examples

### 3. MCP Server (`aira/mcp/`)
Hosted Model Context Protocol server:
- HTTP JSON-RPC interface
- STDIO protocol support
- REST-like resource endpoints
- Tool-based code review

### 4. Unified Engine (`aira/analyze.py`)
Single interface for static/hybrid/LLM scanning:
```python
from aira.analyze import Engine, EngineConfig, analyze_path

config = EngineConfig(mode="static", provider="nvidia")
result = analyze_path("/path/to/code", config=config)
```

---

## Fail-Soft Patterns Reference

### C01 - Success Integrity Violation
**Problem:** System returns success despite operation failure

```python
# BAD
try:
    db.insert(record)
except Exception:
    return True  # Silent success after failure!

# GOOD
try:
    db.insert(record)
    return True
except Exception as e:
    logger.error(f"Insert failed: {e}")
    return False  # Explicit failure
```

### C03 - Broad Exception Suppression
**Problem:** Catch-all exceptions swallowed silently

```python
# BAD
try:
    important_operation()
except:
    pass  # Silent failure!

# GOOD
try:
    important_operation()
except SpecificError as e:
    logger.error(f"Known error: {e}")
    raise  # Or handle appropriately
except Exception as e:
    logger.error(f"Unexpected error: {e}")
    raise  # Don't swallow unexpected errors
```

---

## How to Use the MCP Server

### Start the Server
```bash
# With NVIDIA API
export NVIDIA_API_KEY="your-key"
python -m aira.mcp.server --port 8080

# Or via Docker
docker build -f Dockerfile.nvidiareview -t nvidiareview-mcp .
docker run -p 8080:8080 -e NVIDIA_API_KEY="your-key" nvidiareview-mcp
```

### Via HTTP API
```bash
# Health check
curl http://localhost:8080/health

# List tools
curl http://localhost:8080/tools

# Review code (POST)
curl -X POST http://localhost:8080 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
    "name":"review_code",
    "arguments":{"code":"try:\n  op()\nexcept:\n  pass","language":"python"}
  }}'
```

### Via MCP Client
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "review_code",
    "arguments": {"code": "your code here"}
  },
  "id": 1
}
```

---

## Integration Patterns for Other Models

### Pattern 1: Post-Hoc Review
After generating/modifying code, run NVIDIAReview for validation:

```bash
# Generate with Model A
python script_a.py > output.py

# Review with NVIDIAReview (Model B)
aira scan output.py --engine static --provider nvidia

# Fix issues
aira fix output.py --apply
```

### Pattern 2: Continuous Review
Run NVIDIAReview in a loop, feed findings to next iteration:

```python
while True:
    result = aira.scan(".", engine="hybrid", provider="nvidia")
    if not result.findings:
        break
    # Apply suggestions from result
    apply_fixes(result.findings)
```

### Pattern 3: Cross-Model Review Pipeline
```
[Model A] --> Code Generation
    |
    v
[Static Scan] --> Issues Found?
    |
    v (if issues)
[NVIDIAReview] --> Fix Suggestions
    |
    v
[Regenerate with Model A + fixes]
```

### Pattern 4: MCP-as-a-Service
Other models can call NVIDIAReview as an external service:

```python
import requests

def validate_code(code: str) -> dict:
    response = requests.post(
        "http://nvidiareview:8080",
        json={
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "review_code",
                "arguments": {"code": code, "language": "python"}
            }
        }
    )
    return response.json()
```

---

## Prerequisites

### NVIDIA API Setup
```bash
# 1. Get API key from https://build.nvidia.com/
export NVIDIA_API_KEY="nvapi-..."

# 2. Test connectivity
curl -H "Authorization: Bearer $NVIDIA_API_KEY" \
  https://integrate.api.nvidia.com/v1/models
```

### AIRA Scanner Setup
```bash
pip install -e /path/to/cli
aira health --check-research
```

---

## Available Check IDs

| ID | Name | Severity | Category |
|----|------|----------|----------|
| C01 | Success Integrity Violation | HIGH | success |
| C02 | Audit & Evidence Gap | HIGH | audit |
| C03 | Broad Exception Suppression | HIGH | exception |
| C04 | Fallback & Degradation | MEDIUM | fallback |
| C05 | Bypass Path | MEDIUM | bypass |
| C06 | Ambiguous Return | MEDIUM | return |
| C08 | Unsupervised Background | MEDIUM | background |
| C09 | Environment-Drift | MEDIUM | environment |
| C10 | Startup Weakness | MEDIUM | initialization |
| C11 | Determinism Drift | MEDIUM | determinism |
| C13 | Confidence Misrep | LOW | confidence |
| C14 | Test Coverage Asymmetry | LOW | testing |
| C15 | Retry Idempotency | LOW | idempotency |
| C07, C12 | Human Review Only | UNKNOWN | - |

---

## Configuration Options

### Environment Variables
```bash
export NVIDIA_API_KEY="your-key"
export AIRA_NVIDIA_MODEL="openai/gpt-oss-20b"
export AIRA_TIMEOUT=120
export AIRA_MAX_CONTEXT_CHARS=120000
export AIRA_PROVIDER="nvidia"
```

### CLI Flags
```bash
aira scan /path \
  --engine static \
  --provider nvidia \
  --model openai/gpt-oss-20b \
  --timeout 120 \
  --fail-on medium
```

---

## Verification Commands

```bash
# Check NVIDIAReview health
aira health --check-research

# Self-scan with improvements
aira scan . --exclude "tests/,fixture_violations.py,test_,venv/" --engine static

# Get pattern documentation
aira doc --output patterns.md

# Test fix suggestions
aira fix --dry-run /path/to/code.py
```

---

## Troubleshooting

### Connection Refused
```bash
# Check MCP server logs
docker logs nvidiareview-mcp

# Verify NVIDIA API
curl -H "Authorization: Bearer $NVIDIA_API_KEY" \
  https://integrate.api.nvidia.com/v1/models
```

### High Latency
- Reduce `AIRA_MAX_CONTEXT_CHARS`
- Use `--engine static` for faster baseline
- Check NVIDIA API rate limits

### API Errors
- Verify `NVIDIA_API_KEY` is valid
- Check `AIRA_NVIDIA_MODEL` is supported
- Review NVIDIA NIM model availability

---

## Integration with Poolside Agents

### For Poolside Build Mode
```yaml
# In agent configuration
tasks:
  - action: run_mcp_server
    config:
      command: "python -m aira.mcp.server --stdio"
      
  - action: call_mcp_tool
    tool: review_code
    arguments:
      code: "{{generated_code}}"
      
  - action: apply_fixes
    from: mcp_result
```

### For Model Review Request
```json
{
  "pr_number": 8,
  "review_type": "cross_model",
  "reviewer": "nvidiareview",
  "model": "openai/gpt-oss-20b",
  "context": {
    "findings": "0 HIGH, 24 MEDIUM, 1 LOW",
    "baseline": "116 total findings",
    "reduction": "78.4%"
  }
}
```

---

## Contact & Support

- Repository: https://github.com/BDBLabs/aira-scanner
- Documentation: https://arxiv.org/abs/2604.17587
- Paper: "AIRA: Static Analysis for AI-Induced Risk in code"

---

*Generated by AIRA Scanner Documentation System*
*Version: 1.0.0*
*Schema: aira-patterns-v1*