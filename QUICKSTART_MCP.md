# NVIDIAReview MCP Server - Quick Reference

## TL;DR - Get Started in 60 Seconds

```bash
# 1. Install
pip install -e CLI/

# 2. Set API key
export NVIDIA_API_KEY="your-key-here"

# 3. Start server
python -m aira.mcp.server --port 8080

# 4. Test
curl http://localhost:8080/health
# → {"status": "healthy", "provider": "nvidia"}
```

## What We Built

| Component | Location | Purpose |
|-----------|----------|---------|
| Fix Suggestions | `CLI/aira/fix/` | C01-C15 remediation |
| Pattern Docs | `CLI/aira/doc/` | Machine/human readable docs |
| MCP Server | `CLI/aira/mcp/` | HTTP/MCP interface |
| Unified Engine | `CLI/aira/analyze.py` | Single scan interface |

## Use Cases

### Use Case 1: Code Review
```json
{
  "method": "tools/call",
  "params": {
    "name": "review_code",
    "arguments": {"code": "your code here"}
  }
}
```

### Use Case 2: Fix Suggestions
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_fix_suggestions",
    "arguments": {"check_ids": ["C01", "C03"]}
  }
}
```

### Use Case 3: Get Pattern Info
```json
{
  "method": "tools/call",
  "params": {
    "name": "explain_pattern",
    "arguments": {"check_id": "C01"}
  }
}
```

## Available Patterns

- **C01**: Success after failure
- **C03**: Silent exception suppression  
- **C10**: Startup with weak validation

## Integration

```python
import requests

response = requests.post(
    "http://nvidiareview:8080",
    json={"jsonrpc": "2.0", "method": "tools/call", "params": {...}}
)
```

## Files to Share

1. `DOCKER_MCP_QUICKSTART.md` - Full guide
2. `MCP_INTEGRATION_MANUAL.md` - Detailed reference
3. `/tmp/ai-enhancements.patch` - Code changes
4. `CLI/aira/mcp/server.py` - Server implementation