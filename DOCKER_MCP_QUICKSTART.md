# NVIDIAReview MCP Server - Quick Start Guide

> Integration status: use `python -m aira.mcp.server --stdio` with standard MCP clients.
> HTTP is a simple JSON-RPC adapter, not a Streamable HTTP/SSE transport; it binds to loopback by default.
> Send JSON-RPC requests with `"jsonrpc": "2.0"`, an `id`, and a `method`.
> Tool output is in `result.content` text blocks; resources are in `result.contents`.
> The static review supports Python C01/C03 only; NVIDIA review requires your own runtime key.
> Committed documentation covers C01–C03; fix templates cover C01–C05, C10, and C15.
> `aira fix --dry-run` reports suggestions. Automatic `--apply` is not implemented and returns an error.
> The analyzer is an optional scanner adapter; existing CLI scans still use AIRAScanner directly.
> Docker builds the local checkout. Start with `docker compose -f docker-compose.mcp.yml up --build nvidiareview-mcp`.
> Docker validation requires a running Docker service. No live NVIDIA request was made during integration.


## Prerequisites

- Docker installed
- NVIDIA API key (set in `.env` file or environment)

## Quick Deployment

### 1. Set Environment Variables

Create a `.env` file:
```bash
echo "NVIDIA_API_KEY=your-nvidia-api-key-here" > .env
```

### 2. Build and Run

```bash
# Using Docker Compose
docker-compose -f docker-compose.mcp.yml up -d

# Or using Docker directly
docker build -f Dockerfile.nvidiareview -t nvidiareview-mcp .
docker run -d -p 8080:8080 --name nvidiareview-mcp \
  -e NVIDIA_API_KEY="your-key" \
  nvidiareview-mcp
```

### 3. Verify Deployment

```bash
# Check container is running
docker ps

# Check health
curl -f http://localhost:8080/

# View logs
docker logs nvidiareview-mcp
```

## Using the MCP Server

### Via HTTP API

```bash
# List available resources
curl http://localhost:8080/resources

# Get fail-soft pattern documentation
curl http://localhost:8080/resources/aira://patterns

# Get pattern in markdown
curl http://localhost:8080/resources/aira://patterns.md
```

### Via MCP Client

```bash
# Connect via stdio
python -m aira.mcp.server --stdio
```

### Example: Review Code

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "review_code",
    "arguments": {
      "code": "try:\n    db.insert(record)\nexcept:\n    return True",
      "language": "python"
    }
  },
  "id": 1
}
```

## Available Tools

1. **review_code** - Review code for fail-soft patterns
2. **scan_code** - Scan code with detailed analysis
3. **get_fix_suggestions** - Get fix suggestions for check IDs
4. **explain_pattern** - Get detailed pattern explanation

## Resources

- `/resources/aira://patterns` - JSON pattern documentation
- `/resources/aira://patterns.md` - Human-readable markdown
- `/resources/aira://config` - Current configuration

## Troubleshooting

### Connection Refused
```bash
# Check logs
docker logs nvidiareview-mcp

# Verify NVIDIA API key
echo $NVIDIA_API_KEY
```

### Health Check Fails
```bash
# Manual health check
docker exec nvidiareview-mcp python -c "from aira.mcp.server import validate_configuration; print(validate_configuration())"
```

## Configuration Options

| Env Variable | Default | Description |
|--------------|---------|-------------|
| NVIDIA_API_KEY | (required) | Your NVIDIA NIM API key |
| AIRA_NVIDIA_MODEL | openai/gpt-oss-20b | Model to use for review |
| AIRA_TIMEOUT | 120 | Request timeout in seconds |
| AIRA_MAX_CONTEXT_CHARS | 120000 | Max tokens for context |
| AIRA_PROVIDER | nvidia | Provider (nvidia/ollama/openai-compatible) |
