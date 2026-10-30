"""
MCP (Model Context Protocol) Server for NVIDIAReview Agent

Provides MCP endpoints for:
- Code review
- Fix suggestions
- Pattern explanations
- Research validation

Usage:
    # Via MCP client
    mcp-client connect stdio python -m aira.mcp.server --stdio

    # Or via HTTP
    python -m aira.mcp.server --host 0.0.0.0 --port 8080
"""

from .server import main

__all__ = ["main"]
