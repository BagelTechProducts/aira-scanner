"""
MCP Server for NVIDIAReview Agent

A lightweight, self-contained MCP server for code review.
Provides JSON-RPC over HTTP for integration with MCP clients.

Usage:
    python -m aira.mcp.server --port 8080
    python -m aira.mcp.server --stdio  # For MCP stdio protocol
"""

from __future__ import annotations

import ast
import json
import logging
import os
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nvidiareview-mcp")


@dataclass
class ReviewConfig:
    """Configuration for NVIDIA Review mode."""
    provider: str = "nvidia"
    model: str = os.environ.get("AIRA_NVIDIA_MODEL", "openai/gpt-oss-20b")
    api_key: str = os.environ.get("NVIDIA_API_KEY", "")
    timeout: int = int(os.environ.get("AIRA_TIMEOUT", "120"))
    max_context_chars: int = int(os.environ.get("AIRA_MAX_CONTEXT_CHARS", "120000"))


CONFIG = ReviewConfig()


class ReviewService:
    """Transport-independent review tools and resources."""

    def _list_tools(self) -> List[Dict[str, Any]]:
        """List available tools."""
        return [
            {
                "name": "review_code",
                "description": "Review code for fail-soft patterns C01-C15",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Code to review"},
                        "language": {"type": "string", "default": "python", "description": "Language"},
                    },
                    "required": ["code"],
                },
            },
            {
                "name": "get_fix_suggestions",
                "description": "Get fix suggestions for check IDs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "check_ids": {"type": "array", "items": {"type": "string"}, "description": "Check IDs like C01, C03"},
                    },
                },
            },
            {
                "name": "explain_pattern",
                "description": "Get detailed explanation of a pattern",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "check_id": {"type": "string", "description": "Check ID"},
                    },
                    "required": ["check_id"],
                },
            },
        ]

    def _list_resources_static(self) -> List[Dict[str, str]]:
        """List available resources."""
        return [
            {
                "uri": "aira://patterns",
                "name": "Fail-soft Patterns",
                "description": "Machine-readable pattern documentation",
                "mimeType": "application/json",
            },
            {
                "uri": "aira://patterns.md",
                "name": "Patterns Markdown",
                "description": "Human-readable pattern documentation",
                "mimeType": "text/markdown",
            },
        ]

    def _read_resource_static(self, uri: str) -> Dict[str, Any]:
        """Read a resource by URI."""
        if uri == "aira://patterns":
            return {"contents": [{"uri": uri, "mimeType": "application/json", "text": self._get_patterns_json()}]}
        elif uri == "aira://patterns.md":
            return {"contents": [{"uri": uri, "mimeType": "text/markdown", "text": self._get_patterns_markdown()}]}
        return {"error": f"Unknown resource: {uri}"}

    def _get_patterns_json(self) -> str:
        """Get patterns in JSON format."""
        # Import here to avoid circular imports
        from aira.doc import to_machine_readable
        return json.dumps(to_machine_readable(), indent=2)

    def _get_patterns_markdown(self) -> str:
        """Get patterns in Markdown format."""
        from aira.doc import to_markdown
        return to_markdown()

    def _call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool by name."""
        if name == "review_code":
            return {"content": [{"type": "text", "text": self._review_code(args)}]}
        elif name == "get_fix_suggestions":
            return {"content": [{"type": "text", "text": self._get_fix_suggestions(args)}]}
        elif name == "explain_pattern":
            return {"content": [{"type": "text", "text": self._explain_pattern(args)}]}
        return {"error": f"Unknown tool: {name}"}

    def _review_code(self, args: Dict[str, Any]) -> str:
        """Review code for fail-soft patterns (C01-C15).

        When an NVIDIA API key is configured the code is sent to the review
        model (openai/gpt-oss-20b) over the NIM chat/completions endpoint.
        With no key (or on any NIM error) it falls back to the built-in static
        AST scanner (C01 / C03 / SYNTAX). The API key is read into
        ReviewConfig.api_key at import time and is never logged.
        """
        code = args.get("code", "")
        language = args.get("language", "python")
        if not code:
            return json.dumps({"error": "No code provided"})

        if len(code) > CONFIG.max_context_chars:
            return json.dumps({"error": "Code exceeds configured context limit"})
        if language.lower() not in {"python", "py"} and not CONFIG.api_key:
            return json.dumps({"error": "Static review only supports Python; configure NVIDIA for other languages"})

        # Model-powered review via NVIDIA NIM (requires NVIDIA_API_KEY)
        if CONFIG.api_key and CONFIG.provider == "nvidia":
            llm = self._llm_review(code, language)
            if llm is not None:
                return json.dumps(llm)
            # Fall through to the static scanner on any NIM error.

        if language.lower() not in {"python", "py"}:
            return json.dumps({"error": "Model review failed; static review only supports Python"})
        return json.dumps(self._static_review(code))

    def _llm_review(self, code: str, language: str) -> Optional[Dict[str, Any]]:
        """Call NVIDIA NIM chat/completions for an AIRA fail-soft review.

        Credentials come from ReviewConfig (loaded from the environment at
        import time) and are never echoed or logged. Uses only the stdlib so
        the server stays dependency-light.
        """
        import urllib.request as _urllib

        base_url = os.environ.get(
            "AIRA_NVIDIA_BASE_URL",
            "https://integrate.api.nvidia.com/v1/chat/completions",
        )
        headers = {
            "Authorization": f"Bearer {CONFIG.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        system = (
            "You are AIRA (AI-Induced Risk Audit), a fail-soft pattern reviewer. "
            "Review the following code for fail-soft / fail-open anti-patterns from "
            "the AIRA C01-C15 taxonomy and return ONLY a JSON object with this exact "
            'shape: {"findings":[{"check_id":"C0x","severity":"HIGH|MEDIUM|LOW",'
            '"line":int,"description":str}],"summary":str,'
            '"confidence":"HIGH|MEDIUM|LOW","engine":"nvidiareview:nvidia-nim"}. '
            "If a line number cannot be determined use 0. Flag 'return <truthy>' "
            "inside an except block as C01, swallow broad or bare excepts (C03), "
            "silent 'pass' in an except as C02/C03, and any other fail-soft pattern "
            "from the taxonomy. No prose outside the JSON."
        )
        payload = {
            "model": CONFIG.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": f"```{language}\n{code}\n```"},
            ],
            "max_tokens": 2048,
            "temperature": 0.0,
        }
        try:
            req = _urllib.Request(
                base_url, data=json.dumps(payload).encode(),
                headers=headers, method="POST",
            )
            with _urllib.urlopen(req, timeout=CONFIG.timeout) as resp:
                data = json.loads(resp.read().decode())
            content = data["choices"][0]["message"]["content"].strip()
            # Some NIM responses wrap the JSON in a markdown code fence.
            if content.startswith("```"):
                first_nl = content.find("\n")
                last_fence = content.rfind("```")
                if first_nl != -1 and last_fence > first_nl:
                    content = content[first_nl + 1:last_fence].strip()
            result = json.loads(content)
            result.setdefault("model", CONFIG.model)
            return result
        except Exception as exc:  # noqa: BLE001 - degrade to static scan
            logger.warning("NIM review failed (%s); falling back to static AST", exc)
            return None

    def _static_review(self, code: str) -> Dict[str, Any]:
        """Built-in AST scanner (C01/C03/SYNTAX) - static fallback / no-key path."""
        findings: List[Dict[str, Any]] = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # Check for bare except
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    findings.append({
                        "check_id": "C03",
                        "severity": "HIGH",
                        "description": "Bare exception handler - silent failure risk",
                        "line": node.lineno,
                    })

                # Check for return True in except
                if isinstance(node, ast.ExceptHandler):
                    for stmt in node.body:
                        if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Constant) \
                                and stmt.value.value is True:
                            findings.append({
                                "check_id": "C01",
                                "severity": "HIGH",
                                "description": "Returns success after exception",
                                "line": stmt.lineno,
                            })
        except SyntaxError as e:
            findings.append({
                "check_id": "SYNTAX",
                "severity": "LOW",
                "description": f"Syntax error: {e.msg}",
                "line": e.lineno or 0,
            })

        return {
            "findings": findings,
            "count": len(findings),
            "engine": "nvidiareview:ast-static",
            "model": "static",
        }

    def _get_fix_suggestions(self, args: Dict[str, Any]) -> str:
        """Get fix suggestions."""
        check_ids = args.get("check_ids", [])

        # Import fix module
        try:
            from aira.fix import get_fix_suggestion
            suggestions = []
            for cid in check_ids:
                s = get_fix_suggestion(cid)
                if s:
                    suggestions.append(s)
            return json.dumps(suggestions)
        except ImportError:
            # Provide inline suggestions
            inline = {
                "C01": {"check_id": "C01", "problem": "Success after failure", "suggestion": "Return False or re-raise"},
                "C03": {"check_id": "C03", "problem": "Silent exception suppression", "suggestion": "Log and re-raise specific exceptions"},
            }
            return json.dumps([inline.get(c, {"error": f"Unknown: {c}"}) for c in check_ids])

    def _explain_pattern(self, args: Dict[str, Any]) -> str:
        """Explain a pattern."""
        check_id = args.get("check_id", "")
        if not check_id:
            return json.dumps({"error": "No check_id provided"})

        try:
            from aira.doc import get_pattern
            p = get_pattern(check_id)
            if p:
                return json.dumps({
                    "check_id": p.check_id,
                    "name": p.name,
                    "description": p.description,
                    "severity": p.severity,
                    "root_causes": p.root_causes,
                    "prevention_strategies": p.prevention_strategies,
                })
            return json.dumps({"error": f"Pattern {check_id} not found"})
        except ImportError:
            return json.dumps({"error": "Doc module not available"})


SERVICE = ReviewService()


def dispatch(request):
    """Process JSON-RPC for HTTP and newline-delimited MCP stdio."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    request_id = request.get("id")
    method = request.get("method")
    if not isinstance(method, str):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32600, "message": "Invalid Request"}}
    if "id" not in request:
        return None
    try:
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("params must be an object")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}, "resources": {}},
                      "serverInfo": {"name": "aira-nvidiareview", "version": "1.0.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": SERVICE._list_tools()}
        elif method == "resources/list":
            result = {"resources": SERVICE._list_resources_static()}
        elif method == "resources/read":
            result = SERVICE._read_resource_static(params.get("uri"))
        elif method == "tools/call":
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                raise ValueError("arguments must be an object")
            result = SERVICE._call_tool(params.get("name"), arguments)
        else:
            return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "Method not found"}}
        if "error" in result:
            raise ValueError(result["error"])
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except (ValueError, TypeError, AttributeError, KeyError):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": -32602, "message": "Invalid params"}}


class MCPRequestHandler(BaseHTTPRequestHandler):
    """Simple JSON-RPC HTTP adapter; standard MCP clients should use stdio."""
    def _send_json(self, payload, status=200):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send_json({"status": "healthy", "provider": CONFIG.provider})
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        # This unauthenticated adapter is intended for loopback use only.
        if self.headers.get("Origin"):
            self._send_json({"error": "Browser origins are not accepted"}, 403)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                self._send_json({"error": "Invalid body size"}, 413)
                return
            request = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._send_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, 400)
            return
        response = dispatch(request)
        if response is None:
            self.send_response(204)
            self.end_headers()
        else:
            self._send_json(response)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AIRA MCP stdio server / JSON-RPC HTTP adapter")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--stdio", action="store_true")
    args = parser.parse_args()
    if args.stdio:
        for line in sys.stdin:
            try:
                response = dispatch(json.loads(line))
            except (ValueError, UnicodeDecodeError):
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            if response is not None:
                print(json.dumps(response), flush=True)
    else:
        with HTTPServer((args.host, args.port), MCPRequestHandler) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    main()
