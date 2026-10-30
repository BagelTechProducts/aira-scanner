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
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

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
    # OpenCode API: shell out to `opencode` (opencrunc), which holds its own
    # model credentials, so the server need not carry an API key.
    model_source: str = os.environ.get("AIRA_MODEL_SOURCE", "auto")
    open_code_model: str = os.environ.get("AIRA_OPENCODE_MODEL", "openai/gpt-oss-20b")
    open_code_bin: str = os.environ.get("AIRA_OPENCODE_BIN", "opencode")


CONFIG = ReviewConfig()


class MCPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for MCP JSON-RPC protocol."""
    
    def log_message(self, format, *args):
        """Custom log format."""
        logger.info("%s - %s", self.address_string(), format % args)
    
    def _send_json_response(self, data: Dict[str, Any], status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests for resources."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        
        if path == "/health":
            self._send_json_response({"status": "healthy", "provider": CONFIG.provider})
        elif path == "/resources":
            self._list_resources()
        elif path.startswith("/resources/"):
            uri = path[len("/resources/"):]
            self._read_resource(uri)
        else:
            self._send_json_response({"error": "Not found"}, 404)
    
    def do_POST(self):
        """Handle POST requests for RPC calls."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        
        try:
            request = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json_response({"error": "Invalid JSON"}, 400)
            return
        
        method = request.get("jsonrpc") == "2.0" and request.get("method")
        params = request.get("params", {})
        
        if method == "tools/call":
            result = self._call_tool(params.get("name"), params.get("arguments"))
        elif method == "tools/list":
            result = {"tools": self._list_tools()}
        elif method == "resources/list":
            result = {"resources": self._list_resources_static()}
        elif method == "resources/read":
            result = self._read_resource_static(params.get("uri"))
        else:
            result = {"error": f"Unknown method: {method}"}
        
        response = {"jsonrpc": "2.0", "id": request.get("id"), **result}
        self._send_json_response(response)
    
    def _list_tools(self) -> List[Dict[str, Any]]:
        """List available tools."""
        return [
            {
                "type": "function",
                "name": "review_code",
                "description": "Review code for fail-soft patterns C01-C15",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string", "description": "Code to review"},
                        "language": {"type": "string", "default": "python", "description": "Language"},
                    },
                    "required": ["code"],
                },
            },
            {
                "type": "function",
                "name": "get_fix_suggestions",
                "description": "Get fix suggestions for check IDs",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "check_ids": {"type": "array", "items": {"type": "string"}, "description": "Check IDs like C01, C03"},
                    },
                },
            },
            {
                "type": "function",
                "name": "explain_pattern",
                "description": "Get detailed explanation of a pattern",
                "parameters": {
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
    
    def _read_resource(self, uri: str):
        """Read resource via GET."""
        resource = self._read_resource_static(uri) if uri else {"error": "No URI"}
        self._send_json_response(resource)
    
    def _read_resource_static(self, uri: str) -> Dict[str, Any]:
        """Read a resource by URI."""
        if uri == "aira://patterns":
            return {"contents": self._get_patterns_json()}
        elif uri == "aira://patterns.md":
            return {"contents": self._get_patterns_markdown()}
        return {"error": f"Unknown resource: {uri}"}
    
    def _get_patterns_json(self) -> str:
        """Get patterns in JSON format."""
        # Import here to avoid circular imports
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from doc import to_machine_readable
        return json.dumps(to_machine_readable(), indent=2)
    
    def _get_patterns_markdown(self) -> str:
        """Get patterns in Markdown format."""
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from doc import to_markdown
        return to_markdown()
    
    def _list_resources(self):
        """List resources via GET."""
        self._send_json_response({
            "resources": [
                {"uri": "aira://patterns", "name": "Patterns (JSON)"},
                {"uri": "aira://patterns.md", "name": "Patterns (Markdown)"},
            ]
        })
    
    def _list_tools(self):
        """List tools via GET."""
        self._send_json_response({"tools": self._list_tools()})
    
    def _call_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool by name."""
        if name == "review_code":
            return {"content": self._review_code(args)}
        elif name == "get_fix_suggestions":
            return {"content": self._get_fix_suggestions(args)}
        elif name == "explain_pattern":
            return {"content": self._explain_pattern(args)}
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

        # Model-powered review via NVIDIA NIM (requires NVIDIA_API_KEY)
        if CONFIG.api_key and CONFIG.provider == "nvidia":
            llm = self._llm_review(code, language)
            if llm is not None:
                return json.dumps(llm)
            # Fall through to the static scanner on any NIM error.

        return json.dumps(self._static_review(code))

    def _review_code(self, args: Dict[str, Any]) -> str:
        """Review code for fail-soft patterns (C01-C15).

        Resolution order for the model-powered path:
          1. OpenCode API — shell out to `opencode` (opencrunc) when
             AIRA_MODEL_SOURCE allows it and the binary is on PATH. opencrunc
             holds its own model credentials, so no API key is required here.
          2. NVIDIA NIM — POST to chat/completions (openai/gpt-oss-20b) when
             NVIDIA_API_KEY is set.
          3. Static AST scanner (C01 / C03 / SYNTAX) — always-available fallback.
        The API key (when used) is read into ReviewConfig.api_key at import and
        is never logged.
        """
        code = args.get("code", "")
        language = args.get("language", "python")
        if not code:
            return json.dumps({"error": "No code provided"})

        # 1) OpenCode API (preferred: opencrunc supplies the model credentials)
        src = CONFIG.model_source
        if src in ("auto", "opencode"):
            oc = self._open_code_review(code, language)
            if oc is not None:
                return json.dumps(oc)
            if src == "opencode":
                # Explicit OpenCode mode; it failed -> do not guess another backend.
                return json.dumps(self._static_review(code))
            # auto mode: fall through to NVIDIA NIM, then static.

        # 2) NVIDIA NIM (requires NVIDIA_API_KEY)
        if CONFIG.api_key and CONFIG.provider == "nvidia":
            llm = self._llm_review(code, language)
            if llm is not None:
                return json.dumps(llm)
            # Fall through to the static scanner on any NIM error.

        # 3) Static fallback
        return json.dumps(self._static_review(code))

    def _open_code_review(self, code: str, language: str) -> Optional[Dict[str, Any]]:
        """Review code via the OpenCode API (opencrunc `opencode run`).

        opencrunc holds its own model credentials, so the server does not need
        an API key on this path. Returns the parsed review dict, or None on any
        failure so the caller can fall back (graceful degradation).
        """
        import shutil
        import subprocess
        import tempfile

        bin_name = CONFIG.open_code_bin
        if not shutil.which(bin_name):
            logger.debug("opencode not on PATH; skipping OpenCode arm")
            return None

        suffix = ".py" if language == "python" else f".{language}"
        fd, tmp = tempfile.mkstemp(suffix=suffix, text=True)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(code)
            prompt = (
                'You are AIRA (AI-Induced Risk Audit), a fail-soft pattern '
                'reviewer (taxonomy C01-C15). Review the attached file for '
                'fail-soft/fail-open defects: C01 success-after-exception, '
                'C03 bare/broad swallowed excepts, C04 silent fallbacks, '
                'C02 missing audit evidence, C06 ambiguous returns, C15 retry-'
                'without-idempotency near writes, C09 env-dependent safety '
                'drift, and any other C01-C15 pattern. C07 and C12 require '
                'human review only. Do NOT call any tools. Return ONLY a JSON '
                'object with keys: findings (list of {check_id, severity, line, '
                'description}), summary, confidence, engine. If a line cannot be '
                'determined use 0. No prose before or after.'
            )
            cmd = [bin_name, "run", "--auto", "-m", CONFIG.open_code_model,
                   "-f", tmp, prompt]
            try:
                proc = subprocess.run(cmd, timeout=CONFIG.timeout,
                                      capture_output=True, text=True)
            except subprocess.TimeoutExpired:
                logger.warning("OpenCode review timed out; falling back to static AST")
                return None
            except FileNotFoundError:
                logger.warning("opencode binary disappeared; falling back to static AST")
                return None

            if proc.returncode != 0:
                logger.warning("OpenCode review failed (rc=%s): %s",
                               proc.returncode, (proc.stderr or "")[:300])
                return None

            parsed = self._parse_model_json(proc.stdout)
            if parsed is not None:
                parsed.setdefault("engine", "nvidiareview:opencode")
                parsed.setdefault("model", CONFIG.open_code_model)
            return parsed
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def _parse_model_json(self, raw: str) -> Optional[Dict[str, Any]]:
        """Extract a JSON review object from raw model output.

        Unwraps a ```json ... ``` fence (string ops, no regex), then locates the
        first balanced {...} object and parses it. Returns None if no JSON object
        can be parsed.
        """
        if not raw:
            return None
        import re as _re
        text = _re.sub(r"<arg_key>thought</arg_key><arg_key>analysis</arg_key>.*?</arg_key><arg_key>analysis</arg_key>",
                       "", raw, flags=_re.DOTALL)
        # Unwrap a ```json (or ```text) fenced block if present.
        if "```" in text:
            segs = text.split("```")
            if len(segs) >= 3 and segs[1].strip():
                inner = segs[1].strip()
                first_line = inner.split("\n", 1)[0].strip()
                if first_line in ("json", "text"):
                    inner = inner.split("\n", 1)[1]
                text = inner
        start = text.find("{")
        if start == -1:
            return None
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ord(ch) == 92:  # backslash
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[start:i + 1])
                        except json.JSONDecodeError:
                            return None
        return None

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
        sys.path.insert(0, str(Path(__file__).parent.parent))
        try:
            from fix import get_fix_suggestion
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
        
        sys.path.insert(0, str(Path(__file__).parent.parent))
        try:
            from doc import get_pattern
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


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="NVIDIAReview MCP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--stdio", action="store_true", help="Use stdio protocol")
    args = parser.parse_args()
    
    if args.stdio:
        print("NVIDIAReview MCP Server (stdio mode)", file=sys.stderr)
        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                try:
                    req = json.loads(line)
                    handler = MCPRequestHandler(None, None, None)
                    result = handler._call_tool(req.get("method", ""), req.get("params", {}))
                    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": req.get("id"), **result}) + "\n")
                    sys.stdout.flush()
                except Exception as e:
                    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": str(e)}) + "\n")
                    sys.stdout.flush()
            except KeyboardInterrupt:
                break
    else:
        server = ThreadingHTTPServer((args.host, args.port), MCPRequestHandler)
        logger.info("NVIDIAReview MCP server running on %s:%d", args.host, args.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            server.shutdown()


if __name__ == "__main__":
    main()