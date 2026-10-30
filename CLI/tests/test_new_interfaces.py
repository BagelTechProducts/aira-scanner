import io
import json
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest
from aira.analyze import Engine, EngineConfig
from aira.cli import main
from aira.mcp.server import CONFIG, dispatch
from aira.scanner import AIRAScanner


def rpc(method, params=None):
    return dispatch({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})


def test_mcp_initialize_and_discover_tools():
    assert rpc("initialize")["result"]["capabilities"] == {"tools": {}, "resources": {}}
    tools = rpc("tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == {"review_code", "get_fix_suggestions", "explain_pattern"}
    assert all("inputSchema" in t for t in tools)
    assert dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_mcp_tools_resources_and_invalid_requests(monkeypatch):
    monkeypatch.setattr(CONFIG, "api_key", "")
    result = rpc("tools/call", {"name": "review_code", "arguments": {"code": "try:\n    op()\nexcept:\n    pass"}})
    text = result["result"]["content"][0]["text"]
    assert json.loads(text)["findings"][0]["check_id"] == "C03"
    resource = rpc("resources/read", {"uri": "aira://patterns"})["result"]["contents"][0]
    assert resource["mimeType"] == "application/json"
    json.loads(resource["text"])
    for name, arguments in [("get_fix_suggestions", {"check_ids": ["C01"]}), ("explain_pattern", {"check_id": "C01"})]:
        assert rpc("tools/call", {"name": name, "arguments": arguments})["result"]["content"][0]["type"] == "text"
    assert rpc("missing")["error"]["code"] == -32601
    assert rpc("tools/call", {"arguments": []})["error"]["code"] == -32602
    assert dispatch([])["error"]["code"] == -32600


def test_stdio_initializes_and_lists_tools():
    payloads = [{"jsonrpc": "2.0", "id": n, "method": method} for n, method in enumerate(["initialize", "tools/list"])]
    process = subprocess.run([sys.executable, "-m", "aira.mcp.server", "--stdio"],
                             input="".join(json.dumps(p) + "\n" for p in payloads),
                             text=True, capture_output=True, cwd=Path(__file__).parents[1], timeout=10)
    assert process.returncode == 0, process.stderr
    replies = [json.loads(line) for line in process.stdout.splitlines()]
    assert replies[0]["result"]["serverInfo"]["name"] == "aira-nvidiareview"
    assert len(replies[1]["result"]["tools"]) == 3


def test_analyzer_preserves_incomplete_coverage(tmp_path):
    target = tmp_path / "broken.py"
    target.write_text("def broken(:\n")
    baseline = AIRAScanner(str(target)).scan()
    result = Engine(EngineConfig(str(target))).execute()
    assert result.check_results == baseline.check_results
    assert result.files_failed == 1
    assert result.files_discovered == 1
    assert result.exit_code == 2


def test_analyzer_passes_provider_configuration(tmp_path):
    target = tmp_path / "safe.py"
    target.write_text("print('safe')\n")
    baseline = AIRAScanner(str(target)).scan()
    with patch("aira.scanner.AIRAScanner.scan", return_value=baseline) as scan:
        Engine(EngineConfig(str(target), provider="ollama", model="test-model", timeout_seconds=8)).execute()
    config = scan.call_args.kwargs["llm_config"]
    assert (config.provider, config.model, config.timeout_seconds) == ("ollama", "test-model", 8)


def test_fix_command_reports_suggestions_without_writing(tmp_path):
    target = tmp_path / "bad.py"
    source = "def f():\n    try:\n        op()\n    except:\n        return True\n"
    target.write_text(source)
    output = io.StringIO()
    with patch("sys.argv", ["aira", "fix", str(target), "--dry-run", "--output", "json"]), redirect_stdout(output):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 0
    assert json.loads(output.getvalue())["suggestions"]
    assert target.read_text() == source
    with patch("sys.argv", ["aira", "fix", str(target), "--apply"]), redirect_stderr(io.StringIO()):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 2
    assert target.read_text() == source
