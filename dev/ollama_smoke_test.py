"""Smoke test for driving an Ollama Cloud model through a tool-calling loop.

This is the prototype for the /lead orchestrator. It proves the one thing the
whole approach depends on: that `deepseek-v4-pro:cloud` on Ollama Cloud can
(a) emit tool calls and (b) act on the results we feed back, with no Claude Code.

Usage:
    export OLLAMA_API_KEY=...          # from https://ollama.com/settings/keys
    poetry run python dev/ollama_smoke_test.py

Optional env:
    OLLAMA_BASE_URL  (default https://ollama.com)
    OLLAMA_MODEL     (default deepseek-v4-pro:cloud)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = os.environ.get("OLLAMA_BASE_URL", "https://ollama.com")
API_KEY = os.environ.get("OLLAMA_API_KEY", "")
MODEL = os.environ.get("OLLAMA_MODEL", "deepseek-v4-pro:0813")

REPO_ROOT = Path(__file__).resolve().parent.parent

MAX_TURNS = 30
MAX_TOOL_OUTPUT = 20_000  # chars; truncate long tool results


# --- Tools -----------------------------------------------------------------


def _read_file(path: str) -> str:
    p = (REPO_ROOT / path).resolve()
    if not str(p).startswith(str(REPO_ROOT)):
        return "Error: path escapes the repo root"
    if not p.exists():
        return f"Error: no such file: {path}"
    return p.read_text(encoding="utf-8")


def _run_bash(command: str) -> str:
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 120s"
    out = proc.stdout
    if proc.stderr:
        out += "\n[stderr]\n" + proc.stderr
    return out or "(no output)"


def _glob(pattern: str) -> str:
    matches = sorted(str(p.relative_to(REPO_ROOT)) for p in REPO_ROOT.glob(pattern))
    return "\n".join(matches[:200]) or "(no matches)"


def _grep(pattern: str, path: str) -> str:
    p = (REPO_ROOT / path).resolve()
    if not str(p).startswith(str(REPO_ROOT)):
        return "Error: path escapes the repo root"
    if not p.exists():
        return f"Error: no such file: {path}"
    try:
        proc = subprocess.run(
            ["grep", "-rn", "--", pattern, str(p)],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return "Error: grep timed out"
    return proc.stdout or "(no matches)"


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file under the repo root and return its contents.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Repo-relative path"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_bash",
            "description": "Run a shell command in the repo root and return stdout/stderr.",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "glob",
            "description": "Glob for files under the repo root.",
            "parameters": {
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep",
            "description": "Recursively grep a file or directory for a pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["pattern", "path"],
            },
        },
    },
]

TOOL_IMPL = {
    "read_file": _read_file,
    "run_bash": _run_bash,
    "glob": _glob,
    "grep": _grep,
}


# --- Client ----------------------------------------------------------------


def chat(messages: list[dict], tools: list[dict] | None = None) -> dict:
    payload = {"model": MODEL, "messages": messages, "stream": False}
    if tools:
        payload["tools"] = tools
    req = urllib.request.Request(
        f"{BASE_URL}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"Ollama HTTP {exc.code}: {body}") from exc
    if "error" in data:
        raise RuntimeError(f"Ollama error: {data['error']}")
    return data


def run_agent(system: str, task: str) -> str:
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": task},
    ]
    for _ in range(MAX_TURNS):
        data = chat(messages, TOOLS)
        msg = data.get("message", {})
        tool_calls = msg.get("tool_calls") or []
        if not tool_calls:
            return msg.get("content") or "(empty response)"
        messages.append(msg)
        for call in tool_calls:
            fn = call.get("function", {})
            name = fn.get("name", "")
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            impl = TOOL_IMPL.get(name)
            if impl is None:
                result = f"Error: unknown tool {name}"
            else:
                try:
                    result = impl(**args)
                except TypeError as exc:
                    result = f"Error: bad arguments for {name}: {exc}"
            result = str(result)[:MAX_TOOL_OUTPUT]
            print(f"\n[tool] {name}({args}) -> {len(result)} chars", file=sys.stderr)
            messages.append({"role": "tool", "content": result, "name": name})
    return "(hit MAX_TURNS without a final answer)"


# --- Main ------------------------------------------------------------------


def main() -> int:
    if not API_KEY:
        print(
            "OLLAMA_API_KEY is not set. Export it from https://ollama.com/settings/keys",
            file=sys.stderr,
        )
        return 1
    print(f"Model: {MODEL}  Base URL: {BASE_URL}", file=sys.stderr)
    system = (
        "You are a coding agent working in the WeftID repository. Use the provided "
        "tools to inspect the codebase, then answer concisely."
    )
    task = (
        "Read CLAUDE.md and report: (1) the project name, (2) one architectural rule "
        "about where business logic lives, and (3) the exact command to run tests. "
        "Use the tools to find the answers; do not guess."
    )
    answer = run_agent(system, task)
    print("\n=== FINAL ANSWER ===\n")
    print(answer)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
