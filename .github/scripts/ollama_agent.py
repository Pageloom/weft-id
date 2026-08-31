"""Reusable Ollama Cloud agent harness (tool-calling loop), no Claude Code.

Drives a model on Ollama Cloud (https://ollama.com/api/chat) through a
tool-calling loop: the model emits tool calls, we execute them, and feed the
results back until it produces a final answer.

Shared by the /lead orchestrator (lead_agent.py). The smoke test
(dev/ollama_smoke_test.py) is a self-contained copy of this loop.

Env:
    OLLAMA_API_KEY   (required)  from https://ollama.com/settings/keys
    OLLAMA_BASE_URL  (default https://ollama.com)
    OLLAMA_MODEL     (default deepseek-v4-flash:0731)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = os.environ.get("OLLAMA_BASE_URL") or "https://ollama.com"
API_KEY = os.environ.get("OLLAMA_API_KEY") or ""
MODEL = os.environ.get("OLLAMA_MODEL") or "deepseek-v4-flash:0731"

# .github/scripts/ollama_agent.py -> repo root is three parents up.
REPO_ROOT = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parent.parent.parent))

MAX_TOOL_OUTPUT = 20_000  # chars; truncate long tool results
# Consecutive blank turns (no tool calls, no content) tolerated before an
# agent is given up on. Some models emit a turn carrying only `thinking`,
# or get cut mid-generation while building a large tool argument; treating
# the first blank turn as 'finished' silently ends the agent having done
# nothing at all.
MAX_EMPTY_TURNS = 3


# --- Tools -----------------------------------------------------------------


def _resolve(path: str) -> Path:
    p = (REPO_ROOT / path).resolve()
    if not str(p).startswith(str(REPO_ROOT)):
        raise ValueError(f"path escapes the repo root: {path}")
    return p


def _read_file(path: str) -> str:
    try:
        p = _resolve(path)
    except ValueError as exc:
        return f"Error: {exc}"
    if not p.exists():
        return f"Error: no such file: {path}"
    return p.read_text(encoding="utf-8")


def _write_file(path: str, content: str) -> str:
    try:
        p = _resolve(path)
    except ValueError as exc:
        return f"Error: {exc}"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return f"Wrote {len(content)} chars to {path}"


def _edit_file(path: str, old_string: str, new_string: str) -> str:
    try:
        p = _resolve(path)
    except ValueError as exc:
        return f"Error: {exc}"
    if not p.exists():
        return f"Error: no such file: {path}"
    text = p.read_text(encoding="utf-8")
    count = text.count(old_string)
    if count == 0:
        return "Error: old_string not found in file"
    if count > 1:
        return f"Error: old_string is not unique ({count} matches); provide more context"
    p.write_text(text.replace(old_string, new_string, 1), encoding="utf-8")
    return f"Edited {path} (1 replacement)"


def _run_bash(command: str) -> str:
    try:
        proc = subprocess.run(
            command,
            shell=True,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 300s"
    out = proc.stdout
    if proc.stderr:
        out += "\n[stderr]\n" + proc.stderr
    return out or "(no output)"


def _glob(pattern: str) -> str:
    matches = sorted(str(p.relative_to(REPO_ROOT)) for p in REPO_ROOT.glob(pattern))
    return "\n".join(matches[:200]) or "(no matches)"


def _grep(pattern: str, path: str) -> str:
    try:
        p = _resolve(path)
    except ValueError as exc:
        return f"Error: {exc}"
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


def _tool_schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


TOOLS = [
    _tool_schema(
        "read_file",
        "Read a file under the repo root and return its contents.",
        {"path": {"type": "string", "description": "Repo-relative path"}},
        ["path"],
    ),
    _tool_schema(
        "write_file",
        "Create or overwrite a file under the repo root.",
        {
            "path": {"type": "string", "description": "Repo-relative path"},
            "content": {"type": "string", "description": "Full file contents"},
        },
        ["path", "content"],
    ),
    _tool_schema(
        "edit_file",
        "Replace one exact, unique substring in a file with new text.",
        {
            "path": {"type": "string", "description": "Repo-relative path"},
            "old_string": {"type": "string", "description": "Exact text to replace"},
            "new_string": {"type": "string", "description": "Replacement text"},
        },
        ["path", "old_string", "new_string"],
    ),
    _tool_schema(
        "run_bash",
        "Run a shell command in the repo root and return stdout/stderr.",
        {"command": {"type": "string"}},
        ["command"],
    ),
    _tool_schema(
        "glob",
        "Glob for files under the repo root.",
        {"pattern": {"type": "string"}},
        ["pattern"],
    ),
    _tool_schema(
        "grep",
        "Recursively grep a file or directory for a pattern.",
        {
            "pattern": {"type": "string"},
            "path": {"type": "string"},
        },
        ["pattern", "path"],
    ),
]

TOOL_IMPL = {
    "read_file": _read_file,
    "write_file": _write_file,
    "edit_file": _edit_file,
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


def run_agent(
    system: str,
    task: str,
    tools: list[dict] | None = None,
    max_turns: int = 100,
    verbose: bool = True,
) -> str:
    """Run one agent turn-loop and return the final assistant text."""
    tools = TOOLS if tools is None else tools
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": task},
    ]
    empty_turns = 0
    for _ in range(max_turns):
        data = chat(messages, tools)
        msg = data.get("message", {})
        tool_calls = msg.get("tool_calls") or []
        content = msg.get("content") or ""
        if not tool_calls:
            if content.strip():
                return content
            # Blank turn: nudge rather than accept it as a finished agent.
            empty_turns += 1
            thinking = msg.get("thinking") or ""
            if verbose:
                print(
                    f"\n[warn] blank turn {empty_turns}/{MAX_EMPTY_TURNS} "
                    f"(done_reason={data.get('done_reason')!r}, "
                    f"message keys={sorted(msg)}, thinking={len(thinking)} chars)",
                    file=sys.stderr,
                )
                if thinking:
                    print(f"[warn] thinking tail: ...{thinking[-400:]}", file=sys.stderr)
            if empty_turns >= MAX_EMPTY_TURNS:
                return "(model returned only blank turns)"
            messages.append({"role": "assistant", "content": content})
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your last turn was empty: no tool call and no text. Do not "
                        "reply with prose. Make your next tool call now -- if the "
                        "file you are writing is large, write it in smaller pieces "
                        "(one write_file for a first section, then edit_file to "
                        "append) rather than in a single call."
                    ),
                }
            )
            continue
        empty_turns = 0
        # Append a clean assistant message (drop `thinking` to keep context lean).
        assistant = {"role": "assistant", "content": msg.get("content", "")}
        assistant["tool_calls"] = tool_calls
        messages.append(assistant)
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
            if verbose:
                print(f"\n[tool] {name}({args}) -> {len(result)} chars", file=sys.stderr)
            messages.append({"role": "tool", "content": result, "name": name})
    return "(hit max_turns without a final answer)"
