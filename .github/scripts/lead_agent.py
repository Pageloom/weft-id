"""Autonomous /lead orchestrator on Ollama Cloud (no Claude Code).

Replicates the /lead skill's loop: for each iteration in
`specs/<slug>.md`, spawn a dev agent, run the quality gate
(`make check && make test`), spawn a test agent, triage via a lead agent,
and commit. Each iteration is pushed as soon as it is committed, so a
mid-run failure keeps the completed iterations. After the last iteration,
run the final review pass (test/security/compliance/tech-writer) and triage.

The loop is deterministic; the model only decides what to read/write/run via
tool calls. Subagents are separate model calls whose system prompt points at
the corresponding skill's Headless Mode section.

Usage:
    export OLLAMA_API_KEY=...
    python3 .github/scripts/lead_agent.py <slug> [--branch B] [--push]

Env:
    OLLAMA_API_KEY   (required)
    OLLAMA_BASE_URL  (default https://ollama.com)
    OLLAMA_MODEL     (default deepseek-v4-flash:0731)
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import PurePosixPath

from ollama_agent import MODEL, REPO_ROOT, run_agent

GATE_CMD = "make check && make test"
MAX_FIX_ATTEMPTS = 3
# Re-prompts allowed when the dev agent finishes without touching a file.
MAX_EMPTY_ATTEMPTS = 2

# Branch to push to after every iteration commit; None disables pushing.
# Set from --push in main().
_PUSH_BRANCH: str | None = None

# Basename globs for throwaway files agents leave behind while debugging.
# `_commit` uses `git add -A`, so anything untracked and unignored would
# otherwise be committed (a real run left `tests/routers/test_tmp_dbg.py`
# behind). Matched against the basename of UNTRACKED files only, so a tracked
# file named `debug.py` is never at risk. Keep these narrow and explicit:
# sweeping a file the agent genuinely meant to add is worse than committing junk.
SCRATCH_GLOBS = (
    "test_tmp*.py",
    "tmp_*.py",
    "debug_*.py",
    "*_dbg.py",
    "*_scratch.py",
    "scratch*.py",
    "*.tmp",
    "*.orig",
    "*.rej",
    "nohup.out",
)


# --- Git helpers -----------------------------------------------------------


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, timeout=300
    )
    return proc.stdout.strip()


def _run(cmd: str, timeout: int = 1800) -> tuple[int, str]:
    proc = subprocess.run(
        cmd, shell=True, cwd=REPO_ROOT, capture_output=True, text=True, timeout=timeout
    )
    out = proc.stdout
    if proc.stderr:
        out += "\n[stderr]\n" + proc.stderr
    return proc.returncode, out


def _changed_files() -> str:
    return _git("diff", "HEAD", "--name-only")


def _commit(subject: str, body: str) -> bool:
    """Stage everything and commit. Returns True only if a commit was created.

    The caller must not announce or push a commit this returns False for: an
    agent that changed nothing would otherwise produce a clean-looking
    `[commit]` / `[push]` pair in the log while the remote never moves.
    """
    _git("add", "-A")
    msg = f"{subject}\n\n{body}"
    proc = subprocess.run(
        ["git", "commit", "-m", msg], cwd=REPO_ROOT, capture_output=True, text=True
    )
    if proc.returncode == 0:
        return True
    combined = proc.stdout + proc.stderr
    if "nothing to commit" not in combined:
        print(f"[commit] failed: {combined}", file=sys.stderr)
    return False


def _has_changes() -> bool:
    """Whether the working tree differs from HEAD (tracked or untracked)."""
    return bool(_git("status", "--porcelain").strip())


def _sweep_scratch() -> None:
    """Delete untracked scratch files before they reach `git add -A`.

    Only untracked, unignored files whose basename matches `SCRATCH_GLOBS` are
    removed, and every removal is logged so a wrongly-swept file is visible in
    the run log rather than silently gone.
    """
    listing = _git("ls-files", "--others", "--exclude-standard")
    for rel in filter(None, (line.strip() for line in listing.splitlines())):
        if not any(fnmatch(PurePosixPath(rel).name, pat) for pat in SCRATCH_GLOBS):
            continue
        target = REPO_ROOT / rel
        try:
            target.unlink()
        except OSError as exc:
            print(f"[scratch] could not remove {rel}: {exc}", file=sys.stderr)
        else:
            print(f"[scratch] removed {rel}", file=sys.stderr)


def _push(label: str) -> None:
    """Push HEAD to the tracked branch, if pushing is enabled.

    Called after every iteration commit so a mid-run failure (a model quota
    error, a timeout, a gate that will not go green) leaves the iterations that
    already passed the gate on the remote instead of discarding them with the
    runner. A push failure is reported but never fatal: losing the remaining
    iterations is better than losing the completed ones too.
    """
    if _PUSH_BRANCH is None:
        return
    # actions/checkout leaves a detached HEAD, so push HEAD explicitly rather
    # than a local branch name (which does not exist in that state).
    proc = subprocess.run(
        ["git", "push", "origin", f"HEAD:{_PUSH_BRANCH}"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode == 0:
        print(f"[push] {label} -> {_PUSH_BRANCH}", file=sys.stderr)
    else:
        print(
            f"[push] FAILED ({label} -> {_PUSH_BRANCH}):\n{proc.stdout}{proc.stderr}",
            file=sys.stderr,
        )


# --- Iteration file parsing -------------------------------------------------


def _read_spec(slug: str) -> str:
    path = REPO_ROOT / f"specs/{slug}.md"
    if not path.exists():
        raise SystemExit(f"iteration file not found: {path}")
    return path.read_text(encoding="utf-8")


def _current_iteration(content: str) -> int | None:
    pattern = re.compile(r"## Iteration (\d+)[^\n]*\n\*\*Status\*\*:\s*([^\n]+)")
    for m in pattern.finditer(content):
        status = m.group(2).strip()
        if "Complete" not in status:
            return int(m.group(1))
    return None


# --- Agent prompts ----------------------------------------------------------


def _dev_prompt(slug: str, n: int) -> tuple[str, str]:
    system = (
        "You are the dev agent in the WeftID /lead workflow, running autonomously in CI "
        "with no human available. Read `.claude/skills/dev/SKILL.md` and follow its "
        "Headless Mode section. Read `CLAUDE.md` for architectural rules and "
        "`.claude/THOUGHT_ERRORS.md` for common mistakes. Inspect the codebase before "
        "writing code, then WRITE THE CODE. You produce changes on disk, not plans: "
        "`write_file` creates a new file and `edit_file` changes an existing one. "
        "Reading, grepping and describing an approach are not progress. An iteration "
        "that ends with no files created or modified has failed."
    )
    task = (
        f"Read `specs/{slug}.md` and implement Iteration {n} end to end. "
        "Survey the code you need to mirror, then create every file the acceptance "
        "criteria call for using `write_file` and `edit_file` -- migration, database "
        "modules, service, router, schemas, templates and tests as applicable. Do not "
        "stop after planning: a plan you have not written to disk is worth nothing "
        "here, and no human will act on it.\n\n"
        "Then run `make check` and `make test` yourself and fix any failures. Delete "
        "any temporary or debug files you created along the way; only the real "
        "implementation and its tests should be left on disk.\n\n"
        "Before you finish, run `git status --short` and confirm your new and changed "
        "files are listed. If that output is empty you have not done the work -- go "
        "back and write the files. Do not commit. When done, report: files changed, "
        "what each does, tests added, and any decisions you made."
    )
    return system, task


def _empty_prompt(slug: str, n: int) -> tuple[str, str]:
    """Re-prompt after a dev agent finished without changing a single file."""
    system = (
        "You are the dev agent in the WeftID /lead workflow, running autonomously in "
        "CI. Your previous attempt ended with an empty `git status` -- you explored the "
        "codebase and then stopped without writing anything. That is a failed "
        "iteration. This time, write files."
    )
    task = (
        f"`git status --short` is empty: Iteration {n} of `specs/{slug}.md` is not "
        "implemented. You have already surveyed the codebase, so skip further "
        "exploration and start with your first `write_file` call now.\n\n"
        "Create the files the acceptance criteria require, one `write_file` or "
        "`edit_file` call at a time, then run `make check` and `make test` and fix what "
        "fails. Verify with `git status --short` that your files are listed before you "
        "finish. Do not reply with a plan, a summary, or an explanation of what you "
        "would do -- only actual tool calls that change files count."
    )
    return system, task


def _fix_prompt(slug: str, n: int, gate_output: str) -> tuple[str, str]:
    system, _ = _dev_prompt(slug, n)
    task = (
        f"The quality gate (`{GATE_CMD}`) failed after your implementation of "
        f"Iteration {n}. Fix the failures and re-run the gate until it passes. "
        f"Do not commit.\n\n=== GATE OUTPUT ===\n{gate_output[-8000:]}"
    )
    return system, task


def _test_prompt(slug: str, n: int, changed: str) -> tuple[str, str]:
    system = (
        "You are the test agent in the WeftID /lead workflow. Read "
        "`.claude/skills/test/SKILL.md` and follow its Headless Mode section."
    )
    task = (
        f"Changed files:\n{changed}\n\n"
        f"Acceptance criteria: see Iteration {n} in `specs/{slug}.md`. "
        "Review the changes for coverage gaps, missing edge cases, and bugs. "
        "Report findings with severity and a concrete fix for each."
    )
    return system, task


def _lead_prompt(
    slug: str, n: int, dev_report: str, test_findings: str, gate_output: str
) -> tuple[str, str]:
    system = (
        "You are the tech lead in the WeftID /lead workflow. Read "
        "`.claude/skills/lead/SKILL.md` for the iteration file format and the Step 5g "
        "close-out steps. You have write/edit tools."
    )
    today = datetime.datetime.now(tz=datetime.UTC).date().isoformat()
    task = (
        f"Close out Iteration {n} in `specs/{slug}.md`: mark it Complete "
        f"with today's date ({today}), check off the "
        "acceptance criteria, replace the Layers/Guidance sections with a 'What was "
        "done' list, and add 'Tests added', 'Test review', 'Reconceptualisations', and "
        "'Decisions log' sections. If the test findings reveal a real bug, fix it with "
        "the tools and re-run `make check && make test` before closing. Update the "
        "top-level Status line to the next iteration.\n\n"
        f"=== DEV REPORT ===\n{dev_report}\n\n"
        f"=== TEST FINDINGS ===\n{test_findings}\n\n"
        f"=== GATE OUTPUT (tail) ===\n{gate_output[-4000:]}"
    )
    return system, task


# --- Iteration loop ---------------------------------------------------------


def run_iteration(slug: str, n: int) -> None:
    print(f"\n{'=' * 70}\nITERATION {n}\n{'=' * 70}", file=sys.stderr)

    # 1. Dev agent implements.
    system, task = _dev_prompt(slug, n)
    dev_report = run_agent(system, task)
    print(f"\n[dev] report:\n{dev_report}\n", file=sys.stderr)

    # 1b. An agent that changed nothing has not implemented anything. Re-prompt
    # bluntly, then fail: the gate passes trivially on an unchanged tree and the
    # loop would otherwise re-run this same iteration until the job times out.
    empty_attempts = 0
    while not _has_changes() and empty_attempts < MAX_EMPTY_ATTEMPTS:
        empty_attempts += 1
        print(
            f"\n[dev] no files changed (attempt {empty_attempts}); re-prompting",
            file=sys.stderr,
        )
        system, task = _empty_prompt(slug, n)
        dev_report = run_agent(system, task)
        print(f"\n[dev] report:\n{dev_report}\n", file=sys.stderr)
    if not _has_changes():
        raise SystemExit(
            f"iteration {n}: dev agent produced no file changes after "
            f"{MAX_EMPTY_ATTEMPTS + 1} attempts"
        )

    # 2. Quality gate (deterministic).
    code, gate_output = _run(GATE_CMD)
    attempts = 0
    while code != 0 and attempts < MAX_FIX_ATTEMPTS:
        attempts += 1
        print(f"\n[gate] failed (attempt {attempts}); asking dev to fix", file=sys.stderr)
        system, task = _fix_prompt(slug, n, gate_output)
        dev_report = run_agent(system, task)
        code, gate_output = _run(GATE_CMD)
    if code != 0:
        raise SystemExit(f"quality gate still failing after {MAX_FIX_ATTEMPTS} fix attempts")

    # 3. Test agent reviews.
    changed = _changed_files()
    system, task = _test_prompt(slug, n, changed)
    test_findings = run_agent(system, task)

    # 4. Lead agent triages and updates the iteration file.
    system, task = _lead_prompt(slug, n, dev_report, test_findings, gate_output)
    run_agent(system, task)

    # 5. Commit.
    subject = f"Implement {slug} iteration {n}"
    body = f"Implements iteration {n} of the {slug} feature. See specs/{slug}.md."
    _sweep_scratch()
    if not _commit(subject, body):
        raise SystemExit(f"iteration {n}: nothing to commit after a passing gate")
    print(f"[commit] {subject}", file=sys.stderr)
    _push(f"iteration {n}")


# --- Final review pass ------------------------------------------------------


def _review_prompt(agent: str, changed: str, slug: str) -> tuple[str, str]:
    system = (
        f"You are the {agent} agent in the WeftID /lead workflow. Read "
        f"`.claude/skills/{agent}/SKILL.md` and follow its Headless Mode section."
    )
    task = (
        f"Changed files (full feature branch):\n{changed}\n\n"
        f"Feature context: see `specs/{slug}.md`. Review the changes and "
        "report findings with severity and a concrete fix for each."
    )
    return system, task


def final_review(slug: str) -> None:
    print(f"\n{'=' * 70}\nFINAL REVIEW PASS\n{'=' * 70}", file=sys.stderr)
    changed = _git("diff", "main...HEAD", "--name-only")
    findings: dict[str, str] = {}
    for agent in ("test", "security", "compliance", "tech-writer"):
        print(f"\n[review] {agent}", file=sys.stderr)
        system, task = _review_prompt(agent, changed, slug)
        findings[agent] = run_agent(system, task)

    system = (
        "You are the tech lead in the WeftID /lead workflow. Read "
        "`.claude/skills/lead/SKILL.md` for the Step 8 close-out. You have write/edit tools."
    )
    task = (
        "Triage the final review findings below. Fix accepted issues with the tools, "
        "log deferred items to `.claude/ISSUES.md`, re-run `make check && make test` "
        "after changes, and set the iteration file status to 'Feature complete'.\n\n"
        + "\n\n".join(f"=== {k.upper()} ===\n{v}" for k, v in findings.items())
    )
    run_agent(system, task)
    _sweep_scratch()
    if _commit(f"Final review pass for {slug}", f"Addresses review findings for {slug}."):
        _push("final review")
    else:
        print("[commit] final review made no changes", file=sys.stderr)


# --- Main -------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Autonomous /lead orchestrator on Ollama Cloud")
    parser.add_argument("slug", help="iteration file slug (e.g. oidc_upstream)")
    parser.add_argument("--branch", default=None, help="branch to work on (default: current)")
    parser.add_argument("--push", action="store_true", help="push to remote after every iteration")
    parser.add_argument("--model", default=None, help="override OLLAMA_MODEL")
    args = parser.parse_args()

    global _PUSH_BRANCH

    if args.model:
        os.environ["OLLAMA_MODEL"] = args.model
    if not os.environ.get("OLLAMA_API_KEY"):
        raise SystemExit("OLLAMA_API_KEY is not set")

    print(f"Model: {MODEL}  Slug: {args.slug}", file=sys.stderr)

    if args.push:
        _PUSH_BRANCH = args.branch or _git("rev-parse", "--abbrev-ref", "HEAD")
        print(f"[push] enabled -> {_PUSH_BRANCH} (after every iteration)", file=sys.stderr)
    else:
        print("[push] skipped (pass --push to push)", file=sys.stderr)

    content = _read_spec(args.slug)
    n = _current_iteration(content)
    if n is None:
        print("No incomplete iterations found; running final review only.", file=sys.stderr)
    while n is not None:
        run_iteration(args.slug, n)
        content = _read_spec(args.slug)
        n = _current_iteration(content)

    final_review(args.slug)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
