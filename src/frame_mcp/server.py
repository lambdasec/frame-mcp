"""MCP stdio server that exposes the Frame security scanner CLI as tools.

The server shells out to the ``frame`` command line program using an explicit
argument list (never ``shell=True``). It prefers the ``frame`` executable that
sits next to the running Python interpreter, falling back to ``PATH``.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional, Union

try:
    # mcp 1.x
    from mcp.server.fastmcp import FastMCP as _Server
except ModuleNotFoundError:
    # mcp 2.x renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as _Server

from mcp.types import ToolAnnotations

FindingsInput = Union[str, dict, list]

# Environment variables the Frame LLM layer reads. They are inherited from the
# server process environment and forwarded to every subprocess.
_FRAME_LLM_ENV = (
    "FRAME_LLM_BASE_URL",
    "FRAME_LLM_API_KEY",
    "FRAME_LLM_MODEL",
    "FRAME_LLM_REPO_ROOT",
)

mcp = _Server("frame")


# --------------------------------------------------------------------------
# process helpers
# --------------------------------------------------------------------------
def _frame_executable() -> str:
    """Resolve the frame binary: next to sys.executable first, then PATH."""
    candidate = Path(sys.executable).resolve().parent / "frame"
    if candidate.is_file():
        return str(candidate)
    found = shutil.which("frame")
    if found:
        return found
    # Let subprocess raise a clear FileNotFoundError if it is genuinely absent.
    return "frame"


def _subprocess_env() -> dict:
    """Copy the current environment (carries the FRAME_LLM_* passthrough)."""
    env = os.environ.copy()
    # Explicit: ensure the documented variables survive even if a caller
    # restricted the inherited environment. Absent ones are simply skipped.
    for name in _FRAME_LLM_ENV:
        value = os.environ.get(name)
        if value is not None:
            env[name] = value
    return env


def _parse_output(proc: subprocess.CompletedProcess) -> Any:
    """Return parsed JSON stdout, else a raw stdout/stderr/exit_code fallback."""
    text = proc.stdout or ""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return {
            "stdout": text,
            "stderr": proc.stderr or "",
            "exit_code": proc.returncode,
        }


def _run_frame(
    args: list[str],
    *,
    timeout: float,
    ok_codes: tuple[int, ...] = (0, 1),
) -> Any:
    """Run ``frame <args>`` and return parsed JSON, raising on an error exit.

    Exit codes in ``ok_codes`` (default 0 and 1) are treated as success. Any
    other code (for example 2, the "cannot verify" status) is surfaced as an
    error that carries the captured stderr.
    """
    cmd = [_frame_executable(), *args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=_subprocess_env(),
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "The 'frame' executable was not found. Install frame-security "
            "with: pip install 'frame-security[scan]'."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"frame timed out after {timeout:g}s: {' '.join(args)}"
        ) from exc

    if proc.returncode not in ok_codes:
        stderr = (proc.stderr or "").strip()
        stdout = (proc.stdout or "").strip()
        detail = stderr or stdout or "no output"
        raise RuntimeError(
            f"frame exited with status {proc.returncode}: {detail}"
        )
    return _parse_output(proc)


def _write_findings_tempfile(findings_json: FindingsInput) -> str:
    """Accept a JSON string or an object and write it to a temp file.

    Returns the path to a temporary file the caller is responsible for
    deleting.
    """
    if isinstance(findings_json, (dict, list)):
        payload = json.dumps(findings_json)
    else:
        payload = str(findings_json)
    handle = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    try:
        handle.write(payload)
    finally:
        handle.close()
    return handle.name


# --------------------------------------------------------------------------
# argument builders (pure functions, unit tested without any process launch)
# --------------------------------------------------------------------------
def _build_scan_args(
    path: str,
    language: Optional[str] = None,
    ai: bool = False,
    changed_ref: Optional[str] = None,
    files: Optional[list[str]] = None,
    baseline: Optional[str] = None,
    min_severity: Optional[str] = None,
    fail_on: str = "none",
    root: Optional[str] = None,
    no_cross_file: bool = False,
    packs: Optional[list[str]] = None,
) -> list[str]:
    args = ["scan", path, "-f", "json", "--fail-on", fail_on]
    if language:
        args += ["-l", language]
    if ai:
        args += ["--ai"]
    if changed_ref is not None:
        args += ["--changed", changed_ref]
    if files:
        args += ["--files", *files]
    if baseline:
        args += ["--baseline", baseline]
    if min_severity:
        args += ["--min-severity", min_severity]
    if root:
        args += ["--root", root]
    if no_cross_file:
        args += ["--no-cross-file"]
    for pack in packs or []:
        args += ["--pack", pack]
    return args


def _build_write_baseline_args(path: str, baseline_file: str) -> list[str]:
    return ["scan", path, "--write-baseline", baseline_file, "--fail-on", "none"]


def _build_verify_args(
    findings_source: str, ids: Optional[list[str]] = None
) -> list[str]:
    args = ["verify", findings_source, "-f", "json"]
    for fp in ids or []:
        args += ["--id", fp]
    return args


def _build_fix_args(
    path: str, guidance_file: str, in_place: bool = False
) -> list[str]:
    args = ["fix", path, "--guidance", guidance_file, "--format", "json"]
    if in_place:
        args += ["--in-place"]
    return args


def _build_exploit_args(
    target: str,
    guidance_file: Optional[str] = None,
    goal: Optional[str] = None,
    success_check: Optional[str] = None,
    max_steps: Optional[int] = None,
) -> list[str]:
    args = ["exploit", "--target", target, "--format", "json"]
    if guidance_file:
        args += ["--guidance", guidance_file]
    if goal:
        args += ["--goal", goal]
    if success_check:
        args += ["--success-check", success_check]
    if max_steps is not None:
        args += ["--max-steps", str(max_steps)]
    return args


def _build_solve_args(entailment: str, model: bool = False) -> list[str]:
    args = ["solve", entailment, "--format", "json"]
    if model:
        args += ["--model"]
    return args


def _build_packs_list_args(path: Optional[str] = None) -> list[str]:
    args = ["packs", "list"]
    if path:
        args += ["--project", path]
    return args


def _build_packs_check_args(files: list[str]) -> list[str]:
    return ["packs", "check", *files]


# --------------------------------------------------------------------------
# tools
# --------------------------------------------------------------------------
@mcp.tool(
    annotations=ToolAnnotations(title="Scan source for vulnerabilities", readOnlyHint=True),
)
def scan(
    path: str,
    language: Optional[str] = None,
    ai: bool = False,
    changed_ref: Optional[str] = None,
    files: Optional[list[str]] = None,
    baseline: Optional[str] = None,
    min_severity: Optional[str] = None,
    fail_on: str = "none",
    root: Optional[str] = None,
    no_cross_file: bool = False,
    packs: Optional[list[str]] = None,
) -> Any:
    """Scan a file or directory for security vulnerabilities with Frame.

    Runs taint analysis plus separation logic verification and returns the
    findings as JSON. Set ``ai=True`` to add the LLM detection and triage
    layer (needs the FRAME_LLM_* environment variables). ``changed_ref`` scans
    only files that differ from a git ref; ``files`` restricts the scan to a
    list of files; ``baseline`` reports only findings absent from a baseline
    file; ``packs`` loads extra framework packs. This tool does not modify any
    files.
    """
    args = _build_scan_args(
        path,
        language=language,
        ai=ai,
        changed_ref=changed_ref,
        files=files,
        baseline=baseline,
        min_severity=min_severity,
        fail_on=fail_on,
        root=root,
        no_cross_file=no_cross_file,
        packs=packs,
    )
    timeout = 1800.0 if ai else 300.0
    return _run_frame(args, timeout=timeout, ok_codes=(0, 1))


@mcp.tool(
    annotations=ToolAnnotations(
        title="Write a scan baseline file",
        readOnlyHint=False,
        destructiveHint=False,
    ),
)
def write_baseline(path: str, baseline_file: str) -> Any:
    """Scan ``path`` and record the findings as a baseline file.

    Writes ``baseline_file`` to disk (creating or overwriting it) and uses
    ``--fail-on none`` so the current state is accepted. Later scans can pass
    this file as ``baseline`` to report only new findings.
    """
    args = _build_write_baseline_args(path, baseline_file)
    return _run_frame(args, timeout=300.0, ok_codes=(0, 1))


@mcp.tool(
    annotations=ToolAnnotations(title="Verify earlier findings are fixed", readOnlyHint=True),
)
def verify(findings_json: FindingsInput, ids: Optional[list[str]] = None) -> Any:
    """Re-scan the files behind earlier findings and report their status.

    ``findings_json`` is the JSON produced by ``scan`` (a JSON string or the
    parsed object). Each finding comes back as fixed, file_removed, present,
    suppressed, uncertain or unverifiable. Pass ``ids`` (finding fingerprints)
    to check only specific findings. This tool does not modify any files.
    """
    findings_file = _write_findings_tempfile(findings_json)
    try:
        args = _build_verify_args(findings_file, ids=ids)
        return _run_frame(args, timeout=300.0, ok_codes=(0, 1))
    finally:
        _safe_unlink(findings_file)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Generate verified security fixes",
        readOnlyHint=False,
        destructiveHint=True,
    ),
)
def fix(path: str, findings_json: FindingsInput, in_place: bool = False) -> Any:
    """Generate and verify fixes for scan findings.

    By default this returns a unified diff and does not touch any files. Set
    ``in_place=True`` to write the patches to the source files. Each patch is
    verified by re-scanning the patched code. This tool needs the FRAME_LLM_*
    environment variables (FRAME_LLM_BASE_URL, FRAME_LLM_MODEL, and an API key
    when the endpoint requires one).
    """
    findings_file = _write_findings_tempfile(findings_json)
    try:
        args = _build_fix_args(path, findings_file, in_place=in_place)
        return _run_frame(args, timeout=1800.0, ok_codes=(0, 1))
    finally:
        _safe_unlink(findings_file)


@mcp.tool(
    annotations=ToolAnnotations(
        title="Drive an exploitation agent against a target",
        readOnlyHint=False,
        destructiveHint=True,
        openWorldHint=True,
    ),
)
def exploit(
    target: str,
    findings_json: Optional[FindingsInput] = None,
    goal: Optional[str] = None,
    success_check: Optional[str] = None,
    max_steps: Optional[int] = None,
) -> Any:
    """Drive an LLM agent to exploit a live target. Authorized use only.

    Run this only against systems you own or are explicitly authorized to
    test. ``target`` is a URL such as http://app:8080. Optionally prime the
    agent with ``findings_json`` from ``scan``, a plain-language ``goal``, a
    ``success_check`` shell command (exit 0 means solved), and ``max_steps``.
    Needs the FRAME_LLM_* environment variables.
    """
    findings_file = (
        _write_findings_tempfile(findings_json) if findings_json is not None else None
    )
    try:
        args = _build_exploit_args(
            target,
            guidance_file=findings_file,
            goal=goal,
            success_check=success_check,
            max_steps=max_steps,
        )
        return _run_frame(args, timeout=1800.0, ok_codes=(0, 1))
    finally:
        if findings_file is not None:
            _safe_unlink(findings_file)


@mcp.tool(
    annotations=ToolAnnotations(title="List loadable framework packs", readOnlyHint=True),
)
def packs_list(path: Optional[str] = None) -> Any:
    """List the framework packs a scan would load.

    Packs teach Frame a framework's sources, sinks, sanitizers and entry
    points. Pass ``path`` to include a project directory's .frame/packs.
    """
    args = _build_packs_list_args(path)
    return _run_frame(args, timeout=60.0, ok_codes=(0, 1))


@mcp.tool(
    annotations=ToolAnnotations(title="Validate framework pack files", readOnlyHint=True),
)
def packs_check(files: list[str]) -> Any:
    """Validate one or more framework pack .toml files or directories."""
    args = _build_packs_check_args(files)
    return _run_frame(args, timeout=60.0, ok_codes=(0, 1))


@mcp.tool(
    annotations=ToolAnnotations(title="Check a separation logic entailment", readOnlyHint=True),
)
def solve(entailment: str, model: bool = False) -> Any:
    """Check whether a separation logic entailment ``P |- Q`` is valid.

    Example entailment: ``x |-> 5 |- x |-> 5``. Set ``model=True`` to return a
    countermodel when the entailment is invalid.
    """
    args = _build_solve_args(entailment, model=model)
    return _run_frame(args, timeout=60.0, ok_codes=(0, 1))


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# --------------------------------------------------------------------------
# prompt
# --------------------------------------------------------------------------
@mcp.prompt(name="security-review")
def security_review(path: str) -> str:
    """Scan a project with the AI layer, verify, then offer to fix."""
    return (
        f"Review the code at '{path}' for security vulnerabilities.\n\n"
        "1. Call the 'scan' tool with path set to this location and ai=true to "
        "run taint analysis plus the LLM detection and triage layer.\n"
        "2. Pass the scan result to the 'verify' tool to confirm which findings "
        "are still present.\n"
        "3. Summarize each confirmed finding (CWE, file, line, data flow). For "
        "findings that remain present, offer to call the 'fix' tool, which "
        "returns a verified diff by default (or writes changes with "
        "in_place=true). Do not fix anything without the user's go-ahead."
    )


def main() -> None:
    """Console-script entry point: run the stdio MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
