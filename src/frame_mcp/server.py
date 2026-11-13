"""MCP stdio server that exposes the Frame security scanner CLI as tools.

The server shells out to the ``frame`` command line program using an explicit
argument list (never ``shell=True``). It prefers the ``frame`` executable that
sits next to the running Python interpreter, falling back to ``PATH``.
"""

from __future__ import annotations

import atexit
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
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

# Environment variables the Frame LLM layer reads (Frame 1.1: every other LLM setting is
# the `[llm]` table of the project's .frame.toml). They are inherited from the server
# process environment and forwarded to every subprocess.
_FRAME_LLM_ENV = (
    "FRAME_LLM_BASE_URL",
    "FRAME_LLM_API_KEY",
    "FRAME_LLM_MODEL",
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
    timeout: Optional[float],
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
    hunt_authz: bool = False,
) -> list[str]:
    args = ["scan", path, "-f", "json", "--fail-on", fail_on]
    if language:
        args += ["-l", language]
    if ai:
        args += ["--ai"]
    if hunt_authz:
        args += ["--hunt-authz"]
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
# warm engine queries (`frame query DIR --serve`, Frame 1.1.5+)
# --------------------------------------------------------------------------
_QUERY_TOOLS = (
    "handlers", "handler_facts", "siblings", "trace", "callers", "callees", "guards", "check",
)


def _build_query_serve_args(
    path: str, language: Optional[str] = None, packs: Optional[list[str]] = None
) -> list[str]:
    args = ["query", path, "--serve"]
    if language:
        args += ["-l", language]
    for pack in packs or []:
        args += ["--pack", pack]
    return args


class _QueryServer:
    """One long-lived ``frame query --serve`` process for one project.

    The process translates the project once and answers each request from memory; it
    rebuilds by itself when a source file under the project changes. Requests on one
    process are serialized (one JSON line out, one JSON line back).
    """

    def __init__(self, args: list[str]):
        self.args = args
        self.proc: Optional[subprocess.Popen] = None
        self.lock = threading.Lock()
        self.ids = itertools.count(1)

    def _start(self) -> None:
        try:
            self.proc = subprocess.Popen(
                [_frame_executable(), *self.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=_subprocess_env(),
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "The 'frame' executable was not found. Install frame-security "
                "with: pip install 'frame-security[scan]'."
            ) from exc

    def _exchange(self, request: dict) -> Optional[dict]:
        if self.proc is None or self.proc.poll() is not None:
            self._start()
        assert self.proc is not None and self.proc.stdin and self.proc.stdout
        try:
            self.proc.stdin.write(json.dumps(request) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            return None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                return None                      # the process ended
            try:
                answer = json.loads(line)
            except ValueError:
                continue
            if answer.get("id") == request["id"]:
                return answer

    def ask(self, tool: str, args: dict) -> dict:
        with self.lock:
            request = {"id": next(self.ids), "tool": tool, "args": args}
            answer = self._exchange(request)
            if answer is None:                   # restart once: the process may have died
                self.close()
                answer = self._exchange({**request, "id": next(self.ids)})
            if answer is None:
                stderr = ""
                if self.proc is not None and self.proc.stderr is not None:
                    try:
                        stderr = self.proc.stderr.read() or ""
                    except (OSError, ValueError):
                        stderr = ""
                self.close()
                hint = " (frame query needs frame-security 1.1.5 or later)" \
                    if "invalid choice" in stderr else ""
                raise RuntimeError(
                    f"frame query ended without answering{hint}: {stderr.strip()[-2000:]}"
                )
            answer.pop("id", None)
            return answer

    def close(self) -> None:
        proc, self.proc = self.proc, None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            proc.kill()


_QUERY_SERVERS: dict[tuple, _QueryServer] = {}
_QUERY_SERVERS_LOCK = threading.Lock()


def _query(path: str, tool: str, args: dict, language: Optional[str] = None,
           packs: Optional[list[str]] = None) -> Any:
    """Ask the warm engine for ``path`` (started on first use, kept for later calls)."""
    root = str(Path(path).expanduser().resolve())
    if not Path(root).is_dir():
        raise RuntimeError(f"{path} is not a directory")
    key = (root, language or "", tuple(packs or ()))
    with _QUERY_SERVERS_LOCK:
        server = _QUERY_SERVERS.get(key)
        if server is None:
            server = _QUERY_SERVERS[key] = _QueryServer(
                _build_query_serve_args(root, language, packs))
    clean = {k: v for k, v in args.items() if v is not None}
    return server.ask(tool, clean)


@atexit.register
def _close_query_servers() -> None:
    for server in list(_QUERY_SERVERS.values()):
        server.close()


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
    hunt_authz: bool = False,
) -> Any:
    """Scan a file or directory for security vulnerabilities with Frame.

    Runs taint analysis plus separation logic verification and returns the
    findings as JSON. Set ``ai=True`` to add the LLM detection and triage
    layer (needs the FRAME_LLM_* environment variables). ``changed_ref`` scans
    only files that differ from a git ref; ``files`` restricts the scan to a
    list of files; ``baseline`` reports only findings absent from a baseline
    file; ``packs`` loads extra framework packs. ``hunt_authz=True`` adds the
    agentic authorization hunt (IDOR, missing authorization, privilege
    escalation; needs a model): every handler gets a verdict, and the result's
    ``hunt`` section lists how it ended and what it left unresolved. A hunt runs
    one agent per group of handlers and can take hours on a large application;
    it is bounded by its step budgets, not by a timeout. This tool does not
    modify any files.
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
        hunt_authz=hunt_authz,
    )
    timeout = None if hunt_authz else (1800.0 if ai else 300.0)
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


_ENGINE_NOTE = (
    " The first call on a project translates it (seconds to minutes on a large one); later "
    "calls answer from memory and the index rebuilds by itself when a source file changes. "
    "Every answer carries `result`, the `evidence` it rests on, the `resolution` (how a name "
    "became a function), its `limits`, the `index` it was computed over and `query_ms`."
)


def _engine_tool(title: str):
    def register(fn):
        fn.__doc__ = (fn.__doc__ or "") + _ENGINE_NOTE    # read when the tool is registered
        return mcp.tool(annotations=ToolAnnotations(title=title, readOnlyHint=True))(fn)
    return register


@_engine_tool("List the entry points the engine knows")
def engine_handlers(path: str, language: Optional[str] = None,
                    packs: Optional[list[str]] = None) -> Any:
    """Every entry point (route handler) Frame finds in the project at ``path``: name, file,
    line, whether an authorization gate or the caller's identity protects it, whether it
    reaches a resource / database, and the sink kinds it reaches."""
    return _query(path, "handlers", {}, language, packs)


@_engine_tool("Engine facts for a handler or function")
def engine_handler_facts(path: str, name: str, file: Optional[str] = None,
                         language: Optional[str] = None,
                         packs: Optional[list[str]] = None) -> Any:
    """Facts for one handler or function ``name`` (``file`` picks among same-named ones):
    protection, resource reach, sinks, decorators, parameters, the engine's own findings in
    its range, and its source."""
    return _query(path, "handler_facts", {"name": name, "file": file}, language, packs)


@_engine_tool("Sibling handlers and the guards at their data accesses")
def engine_siblings(path: str, name: str, file: Optional[str] = None,
                    language: Optional[str] = None,
                    packs: Optional[list[str]] = None) -> Any:
    """The handlers of the same class or file as ``name``, each with its gate and the
    conditions that hold at its data accesses: a sibling that checks what this one does not
    is the usual missing-authorization signal."""
    return _query(path, "siblings", {"name": name, "file": file}, language, packs)


@_engine_tool("Data flows the engine found in a function")
def engine_trace(path: str, name: str, file: Optional[str] = None,
                 language: Optional[str] = None,
                 packs: Optional[list[str]] = None) -> Any:
    """The engine's source-to-sink flows inside ``name``, each with its CWE and evidence
    level (solver-verified, data-flow, matched). A flow is listed where its sink is."""
    return _query(path, "trace", {"name": name, "file": file}, language, packs)


@_engine_tool("Who calls a function")
def engine_callers(path: str, name: str, language: Optional[str] = None,
                   packs: Optional[list[str]] = None) -> Any:
    """Every call of ``name`` across the project, with the caller, file, line and the call's
    line of code. Matched by simple name, not by type."""
    return _query(path, "callers", {"name": name}, language, packs)


@_engine_tool("What a function calls")
def engine_callees(path: str, name: str, file: Optional[str] = None,
                   language: Optional[str] = None,
                   packs: Optional[list[str]] = None) -> Any:
    """The calls ``name`` makes, each with its line of code and where the callee is defined
    in the project (several definitions = ambiguous; library calls have none)."""
    return _query(path, "callees", {"name": name, "file": file}, language, packs)


@_engine_tool("Conditions that hold on every path to a line")
def engine_guards(path: str, name: str, line: Optional[int] = None,
                  file: Optional[str] = None, language: Optional[str] = None,
                  packs: Optional[list[str]] = None) -> Any:
    """The branch conditions, authorization-gate decorators and identity scoping that hold on
    every feasible path to ``line`` in ``name`` (without ``line``: its data-access lines)."""
    return _query(path, "guards", {"name": name, "line": line, "file": file}, language, packs)


@_engine_tool("Decide a claim about a line over the feasible paths")
def engine_check(path: str, name: str, line: int, kind: str,
                 pattern: Optional[str] = None, file: Optional[str] = None,
                 language: Optional[str] = None,
                 packs: Optional[list[str]] = None) -> Any:
    """Decide a claim about ``line`` in ``name``. ``kind`` is ``guarded_by`` (every feasible
    path passes a condition or gate matching ``pattern``) or ``scoped_by_identity`` (the
    resource operation there is filtered by the caller's identity). The verdict is
    ``proved``, ``refuted`` with a witness path, or ``unknown`` when the engine has no facts."""
    return _query(path, "check", {"name": name, "line": line, "kind": kind,
                                  "pattern": pattern, "file": file}, language, packs)


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
