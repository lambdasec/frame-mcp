---
name: frame
description: Find and verify security vulnerabilities in a codebase with Frame. Use it when the user asks for a security review, asks whether code is vulnerable (SQL injection, command injection, XSS, path traversal, SSRF, deserialization, authorization flaws), wants a fix checked, or before merging code that handles request data. Needs the frame MCP server (scan, verify, fix, write_baseline, engine_* tools).
license: Apache-2.0
compatibility: Needs the frame MCP server (uvx frame-mcp, Python 3.10 or later, uv). The ai, hunt_authz, fix and exploit options need an OpenAI-compatible endpoint in FRAME_LLM_BASE_URL, FRAME_LLM_MODEL and FRAME_LLM_API_KEY; everything else runs locally with no model and no key.
---

# Frame security review

Frame finds data-flow vulnerabilities by taint analysis and checks each reported path with an SMT solver, so a finding marked `solver-verified` has a feasible path from attacker data to the sink. It reads Python, JavaScript/TypeScript, Java, C# and C/C++.

## Reviewing code

1. Call `scan` on the directory (or file). Leave `ai` off first: the result is deterministic and needs no model.
2. Report findings by severity. For each, give the file and line, the CWE, the source and sink, and the `evidence` (`solver-verified` is a feasible path; `data-flow` is unverified; `matched` is a pattern).
3. For a finding you are unsure about, use the engine: `engine_trace` (the flows in a function), `engine_guards` (what holds on every path to a line), `engine_callers` (who calls it).
4. Only with an LLM endpoint configured: `scan` with `ai: true` adds detection and triage, and `hunt_authz: true` hunts authorization flaws (IDOR, missing checks).

## Fixing

- `fix` proposes fixes and re-checks them; it returns a diff by default. Apply one only when the user agrees (`in_place` writes files).
- After a change, call `verify` with the earlier findings: each comes back `fixed`, `present`, `suppressed` or `uncertain`.
- `write_baseline` records today's findings so later scans report only new ones.

## Authorization questions

`engine_handlers` lists every entry point with whether it is protected and what it reaches. `engine_check` decides a claim about a line (`guarded_by` a pattern, `scoped_by_identity`): proved, refuted with a witness path, or unknown. Say which: never present an unknown as proved.

## Do not

- Do not call `exploit` unless the user owns the target or is explicitly authorized to test it, and says so.
- Do not call a finding a false positive without reading the code path it names.
