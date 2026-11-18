# Frame for Hermes Agent

[Frame](https://github.com/lambdasec/frame) is a verification-driven security agent: it finds data-flow vulnerabilities (SQL injection, command injection, XSS, path traversal, SSRF, deserialization and more) by taint analysis, and checks each reported path with the Z3 solver, in Python, JavaScript/TypeScript, Java, C# and C/C++. This directory is an Agent Plugins v1 package (`plugin.json`, `mcp.json`, `skills/`), configuration only: it runs this repository's MCP server, [frame-mcp](../README.md), and adds a `frame:frame` skill that tells the agent when and how to use it.

```bash
hermes plugins install frame
hermes plugins enable frame
```

## Tools

`scan`, `verify`, `packs_list`, `packs_check`, `solve` and the `engine_*` queries are read-only. `write_baseline` writes a baseline file, `fix` can write the fixes it proposes (`in_place`), and `exploit` drives an agent against a live target you are authorized to test. The package marks the server `untrusted`, so Hermes asks before each of those three and refuses them in unattended runs. Scans of large projects take minutes, so the package raises this server's tool-call timeout to 30 minutes.

## What it does on your machine

- **Download:** the server runs as `uvx --from frame-mcp==0.3.0 --with "frame-security[scan]==1.1.7" frame-mcp`. On first run uv downloads those two packages and their dependencies from PyPI (Apache-2.0); they are pinned by version here, but not covered by the catalog's commit pin. It needs `uv` on the host.
- **Files:** it reads the source files you ask it to scan. `write_baseline` writes the baseline file you name; `fix` writes files only with `in_place`. Frame's knowledge-base and advisory caches live under `~/.cache/frame`.
- **Network:** a scan makes no network calls. `scan` with `ai` or `hunt_authz`, `fix` and `exploit` send source code to the OpenAI-compatible endpoint you configure, and nothing happens without one. `exploit` sends requests to the target you name.
- **Credentials:** it reads none itself. For the model features, set `FRAME_LLM_BASE_URL`, `FRAME_LLM_MODEL` and `FRAME_LLM_API_KEY` in your shell or Hermes profile `.env`; the package passes only those three to the server, and only when they are set.
- **Processes:** the `engine_*` tools keep one `frame query --serve` process per project for the session, so later queries answer from memory.
- No telemetry.
