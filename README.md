# frame-mcp

mcp-name: io.github.lambdasec/frame-mcp

An MCP server that exposes the [Frame](https://github.com/lambdasec/frame) security scanner to any MCP client, so a coding agent can scan code, verify fixes, and reason about vulnerabilities over stdio.

Frame combines taint analysis with separation logic verification to find data-flow vulnerabilities (SQL injection, command injection, path traversal, and more), and checks each reported path with a solver. This package wraps the `frame` command line program as MCP tools. It launches `frame` as a subprocess with an explicit argument list, never a shell, and prefers the `frame` executable installed next to the running Python interpreter.

## Install

Run directly with uvx (no separate install step):

```bash
uvx frame-mcp
```

### Claude Code

```bash
claude mcp add frame -- uvx frame-mcp
```

### Codex

Add this stanza to `~/.codex/config.toml`:

```toml
[mcp_servers.frame]
command = "uvx"
args = ["frame-mcp"]
```

### Cursor

Create `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "frame": {
      "command": "uvx",
      "args": ["frame-mcp"]
    }
  }
}
```

### VS Code

Create `.vscode/mcp.json`:

```json
{
  "servers": {
    "frame": {
      "type": "stdio",
      "command": "uvx",
      "args": ["frame-mcp"]
    }
  }
}
```

### Windsurf

Add to `~/.codeium/windsurf/mcp_config.json` under the `mcpServers` key:

```json
{
  "mcpServers": {
    "frame": {
      "command": "uvx",
      "args": ["frame-mcp"]
    }
  }
}
```

### Gemini CLI

Add to `~/.gemini/settings.json` under the `mcpServers` key:

```json
{
  "mcpServers": {
    "frame": {
      "command": "uvx",
      "args": ["frame-mcp"]
    }
  }
}
```

### Zed

Add to Zed `settings.json` under `context_servers`:

```json
{
  "context_servers": {
    "frame": {
      "command": {
        "path": "uvx",
        "args": ["frame-mcp"]
      }
    }
  }
}
```

## Tools

| Tool | Purpose | Read only |
| --- | --- | --- |
| `scan` | Scan a file or directory for vulnerabilities and return findings as JSON. | yes |
| `write_baseline` | Scan a path and record the findings as a baseline file. | no |
| `verify` | Re-scan the files behind earlier findings and report whether each is fixed. | yes |
| `fix` | Generate and verify fixes for findings. Returns a diff by default. | no |
| `exploit` | Drive an agent to exploit a live, authorized target. | no |
| `packs_list` | List the framework packs a scan would load. | yes |
| `packs_check` | Validate framework pack files. | yes |
| `solve` | Check a separation logic entailment `P \|- Q`. | yes |

A `security-review` prompt chains `scan` (with the AI layer), `verify`, and an offer to `fix`.

## AI features and environment variables

The `scan` tool with `ai=true`, along with `fix` and `exploit`, call an LLM through an OpenAI-compatible endpoint. Configure it with these environment variables in the MCP client that launches the server:

| Variable | Purpose |
| --- | --- |
| `FRAME_LLM_BASE_URL` | Base URL of the LLM endpoint, for example a local server or a hosted API. |
| `FRAME_LLM_API_KEY` | API key for the endpoint, when it requires one. |
| `FRAME_LLM_MODEL` | Model name to request. |
| `FRAME_LLM_REPO_ROOT` | Repository root for relative path resolution. |

These are inherited from the server process environment and forwarded to each `frame` subprocess. The plain `scan` (taint analysis plus verification) needs none of them.

## Exploit authorization

The `exploit` tool drives an autonomous agent that sends live traffic to a target. Run it only against systems you own or are explicitly authorized to test. Unauthorized testing of systems you do not control may be illegal.

## License

Apache-2.0. See [LICENSE](LICENSE).
