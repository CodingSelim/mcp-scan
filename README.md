<div align="center">

# 🛡️ mcp-scan

**Security scanner for Model Context Protocol servers.**
Point it at any running MCP server. It audits the live server against the **OWASP MCP Top 10** and grades it **A–F**.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen.svg)](https://nodejs.org)
[![CI](https://github.com/CodingSelim/mcp-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/CodingSelim/mcp-scan/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-48%20passing-brightgreen.svg)](#develop)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP%20MCP%20Top%2010-full%20coverage-blue.svg)](https://owasp.org/www-project-mcp-top-10/)

```bash
npx mcp-scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

<img src="./docs/demo.svg" alt="mcp-scan console report: an F-graded MCP server with critical findings" width="720">

</div>

---

## Why

MCP tool descriptions are fed straight into your model's context, and most public servers were never security-reviewed. A bad one can hide instructions in a description, expose a raw-shell tool, or leak a key; and your agent acts on it. Endor Labs found **82%** of servers prone to path traversal, **34%** to command injection.

**mcp-scan is the gut-check before you wire a server in.** It's passive: it reads advertised capabilities and analyzes them statically, never invoking tools, so it's safe against production servers.

## Real findings on real servers

12 popular npm servers, actual output (snapshot 2026-07-11, [full benchmark](./docs/BENCHMARK.md)):

| Server | Tools | Grade | 🔴 | 🟠 | 🟡 | Notable |
|---|---:|:---:|---:|---:|---:|---|
| `firecrawl-mcp` | 26 | **F** | 2 | 11 | 1 | **lethal trifecta** (MCP10) + `code` exec (MCP05) |
| `@modelcontextprotocol/server-filesystem` | 14 | **F** | 0 | 1 | 11 | unconstrained path params (MCP01) |
| `@modelcontextprotocol/server-puppeteer` | 7 | **F** | 1 | 2 | 0 | `script` param executes JS (MCP05) |
| `tavily-mcp` | 5 | **F** | 0 | 3 | 1 | untrusted-input + exfiltration (MCP10) |
| `@modelcontextprotocol/server-memory` | 9 | **F** | 0 | 3 | 0 | `delete_*` tools, no confirmation (MCP02) |
| `@modelcontextprotocol/server-github` | 26 | **D** | 0 | 0 | 2 | state-changing tools (MCP02) |
| `@modelcontextprotocol/server-slack` | 8 | **C** | 0 | 1 | 0 | reads + posts = data + exfil (MCP10) |
| `@modelcontextprotocol/server-everything` | 13 | **A** | 0 | 0 | 0 | clean ✓ |
| `@kazuph/mcp-fetch` | 1 | **A** | 0 | 0 | 0 | clean ✓ |

**9 of 12 flagged, 3 clean**, every row audited finding-by-finding, false positives stripped rather than padded.

## Use it

**CLI**

```bash
npx mcp-scan --stdio "<command>"                                  # local stdio server
npx mcp-scan --url https://host/mcp --header "Authorization: Bearer $TOKEN"
npx mcp-scan --config ~/.cursor/mcp.json --format sarif --output mcp.sarif
```

**As an MCP server**,  let your agent scan servers on demand (*"scan this MCP server before I add it"*). Add to any client; this `mcpServers` shape works in Claude Code, Claude Desktop, Cursor, Windsurf, VS Code, and Gemini CLI:

```json
{ "mcpServers": { "mcp-scan": { "command": "npx", "args": ["-y", "mcp-scan", "--serve"] } } }
```

OpenAI Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.mcp-scan]
command = "npx"
args = ["-y", "mcp-scan", "--serve"]
```

Exposes two tools: **`scan_mcp_server`** (audit a stdio/HTTP target) and **`list_checks`**.

**Claude Code plugin**

```
/plugin marketplace add CodingSelim/mcp-scan
/plugin install mcp-scan@mcp-scan
```

Also on the official MCP registry as `io.github.codingselim/mcp-scan`. Publishing steps: [PUBLISHING.md](./PUBLISHING.md).

## What it checks

Full **OWASP MCP Top 10 (2025)** coverage, 12 checks:

| Check | OWASP | Catches |
|---|---|---|
| `secret-exposure` | MCP01 | AWS / OpenAI / Anthropic / GitHub / GitLab / Stripe / SendGrid / npm / HF / DB URIs / JWT / private keys in advertised text |
| `transport` | MCP01 | Plaintext `http://` to a non-loopback host |
| `path-traversal` | MCP01 | `file:///{path}` templates and unconstrained path params |
| `excessive-scope` | MCP02 | Destructive tools (`delete`, `drop`, `transfer`) with no confirmation |
| `tool-poisoning` | MCP03 | Instruction overrides, hidden exfiltration directives, zero-width / Unicode-tag smuggling |
| `tool-shadowing` | MCP03 / MCP09 | Duplicate tool-name collisions and "call me first" precedence injection |
| `supply-chain` | MCP04 / MCP09 | Unpinned/placeholder versions and homoglyph server names |
| `command-injection` | MCP05 | Unconstrained `command` / `shell` / `code` params, raw SQL, advertised execution |
| `ssrf` | MCP05 | Arbitrary `url` / `host` params with no allowlist |
| `tool-poisoning` (dynamic) | MCP06 | Injection in resource contents and server instructions |
| `authn` | MCP07 | HTTP servers that complete an unauthenticated handshake |
| `telemetry` | MCP08 | High-impact tools with no audit trail (advisory, unscored) |
| `toxic-flow` | MCP10 | **Lethal trifecta**: one server that reads private data, ingests untrusted content, and can exfiltrate |

`toxic-flow` is the standout, it reasons across the whole toolset, catching the GitHub-MCP / email-agent injection shape that per-tool checks miss.

## Output & CI

`console` (default) · `json` · `sarif` (GitHub Code Scanning). Exit code is non-zero at/above `--fail-on` (default `high`), so it gates CI:

```yaml
- run: npx mcp-scan --url ${{ secrets.MCP_URL }} --format sarif --output mcp.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: mcp.sarif }
```

## Notes

- Static analysis can't see runtime sandboxing, a server that safely confines paths still flags them. Verify against actual enforcement.
- Auth and transport checks apply to HTTP targets only.
- Heuristics favor recall; triage findings in context.
- Scanning a stdio target spawns that command, so run it only on servers you trust.

## Develop

```bash
npm install && npm run build && npm test   # 48 tests, incl. live end-to-end fixture scans
```

Checks are pure and isolated (`src/checks/`), reusing detectors in `src/detectors/`. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## References

[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) · [MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html) · [Vulnerable MCP Project](https://vulnerablemcp.info/) · [MCPTox](https://arxiv.org/pdf/2508.14925)

MIT © [CodingSelim](https://github.com/CodingSelim)
