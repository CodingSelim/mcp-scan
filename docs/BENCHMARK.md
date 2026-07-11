# mcp-scan benchmark — real published servers

These are **actual `mcp-scan` results** against popular MCP servers pulled live from npm.
Reproduce any row with the command shown. Snapshot date: **2026-07-11** (package versions drift, so re-run to confirm).

| Server (npm) | Tools | Grade | Critical | High | Medium | Low | OWASP categories |
|---|---:|:---:|---:|---:|---:|---:|---|
| `firecrawl-mcp` | 26 | **F** | 1 | 11 | 12 | 1 | MCP01, MCP02, MCP05 |
| `@modelcontextprotocol/server-filesystem` | 14 | **F** | 0 | 1 | 11 | 2 | MCP01, MCP02 |
| `@modelcontextprotocol/server-memory` | 9 | **F** | 0 | 3 | 0 | 2 | MCP02 |
| `@modelcontextprotocol/server-github` | 26 | **D** | 0 | 0 | 2 | 9 | MCP01, MCP02 |
| `@kazuph/mcp-fetch` | 1 | **C** | 0 | 4 | 0 | 0 | MCP01 |
| `@modelcontextprotocol/server-everything` | 13 | **A** | 0 | 0 | 0 | 0 | — (clean) |
| `@modelcontextprotocol/server-sequential-thinking` | 1 | **A** | 0 | 0 | 0 | 0 | — (clean) |

**5 of 7 servers flagged; 2 graded clean.** The scanner discriminates — it is not a blanket fail machine.

## Headline finding

`firecrawl-mcp`'s `firecrawl_interact` tool exposes an unconstrained `code` string parameter
(**OWASP MCP05 — Command Injection & Execution**). Model-supplied code reaching an interpreter
with no schema constraint is a textbook injection sink.

```
CRITICAL  Tool 'firecrawl_interact' takes an unconstrained command parameter
          [OWASP MCP05 · command-injection/unconstrained-command-param]
          evidence: param 'code': string (unconstrained)
```

## Reproduce

```bash
npx mcp-scan --stdio "npx -y firecrawl-mcp" --fail-on none
npx mcp-scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"
npx mcp-scan --stdio "npx -y @modelcontextprotocol/server-memory"
```

## Notes on precision

`mcp-scan` performs **static capability analysis** — it reads what a server advertises, it does
not exploit. Two consequences visible in this table:

- The filesystem server sandboxes paths to allowed roots at runtime; the scanner still flags its
  unconstrained path params (MCP01) because it cannot observe that enforcement. Verify against the
  server's actual guardrails.
- Findings favor recall. Every finding ships with evidence and a remediation so you can triage in
  context.
