# mcp-scan benchmark: real published servers

These are **actual `mcp-scan` results** against popular MCP servers pulled live from npm, with no
synthetic inputs and no cherry-picking. Reproduce any row with the command shown. Every server was
spawned as a real stdio MCP server and scanned end-to-end.

Snapshot date: **2026-07-11**, mcp-scan **0.2.0** (package versions drift, so re-run to confirm).

| Server (npm) | Tools | Grade | 🔴 Crit | 🟠 High | 🟡 Med | ⚪ Low | OWASP categories |
|---|---:|:---:|---:|---:|---:|---:|---|
| `firecrawl-mcp` | 26 | **F** | 2 | 11 | 1 | 1 | MCP01, MCP02, MCP05, MCP08, **MCP10** |
| `@modelcontextprotocol/server-filesystem` | 14 | **F** | 0 | 1 | 11 | 2 | MCP01, MCP02, MCP08 |
| `@modelcontextprotocol/server-puppeteer` | 7 | **F** | 1 | 2 | 0 | 0 | MCP05, MCP08 |
| `tavily-mcp` | 5 | **F** | 0 | 3 | 1 | 0 | MCP02, MCP05, MCP08, **MCP10** |
| `@modelcontextprotocol/server-memory` | 9 | **F** | 0 | 3 | 0 | 2 | MCP02, MCP08 |
| `@modelcontextprotocol/server-github` | 26 | **D** | 0 | 0 | 2 | 9 | MCP01, MCP02 |
| `@upstash/context7-mcp` | 2 | **D** | 0 | 2 | 0 | 0 | MCP02, MCP08 |
| `@modelcontextprotocol/server-slack` | 8 | **C** | 0 | 1 | 0 | 0 | MCP08, **MCP10** |
| `@browsermcp/mcp` | 12 | **C** | 0 | 1 | 0 | 0 | MCP05 |
| `@modelcontextprotocol/server-everything` | 13 | **A** | 0 | 0 | 0 | 0 | clean |
| `@modelcontextprotocol/server-sequential-thinking` | 1 | **A** | 0 | 0 | 0 | 0 | clean |
| `@kazuph/mcp-fetch` | 1 | **A** | 0 | 0 | 0 | 0 | clean |

**9 of 12 servers flagged; 3 graded clean.** The scanner discriminates by real risk; it is not a
blanket fail machine, and three widely-used servers pass cleanly.

## Headline findings

**1. `firecrawl-mcp` combines the lethal trifecta (OWASP MCP10).** It exposes tools that read local
data (`firecrawl_parse` takes a `filePath`), ingest untrusted web content (`firecrawl_scrape`,
`firecrawl_crawl`, `firecrawl_search`), and reach arbitrary external URLs. A prompt injection buried
in scraped content can drive the agent to read local data and ship it out, with no code exploit needed.
This is the same capability shape behind the 2025 GitHub-MCP and email-agent injection incidents.

```
CRITICAL  Server combines the lethal trifecta (private data + untrusted input + exfiltration)
          [OWASP MCP10 · toxic-flow/lethal-trifecta]
          evidence: reads private data (firecrawl_parse) · ingests untrusted content
          (firecrawl_scrape, firecrawl_search, firecrawl_crawl +2 more) · exfiltrates externally (...)
```

**2. Model-supplied code with no schema constraint (OWASP MCP05).** Both `firecrawl-mcp`
(`firecrawl_interact`, `code` param) and `@modelcontextprotocol/server-puppeteer`
(`puppeteer_evaluate`, `script` param) accept free-form code or scripts that execute, a textbook
injection sink an autonomous agent can be steered into.

```
CRITICAL  Tool 'firecrawl_interact' takes an unconstrained command parameter
          [OWASP MCP05 · command-injection/unconstrained-command-param]
          evidence: param 'code': string (unconstrained)
```

**3. `tavily-mcp` and `@modelcontextprotocol/server-slack` show partial toxic flows (MCP10).** Slack
reads messages/channels and can post externally (`private-data-plus-exfiltration`, high); Tavily
ingests web content and can reach external URLs (`untrusted-input-plus-exfiltration`, medium). Each
is one capability away from the full trifecta.

## Reproduce

```bash
npx mcp-scan --stdio "npx -y firecrawl-mcp"                                   # F: trifecta + code exec
npx mcp-scan --stdio "npx -y @modelcontextprotocol/server-puppeteer"         # F: script exec
npx mcp-scan --stdio "npx -y tavily-mcp"                                      # F: toxic flow
npx mcp-scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"   # F: path params
npx mcp-scan --stdio "npx -y @modelcontextprotocol/server-everything"        # A: clean
```

(Servers that gate tool *calls* behind an API key still enumerate their tool *definitions* on
connect, which is all a passive scan reads, so pass a placeholder env var where one is required.)

## Precision: what we deliberately do NOT flag

A scanner is only useful if its findings are trusted, so this benchmark was audited finding-by-finding
and several false-positive classes were removed rather than shipped for a scarier table:

- **URLs and file paths** in descriptions are high-entropy but are not secrets, so they are excluded
  from the secret detector.
- **Non-Latin prose** (for example Japanese tool descriptions) is high-entropy per character, so it
  is excluded and no longer mistaken for a credential.
- **Geographic `location` params** are no longer classified as filesystem paths (they were inflating
  path-traversal counts on web servers like `firecrawl`).
- **Benign multi-tool routing guidance** ("use `crawl` instead of `scrape` for a whole site") is
  common in good documentation and is **not** treated as cross-tool poisoning. Only objective
  signals trip the shadowing check: duplicate tool names and explicit "call me before every other
  tool" precedence directives.

## Notes on static analysis

`mcp-scan` reads what a server advertises; it does not exploit. Two consequences visible above:

- The filesystem server sandboxes paths to allowed roots at runtime; the scanner still flags its
  unconstrained path params (MCP01) because it cannot observe that enforcement. Verify against the
  server's actual guardrails.
- MCP08 (audit/telemetry) findings are advisory (`info`, unscored): the protocol has no standard
  audit trail, so exposure to high-impact tools is flagged as a gap to verify, not a proven defect.
