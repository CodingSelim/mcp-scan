# Security Policy

`mcp-scan` is a **passive** auditor: it connects to an MCP server, reads the
capabilities the server advertises, and analyzes them statically. It never
invokes tools, fuzzes inputs, or sends exploit payloads, so running it against
a production server is safe.

## Scope & threat model

- **What it sees:** tool / prompt / resource descriptions, input schemas,
  server instructions, and transport facts gathered during the handshake.
- **What it does not do:** call tools, follow URLs, read files, or execute
  anything on the target. Findings are derived only from advertised metadata.
- **Where it runs:** for `--stdio` targets it spawns the given command as a
  local child process. Only scan commands you trust — the child runs with your
  privileges. For `--url` targets nothing is executed locally.

## Reporting a vulnerability in mcp-scan itself

If you find a security issue in this tool (for example, a way a malicious
server could exploit the scanner during a scan), please **do not open a public
issue**. Instead use GitHub's private vulnerability reporting:

> Repository → **Security** tab → **Report a vulnerability**

Please include reproduction steps and the affected version. We aim to
acknowledge reports within 5 business days.

## Supported versions

The latest published `0.x` release receives fixes. `mcp-scan` is pre-1.0;
detection heuristics may change between minor versions.
