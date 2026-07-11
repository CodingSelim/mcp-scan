# Publishing mcp-scan

Three distribution channels. The manifests are already in the repo; these are
the one-time steps to make each live. They must be run by the repo/npm owner.

## 1. npm (the foundation for everything else)

The npm package is **`owasp-mcp-scan`** (`mcp-scan` was already taken). The
Claude Code plugin and the MCP registry entry both run `npx -y owasp-mcp-scan
--serve`, so the npm package must exist first.

```bash
npm login
npm publish            # unscoped + public; runs the build via prepublishOnly
```

Bump `version` in `package.json`, `server.json`, and the plugin manifests together on each release.

## 2. Claude Code plugin marketplace (`/plugin`)

This repo is a marketplace (`.claude-plugin/marketplace.json`) with one plugin
(`plugins/mcp-scan/`). It is live as soon as this repo is pushed to GitHub, no
extra publish step. Users run:

```
/plugin marketplace add CodingSelim/mcp-scan
/plugin install mcp-scan@mcp-scan
```

Installing adds the bundled MCP server (`plugins/mcp-scan/.mcp.json`), which runs
`npx -y owasp-mcp-scan --serve`, so it needs step 1 done to actually start.

## 3. Official MCP registry (any MCP client)

`server.json` describes the server for the tool-agnostic registry at
registry.modelcontextprotocol.io. `package.json` carries the matching
`mcpName` field the registry uses to verify npm ownership.

```bash
# one-time: install the publisher CLI
brew install mcp-publisher      # or: see modelcontextprotocol/registry releases

mcp-publisher login github      # authenticates the io.github.codingselim/* namespace
mcp-publisher publish           # validates and submits server.json
```

After this, registry-aware clients can discover mcp-scan by name.
