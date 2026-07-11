# Contributing to mcp-scan

Thanks for helping make MCP servers safer. This project values **precise,
low-false-positive detection** above raw coverage — a scanner is only useful
if its findings are trusted.

## Setup

```bash
npm install
npm run build      # tsc -> dist/
npm test           # vitest run (unit + live end-to-end fixture scans)
npm run coverage   # coverage on detection logic
```

TypeScript `strict` is the only gate (there is no separate lint step). Always
run `npm run build && npm test` before opening a PR.

## Architecture

Data flows: **connect → build `ScanContext` → run checks → score → render.**

- `src/checks/*` — one file per check. A check is **pure and isolated**: it
  takes a `ScanContext` and returns `Finding[]`, never mutating the context or
  depending on another check. `runChecks` catches throws per-check.
- `src/detectors/*` — reusable heuristics (`secrets`, `injection`, `schema`,
  `capabilities`). Prefer extending a detector over inlining regexes in checks.
- `src/types.ts` — the source of truth for `Finding`, `ScanContext`,
  `CheckCategory`, `OwaspMcpId`, and the `OWASP_TITLES` map.

`category` (scanner check family) and `owasp` (official OWASP MCP Top 10 id)
are **distinct** — never reuse one as the other.

## Adding a check

1. Create `src/checks/<name>.ts` exporting a `Check` with a unique `id`
   (a `CheckCategory`) and findings tagged with the correct `owasp` id.
2. Register it in `src/registry.ts`.
3. Add a unit test in `test/checks.test.ts`. If it should fire end-to-end,
   extend `test/fixtures/vulnerable-server.mjs` and the assertion in
   `test/e2e.test.ts`.
4. If it needs a new `CheckCategory` or `OwaspMcpId`, update `types.ts` first.

## False positives are bugs

When adding or tightening a heuristic, **add a test that pins both a true
positive and a benign case that must NOT fire.** Real-world tool descriptions
are verbose and cross-reference each other; a rule that fires on legitimate
documentation is a regression even if it also catches the attack. If you tune a
rule to kill a false positive, add the regression test alongside it.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`). Keep PRs
focused; describe the detection change and its false-positive profile.
