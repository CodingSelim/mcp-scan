import type { ScanResult } from "../types.js";

export function renderJson(result: ScanResult): string {
  return JSON.stringify(
    {
      tool: "mcp-scan",
      version: "0.1.0",
      target: result.target,
      server: result.serverInfo ?? null,
      score: result.score,
      grade: result.grade,
      counts: result.counts,
      stats: result.stats,
      findings: result.findings,
      errors: result.errors,
    },
    null,
    2,
  );
}
