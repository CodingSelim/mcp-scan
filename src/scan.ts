import type { ScanContext, ScanResult } from "./types.js";
import { runChecks, ALL_CHECKS } from "./registry.js";
import { countBySeverity, computeScore, gradeFor, sortFindings } from "./score.js";
import { buildScanContext, type Target } from "./connect.js";

export async function scanContext(ctx: ScanContext): Promise<ScanResult> {
  const { findings, errors } = await runChecks(ctx, ALL_CHECKS);
  const sorted = sortFindings(findings);
  const counts = countBySeverity(sorted);
  const score = computeScore(sorted);

  return {
    target: ctx.target,
    serverInfo: ctx.serverInfo,
    findings: sorted,
    score,
    grade: gradeFor(score, counts),
    counts,
    stats: {
      tools: ctx.tools.length,
      prompts: ctx.prompts.length,
      resources: ctx.resources.length,
      resourceTemplates: ctx.resourceTemplates.length,
    },
    errors,
  };
}

export async function scanTarget(target: Target): Promise<ScanResult> {
  const ctx = await buildScanContext(target);
  return scanContext(ctx);
}
