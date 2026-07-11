import type { Finding, ScanResult, Severity } from "./types.js";
import { SEVERITY_ORDER, SEVERITY_WEIGHT } from "./types.js";

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function computeScore(findings: readonly Finding[]): number {
  const raw = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return Math.min(100, raw);
}

export function gradeFor(score: number, counts: Record<Severity, number>): ScanResult["grade"] {
  if (counts.critical > 0) return "F";
  if (score >= 60) return "F";
  if (score >= 40) return "D";
  if (score >= 20) return "C";
  if (score >= 1) return "B";
  return "A";
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySev = severityRank(a.severity) - severityRank(b.severity);
    if (bySev !== 0) return bySev;
    return a.checkId.localeCompare(b.checkId);
  });
}
