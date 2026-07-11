import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "../types.js";

const SEV_LABEL: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(pc.bold(s))),
  high: (s) => pc.red(pc.bold(s)),
  medium: (s) => pc.yellow(s),
  low: (s) => pc.cyan(s),
  info: (s) => pc.gray(s),
};

const GRADE_COLOR: Record<ScanResult["grade"], (s: string) => string> = {
  A: (s) => pc.green(pc.bold(s)),
  B: (s) => pc.green(s),
  C: (s) => pc.yellow(s),
  D: (s) => pc.red(s),
  F: (s) => pc.bgRed(pc.white(pc.bold(s))),
};

function sevTag(sev: Severity): string {
  return SEV_LABEL[sev](` ${sev.toUpperCase()} `);
}

export function renderConsole(result: ScanResult): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(pc.bold(pc.white("  mcp-scan — MCP Security Report")));
  lines.push(pc.gray(`  Target: ${result.target}`));
  if (result.serverInfo?.name) {
    lines.push(pc.gray(`  Server: ${result.serverInfo.name} ${result.serverInfo.version ?? ""}`));
  }
  lines.push(
    pc.gray(
      `  Surface: ${result.stats.tools} tools, ${result.stats.prompts} prompts, ${result.stats.resources} resources, ${result.stats.resourceTemplates} templates`,
    ),
  );
  lines.push("");

  const { counts } = result;
  const summary = `  ${sevTag("critical")} ${counts.critical}   ${sevTag("high")} ${counts.high}   ${sevTag("medium")} ${counts.medium}   ${sevTag("low")} ${counts.low}   ${sevTag("info")} ${counts.info}`;
  lines.push(summary);
  lines.push("");
  lines.push(
    `  Risk score: ${pc.bold(String(result.score))}/100    Grade: ${GRADE_COLOR[result.grade](` ${result.grade} `)}`,
  );
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(pc.green("  ✓ No security findings detected."));
  } else {
    lines.push(pc.bold(`  Findings (${result.findings.length}):`));
    lines.push("");
    result.findings.forEach((f, i) => lines.push(renderFinding(f, i + 1)));
  }

  if (result.errors.length > 0) {
    lines.push("");
    lines.push(pc.yellow(`  ⚠ ${result.errors.length} check error(s):`));
    for (const e of result.errors) lines.push(pc.gray(`    - ${e}`));
  }

  lines.push("");
  return lines.join("\n");
}

function renderFinding(f: Finding, n: number): string {
  const out: string[] = [];
  out.push(`  ${pc.dim(String(n).padStart(2, "0"))} ${sevTag(f.severity)} ${pc.bold(f.title)}  ${pc.dim(`[${f.checkId}/${f.rule}]`)}`);
  out.push(`      ${pc.gray("where:")} ${f.location}`);
  out.push(`      ${wrap(f.description, "      ")}`);
  if (f.evidence) out.push(`      ${pc.dim("evidence: " + truncate(f.evidence, 160))}`);
  out.push(`      ${pc.green("fix:")} ${wrap(f.remediation, "      ")}`);
  out.push("");
  return out.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function wrap(text: string, indent: string, width = 90): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let cur = "";
  for (const w of words) {
    if ((cur + " " + w).trim().length > width) {
      lines.push(cur.trim());
      cur = w;
    } else {
      cur += " " + w;
    }
  }
  if (cur.trim()) lines.push(cur.trim());
  return lines.join("\n" + indent);
}
