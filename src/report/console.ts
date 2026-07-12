import pc from "picocolors";
import gradient from "gradient-string";
import logSymbols from "log-symbols";
import boxen from "boxen";
import figures from "figures";
import Table from "cli-table3";
import type { Finding, ScanResult, Severity } from "../types.js";

const BRAND = gradient(["#fde047", "#facc15", "#f59e0b"]);
const GUTTER = "  "; // left page margin
const indent = (block: string, pad = GUTTER): string =>
  block
    .split("\n")
    .map((l) => pad + l)
    .join("\n");

// Black and yellow theme. Severity reads through yellow intensity plus an inverted badge for critical.
const SEV_TAG: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  high: (s) => pc.yellow(pc.bold(s)),
  medium: (s) => pc.yellow(s),
  low: (s) => pc.dim(pc.yellow(s)),
  info: (s) => pc.gray(s),
};

const SEV_PAINT: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bold(pc.yellow(s)),
  high: (s) => pc.yellow(s),
  medium: (s) => pc.yellow(s),
  low: (s) => pc.dim(pc.yellow(s)),
  info: (s) => pc.gray(s),
};

const GRADE_BADGE: Record<ScanResult["grade"], (s: string) => string> = {
  A: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  B: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  C: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  D: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  F: (s) => pc.bgYellow(pc.black(pc.bold(s))),
};

const gradePaint = (_g: ScanResult["grade"]): ((s: string) => string) => (s) => pc.bold(pc.yellow(s));

function sevTag(sev: Severity): string {
  return SEV_TAG[sev](` ${sev.toUpperCase()} `);
}

function header(): string {
  const title = `${BRAND("◆ mcp-scan")}   ${pc.dim("MCP Security Report")}`;
  const box = boxen(title, {
    padding: { top: 0, bottom: 0, left: 2, right: 2 },
    borderStyle: "round",
    borderColor: "yellow",
  });
  return indent(box);
}

function metaRow(label: string, value: string): string {
  return `${GUTTER}${pc.dim(figures.pointerSmall)} ${pc.dim(label.padEnd(8))}${value}`;
}

function severityTable(counts: Record<Severity, number>): string {
  const table = new Table({
    head: [
      pc.bgYellow(pc.black(pc.bold(" CRITICAL "))),
      pc.yellow(pc.bold("HIGH")),
      pc.yellow("MEDIUM"),
      pc.dim(pc.yellow("LOW")),
      pc.gray("INFO"),
    ],
    colAligns: ["center", "center", "center", "center", "center"],
    // cli-table3 forces its own border color and ignores NO_COLOR, so only enable it when color is supported.
    style: { head: [], border: pc.isColorSupported ? ["gray"] : [] },
  });
  const cell = (sev: Severity): string =>
    counts[sev] > 0 ? SEV_PAINT[sev](pc.bold(String(counts[sev]))) : pc.dim("0");
  table.push([cell("critical"), cell("high"), cell("medium"), cell("low"), cell("info")]);
  return indent(table.toString());
}

function scoreMeter(score: number, grade: ScanResult["grade"]): string {
  const barW = 22;
  const filled = Math.round((score / 100) * barW);
  const paint = gradePaint(grade);
  const bar = paint("█".repeat(filled)) + pc.dim("░".repeat(barW - filled));
  return (
    `${GUTTER}${pc.dim("Risk score:")}  ${bar}  ${pc.bold(String(score))}${pc.dim("/100")}` +
    `     ${pc.dim("Grade")}  ${GRADE_BADGE[grade](` ${grade} `)}`
  );
}

export function renderConsole(result: ScanResult): string {
  const lines: string[] = [""];
  lines.push(header());
  lines.push("");

  lines.push(metaRow("Target", result.target));
  if (result.serverInfo?.name) {
    lines.push(metaRow("Server", `${result.serverInfo.name} ${result.serverInfo.version ?? ""}`.trim()));
  }
  const { stats } = result;
  lines.push(
    metaRow(
      "Surface",
      pc.gray(
        `${stats.tools} tools · ${stats.prompts} prompts · ${stats.resources} resources · ${stats.resourceTemplates} templates`,
      ),
    ),
  );
  lines.push("");

  lines.push(severityTable(result.counts));
  lines.push("");
  lines.push(scoreMeter(result.score, result.grade));
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(`${GUTTER}${logSymbols.success}  ${pc.bold("No security findings detected.")}`);
    lines.push(`${GUTTER}${pc.dim("This server passed every OWASP MCP Top 10 check.")}`);
  } else {
    lines.push(`${GUTTER}${pc.bold("Findings")} ${pc.dim(`(${result.findings.length})`)}`);
    lines.push("");
    result.findings.forEach((f, i) => lines.push(renderFinding(f, i + 1)));
  }

  if (result.errors.length > 0) {
    lines.push("");
    lines.push(`${GUTTER}${logSymbols.warning}  ${pc.yellow(`${result.errors.length} check error(s):`)}`);
    for (const e of result.errors) lines.push(`${GUTTER}${pc.dim(`  ${e}`)}`);
  }

  lines.push("");
  return lines.join("\n");
}

function renderFinding(f: Finding, n: number): string {
  const bar = SEV_PAINT[f.severity]("▎");
  const idx = pc.dim(String(n).padStart(2, "0"));
  const tag = pc.dim(`[OWASP ${f.owasp} · ${f.category}/${f.rule}]`);
  const guide = `${GUTTER}${bar}     `;

  const out: string[] = [];
  out.push(`${GUTTER}${bar} ${idx} ${sevTag(f.severity)} ${pc.bold(f.title)}`);
  out.push(`${guide}${tag}`);
  out.push(`${guide}${pc.dim(figures.arrowRight)} ${pc.dim("where")}  ${f.location}`);
  out.push(`${guide}${wrap(f.description, guide)}`);
  if (f.evidence) out.push(`${guide}${pc.dim(figures.arrowRight)} ${pc.dim("evidence")}  ${pc.dim(truncate(f.evidence, 160))}`);
  out.push(`${guide}${pc.yellow(figures.tick)} ${pc.yellow("fix")}  ${wrap(f.remediation, guide)}`);
  out.push("");
  return out.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function wrap(text: string, indentStr: string, width = 84): string {
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
  return lines.join("\n" + indentStr);
}
