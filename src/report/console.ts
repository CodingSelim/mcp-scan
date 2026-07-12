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

const RULE_W = 66;
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// A section header: a label followed by a dim rule that fills the width.
function ruleLine(plainLabel: string, coloredLabel: string): string {
  const dashes = Math.max(0, RULE_W - plainLabel.length - 1);
  return `${GUTTER}${coloredLabel} ${pc.dim("─".repeat(dashes))}`;
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
    const total = result.findings.length;
    lines.push(ruleLine(`FINDINGS  ${total}`, `${pc.bold(pc.yellow("FINDINGS"))}  ${pc.dim(String(total))}`));
    lines.push("");

    let n = 0;
    for (const sev of SEV_ORDER) {
      const group = result.findings.filter((f) => f.severity === sev);
      if (group.length === 0) continue;
      const badge = SEV_TAG[sev](` ${sev.toUpperCase()} `);
      const plain = ` ${sev.toUpperCase()}   ${group.length}`;
      lines.push(ruleLine(plain, `${badge}  ${pc.dim(String(group.length))}`));
      lines.push("");
      for (const f of group) {
        n += 1;
        lines.push(renderFinding(f, n));
      }
    }
  }

  if (result.errors.length > 0) {
    lines.push(
      ruleLine("CHECK ERRORS", `${logSymbols.warning} ${pc.yellow(`${result.errors.length} check error(s)`)}`),
    );
    for (const e of result.errors) lines.push(`${GUTTER}${pc.dim(`  ${e}`)}`);
    lines.push("");
  }

  lines.push("");
  return lines.join("\n");
}

// One finding, laid out as a title line plus an aligned label column under a severity-colored gutter.
function renderFinding(f: Finding, n: number): string {
  const bar = SEV_PAINT[f.severity]("▎");
  const idx = pc.dim(String(n).padStart(2, "0"));
  const sub = `${GUTTER}${bar}      `; // sub-line indent, keeps the gutter bar running down
  const valueIndent = sub + " ".repeat(10); // wrapped continuation lines align under the value column
  const label = (t: string): string => pc.dim(t.padEnd(10));

  const out: string[] = [];
  out.push(`${GUTTER}${bar}  ${idx}  ${pc.bold(f.title)}`);
  out.push(`${sub}${pc.dim(`${f.owasp} · ${f.category}/${f.rule}`)}`);
  out.push(`${sub}${label("where")}${f.location}`);
  out.push(`${sub}${label("detail")}${wrap(f.description, valueIndent, 74)}`);
  if (f.evidence) out.push(`${sub}${label("evidence")}${pc.dim(truncate(f.evidence, 140))}`);
  out.push(`${sub}${label("fix")}${pc.yellow(wrap(f.remediation, valueIndent, 74))}`);
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
