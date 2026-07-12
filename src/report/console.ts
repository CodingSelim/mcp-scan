import pc from "picocolors";
import cfonts from "cfonts";
import boxen from "boxen";
import figures from "figures";
import logSymbols from "log-symbols";
import cliTruncate from "cli-truncate";
import stringWidth from "string-width";
import Table from "cli-table3";
import type { Finding, ScanResult, Severity } from "../types.js";

// Responsive to the terminal, clamped so it stays tidy on very wide or very narrow windows.
const COLS = Math.min(Math.max(process.stdout.columns || 96, 72), 120);
const GUTTER = "  ";
const INNER = COLS - GUTTER.length * 2;
const RULE_W = Math.min(INNER, 72);

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

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

const indent = (block: string, pad = GUTTER): string =>
  block
    .split("\n")
    .map((l) => pad + l)
    .join("\n");

// A section header: a label followed by a dim rule that fills the width.
function ruleLine(coloredLabel: string): string {
  const dashes = Math.max(0, RULE_W - stringWidth(coloredLabel) - 1);
  return `${GUTTER}${coloredLabel} ${pc.dim("─".repeat(dashes))}`;
}

function banner(): string {
  const rendered = cfonts.render("mcp-scan", { font: "tiny", colors: ["yellow"], space: false, env: "node" });
  const art = (rendered ? rendered.string : "mcp-scan").replace(/^\n+|\n+$/g, "");
  const lines = indent(art).split("\n");
  lines.push(`${GUTTER}${pc.dim("MCP Security Report")}   ${pc.dim(figures.pointerSmall)}   ${pc.dim("OWASP MCP Top 10 audit")}`);
  return lines.join("\n");
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

function verdictPanel(score: number, grade: ScanResult["grade"]): string {
  const barW = 20;
  const filled = Math.round((score / 100) * barW);
  const bar = pc.bold(pc.yellow("█".repeat(filled))) + pc.dim("░".repeat(barW - filled));
  const text =
    `${pc.dim("Grade")}  ${GRADE_BADGE[grade](` ${grade} `)}     ` +
    `${pc.dim("Risk score:")} ${bar} ${pc.bold(String(score))}${pc.dim("/100")}`;
  const box = boxen(text, {
    padding: { top: 0, bottom: 0, left: 1, right: 1 },
    borderStyle: "round",
    borderColor: "yellow",
  });
  return indent(box);
}

export function renderConsole(result: ScanResult): string {
  const lines: string[] = [""];
  lines.push(banner());
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
  lines.push(verdictPanel(result.score, result.grade));
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(`${GUTTER}${logSymbols.success}  ${pc.bold("No security findings detected.")}`);
    lines.push(`${GUTTER}${pc.dim("This server passed every OWASP MCP Top 10 check.")}`);
  } else {
    const total = result.findings.length;
    lines.push(ruleLine(`${pc.bold(pc.yellow("FINDINGS"))}  ${pc.dim(String(total))}`));
    lines.push("");

    let n = 0;
    for (const sev of SEV_ORDER) {
      const group = result.findings.filter((f) => f.severity === sev);
      if (group.length === 0) continue;
      lines.push(ruleLine(`${SEV_TAG[sev](` ${sev.toUpperCase()} `)}  ${pc.dim(String(group.length))}`));
      lines.push("");
      for (const f of group) {
        n += 1;
        lines.push(renderFinding(f, n));
      }
    }
  }

  if (result.errors.length > 0) {
    lines.push(ruleLine(`${logSymbols.warning} ${pc.yellow(`${result.errors.length} check error(s)`)}`));
    for (const e of result.errors) lines.push(`${GUTTER}${pc.dim(`  ${e}`)}`);
    lines.push("");
  }

  if (result.findings.length > 0) {
    lines.push(`${GUTTER}${pc.dim(`${figures.pointerSmall} full descriptions and remediation: --format json or sarif`)}`);
  }

  lines.push("");
  return lines.join("\n");
}

// One finding as a compact card: bold title, a dim meta line, then the fix. Yellow is an accent only.
function renderFinding(f: Finding, n: number): string {
  const pad = `${GUTTER}  `; // 4 cols, findings sit under their severity header
  const sub = `${pad}    `; // 8 cols, aligns sub-lines under the title text
  const idx = pc.yellow(String(n).padStart(2, "0"));
  const valueBudget = Math.max(28, INNER - 18);

  const out: string[] = [];
  out.push(`${pad}${idx}  ${pc.bold(cliTruncate(oneLine(f.title), INNER - 6))}`);
  out.push(`${sub}${pc.dim(cliTruncate(`${oneLine(f.location)}   ${f.owasp} ${f.category}/${f.rule}`, INNER - 8))}`);
  if (f.evidence) out.push(`${sub}${pc.dim(`evidence  ${cliTruncate(oneLine(f.evidence), valueBudget)}`)}`);
  out.push(`${sub}${pc.yellow("fix")}       ${cliTruncate(oneLine(f.remediation), valueBudget)}`);
  out.push("");
  return out.join("\n");
}

// Collapse any whitespace (including embedded newlines) so a value renders as one clean line.
function oneLine(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}
