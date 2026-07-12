import pc from "picocolors";
import gradient from "gradient-string";
import logSymbols from "log-symbols";
import type { Finding, ScanResult, Severity } from "../types.js";

const BRAND = gradient(["#22d3ee", "#818cf8", "#c084fc"]);

// Visible width, ignoring ANSI color escapes, so boxes line up when the content is colored.
const ANSI_RE = new RegExp(String.fromCharCode(27) + "\\[[0-9;]*m", "g");
const vlen = (s: string): number => s.replace(ANSI_RE, "").length;
const padEnd = (s: string, w: number): string => s + " ".repeat(Math.max(0, w - vlen(s)));

const WIDTH = 64; // inner box width
const GUTTER = "  "; // left page margin

const SEV_TAG: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(pc.bold(s))),
  high: (s) => pc.red(pc.bold(s)),
  medium: (s) => pc.yellow(pc.bold(s)),
  low: (s) => pc.cyan(s),
  info: (s) => pc.gray(s),
};

const SEV_PAINT: Record<Severity, (s: string) => string> = {
  critical: pc.red,
  high: pc.red,
  medium: pc.yellow,
  low: pc.cyan,
  info: pc.gray,
};

const GRADE_BADGE: Record<ScanResult["grade"], (s: string) => string> = {
  A: (s) => pc.bgGreen(pc.black(pc.bold(s))),
  B: (s) => pc.bgGreen(pc.black(pc.bold(s))),
  C: (s) => pc.bgYellow(pc.black(pc.bold(s))),
  D: (s) => pc.bgRed(pc.white(pc.bold(s))),
  F: (s) => pc.bgRed(pc.white(pc.bold(s))),
};

const gradePaint = (g: ScanResult["grade"]): ((s: string) => string) =>
  g === "A" || g === "B" ? pc.green : g === "C" ? pc.yellow : pc.red;

function sevTag(sev: Severity): string {
  return SEV_TAG[sev](` ${sev.toUpperCase()} `);
}

function headerBox(): string[] {
  const title = ` ${BRAND("◆ mcp-scan")}  ${pc.dim("MCP Security Report")}`;
  return [
    pc.gray(`${GUTTER}╭${"─".repeat(WIDTH)}╮`),
    `${GUTTER}${pc.gray("│")}${padEnd(title, WIDTH)}${pc.gray("│")}`,
    pc.gray(`${GUTTER}╰${"─".repeat(WIDTH)}╯`),
  ];
}

function metaRow(label: string, value: string): string {
  return `${GUTTER}${pc.dim(label.padEnd(8))}${value}`;
}

function severityStrip(counts: Record<Severity, number>): string {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const cells = order.map((sev) => {
    const n = counts[sev];
    const dot = n > 0 ? SEV_PAINT[sev]("●") : pc.dim("○");
    const label = n > 0 ? sev.toUpperCase() : pc.dim(sev.toUpperCase());
    const num = n > 0 ? pc.bold(String(n)) : pc.dim(String(n));
    return `${dot} ${label} ${num}`;
  });
  return `${GUTTER}${cells.join(pc.dim("   "))}`;
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
  lines.push(...headerBox());
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

  lines.push(severityStrip(result.counts));
  lines.push("");
  lines.push(scoreMeter(result.score, result.grade));
  lines.push("");
  lines.push(pc.gray(`${GUTTER}${"─".repeat(WIDTH + 2)}`));
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
  out.push(`${guide}${pc.dim("where")}  ${f.location}`);
  out.push(`${guide}${wrap(f.description, guide)}`);
  if (f.evidence) out.push(`${guide}${pc.dim("evidence")}  ${pc.dim(truncate(f.evidence, 160))}`);
  out.push(`${guide}${pc.green("fix")}  ${wrap(f.remediation, guide)}`);
  out.push("");
  return out.join("\n");
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

function wrap(text: string, indent: string, width = 84): string {
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
