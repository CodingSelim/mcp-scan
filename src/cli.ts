#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import pc from "picocolors";
import type { Severity, ScanResult } from "./types.js";
import type { Target } from "./connect.js";
import { scanTarget } from "./scan.js";
import { parseConfigFile } from "./config.js";
import { renderConsole } from "./report/console.js";
import { renderJson } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";

interface Options {
  stdio?: string;
  url?: string;
  config?: string;
  header: Record<string, string>;
  env: Record<string, string>;
  format: "console" | "json" | "sarif";
  output?: string;
  failOn: Severity | "none";
  help: boolean;
  version: boolean;
}

const SEV_THRESHOLD: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const HELP = `
${pc.bold("mcp-scan")} — Security scanner for Model Context Protocol servers

${pc.bold("USAGE")}
  mcp-scan --stdio "<command>"        Scan a local stdio MCP server
  mcp-scan --url <http-url>           Scan a remote HTTP/SSE MCP server
  mcp-scan --config <path>            Scan every server in an MCP config file

${pc.bold("OPTIONS")}
  --stdio <cmd>        Command to spawn (e.g. "node server.js" or "npx -y pkg")
  --url <url>          MCP endpoint URL (Streamable HTTP, falls back to SSE)
  --config <path>      Path to a Claude/Cursor mcp.json to scan all servers
  --header <k:v>       Extra HTTP header (repeatable), e.g. --header "Authorization: Bearer x"
  --env <k=v>          Env var for stdio child (repeatable)
  --format <fmt>       console | json | sarif            (default: console)
  --output <file>      Write report to a file instead of stdout
  --fail-on <sev>      Exit non-zero at/above severity: critical|high|medium|low|none (default: high)
  -h, --help           Show this help
  -v, --version        Show version

${pc.bold("EXAMPLES")}
  mcp-scan --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp"
  mcp-scan --url https://mcp.example.com/mcp --header "Authorization: Bearer $TOKEN"
  mcp-scan --config ~/.cursor/mcp.json --format sarif --output mcp.sarif
`;

function parseArgs(argv: string[]): Options {
  const opts: Options = {
    header: {},
    env: {},
    format: "console",
    failOn: "high",
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    switch (a) {
      case "--stdio": opts.stdio = next(); break;
      case "--url": opts.url = next(); break;
      case "--config": opts.config = next(); break;
      case "--header": {
        const v = next();
        const idx = v.indexOf(":");
        if (idx > 0) opts.header[v.slice(0, idx).trim()] = v.slice(idx + 1).trim();
        break;
      }
      case "--env": {
        const v = next();
        const idx = v.indexOf("=");
        if (idx > 0) opts.env[v.slice(0, idx).trim()] = v.slice(idx + 1).trim();
        break;
      }
      case "--format": opts.format = next() as Options["format"]; break;
      case "--output": opts.output = next(); break;
      case "--fail-on": opts.failOn = next() as Options["failOn"]; break;
      case "-h": case "--help": opts.help = true; break;
      case "-v": case "--version": opts.version = true; break;
      default:
        if (a.startsWith("-")) throw new Error(`Unknown option: ${a}`);
    }
  }
  return opts;
}

function splitCommand(cmd: string): { command: string; args: string[] } {
  const parts = cmd.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) ?? [];
  const clean = parts.map((p) => p.replace(/^["']|["']$/g, ""));
  return { command: clean[0], args: clean.slice(1) };
}

function render(result: ScanResult, format: Options["format"]): string {
  if (format === "json") return renderJson(result);
  if (format === "sarif") return renderSarif(result);
  return renderConsole(result);
}

function shouldFail(result: ScanResult, failOn: Options["failOn"]): boolean {
  if (failOn === "none") return false;
  const threshold = SEV_THRESHOLD[failOn];
  return result.findings.some((f) => SEV_THRESHOLD[f.severity] >= threshold);
}

async function main(): Promise<number> {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { process.stdout.write(HELP + "\n"); return 0; }
  if (opts.version) { process.stdout.write("mcp-scan 0.1.0\n"); return 0; }

  const targets: Array<{ name: string; target: Target }> = [];
  if (opts.config) {
    targets.push(...parseConfigFile(opts.config));
  } else if (opts.stdio) {
    const { command, args } = splitCommand(opts.stdio);
    targets.push({ name: command, target: { kind: "stdio", command, args, env: opts.env } });
  } else if (opts.url) {
    targets.push({ name: opts.url, target: { kind: "http", url: opts.url, headers: opts.header } });
  } else {
    process.stderr.write(pc.red("Error: specify one of --stdio, --url, or --config.\n\n"));
    process.stdout.write(HELP + "\n");
    return 2;
  }

  const results: ScanResult[] = [];
  let anyFail = false;

  for (const { name, target } of targets) {
    try {
      const result = await scanTarget(target);
      results.push(result);
      if (shouldFail(result, opts.failOn)) anyFail = true;

      if (opts.format === "console" && !opts.output) {
        if (targets.length > 1) process.stdout.write(pc.bold(pc.underline(`\n══ ${name} ══\n`)));
        process.stdout.write(render(result, "console"));
      }
    } catch (err) {
      anyFail = true;
      process.stderr.write(pc.red(`\n✗ Failed to scan ${name}: ${(err as Error).message}\n`));
    }
  }

  if (opts.format !== "console" || opts.output) {
    const payload =
      opts.format === "console"
        ? results.map((r) => render(r, "console")).join("\n")
        : targets.length > 1 && opts.format === "json"
          ? JSON.stringify(results.map((r) => JSON.parse(renderJson(r))), null, 2)
          : render(results[0] ?? emptyResult(), opts.format);

    if (opts.output) {
      writeFileSync(opts.output, payload);
      process.stderr.write(pc.gray(`Report written to ${opts.output}\n`));
    } else {
      process.stdout.write(payload + "\n");
    }
  }

  return anyFail ? 1 : 0;
}

function emptyResult(): ScanResult {
  return {
    target: "none",
    findings: [],
    score: 0,
    grade: "A",
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    stats: { tools: 0, prompts: 0, resources: 0, resourceTemplates: 0 },
    errors: [],
  };
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(pc.red(`\nFatal: ${(err as Error).message}\n`));
    process.exit(2);
  });
