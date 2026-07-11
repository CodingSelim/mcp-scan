/**
 * mcp-scan as an MCP server.
 *
 * Running `mcp-scan --serve` exposes the scanner over the Model Context
 * Protocol so any MCP client (Claude Code, Codex, Cursor, and so on) can add
 * mcp-scan and tool-call it to audit other MCP servers against the OWASP MCP
 * Top 10. It is still passive: the target is enumerated and analyzed, never
 * exploited.
 *
 * Trust note: scanning a stdio target means spawning the command you pass, so
 * only connect this server in a context where those commands are trusted, the
 * same as running the CLI yourself.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { ScanResult, Severity } from "./types.js";
import { OWASP_TITLES, SEVERITY_ORDER } from "./types.js";
import { ALL_CHECKS } from "./registry.js";
import { scanTarget } from "./scan.js";
import type { Target } from "./connect.js";
import { renderJson } from "./report/json.js";
import { renderSarif } from "./report/sarif.js";

const VERSION = "0.2.0";

const SCAN_TOOL = {
  name: "scan_mcp_server",
  description:
    "Audit a Model Context Protocol server against the OWASP MCP Top 10 and return a graded (A-F) security report. Pass a stdio target ('command' plus optional 'args'/'env') OR a remote 'url' (with optional 'headers'). Passive: it enumerates the server's advertised tools/prompts/resources and analyzes them statically, never invoking tools. Scanning a stdio target spawns that command, so only scan servers you trust.",
  inputSchema: {
    type: "object",
    properties: {
      command: {
        type: "string",
        description: "Executable for a stdio MCP server, e.g. 'npx'. Provide this or 'url'.",
      },
      args: {
        type: "array",
        items: { type: "string" },
        description: "Arguments for the stdio command, e.g. ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'].",
      },
      env: {
        type: "object",
        additionalProperties: { type: "string" },
        description: "Environment variables for the stdio child process.",
      },
      url: {
        type: "string",
        description: "URL of a remote Streamable-HTTP or SSE MCP server. Provide this or 'command'.",
      },
      headers: {
        type: "object",
        additionalProperties: { type: "string" },
        description: "HTTP headers for a url target, e.g. { \"Authorization\": \"Bearer ...\" }.",
      },
      format: {
        type: "string",
        enum: ["summary", "json", "sarif"],
        description: "Report format. 'summary' (default) is a readable digest; 'json' and 'sarif' are machine formats.",
      },
    },
  },
} as const;

const LIST_CHECKS_TOOL = {
  name: "list_checks",
  description:
    "List the security checks mcp-scan runs and their OWASP MCP Top 10 mapping. Takes no arguments.",
  inputSchema: { type: "object", properties: {} },
} as const;

interface ScanArgs {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  format?: "summary" | "json" | "sarif";
}

function targetFromArgs(a: ScanArgs): Target {
  if (a.url) return { kind: "http", url: a.url, headers: a.headers };
  if (a.command) return { kind: "stdio", command: a.command, args: a.args, env: a.env };
  throw new Error("Provide either 'command' (stdio) or 'url' (http).");
}

/** Compact, agent-friendly digest of a scan result. */
export function renderAgentSummary(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(`Target: ${result.target}`);
  if (result.serverInfo?.name) {
    lines.push(`Server: ${result.serverInfo.name} ${result.serverInfo.version ?? ""}`.trim());
  }
  lines.push(`Grade: ${result.grade}   Risk score: ${result.score}/100`);
  const counts = SEVERITY_ORDER.map((s: Severity) => `${result.counts[s]} ${s}`).join(", ");
  lines.push(`Findings: ${counts}`);
  lines.push(
    `Surface: ${result.stats.tools} tools, ${result.stats.prompts} prompts, ${result.stats.resources} resources`,
  );

  if (result.findings.length === 0) {
    lines.push("\nNo security findings.");
  } else {
    lines.push("\nFindings:");
    for (const f of result.findings) {
      lines.push(
        `- [${f.severity.toUpperCase()}] ${f.owasp} ${f.category}/${f.rule}: ${f.title} (at ${f.location})`,
      );
    }
  }
  if (result.errors.length > 0) {
    lines.push(`\nCheck errors: ${result.errors.length}`);
  }
  return lines.join("\n");
}

function renderResult(result: ScanResult, format: ScanArgs["format"]): string {
  if (format === "json") return renderJson(result);
  if (format === "sarif") return renderSarif(result);
  return renderAgentSummary(result);
}

/** Build the mcp-scan MCP server (not yet connected to a transport). */
export function createScanServer(): Server {
  const server = new Server(
    { name: "mcp-scan", version: VERSION },
    {
      capabilities: { tools: {} },
      instructions:
        "Security scanner for MCP servers. Use scan_mcp_server to audit another MCP server against the OWASP MCP Top 10 before trusting it.",
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [SCAN_TOOL, LIST_CHECKS_TOOL],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: rawArgs } = req.params;

    if (name === "list_checks") {
      const payload = {
        checks: ALL_CHECKS.map((c) => ({ id: c.id, name: c.name })),
        owasp: OWASP_TITLES,
      };
      return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
    }

    if (name === "scan_mcp_server") {
      const args = (rawArgs ?? {}) as ScanArgs;
      try {
        const target = targetFromArgs(args);
        const result = await scanTarget(target);
        return { content: [{ type: "text", text: renderResult(result, args.format) }] };
      } catch (err) {
        return {
          content: [{ type: "text", text: `Scan failed: ${(err as Error).message}` }],
          isError: true,
        };
      }
    }

    return {
      content: [{ type: "text", text: `Unknown tool: ${name}` }],
      isError: true,
    };
  });

  return server;
}

/** Run mcp-scan as an MCP server over stdio. Resolves only when the transport closes. */
export async function runMcpServer(): Promise<void> {
  const server = createScanServer();
  await server.connect(new StdioServerTransport());
  // Stay alive until the client disconnects (stdin closes).
  await new Promise<void>((resolve) => {
    server.onclose = () => resolve();
  });
}
