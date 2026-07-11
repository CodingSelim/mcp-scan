import { readFileSync } from "node:fs";
import type { Target } from "./connect.js";

interface McpServerEntry {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  type?: string;
  headers?: Record<string, string>;
}

export function parseConfigFile(path: string): Array<{ name: string; target: Target }> {
  const raw = readFileSync(path, "utf8");
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Config file is not valid JSON: ${(err as Error).message}`);
  }

  const root = json as { mcpServers?: Record<string, McpServerEntry>; servers?: Record<string, McpServerEntry> };
  const servers = root.mcpServers ?? root.servers;
  if (!servers || typeof servers !== "object") {
    throw new Error('Config file has no "mcpServers" (or "servers") object.');
  }

  const out: Array<{ name: string; target: Target }> = [];
  for (const [name, entry] of Object.entries(servers)) {
    if (entry.url) {
      out.push({ name, target: { kind: "http", url: entry.url, headers: entry.headers } });
    } else if (entry.command) {
      out.push({
        name,
        target: { kind: "stdio", command: entry.command, args: entry.args, env: entry.env },
      });
    }
  }
  if (out.length === 0) throw new Error("No usable server entries found in config.");
  return out;
}
