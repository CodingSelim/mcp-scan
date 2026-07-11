import type { Check, Finding, ScanContext } from "../types.js";
import { extractParams } from "../detectors/schema.js";

const DESTRUCTIVE_RE = /\b(delete|remove|destroy|drop|wipe|erase|purge|truncate|revoke|kill|terminate|shutdown|format|overwrite|transfer|withdraw|send (money|funds|payment))\b/i;
const WRITE_RE = /\b(write|create|update|modify|edit|upload|push|deploy|install|grant|approve|pay|charge)\b/i;

/**
 * MCP08 — Excessive tool permissions.
 * Flags tools whose name/description imply destructive or state-changing
 * actions, which should carry human-in-the-loop confirmation.
 */
export const mcp08Permissions: Check = {
  id: "MCP08",
  name: "Excessive tool permissions",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    for (const tool of ctx.tools) {
      const haystack = `${tool.name} ${tool.description ?? ""}`;
      const destructive = DESTRUCTIVE_RE.test(haystack);
      const write = WRITE_RE.test(haystack);
      if (!destructive && !write) continue;

      const paramCount = extractParams(tool.inputSchema).length;

      findings.push({
        checkId: "MCP08",
        rule: destructive ? "destructive-tool" : "state-changing-tool",
        severity: destructive ? "high" : "low",
        title: `Tool '${tool.name}' performs ${destructive ? "destructive" : "state-changing"} actions`,
        description: `The tool appears to ${destructive ? "delete/destroy/move" : "create/modify"} data or resources. When exposed to an autonomous assistant, such tools should require explicit user confirmation and least-privilege scoping; a prompt-injection can otherwise trigger them.`,
        location: `tool:${tool.name}`,
        remediation:
          "Gate destructive/state-changing tools behind human-in-the-loop confirmation, scope credentials to least privilege, and consider making them read-only or dry-run by default.",
        evidence: `${tool.name} (${paramCount} param${paramCount === 1 ? "" : "s"})`,
      });
    }
    return findings;
  },
};
