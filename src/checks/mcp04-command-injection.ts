import type { Check, Finding, ScanContext } from "../types.js";
import {
  extractParams,
  isCommandParam,
  isQueryParam,
  descriptionSuggestsExec,
} from "../detectors/schema.js";

/** Command and code injection surface (OWASP MCP05, Command Injection & Execution). */
export const commandInjectionCheck: Check = {
  id: "command-injection",
  name: "Command / code injection surface",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    for (const tool of ctx.tools) {
      const params = extractParams(tool.inputSchema);
      const desc = tool.description ?? "";

      for (const p of params.filter(isCommandParam)) {
        if (p.type === "string" && !p.constrained) {
          findings.push({
            category: "command-injection",
            owasp: "MCP05",
            rule: "unconstrained-command-param",
            severity: "critical",
            title: `Tool '${tool.name}' takes an unconstrained command parameter`,
            description: `Parameter '${p.name}' is a free-form string that names a command/shell/code input with no enum, pattern, or format constraint. If passed to a shell or interpreter, this is a direct command-injection sink.`,
            location: `tool:${tool.name}`,
            remediation:
              "Never pass model-provided strings to a shell. Use argument arrays with a fixed executable, validate against an allowlist, and constrain the schema (enum/pattern).",
            evidence: `param '${p.name}': string (unconstrained)`,
          });
        }
      }

      if (descriptionSuggestsExec(desc) && params.some((p) => p.type === "string" && !p.constrained)) {
        findings.push({
          category: "command-injection",
          owasp: "MCP05",
          rule: "advertised-execution",
          severity: "high",
          title: `Tool '${tool.name}' advertises arbitrary execution`,
          description:
            "The tool description indicates it executes commands/code, and it accepts an unconstrained string input. This is a high-value target for injection.",
          location: `tool:${tool.name}`,
          remediation:
            "Constrain inputs, sandbox execution, and require explicit user confirmation before running.",
          evidence: desc.slice(0, 120),
        });
      }

      for (const p of params.filter(isQueryParam)) {
        if (p.type === "string" && !p.constrained && /\bsql\b/i.test(p.name)) {
          findings.push({
            category: "command-injection",
            owasp: "MCP05",
            rule: "raw-sql-param",
            severity: "high",
            title: `Tool '${tool.name}' accepts raw SQL`,
            description: `Parameter '${p.name}' accepts a raw SQL string. Without parameterization this enables SQL injection and unrestricted data access.`,
            location: `tool:${tool.name}`,
            remediation:
              "Expose typed operations instead of raw SQL, or run queries through a read-only, parameterized, allowlisted interface.",
            evidence: `param '${p.name}': raw SQL string`,
          });
        }
      }
    }
    return findings;
  },
};
