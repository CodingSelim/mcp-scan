import type { Check, Finding, ScanContext } from "../types.js";
import { detectInjection } from "../detectors/injection.js";

const SEVERITY_BY_RULE: Record<string, Finding["severity"]> = {
  "instruction-override": "critical",
  "exfiltration-directive": "critical",
  "credential-harvest": "critical",
  "hidden-directive": "high",
  "hidden-unicode": "high",
  "unicode-tag-smuggling": "critical",
  "assistant-role-injection": "high",
};

/**
 * MCP03 — Tool poisoning / description injection.
 * Scans everything the model ingests verbatim: tool descriptions, prompt
 * descriptions, resource descriptions, and server instructions.
 */
export const mcp03Poisoning: Check = {
  id: "MCP03",
  name: "Tool poisoning / description injection",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    const surfaces: Array<{ location: string; text?: string }> = [
      { location: "server:instructions", text: ctx.instructions },
      ...ctx.tools.map((t) => ({ location: `tool:${t.name}`, text: t.description })),
      ...ctx.prompts.map((p) => ({ location: `prompt:${p.name}`, text: p.description })),
      ...ctx.resources.map((r) => ({ location: `resource:${r.uri}`, text: r.description })),
    ];

    for (const surface of surfaces) {
      for (const signal of detectInjection(surface.text)) {
        findings.push({
          checkId: "MCP03",
          rule: signal.rule,
          severity: SEVERITY_BY_RULE[signal.rule] ?? "high",
          title: `Suspicious instruction in ${surface.location}`,
          description: `${signal.detail} MCP descriptions are injected verbatim into the model's context, so this text can steer the assistant without the user's awareness (tool poisoning).`,
          location: surface.location,
          remediation:
            "Remove imperative/hidden instructions from descriptions. Descriptions should state what the tool does, not command the assistant. Strip zero-width/tag unicode.",
          evidence: signal.evidence,
        });
      }
    }
    return findings;
  },
};
