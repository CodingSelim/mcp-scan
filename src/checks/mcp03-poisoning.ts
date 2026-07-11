import type { Check, Finding, OwaspMcpId, ScanContext } from "../types.js";
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

// Tool descriptions are static poisoning (MCP03); dynamic resource/instruction
// text is contextual prompt injection (MCP06).
const OWASP_BY_SURFACE = (location: string): OwaspMcpId =>
  location.startsWith("tool:") || location.startsWith("prompt:") ? "MCP03" : "MCP06";

/** Tool poisoning and prompt injection (OWASP MCP03 and MCP06). */
export const toolPoisoningCheck: Check = {
  id: "tool-poisoning",
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
          category: "tool-poisoning",
          owasp: OWASP_BY_SURFACE(surface.location),
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
