import type { Check, Finding, ScanContext } from "../types.js";

const HIGH_IMPACT =
  /\b(delete|remove|destroy|drop|wipe|erase|purge|truncate|revoke|kill|terminate|shutdown|format|overwrite|transfer|withdraw|deploy|install|execute|run|shell|exec|send|post|upload|publish|pay|charge|grant)\b/i;

/**
 * Audit and telemetry gap (OWASP MCP08, Lack of Audit and Telemetry).
 *
 * MCP defines no standard per-call audit trail, so a scanner cannot passively
 * confirm whether tool invocations are logged. What it can confirm is exposure:
 * when a server offers high-impact tools (destructive, state-changing,
 * code-executing, or externally-sending), those actions are unattributable
 * after the fact unless the operator adds logging out of band. This is
 * reported as advisory (info, unscored): it flags a gap to verify, not a
 * proven defect.
 */
export const telemetryCheck: Check = {
  id: "telemetry",
  name: "Audit & telemetry gap",
  run(ctx: ScanContext): Finding[] {
    const impactful = ctx.tools.filter((t) => HIGH_IMPACT.test(`${t.name} ${t.description ?? ""}`));
    if (impactful.length === 0) return [];

    const sample = impactful.slice(0, 5).map((t) => t.name).join(", ");
    const more = impactful.length > 5 ? ` +${impactful.length - 5} more` : "";

    return [
      {
        category: "telemetry",
        owasp: "MCP08",
        rule: "unaudited-high-impact-tools",
        severity: "info",
        title: `${impactful.length} high-impact tool(s) with no protocol-level audit trail`,
        description:
          "MCP has no standard mechanism for auditing tool calls, and this server exposes high-impact tools. Unless the operator logs invocations out-of-band, destructive or external actions triggered by the agent (or a prompt injection) cannot be attributed or investigated afterward.",
        location: "server",
        remediation:
          "Wrap the server with request/response logging that records tool name, arguments, caller, and timestamp; ship those logs to tamper-evident storage and alert on high-impact calls.",
        evidence: `high-impact tools: ${sample}${more}`,
      },
    ];
  },
};
