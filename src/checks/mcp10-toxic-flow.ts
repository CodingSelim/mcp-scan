import type { Check, Finding, ScanContext } from "../types.js";
import { rollupCapabilities } from "../detectors/capabilities.js";

const MAX_LIST = 4;
const fmt = (names: string[]): string =>
  names.length <= MAX_LIST
    ? names.join(", ")
    : `${names.slice(0, MAX_LIST).join(", ")} +${names.length - MAX_LIST} more`;

/**
 * Toxic agent flows (OWASP MCP10, Context Injection & Over-Sharing).
 *
 * Rolls each tool's capabilities up to the server and flags the "lethal
 * trifecta": one server that can read private data, ingest untrusted content,
 * and send data to an external destination. That combination lets a prompt
 * injection hidden in ingested content coerce the agent into exfiltrating
 * private data with no code-level compromise. It is the pattern behind the
 * documented GitHub-MCP and email-agent incidents.
 */
export const toxicFlowCheck: Check = {
  id: "toxic-flow",
  name: "Toxic agent flow (lethal trifecta)",
  run(ctx: ScanContext): Finding[] {
    const { readsPrivate, ingestsUntrusted, exfiltrates } = rollupCapabilities(ctx.tools);
    const hasPrivate = readsPrivate.length > 0;
    const hasUntrusted = ingestsUntrusted.length > 0;
    const hasExfil = exfiltrates.length > 0;

    const legs = [
      hasPrivate ? `reads private data (${fmt(readsPrivate)})` : null,
      hasUntrusted ? `ingests untrusted content (${fmt(ingestsUntrusted)})` : null,
      hasExfil ? `exfiltrates externally (${fmt(exfiltrates)})` : null,
    ].filter(Boolean) as string[];

    // The full trifecta is critical. Private data plus a way out (but no clear
    // injection carrier) is high. Untrusted input plus a way out (but no clear
    // private source) is a medium, SSRF-shaped risk.
    if (hasPrivate && hasUntrusted && hasExfil) {
      return [
        {
          category: "toxic-flow",
          owasp: "MCP10",
          rule: "lethal-trifecta",
          severity: "critical",
          title: "Server combines the lethal trifecta (private data + untrusted input + exfiltration)",
          description:
            "This server exposes tools that together read private data, ingest untrusted/external content, and send data to external destinations. A prompt injection hidden in the untrusted content can drive the agent to read your private data and exfiltrate it, without exploiting any code vulnerability. Splitting these capabilities across trust boundaries removes the flow.",
          location: "server",
          remediation:
            "Break the trifecta: isolate untrusted-content tools from private-data and exfiltration tools (separate servers/sessions), require human confirmation before any external send, and constrain outbound destinations to an allowlist.",
          evidence: legs.join(" · "),
        },
      ];
    }

    if (hasPrivate && hasExfil) {
      return [
        {
          category: "toxic-flow",
          owasp: "MCP10",
          rule: "private-data-plus-exfiltration",
          severity: "high",
          title: "Server can read private data and send it externally",
          description:
            "The same server exposes tools that read private/sensitive data and tools that transmit to external destinations. If any tool description or ingested content carries an injection, private data can be exfiltrated. This is one prompt-injection away from the lethal trifecta.",
          location: "server",
          remediation:
            "Gate external-send tools behind human confirmation, scope data-access credentials to least privilege, and keep read and send capabilities on separate trust boundaries.",
          evidence: legs.join(" · "),
        },
      ];
    }

    if (hasUntrusted && hasExfil) {
      return [
        {
          category: "toxic-flow",
          owasp: "MCP10",
          rule: "untrusted-input-plus-exfiltration",
          severity: "medium",
          title: "Server ingests untrusted content and can send externally",
          description:
            "Tools here ingest external/untrusted content and can transmit to external destinations. Injected instructions in that content could drive server-side requests or outbound sends (SSRF / blind exfiltration), even without a private-data source.",
          location: "server",
          remediation:
            "Constrain outbound destinations to an allowlist, validate resolved IPs against internal ranges, and require confirmation before acting on instructions found in ingested content.",
          evidence: legs.join(" · "),
        },
      ];
    }

    return [];
  },
};
