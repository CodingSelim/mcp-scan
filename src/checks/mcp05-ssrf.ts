import type { Check, Finding, ScanContext } from "../types.js";
import { extractParams, isUrlParam } from "../detectors/schema.js";

const ALLOWLIST_HINT_RE = /\b(allow ?list|allowed (hosts?|domains?)|whitelist|must (start|begin) with|only .*(https?:\/\/|domain))\b/i;

/** SSRF surface (OWASP MCP05, untrusted-input-driven server requests). */
export const ssrfCheck: Check = {
  id: "ssrf",
  name: "Server-side request forgery (SSRF) surface",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    for (const tool of ctx.tools) {
      const params = extractParams(tool.inputSchema);
      const desc = tool.description ?? "";
      const urlParams = params.filter(isUrlParam);
      if (urlParams.length === 0) continue;

      const hasAllowlistHint =
        ALLOWLIST_HINT_RE.test(desc) || urlParams.every((p) => p.constrained);
      if (hasAllowlistHint) continue;

      const names = urlParams.map((p) => p.name).join(", ");
      findings.push({
        category: "ssrf",
        owasp: "MCP05",
        rule: "unrestricted-url-fetch",
        severity: "high",
        title: `Tool '${tool.name}' fetches a caller-supplied URL`,
        description: `Parameter(s) '${names}' accept an arbitrary URL or host with no visible allowlist or format constraint. The server can be coerced into requesting internal addresses such as 169.254.169.254 metadata, localhost admin ports, or RFC1918 hosts. This is classic SSRF.`,
        location: `tool:${tool.name}`,
        remediation:
          "Validate the resolved IP against a denylist of internal/link-local ranges, enforce an allowlist of permitted hosts/schemes, and disable redirects to private ranges.",
        evidence: `param(s): ${names}`,
      });
    }
    return findings;
  },
};
