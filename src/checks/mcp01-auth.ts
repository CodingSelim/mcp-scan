import type { Check, Finding, ScanContext } from "../types.js";

/** Authentication — maps to OWASP MCP07 (Insufficient Authentication & Authorization). */
export const authnCheck: Check = {
  id: "authn",
  name: "Insufficient authentication",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    if (ctx.transport.kind !== "http") return findings;

    if (ctx.transport.unauthenticatedHandshakeSucceeded && !ctx.transport.authRequired) {
      findings.push({
        category: "authn",
        owasp: "MCP07",
        rule: "no-authentication",
        severity: "critical",
        title: "Server accepts unauthenticated connections",
        description:
          "The MCP server completed a full handshake and exposed its tools/resources without requiring any credential. Anyone who can reach this endpoint can invoke every tool.",
        location: `transport:${ctx.transport.url ?? "http"}`,
        remediation:
          "Require authentication on the transport. Prefer OAuth 2.1 (per the MCP authorization spec) or at minimum a bearer token/API key validated before the initialize response.",
        evidence: "initialize + tools/list succeeded with no Authorization header",
      });
    }
    return findings;
  },
};
