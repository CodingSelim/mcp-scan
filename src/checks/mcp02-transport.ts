import type { Check, Finding, ScanContext } from "../types.js";

const LOOPBACK_RE = /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)$/i;

/** MCP02 — Insecure transport (plaintext http to a non-loopback host). */
export const mcp02Transport: Check = {
  id: "MCP02",
  name: "Insecure transport",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];
    if (ctx.transport.kind !== "http" || !ctx.transport.url) return findings;

    let url: URL;
    try {
      url = new URL(ctx.transport.url);
    } catch {
      return findings;
    }

    if (url.protocol === "http:" && !LOOPBACK_RE.test(url.hostname)) {
      findings.push({
        checkId: "MCP02",
        rule: "plaintext-transport",
        severity: "high",
        title: "Server reachable over plaintext HTTP",
        description:
          "The server is served over unencrypted HTTP to a non-loopback host. Tokens, tool arguments, and tool outputs (which frequently contain sensitive data) traverse the network in cleartext and can be intercepted or modified in transit.",
        location: `transport:${url.host}`,
        remediation: "Serve the MCP endpoint over HTTPS/TLS. Redirect or reject plaintext HTTP.",
        evidence: url.origin,
      });
    }
    return findings;
  },
};
