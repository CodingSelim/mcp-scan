import type { Check, Finding, ScanContext } from "../types.js";
import { detectSecrets } from "../detectors/secrets.js";

/** Secret leakage (OWASP MCP01, Token Mismanagement & Secret Exposure). */
export const secretExposureCheck: Check = {
  id: "secret-exposure",
  name: "Sensitive data / secret leakage",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    const blobs: Array<{ location: string; text?: string }> = [
      { location: "server:instructions", text: ctx.instructions },
      { location: "server:name", text: ctx.serverInfo?.name },
      ...ctx.tools.map((t) => ({ location: `tool:${t.name}`, text: t.description })),
      ...ctx.prompts.map((p) => ({ location: `prompt:${p.name}`, text: p.description })),
      ...ctx.resources.map((r) => ({ location: `resource:${r.uri}`, text: r.description })),
    ];

    for (const blob of blobs) {
      if (!blob.text) continue;
      for (const secret of detectSecrets(blob.text)) {
        findings.push({
          category: "secret-exposure",
          owasp: "MCP01",
          rule: "exposed-secret",
          severity: secret.kind === "High-Entropy String" ? "medium" : "critical",
          title: `Possible ${secret.kind} exposed in ${blob.location}`,
          description: `A value matching a ${secret.kind} pattern is exposed in server-advertised text. Anyone able to list this server's capabilities can read it.`,
          location: blob.location,
          remediation:
            "Remove secrets from descriptions/metadata/outputs. Load credentials from the environment or a secret manager and never echo them back to clients.",
          evidence: `${secret.kind}: ${secret.match}`,
        });
      }
    }
    return findings;
  },
};
