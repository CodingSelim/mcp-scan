import type { ScanResult, Severity } from "../types.js";
import { OWASP_TITLES } from "../types.js";

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

export function renderSarif(result: ScanResult): string {
  const ruleIds = new Map<string, { owasp: string; category: string; name: string }>();
  for (const f of result.findings) {
    const id = `${f.category}/${f.rule}`;
    if (!ruleIds.has(id)) ruleIds.set(id, { owasp: f.owasp, category: f.category, name: f.title });
  }

  const rules = [...ruleIds.entries()].map(([id, meta]) => ({
    id,
    name: meta.name,
    properties: {
      tags: ["security", "mcp", meta.owasp, meta.category],
      owasp: `${meta.owasp}:2025 ${OWASP_TITLES[meta.owasp as keyof typeof OWASP_TITLES]}`,
    },
  }));

  const results = result.findings.map((f) => ({
    ruleId: `${f.category}/${f.rule}`,
    level: SARIF_LEVEL[f.severity],
    message: {
      text: `${f.title}. ${f.description} [OWASP ${f.owasp}:2025 ${OWASP_TITLES[f.owasp]}] Remediation: ${f.remediation}`,
    },
    properties: {
      severity: f.severity,
      "security-severity": SECURITY_SEVERITY[f.severity],
      owasp: f.owasp,
      location: f.location,
      evidence: f.evidence ?? "",
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: sanitizeUri(result.target) },
          region: { startLine: 1 },
        },
        logicalLocations: [{ fullyQualifiedName: f.location }],
      },
    ],
  }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-scan",
            version: "0.1.0",
            informationUri: "https://github.com/your-org/mcp-scan",
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

function sanitizeUri(target: string): string {
  try {
    return new URL(target).toString();
  } catch {
    return "mcp-server://" + encodeURIComponent(target).slice(0, 120);
  }
}
