import type { Check, Finding, ScanContext } from "../types.js";
import { extractParams, isPathParam } from "../detectors/schema.js";

/**
 * Path traversal and unrestricted file access (OWASP MCP01). Arbitrary file
 * reads expose credentials and secrets such as SSH keys, .env files, and
 * tokens. It is the most common MCP implementation flaw: Endor Labs found 82%
 * of servers use file operations prone to traversal.
 */
export const pathTraversalCheck: Check = {
  id: "path-traversal",
  name: "Path traversal / unrestricted file access",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    for (const tmpl of ctx.resourceTemplates) {
      if (/^file:/i.test(tmpl.uriTemplate) && /\{[^}]+\}/.test(tmpl.uriTemplate)) {
        findings.push({
          category: "path-traversal",
          owasp: "MCP01",
          rule: "wildcard-file-template",
          severity: "high",
          title: `Resource template exposes parameterized file access`,
          description: `Template '${tmpl.uriTemplate}' lets a caller substitute an arbitrary path into a file:// URI. Without traversal protection this can read any file the server process can access (e.g. ../../etc/passwd, ~/.ssh/id_rsa, .env).`,
          location: `template:${tmpl.uriTemplate}`,
          remediation:
            "Confine access to a fixed base directory, resolve+canonicalize paths, and reject anything escaping the root. Never interpolate raw user input into file URIs.",
          evidence: tmpl.uriTemplate,
        });
      }
    }

    for (const tool of ctx.tools) {
      const params = extractParams(tool.inputSchema).filter(isPathParam);
      for (const p of params) {
        if (p.type === "string" && !p.constrained) {
          findings.push({
            category: "path-traversal",
            owasp: "MCP01",
            rule: "unconstrained-path-param",
            severity: "medium",
            title: `Tool '${tool.name}' takes an unconstrained filesystem path`,
            description: `Parameter '${p.name}' accepts an arbitrary path with no constraint. If used for file I/O this enables path traversal outside any intended directory, exposing credentials and secrets.`,
            location: `tool:${tool.name}`,
            remediation:
              "Canonicalize and confine paths to an allowed root; reject '..' segments and absolute paths outside the sandbox.",
            evidence: `param '${p.name}': unconstrained path`,
          });
        }
      }
    }
    return findings;
  },
};
