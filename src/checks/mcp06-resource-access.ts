import type { Check, Finding, ScanContext } from "../types.js";
import { extractParams, isPathParam } from "../detectors/schema.js";

/**
 * MCP06 — Unrestricted resource / file access.
 * Flags file:// resources/templates and path-taking tools that can traverse
 * the filesystem.
 */
export const mcp06ResourceAccess: Check = {
  id: "MCP06",
  name: "Unrestricted resource / file access",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    for (const tmpl of ctx.resourceTemplates) {
      if (/^file:/i.test(tmpl.uriTemplate) && /\{[^}]+\}/.test(tmpl.uriTemplate)) {
        findings.push({
          checkId: "MCP06",
          rule: "wildcard-file-template",
          severity: "high",
          title: `Resource template exposes parameterized file access`,
          description: `Template '${tmpl.uriTemplate}' lets a caller substitute an arbitrary path into a file:// URI. Without traversal protection this can read any file the server process can access (e.g. ../../etc/passwd, ~/.ssh/id_rsa).`,
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
            checkId: "MCP06",
            rule: "unconstrained-path-param",
            severity: "medium",
            title: `Tool '${tool.name}' takes an unconstrained filesystem path`,
            description: `Parameter '${p.name}' accepts an arbitrary path with no constraint. If used for file I/O this enables path traversal outside any intended directory.`,
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
