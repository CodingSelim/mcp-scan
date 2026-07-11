import type { Check, Finding, ScanContext } from "../types.js";

// A tool instructing the agent to run before/around ALL other tools — a
// "call me first" interceptor. Kept strict so ordinary routing guidance
// ("use scrape for a page, crawl for a site") does not trip it; only an
// explicit precedence-over-other-tools directive matches.
const PRECEDENCE_RE =
  /\b(before (using|calling|invoking) (any )?(other )?(tool|function|tools)|prior to (calling|using|invoking) (any )?(other )?tools?|(call|use|run|invoke) this (tool )?first,? before (any )?(other )?tools?|must (run|be called|be used) (first )?before (any )?(other )?tools?)\b/i;

/**
 * Tool shadowing & name collision — OWASP MCP03 / MCP09.
 *
 * All tool descriptions share the model's context, so a tool can reach past
 * its own boundary two ways: collide on a trusted tool's NAME to shadow it,
 * or instruct the agent to invoke it ahead of every other tool. (Hidden
 * imperative directives — the other half of tool poisoning — are caught by
 * the tool-poisoning check.) These two signals are objective and low-noise;
 * we deliberately do NOT flag benign "use A for X, B for Y" routing guidance.
 */
export const toolShadowingCheck: Check = {
  id: "tool-shadowing",
  name: "Tool shadowing / name collision",
  run(ctx: ScanContext): Finding[] {
    const findings: Finding[] = [];

    // 1. Name collisions — two tools advertising the same name.
    const counts = new Map<string, number>();
    for (const t of ctx.tools) counts.set(t.name, (counts.get(t.name) ?? 0) + 1);
    for (const [name, count] of counts) {
      if (count > 1) {
        findings.push({
          category: "tool-shadowing",
          owasp: "MCP09",
          rule: "duplicate-tool-name",
          severity: "high",
          title: `Duplicate tool name '${name}'`,
          description: `Two or more tools advertise the name '${name}'. Whichever the client binds last shadows the others, so a benign name can be silently overridden — the core of a shadow-server / tool-collision attack.`,
          location: `tool:${name}`,
          remediation:
            "Ensure tool names are unique. Pin trusted servers and alert when a tool's definition changes between sessions (rug-pull detection).",
          evidence: `${count} tools named '${name}'`,
        });
      }
    }

    // 2. Precedence injection — a tool inserting itself ahead of all others.
    for (const tool of ctx.tools) {
      const desc = tool.description ?? "";
      if (desc && PRECEDENCE_RE.test(desc)) {
        findings.push({
          category: "tool-shadowing",
          owasp: "MCP03",
          rule: "precedence-injection",
          severity: "medium",
          title: `Tool '${tool.name}' instructs the agent to run it before other tools`,
          description:
            "This description tells the model to call this tool ahead of every other tool. A 'call me first' tool can intercept context and arguments intended for legitimate tools — a shadowing vector even when the intent is benign (e.g. a mandatory auth step).",
          location: `tool:${tool.name}`,
          remediation:
            "Tool ordering is the client's responsibility; remove precedence directives from descriptions. If a setup step is genuinely required, enforce it server-side, not via model instructions.",
          evidence: desc.replace(/\s+/g, " ").slice(0, 160),
        });
      }
    }

    return findings;
  },
};
