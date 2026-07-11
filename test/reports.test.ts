import { describe, it, expect } from "vitest";
import { writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ScanResult } from "../src/types.js";
import { renderConsole } from "../src/report/console.js";
import { renderJson } from "../src/report/json.js";
import { renderSarif } from "../src/report/sarif.js";
import { parseConfigFile } from "../src/config.js";

const sample: ScanResult = {
  target: "https://mcp.example.com/mcp",
  serverInfo: { name: "demo", version: "1.0.0" },
  findings: [
    {
      category: "command-injection",
      owasp: "MCP05",
      rule: "unconstrained-command-param",
      severity: "critical",
      title: "Tool 'run' takes an unconstrained command parameter",
      description: "free-form shell input",
      location: "tool:run",
      remediation: "use argument arrays",
      evidence: "param 'command'",
    },
    {
      category: "excessive-scope",
      owasp: "MCP02",
      rule: "state-changing-tool",
      severity: "low",
      title: "Tool writes data",
      description: "creates data",
      location: "tool:write",
      remediation: "confirm",
    },
  ],
  score: 43,
  grade: "F",
  counts: { critical: 1, high: 0, medium: 0, low: 1, info: 0 },
  stats: { tools: 2, prompts: 0, resources: 0, resourceTemplates: 0 },
  errors: ["Check MCPXX failed: boom"],
};

const empty: ScanResult = {
  target: "clean",
  findings: [],
  score: 0,
  grade: "A",
  counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  stats: { tools: 1, prompts: 0, resources: 0, resourceTemplates: 0 },
  errors: [],
};

describe("console report", () => {
  it("renders findings, score, grade and errors", () => {
    const out = renderConsole(sample);
    expect(out).toContain("MCP Security Report");
    expect(out).toContain("Risk score:");
    expect(out).toContain("/100");
    expect(out).toContain("tool:run");
    expect(out).toContain("check error");
  });
  it("renders the clean/no-findings path", () => {
    expect(renderConsole(empty)).toContain("No security findings");
  });
});

describe("json report", () => {
  it("is valid JSON carrying findings and grade", () => {
    const parsed = JSON.parse(renderJson(sample));
    expect(parsed.tool).toBe("mcp-scan");
    expect(parsed.grade).toBe("F");
    expect(parsed.findings).toHaveLength(2);
  });
});

describe("sarif report", () => {
  it("emits schema-valid sarif with rules and results", () => {
    const parsed = JSON.parse(renderSarif(sample));
    expect(parsed.version).toBe("2.1.0");
    const run = parsed.runs[0];
    expect(run.tool.driver.name).toBe("mcp-scan");
    expect(run.results).toHaveLength(2);
    expect(run.results[0].level).toBe("error");
    expect(run.results[0].properties["security-severity"]).toBe("9.5");
  });
  it("handles non-url targets", () => {
    const parsed = JSON.parse(renderSarif({ ...sample, target: "node server.js" }));
    expect(parsed.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toContain("mcp-server://");
  });
});

describe("config parsing", () => {
  it("parses mcpServers with stdio and http entries", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-scan-"));
    const p = join(dir, "mcp.json");
    writeFileSync(
      p,
      JSON.stringify({
        mcpServers: {
          fs: { command: "node", args: ["server.js"], env: { X: "1" } },
          remote: { url: "https://example.com/mcp", headers: { Authorization: "Bearer t" } },
        },
      }),
    );
    const targets = parseConfigFile(p);
    expect(targets).toHaveLength(2);
    expect(targets.find((t) => t.name === "fs")?.target.kind).toBe("stdio");
    expect(targets.find((t) => t.name === "remote")?.target.kind).toBe("http");
    rmSync(dir, { recursive: true, force: true });
  });

  it("throws on invalid json and on missing servers", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-scan-"));
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{not json");
    expect(() => parseConfigFile(bad)).toThrow(/valid JSON/);
    const noServers = join(dir, "no.json");
    writeFileSync(noServers, JSON.stringify({ foo: 1 }));
    expect(() => parseConfigFile(noServers)).toThrow(/mcpServers/);
    rmSync(dir, { recursive: true, force: true });
  });
});
