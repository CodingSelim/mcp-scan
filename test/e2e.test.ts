import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanTarget } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, "fixtures", "vulnerable-server.mjs");
const clean = join(here, "fixtures", "clean-server.mjs");

describe("end-to-end scan against live stdio servers", () => {
  it("detects critical findings in the vulnerable server", async () => {
    const result = await scanTarget({ kind: "stdio", command: process.execPath, args: [vulnerable] });

    expect(result.stats.tools).toBeGreaterThanOrEqual(6);
    expect(result.counts.critical).toBeGreaterThan(0);
    expect(result.grade).toBe("F");

    const ids = new Set(result.findings.map((f) => f.checkId));
    // command injection, poisoning, ssrf, resource, secrets, permissions
    for (const id of ["MCP03", "MCP04", "MCP05", "MCP06", "MCP07", "MCP08"]) {
      expect(ids.has(id as any), `expected a ${id} finding`).toBe(true);
    }
    expect(result.errors).toHaveLength(0);
  }, 30000);

  it("gives the clean server a good grade with no criticals", async () => {
    const result = await scanTarget({ kind: "stdio", command: process.execPath, args: [clean] });
    expect(result.counts.critical).toBe(0);
    expect(["A", "B"]).toContain(result.grade);
  }, 30000);
});
