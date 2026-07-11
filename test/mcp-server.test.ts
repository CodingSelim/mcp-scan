import { describe, it, expect } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createScanServer } from "../src/mcp-server.js";

const here = dirname(fileURLToPath(import.meta.url));
const vulnerable = join(here, "fixtures", "vulnerable-server.mjs");
const clean = join(here, "fixtures", "clean-server.mjs");

async function connectedClient(): Promise<Client> {
  const server = createScanServer();
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  await server.connect(serverT);
  const client = new Client({ name: "test", version: "1.0.0" }, { capabilities: {} });
  await client.connect(clientT);
  return client;
}

const textOf = (res: { content: Array<{ text?: string }> }): string =>
  res.content.map((c) => c.text ?? "").join("\n");

describe("mcp-scan as an MCP server", () => {
  it("advertises its scan tools", async () => {
    const client = await connectedClient();
    const { tools } = await client.listTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("scan_mcp_server");
    expect(names).toContain("list_checks");
    await client.close();
  });

  it("scans a vulnerable stdio server and returns an F-graded report", async () => {
    const client = await connectedClient();
    const res = (await client.callTool({
      name: "scan_mcp_server",
      arguments: { command: process.execPath, args: [vulnerable] },
    })) as any;
    const text = textOf(res);
    expect(res.isError).toBeFalsy();
    expect(text).toContain("Grade: F");
    expect(text).toMatch(/\[CRITICAL\]/);
    expect(text).toContain("MCP10");
  }, 30000);

  it("scans a clean stdio server without criticals", async () => {
    const client = await connectedClient();
    const res = (await client.callTool({
      name: "scan_mcp_server",
      arguments: { command: process.execPath, args: [clean] },
    })) as any;
    const text = textOf(res);
    expect(text).toMatch(/Grade: [AB]/);
    expect(text).not.toMatch(/\[CRITICAL\]/);
  }, 30000);

  it("returns json when asked", async () => {
    const client = await connectedClient();
    const res = (await client.callTool({
      name: "scan_mcp_server",
      arguments: { command: process.execPath, args: [vulnerable], format: "json" },
    })) as any;
    const parsed = JSON.parse(textOf(res));
    expect(parsed.grade).toBe("F");
    expect(Array.isArray(parsed.findings)).toBe(true);
  }, 30000);

  it("errors when neither command nor url is supplied", async () => {
    const client = await connectedClient();
    const res = (await client.callTool({ name: "scan_mcp_server", arguments: {} })) as any;
    expect(res.isError).toBe(true);
    expect(textOf(res)).toContain("Provide either");
  });

  it("list_checks reports the OWASP mapping", async () => {
    const client = await connectedClient();
    const res = (await client.callTool({ name: "list_checks", arguments: {} })) as any;
    const text = textOf(res);
    expect(text).toContain("toxic-flow");
    expect(text).toContain("MCP10");
  });
});
