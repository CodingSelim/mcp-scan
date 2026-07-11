import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type {
  PromptInfo,
  ResourceInfo,
  ResourceTemplateInfo,
  ScanContext,
  ToolInfo,
  TransportInfo,
} from "./types.js";

export interface StdioTarget {
  kind: "stdio";
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface HttpTarget {
  kind: "http";
  url: string;
  headers?: Record<string, string>;
}

export type Target = StdioTarget | HttpTarget;

const CLIENT_INFO = { name: "mcp-scan", version: "0.2.1" };

async function collect(client: Client) {
  const safe = async <T>(fn: () => Promise<T>, fallback: T): Promise<T> => {
    try {
      return await fn();
    } catch {
      return fallback;
    }
  };

  const caps = client.getServerCapabilities() ?? {};

  const tools: ToolInfo[] = caps.tools
    ? (await safe(() => client.listTools(), { tools: [] })).tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      }))
    : [];

  const prompts: PromptInfo[] = caps.prompts
    ? (await safe(() => client.listPrompts(), { prompts: [] })).prompts.map((p) => ({
        name: p.name,
        description: p.description,
        arguments: p.arguments,
      }))
    : [];

  const resources: ResourceInfo[] = caps.resources
    ? (await safe(() => client.listResources(), { resources: [] })).resources.map((r) => ({
        uri: r.uri,
        name: r.name,
        description: r.description,
        mimeType: r.mimeType,
      }))
    : [];

  const resourceTemplates: ResourceTemplateInfo[] = caps.resources
    ? (
        await safe(() => client.listResourceTemplates(), { resourceTemplates: [] })
      ).resourceTemplates.map((t) => ({
        uriTemplate: t.uriTemplate,
        name: t.name,
        description: t.description,
      }))
    : [];

  const version = client.getServerVersion();
  return {
    serverInfo: version ? { name: version.name, version: version.version } : undefined,
    instructions: client.getInstructions(),
    tools,
    prompts,
    resources,
    resourceTemplates,
  };
}

async function makeTransport(target: Target) {
  if (target.kind === "stdio") {
    return new StdioClientTransport({
      command: target.command,
      args: target.args ?? [],
      env: { ...process.env, ...(target.env ?? {}) } as Record<string, string>,
      stderr: "ignore",
    });
  }
  const url = new URL(target.url);
  const opts = target.headers
    ? { requestInit: { headers: target.headers } }
    : undefined;
  return new StreamableHTTPClientTransport(url, opts);
}

export async function buildScanContext(target: Target): Promise<ScanContext> {
  const client = new Client(CLIENT_INFO, { capabilities: {} });

  let usedFallback = false;
  try {
    await client.connect(await makeTransport(target));
  } catch (err) {
    if (target.kind === "http") {
      // Fall back to legacy SSE transport for older servers.
      const sse = new SSEClientTransport(
        new URL(target.url),
        target.headers ? { requestInit: { headers: target.headers } } : undefined,
      );
      await client.connect(sse);
      usedFallback = true;
    } else {
      throw err;
    }
  }

  const collected = await collect(client);

  const transport: TransportInfo =
    target.kind === "http"
      ? {
          kind: "http",
          url: target.url,
          authRequired: Boolean(target.headers?.["Authorization"] || target.headers?.["authorization"]),
          unauthenticatedHandshakeSucceeded: !target.headers?.["Authorization"] && !target.headers?.["authorization"],
        }
      : { kind: "stdio", authRequired: false };

  const ctx: ScanContext = {
    target: target.kind === "stdio" ? `${target.command} ${(target.args ?? []).join(" ")}`.trim() : target.url,
    transport,
    ...collected,
  };

  await client.close().catch(() => {});
  void usedFallback;
  return ctx;
}
