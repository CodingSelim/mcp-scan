// A reasonably-secure MCP server fixture: should produce zero critical findings.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ListPromptsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "clean-test-server", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {}, prompts: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_forecast",
      description: "Return a weather forecast for a supported city.",
      inputSchema: {
        type: "object",
        properties: { city: { type: "string", enum: ["london", "paris", "tokyo"] } },
        required: ["city"],
      },
    },
  ],
}));

server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [] }));
server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: [] }));

const transport = new StdioServerTransport();
await server.connect(transport);
