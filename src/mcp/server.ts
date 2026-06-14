import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import path from "node:path";
import { z } from "zod";
import { runPreflightAudit } from "../agent/preflightAgent";

const server = new McpServer({
  name: "vertical-preflight-agent",
  version: "0.1.0"
});

server.registerTool(
  "predeployment_audit",
  {
    title: "Pre-deployment audit",
    description:
      "Runs a LangGraph preflight agent over a code project and returns release-blocking bugs, vulnerabilities, configuration gaps, and test status.",
    inputSchema: {
      projectPath: z.string().describe("Path to the project that should be audited."),
      includeTests: z.boolean().optional().default(true),
      testCommand: z.string().optional().describe("Optional command used for the test gate, for example npm test."),
      maxFiles: z.number().int().positive().optional(),
      maxFileBytes: z.number().int().positive().optional()
    }
  },
  async ({ projectPath, includeTests, testCommand, maxFiles, maxFileBytes }) => {
    const report = await runPreflightAudit({
      projectPath: path.resolve(projectPath),
      includeTests,
      testCommand,
      maxFiles,
      maxFileBytes
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(report, null, 2)
        }
      ]
    };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
