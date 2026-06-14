import cors from "cors";
import express from "express";
import path from "node:path";
import { runPreflightAudit } from "../agent/preflightAgent";
import type { AuditOptions } from "../shared/audit";

const app = express();
const port = Number(process.env.PORT ?? 8787);

app.use(cors());
app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_request, response) => {
  response.json({
    ok: true,
    service: "vertical-preflight-agent",
    graph: ["inventory", "secrets", "dependencies", "static_quality", "configuration", "tests", "synthesize"]
  });
});

app.post("/api/audit", async (request, response) => {
  try {
    const body = request.body as Partial<AuditOptions>;
    const projectPath = path.resolve(body.projectPath ?? process.env.PREFLIGHT_DEFAULT_PROJECT ?? ".");
    const report = await runPreflightAudit({
      projectPath,
      includeTests: body.includeTests ?? true,
      testCommand: body.testCommand,
      maxFiles: body.maxFiles,
      maxFileBytes: body.maxFileBytes
    });

    response.json(report);
  } catch (error) {
    response.status(500).json({
      error: "audit_failed",
      message: error instanceof Error ? error.message : String(error)
    });
  }
});

app.listen(port, "127.0.0.1", () => {
  process.stdout.write(`Vertical Preflight Agent API listening on http://127.0.0.1:${port}\n`);
});
