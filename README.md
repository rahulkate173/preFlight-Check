# Vertical Preflight Agent

A full-stack pre-deployment audit system for projects that need a release gate before shipping. It includes:

- A LangGraph workflow that scans source files, manifests, secrets, dependency hygiene, deployment configuration, static risk patterns, and test status.
- A local Express API used by the web UI.
- An MCP stdio server exposing `predeployment_audit`, so Codex or another MCP-capable coding system can call the vertical agent before deploy.
- A React/Vite operations console with a ChatGPT-style agent session and structured release report.

## Run Locally

```bash
npm install
npm run dev
```

Open the Vite URL shown in the terminal, usually `http://127.0.0.1:5173`.

## MCP Usage

Start the MCP server:

```bash
npm run mcp
```

Expose it to an MCP client with a command equivalent to:

```json
{
  "mcpServers": {
    "vertical-preflight-agent": {
      "command": "npm",
      "args": ["run", "mcp"],
      "cwd": "D:\\OneDrive\\Desktop\\ドキュメント\\secure"
    }
  }
}
```

The server provides this tool:

- `predeployment_audit`

Input:

```json
{
  "projectPath": "D:\\path\\to\\project",
  "includeTests": true,
  "testCommand": "npm test",
  "maxFiles": 250,
  "maxFileBytes": 250000
}
```

## Release Gate Behavior

The agent blocks deployment when it finds critical or high-severity issues. Medium and low-severity findings produce a needs-attention report. A passing report means every configured gate completed without release-blocking findings.

The deterministic scanners work offline. `.env.example` includes optional model settings for future LLM review expansion, but the current release gate does not require an OpenAI API key.
