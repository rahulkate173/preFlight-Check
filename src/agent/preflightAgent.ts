import { Annotation, END, START, StateGraph } from "@langchain/langgraph";
import { exec } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import type {
  AuditFinding,
  AuditGate,
  AuditOptions,
  AuditReport,
  AuditStatus,
  FileSnapshot,
  ProjectInventory
} from "../shared/audit";

const execAsync = promisify(exec);

const DEFAULT_IGNORES = new Set([
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".turbo",
  ".vite",
  "__pycache__"
]);

const TEXT_EXTENSIONS = new Set([
  ".cjs",
  ".css",
  ".env",
  ".html",
  ".js",
  ".json",
  ".jsx",
  ".md",
  ".mjs",
  ".py",
  ".rs",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml"
]);

const AuditState = Annotation.Root({
  options: Annotation<Required<AuditOptions>>(),
  inventory: Annotation<ProjectInventory | null>(),
  gates: Annotation<AuditGate[]>({
    reducer: (left, right) => left.concat(right),
    default: () => []
  }),
  startedAt: Annotation<number>(),
  report: Annotation<AuditReport | null>()
});

type AuditStateType = typeof AuditState.State;

export async function runPreflightAudit(options: AuditOptions): Promise<AuditReport> {
  const startedAt = Date.now();
  const graph = buildGraph();
  const result = await graph.invoke({
    options: normalizeOptions(options),
    inventory: null,
    gates: [],
    startedAt,
    report: null
  });

  if (!result.report) {
    throw new Error("Preflight audit graph completed without a report.");
  }

  return result.report;
}

function buildGraph() {
  return new StateGraph(AuditState)
    .addNode("scan_inventory", inventoryNode)
    .addNode("scan_secrets", secretsNode)
    .addNode("scan_dependencies", dependenciesNode)
    .addNode("scan_static_quality", staticQualityNode)
    .addNode("scan_configuration", configurationNode)
    .addNode("run_tests", testsNode)
    .addNode("synthesize_report", synthesizeNode)
    .addEdge(START, "scan_inventory")
    .addEdge("scan_inventory", "scan_secrets")
    .addEdge("scan_secrets", "scan_dependencies")
    .addEdge("scan_dependencies", "scan_static_quality")
    .addEdge("scan_static_quality", "scan_configuration")
    .addEdge("scan_configuration", "run_tests")
    .addEdge("run_tests", "synthesize_report")
    .addEdge("synthesize_report", END)
    .compile();
}

function normalizeOptions(options: AuditOptions): Required<AuditOptions> {
  return {
    projectPath: path.resolve(options.projectPath || "."),
    includeTests: options.includeTests ?? true,
    testCommand: options.testCommand ?? process.env.PREFLIGHT_TEST_COMMAND ?? "",
    maxFiles: options.maxFiles ?? Number(process.env.PREFLIGHT_MAX_FILES ?? 250),
    maxFileBytes: options.maxFileBytes ?? Number(process.env.PREFLIGHT_MAX_FILE_BYTES ?? 250_000)
  };
}

async function inventoryNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const root = state.options.projectPath;
  const files = await collectTextFiles(root, state.options.maxFiles, state.options.maxFileBytes);
  const manifests = files
    .map((file) => file.path)
    .filter((filePath) => /(^|[/\\])(package\.json|requirements\.txt|pyproject\.toml|Cargo\.toml|go\.mod|Dockerfile|docker-compose\.ya?ml)$/i.test(filePath));

  const missingManifest: AuditFinding[] =
    manifests.length === 0
      ? [
          finding("release.no_manifest", "No project manifest found", "medium", "release", {
            impact: "The preflight agent cannot infer dependency, build, or runtime expectations reliably.",
            recommendation: "Add a package, dependency, or deployment manifest before using this as a release gate."
          })
        ]
      : [];

  return {
    inventory: { root, files, manifests },
    gates: [
      {
        name: "Project Inventory",
        status: missingManifest.length ? "needs_attention" : "passed",
        summary: `Scanned ${files.length} text files and found ${manifests.length} release manifest${manifests.length === 1 ? "" : "s"}.`,
        findings: missingManifest
      }
    ]
  };
}

async function secretsNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const inventory = requireInventory(state);
  const findings: AuditFinding[] = [];
  const patterns = [
    { id: "aws_access_key", label: "AWS access key", regex: /AKIA[0-9A-Z]{16}/g },
    { id: "private_key", label: "Private key block", regex: /-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/g },
    { id: "github_token", label: "GitHub token", regex: /gh[pousr]_[A-Za-z0-9_]{30,}/g },
    { id: "slack_token", label: "Slack token", regex: /xox[baprs]-[A-Za-z0-9-]{20,}/g },
    { id: "generic_secret", label: "Hard-coded secret", regex: /(api[_-]?key|secret|password|token)\s*[:=]\s*["'][^"']{12,}["']/gi }
  ];

  for (const file of inventory.files) {
    if (file.path.endsWith(".env.example")) continue;

    for (const pattern of patterns) {
      const match = pattern.regex.exec(file.text);
      pattern.regex.lastIndex = 0;
      if (!match) continue;

      findings.push(
        finding(`secrets.${pattern.id}.${file.path}`, pattern.label, "critical", "secrets", {
          file: file.path,
          line: lineOf(file.text, match.index),
          evidence: redact(match[0]),
          impact: "A committed credential can be extracted from source control and used outside the intended environment.",
          recommendation: "Remove the value, rotate the credential, and load it from a secret manager or deployment environment."
        })
      );
    }
  }

  return {
    gates: [
      {
        name: "Secret Exposure",
        status: statusFromFindings(findings),
        summary: findings.length ? `Found ${findings.length} potential secret exposure${plural(findings)}.` : "No high-confidence secrets detected.",
        findings
      }
    ]
  };
}

async function dependenciesNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const inventory = requireInventory(state);
  const findings: AuditFinding[] = [];
  const packageJson = inventory.files.find((file) => file.path === "package.json");
  const packageLock = inventory.files.find((file) => file.path === "package-lock.json");

  if (packageJson) {
    try {
      const pkg = JSON.parse(packageJson.text) as {
        dependencies?: Record<string, string>;
        devDependencies?: Record<string, string>;
        scripts?: Record<string, string>;
      };
      const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
      for (const [name, version] of Object.entries(deps)) {
        if (version === "*" || version.startsWith("latest")) {
          findings.push(
            finding(`dependencies.unpinned.${name}`, `Unpinned dependency: ${name}`, "medium", "dependencies", {
              file: packageJson.path,
              impact: "Release builds can change without a code change, making regressions harder to trace.",
              recommendation: "Pin the dependency with a semver range that matches your update policy."
            })
          );
        }
      }
      if (!pkg.scripts?.build) {
        findings.push(
          finding("dependencies.no_build_script", "Missing build script", "medium", "dependencies", {
            file: packageJson.path,
            impact: "The release gate cannot verify that the production artifact compiles.",
            recommendation: "Add a build script that creates the deployable application artifact."
          })
        );
      }
      if (!pkg.scripts?.test) {
        findings.push(
          finding("dependencies.no_test_script", "Missing test script", "low", "tests", {
            file: packageJson.path,
            impact: "Automated regression checks are not wired into the pre-deployment path.",
            recommendation: "Add a test script or configure PREFLIGHT_TEST_COMMAND for this repository."
          })
        );
      }
    } catch {
      findings.push(
        finding("dependencies.invalid_package_json", "Invalid package.json", "high", "dependencies", {
          file: packageJson.path,
          impact: "Dependency and script checks cannot run against malformed package metadata.",
          recommendation: "Fix package.json syntax before deployment."
        })
      );
    }

    if (!packageLock && !inventory.files.some((file) => ["pnpm-lock.yaml", "yarn.lock", "bun.lockb"].includes(file.path))) {
      findings.push(
        finding("dependencies.no_lockfile", "No JavaScript lockfile found", "medium", "dependencies", {
          file: packageJson.path,
          impact: "Install results can drift across environments.",
          recommendation: "Commit the lockfile from the package manager used by the project."
        })
      );
    }
  }

  const requirements = inventory.files.find((file) => file.path === "requirements.txt");
  if (requirements) {
    for (const [index, rawLine] of requirements.text.split(/\r?\n/).entries()) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;
      if (!line.includes("==") && !line.includes("~=")) {
        findings.push(
          finding(`dependencies.python_unpinned.${index}`, "Unpinned Python dependency", "medium", "dependencies", {
            file: requirements.path,
            line: index + 1,
            evidence: line,
            impact: "Python installs can resolve different dependency versions between release attempts.",
            recommendation: "Pin production dependencies with == or a bounded compatible range."
          })
        );
      }
    }
  }

  return {
    gates: [
      {
        name: "Dependency Hygiene",
        status: statusFromFindings(findings),
        summary: findings.length ? `Found ${findings.length} dependency or package concern${plural(findings)}.` : "Dependency manifests look deployable.",
        findings
      }
    ]
  };
}

async function staticQualityNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const inventory = requireInventory(state);
  const findings: AuditFinding[] = [];
  const rules = [
    {
      id: "eval",
      title: "Dynamic code execution",
      severity: "high" as const,
      regex: /\beval\s*\(|new Function\s*\(/g,
      impact: "Dynamic execution can turn user-controlled input into executable code.",
      recommendation: "Replace dynamic execution with explicit parsing or a safe expression evaluator."
    },
    {
      id: "dangerous_html",
      title: "Unsafe HTML injection",
      severity: "high" as const,
      regex: /dangerouslySetInnerHTML|innerHTML\s*=/g,
      impact: "Raw HTML injection can create cross-site scripting vulnerabilities.",
      recommendation: "Render trusted components or sanitize HTML with an allowlist sanitizer."
    },
    {
      id: "todo_release",
      title: "Release-blocking TODO marker",
      severity: "low" as const,
      regex: /TODO|FIXME|HACK/g,
      impact: "Known unfinished work may ship if the release gate does not triage it.",
      recommendation: "Resolve the marker or convert it into an accepted tracked issue before release."
    },
    {
      id: "console_error",
      title: "Debug logging in source",
      severity: "info" as const,
      regex: /console\.(log|debug|trace)\s*\(/g,
      impact: "Debug output can leak implementation details and make production logs noisy.",
      recommendation: "Use structured logging with environment-appropriate levels."
    }
  ];

  for (const file of inventory.files) {
    if (!/\.(ts|tsx|js|jsx|py|html)$/.test(file.path)) continue;

    for (const rule of rules) {
      const match = rule.regex.exec(file.text);
      rule.regex.lastIndex = 0;
      if (!match) continue;
      if (isScannerRuleLiteral(file.text, match.index)) continue;
      findings.push(
        finding(`quality.${rule.id}.${file.path}`, rule.title, rule.severity, rule.severity === "info" ? "quality" : "security", {
          file: file.path,
          line: lineOf(file.text, match.index),
          evidence: match[0],
          impact: rule.impact,
          recommendation: rule.recommendation
        })
      );
    }
  }

  return {
    gates: [
      {
        name: "Static Risk Scan",
        status: statusFromFindings(findings),
        summary: findings.length ? `Found ${findings.length} static code concern${plural(findings)}.` : "No obvious static risk patterns detected.",
        findings
      }
    ]
  };
}

async function configurationNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const inventory = requireInventory(state);
  const findings: AuditFinding[] = [];
  const hasEnvExample = inventory.files.some((file) => file.path === ".env.example" || file.path.endsWith("/.env.example"));
  const hasDockerfile = inventory.files.some((file) => file.path.endsWith("Dockerfile"));
  const hasCi = inventory.files.some((file) => file.path.startsWith(".github/workflows/") || file.path.includes(".gitlab-ci"));

  if (!hasEnvExample) {
    findings.push(
      finding("configuration.no_env_example", "Missing environment template", "low", "configuration", {
        impact: "Operators may not know which settings are required for a safe deployment.",
        recommendation: "Add .env.example or deployment documentation with required variables and safe defaults."
      })
    );
  }

  if (!hasCi) {
    findings.push(
      finding("configuration.no_ci", "No CI workflow detected", "medium", "configuration", {
        impact: "Preflight checks may only run locally and can be skipped accidentally.",
        recommendation: "Add a CI workflow that runs build, tests, and the preflight MCP audit before deployment."
      })
    );
  }

  if (hasDockerfile) {
    const dockerfile = inventory.files.find((file) => file.path.endsWith("Dockerfile"));
    if (dockerfile && /FROM\s+.*:latest/i.test(dockerfile.text)) {
      findings.push(
        finding("configuration.docker_latest", "Docker image uses latest tag", "medium", "configuration", {
          file: dockerfile.path,
          impact: "Base image changes can alter the release artifact without a repository change.",
          recommendation: "Pin the base image tag or digest."
        })
      );
    }
  }

  return {
    gates: [
      {
        name: "Deployment Configuration",
        status: statusFromFindings(findings),
        summary: findings.length ? `Found ${findings.length} deployment configuration gap${plural(findings)}.` : "Deployment configuration has the expected release metadata.",
        findings
      }
    ]
  };
}

async function testsNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const findings: AuditFinding[] = [];
  if (!state.options.includeTests || !state.options.testCommand.trim()) {
    return {
      gates: [
        {
          name: "Automated Tests",
          status: "needs_attention",
          summary: "Test execution was skipped because no test command was configured.",
          findings: [
            finding("tests.skipped", "Test gate skipped", "medium", "tests", {
              impact: "The release report cannot prove that known automated checks pass.",
              recommendation: "Set PREFLIGHT_TEST_COMMAND or pass a test command in the MCP/API request."
            })
          ]
        }
      ]
    };
  }

  try {
    await execAsync(state.options.testCommand, {
      cwd: state.options.projectPath,
      timeout: 120_000,
      windowsHide: true
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    findings.push(
      finding("tests.failed", "Configured test command failed", "high", "tests", {
        evidence: truncate(message, 800),
        impact: "A failing automated check means the project is not ready to ship.",
        recommendation: "Fix the failing tests or update the configured command if it is incorrect."
      })
    );
  }

  return {
    gates: [
      {
        name: "Automated Tests",
        status: statusFromFindings(findings),
        summary: findings.length ? "The configured test command failed." : "The configured test command passed.",
        findings
      }
    ]
  };
}

async function synthesizeNode(state: AuditStateType): Promise<Partial<AuditStateType>> {
  const inventory = requireInventory(state);
  const findings = state.gates.flatMap((gate) => gate.findings);
  const counts = {
    critical: findings.filter((item) => item.severity === "critical").length,
    high: findings.filter((item) => item.severity === "high").length,
    medium: findings.filter((item) => item.severity === "medium").length,
    low: findings.filter((item) => item.severity === "low").length
  };
  const status = overallStatus(findings);
  const score = Math.max(0, 100 - counts.critical * 35 - counts.high * 20 - counts.medium * 8 - counts.low * 3);
  const nextActions = findings
    .filter((item) => item.severity !== "info")
    .slice(0, 6)
    .map((item) => `${item.title}: ${item.recommendation}`);

  return {
    report: {
      projectPath: inventory.root,
      generatedAt: new Date().toISOString(),
      status,
      score,
      summary:
        status === "blocked"
          ? "Deployment should be blocked until critical or high severity findings are resolved."
          : status === "needs_attention"
            ? "Deployment can continue only after the listed medium-risk items are accepted or resolved."
            : "All configured preflight gates passed.",
      gates: state.gates,
      findings,
      nextActions: nextActions.length ? nextActions : ["Keep this audit wired into CI and run it before each deployment."],
      metrics: {
        filesScanned: inventory.files.length,
        manifestsFound: inventory.manifests,
        elapsedMs: Date.now() - state.startedAt,
        ...counts
      }
    }
  };
}

async function collectTextFiles(root: string, maxFiles: number, maxFileBytes: number): Promise<FileSnapshot[]> {
  const files: FileSnapshot[] = [];

  async function walk(current: string) {
    if (files.length >= maxFiles) return;

    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (files.length >= maxFiles) return;
      if (DEFAULT_IGNORES.has(entry.name)) continue;

      const absolutePath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(absolutePath);
        continue;
      }

      if (!entry.isFile()) continue;
      const extension = path.extname(entry.name);
      if (!TEXT_EXTENSIONS.has(extension) && !["Dockerfile", ".env.example"].includes(entry.name)) continue;

      const stat = await fs.stat(absolutePath);
      if (stat.size > maxFileBytes) continue;

      const text = await fs.readFile(absolutePath, "utf8");
      files.push({
        path: path.relative(root, absolutePath).replace(/\\/g, "/"),
        absolutePath,
        text,
        size: stat.size
      });
    }
  }

  await walk(root);
  return files;
}

function requireInventory(state: AuditStateType): ProjectInventory {
  if (!state.inventory) {
    throw new Error("Audit inventory was not initialized.");
  }
  return state.inventory;
}

function finding(
  id: string,
  title: string,
  severity: AuditFinding["severity"],
  category: AuditFinding["category"],
  details: Omit<AuditFinding, "id" | "title" | "severity" | "category">
): AuditFinding {
  return { id, title, severity, category, ...details };
}

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}

function isScannerRuleLiteral(text: string, index: number): boolean {
  const lineStart = text.lastIndexOf("\n", index) + 1;
  const lineEnd = text.indexOf("\n", index);
  const line = text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
  return /(regex|title):/.test(line);
}

function statusFromFindings(findings: AuditFinding[]): AuditStatus {
  if (findings.some((item) => item.severity === "critical" || item.severity === "high")) return "blocked";
  if (findings.some((item) => item.severity === "medium" || item.severity === "low")) return "needs_attention";
  return "passed";
}

function overallStatus(findings: AuditFinding[]): AuditStatus {
  return statusFromFindings(findings);
}

function redact(value: string): string {
  if (value.length <= 8) return "[redacted]";
  return `${value.slice(0, 4)}...[redacted]...${value.slice(-4)}`;
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

function plural(items: unknown[]): string {
  return items.length === 1 ? "" : "s";
}
