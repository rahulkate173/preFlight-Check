export type AuditSeverity = "critical" | "high" | "medium" | "low" | "info";

export type AuditCategory =
  | "security"
  | "secrets"
  | "dependencies"
  | "quality"
  | "tests"
  | "configuration"
  | "release";

export type AuditStatus = "passed" | "needs_attention" | "blocked";

export interface AuditFinding {
  id: string;
  title: string;
  severity: AuditSeverity;
  category: AuditCategory;
  file?: string;
  line?: number;
  evidence?: string;
  impact: string;
  recommendation: string;
}

export interface AuditGate {
  name: string;
  status: AuditStatus;
  summary: string;
  findings: AuditFinding[];
  score: AuditScoreItem;
}

export interface AuditOptions {
  projectPath: string;
  includeTests?: boolean;
  testCommand?: string;
  maxFiles?: number;
  maxFileBytes?: number;
  ignorePatterns?: string[];
  testTimeoutMs?: number;
}

export interface AuditScoreItem {
  gate: string;
  maxPoints: number;
  earnedPoints: number;
  pointsLost: number;
  explanation: string;
}

export interface AuditReport {
  projectPath: string;
  generatedAt: string;
  status: AuditStatus;
  score: number;
  scoreBreakdown: AuditScoreItem[];
  summary: string;
  gates: AuditGate[];
  findings: AuditFinding[];
  nextActions: string[];
  metrics: {
    filesScanned: number;
    manifestsFound: string[];
    elapsedMs: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    ignoredEntries: number;
  };
}

export interface FileSnapshot {
  path: string;
  absolutePath: string;
  text: string;
  size: number;
}

export interface ProjectInventory {
  root: string;
  files: FileSnapshot[];
  manifests: string[];
  ignoredEntries: string[];
}
