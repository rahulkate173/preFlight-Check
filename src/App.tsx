import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  ClipboardList,
  FileWarning,
  Gauge,
  GitPullRequest,
  Loader2,
  Play,
  ShieldCheck,
  Terminal,
  XCircle
} from "lucide-react";
import { FormEvent, useMemo, useState } from "react";
import type { AuditFinding, AuditReport, AuditSeverity, AuditStatus } from "./shared/audit";

type ChatMessage = {
  id: string;
  author: "agent" | "user";
  text: string;
};

const severityOrder: AuditSeverity[] = ["critical", "high", "medium", "low", "info"];

export function App() {
  const [projectPath, setProjectPath] = useState(".");
  const [includeTests, setIncludeTests] = useState(true);
  const [testCommand, setTestCommand] = useState("npm test");
  const [report, setReport] = useState<AuditReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      author: "agent",
      text: "Pre-deployment gate is ready. Point me at a project and I will scan release blockers, vulnerabilities, config gaps, and test status."
    }
  ]);

  const groupedFindings = useMemo(() => groupFindings(report?.findings ?? []), [report]);

  async function runAudit(event: FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setMessages((current) => [
      ...current,
      { id: crypto.randomUUID(), author: "user", text: `Audit ${projectPath}` }
    ]);

    try {
      const response = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          projectPath,
          includeTests,
          testCommand: testCommand.trim() || undefined
        })
      });

      if (!response.ok) {
        const body = (await response.json()) as { message?: string };
        throw new Error(body.message ?? "Audit request failed");
      }

      const nextReport = (await response.json()) as AuditReport;
      setReport(nextReport);
      setMessages((current) => [
        ...current,
        {
          id: crypto.randomUUID(),
          author: "agent",
          text: `${headlineForStatus(nextReport.status)} Score ${nextReport.score}/100. ${nextReport.summary}`
        }
      ]);
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : String(caught);
      setError(message);
      setMessages((current) => [
        ...current,
        { id: crypto.randomUUID(), author: "agent", text: `Audit failed: ${message}` }
      ]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="appShell">
      <aside className="sideRail">
        <div className="brandMark">
          <ShieldCheck size={20} />
        </div>
        <button className="railButton active" aria-label="Audit">
          <ClipboardList size={18} />
        </button>
        <button className="railButton" aria-label="MCP">
          <Terminal size={18} />
        </button>
        <button className="railButton" aria-label="Release">
          <GitPullRequest size={18} />
        </button>
      </aside>

      <section className="workspace">
        <header className="topBar">
          <div>
            <p className="eyebrow">Vertical AI Agent</p>
            <h1>Preflight release gate</h1>
          </div>
          <div className={`statusPill ${report?.status ?? "idle"}`}>
            {report ? statusIcon(report.status) : <Bot size={16} />}
            {report ? labelForStatus(report.status) : "Standing by"}
          </div>
        </header>

        <section className="heroBand">
          <div className="heroCopy">
            <span className="modelBadge">LangGraph MCP agent</span>
            <h2>Catch vulnerabilities, broken checks, and release blockers before code ships.</h2>
          </div>
          <div className="heroMetrics" aria-label="Current audit score">
            <Gauge size={28} />
            <strong>{report?.score ?? "--"}</strong>
            <span>release score</span>
          </div>
        </section>

        <section className="mainGrid">
          <div className="conversationPanel">
            <div className="panelHeader">
              <Bot size={18} />
              <span>Agent session</span>
            </div>
            <div className="messages" aria-live="polite">
              {messages.map((message) => (
                <div className={`message ${message.author}`} key={message.id}>
                  <div className="avatar">{message.author === "agent" ? <Bot size={15} /> : "U"}</div>
                  <p>{message.text}</p>
                </div>
              ))}
            </div>
            <form className="auditComposer" onSubmit={runAudit}>
              <label>
                Project path
                <input value={projectPath} onChange={(event) => setProjectPath(event.target.value)} placeholder="D:\\path\\to\\project" />
              </label>
              <label>
                Test command
                <input value={testCommand} onChange={(event) => setTestCommand(event.target.value)} placeholder="npm test" />
              </label>
              <div className="composerActions">
                <label className="toggle">
                  <input checked={includeTests} onChange={(event) => setIncludeTests(event.target.checked)} type="checkbox" />
                  <span>Run test gate</span>
                </label>
                <button className="primaryButton" disabled={loading} type="submit">
                  {loading ? <Loader2 className="spin" size={17} /> : <Play size={17} />}
                  Run audit
                </button>
              </div>
            </form>
            {error ? <p className="errorLine">{error}</p> : null}
          </div>

          <div className="reportPanel">
            <div className="panelHeader">
              <FileWarning size={18} />
              <span>Gate report</span>
            </div>
            {report ? (
              <>
                <div className="scoreRow">
                  {severityOrder.slice(0, 4).map((severity) => (
                    <SeverityStat key={severity} label={severity} value={severityValue(report, severity)} />
                  ))}
                </div>
                <div className="gates">
                  {report.gates.map((gate) => (
                    <div className="gateRow" key={gate.name}>
                      <div className={`gateIcon ${gate.status}`}>{statusIcon(gate.status)}</div>
                      <div>
                        <strong>{gate.name}</strong>
                        <p>{gate.summary}</p>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="nextActions">
                  <h3>Next actions</h3>
                  {report.nextActions.map((action) => (
                    <p key={action}>{action}</p>
                  ))}
                </div>
              </>
            ) : (
              <div className="emptyState">
                <ShieldCheck size={44} />
                <p>No report yet.</p>
              </div>
            )}
          </div>
        </section>

        <section className="findingsBand">
          <div className="sectionTitle">
            <h2>Findings</h2>
            <span>{report?.metrics.filesScanned ?? 0} files scanned</span>
          </div>
          {report && report.findings.length ? (
            <div className="findingColumns">
              {severityOrder.map((severity) =>
                groupedFindings[severity]?.length ? (
                  <div className="findingColumn" key={severity}>
                    <h3>{severity}</h3>
                    {groupedFindings[severity].map((finding) => (
                      <FindingItem finding={finding} key={finding.id} />
                    ))}
                  </div>
                ) : null
              )}
            </div>
          ) : (
            <div className="quietEmpty">Run an audit to populate release findings.</div>
          )}
        </section>
      </section>
    </main>
  );
}

function SeverityStat({ label, value }: { label: string; value: number }) {
  return (
    <div className={`severityStat ${label}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function FindingItem({ finding }: { finding: AuditFinding }) {
  return (
    <article className={`findingItem ${finding.severity}`}>
      <div>
        <strong>{finding.title}</strong>
        <span>{finding.category}</span>
      </div>
      {finding.file ? (
        <p className="fileRef">
          {finding.file}
          {finding.line ? `:${finding.line}` : ""}
        </p>
      ) : null}
      <p>{finding.impact}</p>
      <p className="recommendation">{finding.recommendation}</p>
    </article>
  );
}

function groupFindings(findings: AuditFinding[]): Record<AuditSeverity, AuditFinding[]> {
  return severityOrder.reduce(
    (accumulator, severity) => {
      accumulator[severity] = findings.filter((finding) => finding.severity === severity);
      return accumulator;
    },
    {} as Record<AuditSeverity, AuditFinding[]>
  );
}

function severityValue(report: AuditReport, severity: AuditSeverity): number {
  if (severity === "critical") return report.metrics.critical;
  if (severity === "high") return report.metrics.high;
  if (severity === "medium") return report.metrics.medium;
  if (severity === "low") return report.metrics.low;
  return report.findings.filter((finding) => finding.severity === severity).length;
}

function statusIcon(status: AuditStatus) {
  if (status === "passed") return <CheckCircle2 size={16} />;
  if (status === "blocked") return <XCircle size={16} />;
  return <AlertTriangle size={16} />;
}

function labelForStatus(status: AuditStatus) {
  if (status === "passed") return "Ready";
  if (status === "blocked") return "Blocked";
  return "Needs attention";
}

function headlineForStatus(status: AuditStatus) {
  if (status === "passed") return "Release gate passed.";
  if (status === "blocked") return "Release gate blocked.";
  return "Release gate needs attention.";
}
