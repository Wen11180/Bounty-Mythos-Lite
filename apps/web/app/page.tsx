import {
  AlertTriangle,
  BadgeCheck,
  BarChart3,
  BookOpen,
  Bot,
  ClipboardCheck,
  Database,
  FileSearch,
  FileText,
  Gauge,
  GitBranch,
  Home,
  Layers,
  ListChecks,
  Lock,
  Settings,
  ShieldCheck,
  Target,
  Upload,
} from "lucide-react";
import { evaluateScopeGuard, getFindings, getPrograms, getReports } from "@/lib/api";
import {
  fallbackFindings,
  fallbackPrograms,
  fallbackReports,
  fallbackScopeGuardDecision,
  fallbackScopeGuardRequest,
  fallbackScopeGuardRule,
} from "@/lib/fallback-data";
import { mythosPipelineStages } from "@/lib/mythos-pipeline-data";
import type { Finding, PolicyStatus, ValidationStatus } from "@/lib/api";

const navigation = [
  { label: "Dashboard", icon: Home },
  { label: "Programs", icon: Target },
  { label: "Assets", icon: Layers },
  { label: "API Model", icon: GitBranch },
  { label: "Business Flows", icon: ListChecks },
  { label: "Hypotheses", icon: Bot },
  { label: "Validation Plans", icon: ClipboardCheck },
  { label: "Findings", icon: FileSearch },
  { label: "Reports", icon: FileText },
  { label: "Submissions", icon: Upload },
  { label: "Knowledge Base", icon: BookOpen },
  { label: "Settings / Policy Guard", icon: Settings },
];

const kpis = [
  { label: "Accepted rate", value: "31%", target: "目标 30%+" },
  { label: "Duplicate rate", value: "22%", target: "目标 <25%" },
  { label: "Informative / N/A", value: "12%", target: "目标 <15%" },
  { label: "Policy violation", value: "0", target: "必须 0" },
];

const guardRules = [
  "禁止自动攻击公网目标",
  "禁止高频扫描和 DoS",
  "禁止触碰真实用户数据",
  "线上验证必须人工确认",
];

const reportReadyStatuses: ValidationStatus[] = [
  "report_ready",
  "human_submitted",
  "accepted",
];

function titleCase(value: string): string {
  return value
    .split("_")
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function formatGuard(finding: Finding): string {
  if (finding.scope_status === "in_scope" && finding.policy_status === "allowed") {
    return "Scope / Policy 通过";
  }

  return "等待人工确认";
}

function formatStatus(status: ValidationStatus): string {
  return titleCase(status);
}

function formatSeverity(severity: string): string {
  return titleCase(severity);
}

function countPolicyBlocked(findings: Finding[]): number {
  return findings.filter((finding) => finding.policy_status === "blocked").length;
}

function countNeedsReview(findings: Finding[]): number {
  const reviewStatuses: PolicyStatus[] = ["blocked", "needs_review"];

  return findings.filter(
    (finding) =>
      finding.scope_status === "needs_review" || reviewStatuses.includes(finding.policy_status),
  ).length;
}

export default async function Dashboard() {
  const [programs, findings, reports] = await Promise.all([
    getPrograms(fallbackPrograms),
    getFindings(fallbackFindings),
    getReports(fallbackReports),
  ]);
  const scopeGuardDecision = await evaluateScopeGuard(
    fallbackScopeGuardRule,
    fallbackScopeGuardRequest,
    fallbackScopeGuardDecision,
  );

  const todayMetrics = [
    { label: "已解析项目", value: String(programs.length) },
    { label: "高价值候选", value: String(findings.length) },
    {
      label: "可提交报告",
      value: String(
        Math.max(
          reports.length,
          findings.filter((finding) => reportReadyStatuses.includes(finding.validation_status)).length,
        ),
      ),
    },
    { label: "需要人工确认", value: String(countNeedsReview(findings)) },
    { label: "Policy 风险拦截", value: String(countPolicyBlocked(findings)) },
  ];

  return (
    <main className="min-h-screen lg:grid lg:grid-cols-[280px_1fr]">
      <aside className="border-b border-[var(--line)] bg-[#ededdf] px-4 py-5 lg:min-h-screen lg:border-b-0 lg:border-r">
        <div className="mb-8 flex items-center gap-3 px-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[var(--foreground)] text-white">
            <ShieldCheck size={22} aria-hidden="true" />
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
              Bounty
            </p>
            <h1 className="text-xl font-semibold">Mythos-Lite</h1>
          </div>
        </div>

        <nav className="grid gap-1">
          {navigation.map((item) => (
            <a
              href="#"
              key={item.label}
              className="flex min-h-10 items-center gap-3 rounded-md px-3 text-sm font-medium text-[#303433] hover:bg-white"
              title={item.label}
            >
              <item.icon size={18} aria-hidden="true" />
              <span>{item.label}</span>
            </a>
          ))}
        </nav>
      </aside>

      <section className="px-5 py-6 sm:px-8 lg:px-10">
        <header className="mb-8 flex flex-col gap-4 border-b border-[var(--line)] pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
              <Gauge size={17} aria-hidden="true" />
              accepted bounty / human hour
            </p>
            <h2 className="max-w-3xl text-3xl font-semibold leading-tight sm:text-4xl">
              以 Scope Guard 和反证为中心的赏金研究工作台
            </h2>
          </div>
          <div className="max-w-sm rounded-md border border-[var(--line)] bg-white p-4">
            <p className="text-sm font-semibold text-[var(--muted)]">当前模式</p>
            <p className="mt-1 text-lg font-semibold">安全初始化骨架</p>
          </div>
        </header>

        <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
          <section className="grid gap-5">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
              {todayMetrics.map((metric) => (
                <div
                  key={metric.label}
                  className="rounded-md border border-[var(--line)] bg-white p-4"
                >
                  <p className="text-sm text-[var(--muted)]">{metric.label}</p>
                  <p className="mt-3 text-3xl font-semibold">{metric.value}</p>
                </div>
              ))}
            </div>

            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              {kpis.map((kpi) => (
                <div
                  key={kpi.label}
                  className="rounded-md border border-[var(--line)] bg-white p-5"
                >
                  <div className="mb-4 flex items-center justify-between">
                    <p className="font-semibold">{kpi.label}</p>
                    <BarChart3 size={18} className="text-[var(--accent)]" aria-hidden="true" />
                  </div>
                  <p className="text-3xl font-semibold">{kpi.value}</p>
                  <p className="mt-2 text-sm text-[var(--muted)]">{kpi.target}</p>
                </div>
              ))}
            </div>

            <section className="rounded-md border border-[var(--line)] bg-white">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
                <h3 className="text-lg font-semibold">Mythos Pipeline</h3>
                <ShieldCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
              </div>
              <div className="grid gap-0 divide-y divide-[var(--line)] md:grid-cols-2 md:divide-x md:divide-y-0 xl:grid-cols-7">
                {mythosPipelineStages.map((stage) => (
                  <div key={stage.label} className="min-h-36 p-4">
                    <p className="text-sm font-semibold">{stage.label}</p>
                    <p className="mt-4 text-xl font-semibold">{stage.status}</p>
                    <p className="mt-3 text-sm text-[var(--muted)]">{stage.count}</p>
                    <p className="mt-2 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                      {stage.risk}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
                <h3 className="text-lg font-semibold">Findings</h3>
                <BadgeCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
              </div>
              <div className="divide-y divide-[var(--line)]">
                {findings.map((finding) => (
                  <article key={finding.id} className="grid gap-4 p-5 lg:grid-cols-[1fr_140px_120px_120px] lg:items-center">
                    <div>
                      <h4 className="font-semibold">{finding.title}</h4>
                      <p className="mt-2 text-sm text-[var(--muted)]">{formatGuard(finding)}</p>
                    </div>
                    <p className="text-sm font-semibold">{formatStatus(finding.validation_status)}</p>
                    <p className="text-sm">
                      <span className="font-semibold">{formatSeverity(finding.severity_estimate)}</span>
                    </p>
                    <p className="text-sm text-[var(--muted)]">置信度 {Math.round(finding.confidence * 100)}%</p>
                  </article>
                ))}
              </div>
            </section>
          </section>

          <aside className="grid content-start gap-5">
            <section className="rounded-md border border-[var(--line)] bg-white p-5">
              <div className="mb-4 flex items-center gap-2">
                <Lock size={19} className="text-[var(--accent)]" aria-hidden="true" />
                <h3 className="text-lg font-semibold">Policy Guard</h3>
              </div>
              <div className="grid gap-3">
                <div className="rounded-md border border-[var(--line)] bg-[#f7f7f4] p-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold">当前验证决策</span>
                    <span className={scopeGuardDecision.allowed ? "text-[var(--accent-strong)]" : "text-[var(--danger)]"}>
                      {scopeGuardDecision.allowed ? "Allowed" : "Blocked"}
                    </span>
                  </div>
                  <p className="mt-2 text-[var(--muted)]">{titleCase(scopeGuardDecision.reason)}</p>
                </div>
                {guardRules.map((rule) => (
                  <div key={rule} className="flex items-start gap-3 text-sm">
                    <AlertTriangle size={16} className="mt-0.5 text-[var(--warning)]" aria-hidden="true" />
                    <span>{rule}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white p-5">
              <div className="mb-4 flex items-center gap-2">
                <Database size={19} className="text-[var(--accent)]" aria-hidden="true" />
                <h3 className="text-lg font-semibold">Pipeline</h3>
              </div>
              <ol className="grid gap-3 text-sm text-[var(--muted)]">
                <li>Policy 解析</li>
                <li>Scope Guard 规则生成</li>
                <li>API / HAR / 代码资料摄入</li>
                <li>安全不变量生成</li>
                <li>反证与低风险验证计划</li>
              </ol>
            </section>
          </aside>
        </div>
      </section>
    </main>
  );
}
