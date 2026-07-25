"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  approveProgramRuleSnapshot,
  getProgramRuleSnapshotDiff,
  listProgramRuleSnapshots,
  listProgramRuleSources,
  listProgramScopeRules,
  refreshProgramRuleSource,
  registerProgramRuleSource,
  rejectProgramRuleSnapshot,
} from "@/lib/api";
import {
  isProgramRuleReviewBindingValid,
  isSafeProgramRuleRegistration,
  programRuleErrorMessage,
  toProgramRuleDiffView,
  toProgramRuleSnapshotView,
  toProgramRuleSourceView,
  toProgramScopeRuleView,
  type ProgramRuleCandidateView,
  type ProgramRuleDiffView,
  type ProgramRuleSnapshotView,
  type ProgramRuleSourceView,
  type ProgramScopeRuleView,
  type SafeRefreshStatus,
} from "@/lib/program-rule-data";
import { formatLabel } from "@/lib/workbench-display";

const safeAliasPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;

export function ProgramRuleIntake() {
  const [sources, setSources] = useState<ProgramRuleSourceView[]>([]);
  const [selectedSourceId, setSelectedSourceId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<ProgramRuleSnapshotView[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [diff, setDiff] = useState<ProgramRuleDiffView | null>(null);
  const [scopeRules, setScopeRules] = useState<ProgramScopeRuleView[]>([]);
  const [programAlias, setProgramAlias] = useState("");
  const [publicRuleUrl, setPublicRuleUrl] = useState("");
  const [reviewerAlias, setReviewerAlias] = useState("");
  const [operatorConfirmed, setOperatorConfirmed] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const sourceDetailsRequest = useRef(0);
  const diffRequest = useRef(0);

  const selectedSource = useMemo(
    () => sources.find((source) => source.sourceId === selectedSourceId) ?? null,
    [selectedSourceId, sources],
  );
  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.snapshotId === selectedSnapshotId) ?? null,
    [selectedSnapshotId, snapshots],
  );
  const reviewContractValid = useMemo(
    () => isProgramRuleReviewBindingValid(selectedSource, selectedSnapshot, diff)
      && scopeRules.every(
        (rule) => rule.contractStatus === "valid" && rule.authorityStatus === "fixed_false",
      ),
    [diff, scopeRules, selectedSnapshot, selectedSource],
  );

  const loadSourceDetails = useCallback(async (source: ProgramRuleSourceView) => {
    const detailsRequestId = ++sourceDetailsRequest.current;
    ++diffRequest.current;
    setDiff(null);
    setOperatorConfirmed(false);
    if (source.sourceId === "unknown_source") {
      setSnapshots([]);
      setSelectedSnapshotId(null);
      setDiff(null);
      setScopeRules([]);
      return;
    }
    try {
      const [rawSnapshots, rawScopeRules] = await Promise.all([
        listProgramRuleSnapshots(source.sourceId),
        source.programId ? listProgramScopeRules(source.programId) : Promise.resolve([]),
      ]);
      if (detailsRequestId !== sourceDetailsRequest.current) return;
      const mappedSnapshots = rawSnapshots.map(toProgramRuleSnapshotView);
      const mappedScopeRules = rawScopeRules.map(toProgramScopeRuleView);
      const selected = mappedSnapshots.find(
        (snapshot) => snapshot.snapshotId === source.pendingSnapshotId,
      ) ?? mappedSnapshots[0] ?? null;
      setSnapshots(mappedSnapshots);
      setScopeRules(mappedScopeRules);
      setSelectedSnapshotId(selected?.snapshotId ?? null);
      if (selected === null || selected.snapshotId === "unknown_snapshot") {
        return;
      }
      const diffRequestId = ++diffRequest.current;
      try {
        const mappedDiff = toProgramRuleDiffView(
          await getProgramRuleSnapshotDiff(source.sourceId, selected.snapshotId),
        );
        if (
          detailsRequestId === sourceDetailsRequest.current
          && diffRequestId === diffRequest.current
        ) setDiff(mappedDiff);
      } catch (error) {
        if (
          detailsRequestId === sourceDetailsRequest.current
          && diffRequestId === diffRequest.current
        ) {
          setDiff(null);
          setNotice(programRuleErrorMessage(error));
        }
      }
    } catch (error) {
      if (detailsRequestId !== sourceDetailsRequest.current) return;
      setSnapshots([]);
      setSelectedSnapshotId(null);
      setDiff(null);
      setScopeRules([]);
      setNotice(programRuleErrorMessage(error));
    }
  }, []);

  const loadSources = useCallback(async (preferredSourceId?: string) => {
    try {
      const mapped = (await listProgramRuleSources()).map(toProgramRuleSourceView);
      const selected = mapped.find((source) => source.sourceId === preferredSourceId)
        ?? mapped[0]
        ?? null;
      setSources(mapped);
      setSelectedSourceId(selected?.sourceId ?? null);
      if (selected) await loadSourceDetails(selected);
      else {
        setSnapshots([]);
        setSelectedSnapshotId(null);
        setDiff(null);
        setScopeRules([]);
      }
    } catch (error) {
      setSources([]);
      setSelectedSourceId(null);
      setNotice(programRuleErrorMessage(error));
    }
  }, [loadSourceDetails]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadSources();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadSources]);

  async function kickStudio(): Promise<SafeRefreshStatus | null> {
    try {
      const result = await window.mythosStudio?.refreshProgramRules();
      if (
        !result
        || !["completed", "failed", "idle"].includes(result.status)
        || typeof result.processed !== "boolean"
      ) {
        setNotice("studio_required");
        return null;
      }
      return result;
    } catch {
      setNotice("studio_required");
      return null;
    }
  }

  async function handleRegister() {
    if (!isSafeProgramRuleRegistration({ programAlias, publicRuleUrl })) {
      setNotice("invalid_public_rule_registration");
      return;
    }
    setBusy("register");
    setNotice(null);
    try {
      const created = toProgramRuleSourceView(await registerProgramRuleSource({
        program_alias: programAlias,
        public_rule_url: publicRuleUrl,
      }));
      await kickStudio();
      await loadSources(created.sourceId);
      setProgramAlias("");
      setPublicRuleUrl("");
    } catch (error) {
      setNotice(programRuleErrorMessage(error));
    } finally {
      setBusy(null);
    }
  }

  async function handleRefresh() {
    if (!selectedSource) return;
    setBusy("refresh");
    setNotice(null);
    try {
      await refreshProgramRuleSource(selectedSource.sourceId);
      await kickStudio();
      await loadSources(selectedSource.sourceId);
    } catch (error) {
      setNotice(programRuleErrorMessage(error));
    } finally {
      setBusy(null);
    }
  }

  async function handleReview(decision: "approve" | "reject") {
    if (
      !selectedSource
      || !selectedSnapshot
      || !reviewContractValid
      || selectedSnapshot.reviewStatus !== "pending"
      || selectedSnapshot.reviewDigest === "unavailable"
      || !safeAliasPattern.test(reviewerAlias)
      || !operatorConfirmed
    ) {
      setNotice("review_confirmation_required");
      return;
    }
    setBusy(decision);
    setNotice(null);
    try {
      const input = {
        expected_review_digest: selectedSnapshot.reviewDigest,
        operator_confirmed: true as const,
        reviewer_alias: reviewerAlias,
      };
      if (decision === "approve") {
        await approveProgramRuleSnapshot(
          selectedSource.sourceId,
          selectedSnapshot.snapshotId,
          input,
        );
      } else {
        await rejectProgramRuleSnapshot(
          selectedSource.sourceId,
          selectedSnapshot.snapshotId,
          input,
        );
      }
      setOperatorConfirmed(false);
      await loadSources(selectedSource.sourceId);
    } catch (error) {
      setNotice(programRuleErrorMessage(error));
    } finally {
      setBusy(null);
    }
  }

  async function handleSelectSource(source: ProgramRuleSourceView) {
    setSelectedSourceId(source.sourceId);
    setDiff(null);
    setNotice(null);
    await loadSourceDetails(source);
  }

  async function handleSelectSnapshot(snapshot: ProgramRuleSnapshotView) {
    if (!selectedSource) return;
    setSelectedSnapshotId(snapshot.snapshotId);
    setOperatorConfirmed(false);
    setDiff(null);
    setNotice(null);
    const diffRequestId = ++diffRequest.current;
    try {
      const mappedDiff = toProgramRuleDiffView(
        await getProgramRuleSnapshotDiff(selectedSource.sourceId, snapshot.snapshotId),
      );
      if (diffRequestId === diffRequest.current) setDiff(mappedDiff);
    } catch (error) {
      if (diffRequestId === diffRequest.current) {
        setDiff(null);
        setNotice(programRuleErrorMessage(error));
      }
    }
  }

  const reviewEnabled = Boolean(
    reviewContractValid
    && selectedSnapshot?.reviewStatus === "pending"
    && selectedSnapshot.reviewDigest !== "unavailable"
    && safeAliasPattern.test(reviewerAlias)
    && operatorConfirmed
    && busy === null,
  );

  return (
    <section
      className="mt-6 border border-[var(--line)] bg-white"
      data-testid="program-rule-intake"
      id="program-rule-intake"
    >
      <div className="border-b border-[var(--line)] px-5 py-4">
        <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
          授权公开策略接入
        </p>
        <h2 className="mt-1 text-lg font-semibold">项目规则</h2>
        <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
          注册一个公开 HTTPS 策略页面。研究工作台执行受限获取；提取的范围仍需审核，
          不授予执行或报告提交权限。
        </p>
      </div>

      <div className="grid gap-5 p-5 xl:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
        <div className="grid content-start gap-5">
          <form
            className="grid gap-3 border border-[var(--line)] p-4"
            onSubmit={(event) => {
              event.preventDefault();
              void handleRegister();
            }}
          >
            <h3 className="font-semibold">注册公开规则 URL</h3>
            <Field label="项目别名">
              <input
                className={inputClassName}
                maxLength={64}
                name="program_alias"
                onChange={(event) => setProgramAlias(event.target.value)}
                placeholder="synthetic_program"
                value={programAlias}
              />
            </Field>
            <Field label="公开 HTTPS 规则 URL">
              <input
                className={inputClassName}
                inputMode="url"
                maxLength={2_048}
                name="public_rule_url"
                onChange={(event) => setPublicRuleUrl(event.target.value)}
                placeholder="https://rules.example.test/program"
                type="url"
                value={publicRuleUrl}
              />
            </Field>
            <button
              className={primaryButtonClassName}
              disabled={busy !== null}
              type="submit"
            >
              {busy === "register" ? "注册中" : "注册来源"}
            </button>
          </form>

          <div className="border border-[var(--line)] p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="font-semibold">来源</h3>
              <button
                className={secondaryButtonClassName}
                disabled={!selectedSource || busy !== null}
                onClick={() => void handleRefresh()}
                type="button"
              >
                {busy === "refresh" ? "刷新中" : "手动刷新"}
              </button>
            </div>
            <div className="mt-3 grid gap-2">
              {sources.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">暂无已注册的公开规则来源。</p>
              ) : sources.map((source) => (
                <button
                  className={`border p-3 text-left text-sm ${
                    source.sourceId === selectedSourceId
                      ? "border-[var(--accent)] bg-[var(--accent-surface)]"
                      : "border-[var(--line)]"
                  }`}
                  key={source.sourceId}
                  onClick={() => void handleSelectSource(source)}
                  type="button"
                >
                  <span className="block font-semibold">{source.programAlias}</span>
                  <span className="mt-1 block break-all text-xs text-[var(--muted)]">
                    {source.canonicalUrl}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {selectedSource ? <SourceStatus source={selectedSource} /> : null}
          {notice ? (
            <p aria-live="polite" className="border border-[var(--warning)] p-3 text-sm text-[var(--warning)]">
              {notice}
            </p>
          ) : null}
        </div>

        <div className="grid content-start gap-5">
          <SnapshotSelector
            onSelect={(snapshot) => void handleSelectSnapshot(snapshot)}
            selectedSnapshotId={selectedSnapshotId}
            snapshots={snapshots}
          />
          {selectedSnapshot ? (
            <>
              <SnapshotStatus snapshot={selectedSnapshot} />
              <ReviewPanel
                busy={busy}
                confirmed={operatorConfirmed}
                enabled={reviewEnabled}
                bindingValid={reviewContractValid}
                onConfirm={setOperatorConfirmed}
                onDecision={(decision) => void handleReview(decision)}
                onReviewer={setReviewerAlias}
                reviewerAlias={reviewerAlias}
                snapshot={selectedSnapshot}
              />
              {diff ? <DiffPanel diff={diff} /> : null}
              <EvidencePanel snapshot={selectedSnapshot} />
              <ScopeRulePanel rules={scopeRules} />
            </>
          ) : (
            <p className="border border-[var(--line)] p-4 text-sm text-[var(--muted)]">
              暂无可审核的快照。研究工作台需要先获取并标准化策略内容。
            </p>
          )}
        </div>
      </div>
    </section>
  );
}

function SourceStatus({ source }: { source: ProgramRuleSourceView }) {
  return (
    <dl className="grid grid-cols-3 gap-2 border border-[var(--line)] p-4 text-xs">
      <Status label="获取状态" value={source.fetchStatus} />
      <Status label="生效状态" value={source.effectiveStatus} />
      <Status label="审核状态" value={source.reviewPending ? "pending" : "none"} />
      <Status label="下次检查" value={source.nextCheckAt ?? "unavailable"} />
      <Status label="契约" value={source.contractStatus} />
      <Status label="权限" value={authorityLabel(source.authorityStatus)} />
    </dl>
  );
}

function SnapshotSelector({
  onSelect,
  selectedSnapshotId,
  snapshots,
}: {
  onSelect: (snapshot: ProgramRuleSnapshotView) => void;
  selectedSnapshotId: string | null;
  snapshots: ProgramRuleSnapshotView[];
}) {
  if (snapshots.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2" aria-label="项目规则快照">
      {snapshots.map((snapshot) => (
        <button
          className={snapshot.snapshotId === selectedSnapshotId
            ? primaryButtonClassName
            : secondaryButtonClassName}
          key={snapshot.snapshotId}
          onClick={() => onSelect(snapshot)}
          type="button"
        >
          {snapshot.fetchedAt ?? "未知时间"} · {formatLabel(snapshot.reviewStatus)}
        </button>
      ))}
    </div>
  );
}

function SnapshotStatus({ snapshot }: { snapshot: ProgramRuleSnapshotView }) {
  return (
    <dl className="grid grid-cols-2 gap-2 border border-[var(--line)] p-4 text-xs md:grid-cols-6">
      <Status label="审核状态" value={snapshot.reviewStatus} />
      <Status label="获取方式" value={snapshot.fetchMode} />
      <Status label="语言" value={snapshot.language} />
      <Status label="AI 状态" value={snapshot.aiStatus} />
      <Status label="契约" value={snapshot.contractStatus} />
      <Status label="权限" value={authorityLabel(snapshot.authorityStatus)} />
    </dl>
  );
}

function ReviewPanel({
  bindingValid,
  busy,
  confirmed,
  enabled,
  onConfirm,
  onDecision,
  onReviewer,
  reviewerAlias,
  snapshot,
}: {
  bindingValid: boolean;
  busy: string | null;
  confirmed: boolean;
  enabled: boolean;
  onConfirm: (value: boolean) => void;
  onDecision: (decision: "approve" | "reject") => void;
  onReviewer: (value: string) => void;
  reviewerAlias: string;
  snapshot: ProgramRuleSnapshotView;
}) {
  return (
    <div className="grid gap-3 border border-[var(--line)] p-4">
      <h3 className="font-semibold">人工快照审核</h3>
      {!bindingValid ? (
        <p className="text-sm text-[var(--warning)]">
          已禁用审核：来源、快照、显示的差异或范围契约无效或不匹配。
        </p>
      ) : null}
      <Field label="审核人别名">
        <input
          className={inputClassName}
          maxLength={64}
          name="reviewer_alias"
          onChange={(event) => onReviewer(event.target.value)}
          value={reviewerAlias}
        />
      </Field>
      <label className="flex items-start gap-2 text-sm">
        <input
          checked={confirmed}
          className="mt-1"
          onChange={(event) => onConfirm(event.target.checked)}
          type="checkbox"
        />
        <span>
          我已审核当前摘要 <code>{shortDigest(snapshot.reviewDigest)}</code>，并了解批准只会
          生成受审核约束的范围规则。
        </span>
      </label>
      <div className="flex flex-wrap gap-2">
        <button
          className={primaryButtonClassName}
          disabled={!enabled}
          onClick={() => onDecision("approve")}
          type="button"
        >
          {busy === "approve" ? "批准中" : "批准快照"}
        </button>
        <button
          className={secondaryButtonClassName}
          disabled={!enabled}
          onClick={() => onDecision("reject")}
          type="button"
        >
          {busy === "reject" ? "拒绝中" : "拒绝快照"}
        </button>
      </div>
    </div>
  );
}

function DiffPanel({ diff }: { diff: ProgramRuleDiffView }) {
  return (
    <div className="grid gap-4 border border-[var(--line)] p-4 text-sm">
      <h3 className="font-semibold">快照差异</h3>
      <dl className="grid grid-cols-2 gap-2 text-xs">
        <Status label="契约" value={diff.contractStatus} />
        <Status label="权限" value={authorityLabel(diff.authorityStatus)} />
      </dl>
      <RuleGroup label="新增规则" rules={diff.addedRules} />
      <RuleGroup label="移除规则" rules={diff.removedRules} />
      <div>
        <p className="text-xs font-semibold uppercase text-[var(--muted)]">修改的规则</p>
        {diff.modifiedRules.length === 0 ? <EmptyValue /> : (
          <ul className="mt-2 grid gap-2">
            {diff.modifiedRules.map((rule, index) => (
              <li className="border border-[var(--line)] p-2" key={`${rule.asset}:${index}`}>
                {rule.asset}: {rule.before.scopeStatus} → {rule.after.scopeStatus}
              </li>
            ))}
          </ul>
        )}
      </div>
      <TextList label="新增禁止项" values={diff.addedProhibitions} />
      <TextList label="移除禁止项" values={diff.removedProhibitions} />
      <div>
        <p className="text-xs font-semibold uppercase text-[var(--muted)]">关联资料</p>
        <ul className="mt-2 grid gap-1 font-mono text-xs">
          {[...diff.addedLinkedArtifacts, ...diff.removedLinkedArtifacts].map((artifact, index) => (
            <li key={`${artifact.normalizedSha256}:${index}`}>
              {shortDigest(artifact.normalizedSha256)} · 不允许提升
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function EvidencePanel({ snapshot }: { snapshot: ProgramRuleSnapshotView }) {
  return (
    <div className="grid gap-3 border border-[var(--line)] p-4 text-sm">
      <h3 className="font-semibold">证据摘录</h3>
      {snapshot.evidence.length === 0 ? <EmptyValue /> : snapshot.evidence.map((evidence) => (
        <blockquote className="border-l-2 border-[var(--accent)] pl-3" key={evidence.evidenceId}>
          <p>{evidence.excerpt}</p>
          <footer className="mt-1 font-mono text-xs text-[var(--muted)]">
            {evidence.locator} · {shortDigest(evidence.documentSha256)}
          </footer>
        </blockquote>
      ))}
      <div className="grid gap-1 font-mono text-xs text-[var(--muted)]">
        {snapshot.linkedDocuments.map((document) => (
          <span key={document.normalizedSha256}>
            已关联 {formatLabel(document.kind)}：{shortDigest(document.normalizedSha256)}
          </span>
        ))}
        {snapshot.linkedArtifacts.map((artifact) => (
          <span key={artifact.normalizedSha256}>
            OpenAPI 候选：{shortDigest(artifact.normalizedSha256)} · 不允许提升
          </span>
        ))}
      </div>
    </div>
  );
}

function ScopeRulePanel({ rules }: { rules: ProgramScopeRuleView[] }) {
  return (
    <div className="grid gap-3 border border-[var(--line)] p-4 text-sm">
      <h3 className="font-semibold">当前生效规则投影</h3>
      {rules.length === 0 ? <EmptyValue /> : rules.map((rule) => (
        <div className="border border-[var(--line)] p-3" key={rule.ruleId}>
          <p className="font-mono text-xs">{rule.asset}</p>
          <p className="mt-1">
            {formatLabel(rule.scopeStatus)} · 自动化 {formatLabel(rule.automation)} · {displayRateLimit(rule.rateLimit)}
          </p>
          <p className="mt-1 text-xs text-[var(--muted)]">
            契约 {formatLabel(rule.contractStatus)}；权限 {authorityLabel(rule.authorityStatus)}。
            {rule.contractStatus === "valid" && rule.authorityStatus === "fixed_false"
              ? ` 已生效 ${formatLabel(rule.effectiveStatus)}；执行与报告提交权限固定为否。`
              : " 此投影不具备审核授权效力。"}
          </p>
        </div>
      ))}
    </div>
  );
}

function RuleGroup({ label, rules }: { label: string; rules: ProgramRuleCandidateView[] }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</p>
      {rules.length === 0 ? <EmptyValue /> : (
        <ul className="mt-2 grid gap-2">
          {rules.map((rule, index) => (
            <li className="border border-[var(--line)] p-2" key={`${rule.asset}:${index}`}>
              <p className="font-mono text-xs">{rule.asset}</p>
              <p className="mt-1">
                {formatLabel(rule.scopeStatus)} · 自动化 {formatLabel(rule.automation)} · {displayRateLimit(rule.rateLimit)}
              </p>
              {rule.prohibited.length > 0 ? (
                <p className="mt-1 text-xs text-[var(--warning)]">
                  已禁止：{rule.prohibited.map((item) => formatLabel(item)).join("、")}
                </p>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TextList({ label, values }: { label: string; values: string[] }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</p>
      <p className="mt-1">{values.length > 0 ? values.map((value) => formatLabel(value)).join("、") : "无"}</p>
    </div>
  );
}

function Status({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="mt-1 break-words font-semibold">{formatLabel(value)}</dd>
    </div>
  );
}

function Field({ children, label }: { children: ReactNode; label: string }) {
  return (
    <label className="grid gap-1 text-sm">
      <span className="font-semibold">{label}</span>
      {children}
    </label>
  );
}

function EmptyValue() {
  return <p className="mt-1 text-sm text-[var(--muted)]">无</p>;
}

function shortDigest(value: string) {
  return value === "unavailable" ? "暂不可用" : `${value.slice(0, 12)}…`;
}

function authorityLabel(status: "fixed_false" | "invalid") {
  return status === "fixed_false" ? "固定为否" : "无效";
}

function displayRateLimit(value: string | null): string {
  if (!value) return "频率需要审核";
  const match = /^(\d+) per(?: every (\d+))? (second|minute|hour|day)$/u.exec(value);
  if (!match) return value;
  const units: Record<string, string> = {
    day: "天",
    hour: "小时",
    minute: "分钟",
    second: "秒",
  };
  const [, requests, period, unit] = match;
  return `${requests} 次/${period ? `${period} ` : ""}${units[unit]}`;
}

const inputClassName = "min-h-10 border border-[var(--line)] bg-white px-3 py-2 outline-none focus:border-[var(--accent)]";
const primaryButtonClassName = "min-h-10 border border-[var(--accent)] bg-[var(--accent)] px-3 py-2 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButtonClassName = "min-h-10 border border-[var(--line)] bg-white px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50";
