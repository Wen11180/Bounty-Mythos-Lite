"use client";

import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";

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

  const selectedSource = useMemo(
    () => sources.find((source) => source.sourceId === selectedSourceId) ?? null,
    [selectedSourceId, sources],
  );
  const selectedSnapshot = useMemo(
    () => snapshots.find((snapshot) => snapshot.snapshotId === selectedSnapshotId) ?? null,
    [selectedSnapshotId, snapshots],
  );

  const loadSourceDetails = useCallback(async (source: ProgramRuleSourceView) => {
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
      const mappedSnapshots = rawSnapshots.map(toProgramRuleSnapshotView);
      const mappedScopeRules = rawScopeRules.map(toProgramScopeRuleView);
      const selected = mappedSnapshots.find(
        (snapshot) => snapshot.snapshotId === source.pendingSnapshotId,
      ) ?? mappedSnapshots[0] ?? null;
      setSnapshots(mappedSnapshots);
      setScopeRules(mappedScopeRules);
      setSelectedSnapshotId(selected?.snapshotId ?? null);
      setOperatorConfirmed(false);
      if (selected === null || selected.snapshotId === "unknown_snapshot") {
        setDiff(null);
        return;
      }
      setDiff(toProgramRuleDiffView(
        await getProgramRuleSnapshotDiff(source.sourceId, selected.snapshotId),
      ));
    } catch (error) {
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
    setNotice(null);
    await loadSourceDetails(source);
  }

  async function handleSelectSnapshot(snapshot: ProgramRuleSnapshotView) {
    if (!selectedSource) return;
    setSelectedSnapshotId(snapshot.snapshotId);
    setOperatorConfirmed(false);
    try {
      setDiff(toProgramRuleDiffView(
        await getProgramRuleSnapshotDiff(selectedSource.sourceId, snapshot.snapshotId),
      ));
    } catch (error) {
      setDiff(null);
      setNotice(programRuleErrorMessage(error));
    }
  }

  const reviewEnabled = Boolean(
    selectedSnapshot?.reviewStatus === "pending"
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
          Authorized public policy intake
        </p>
        <h2 className="mt-1 text-lg font-semibold">Program rules</h2>
        <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
          Register one public HTTPS policy page. Studio performs bounded acquisition; extracted
          scope remains review-required and grants no execution or submission authority.
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
            <h3 className="font-semibold">Register public rule URL</h3>
            <Field label="Program alias">
              <input
                className={inputClassName}
                maxLength={64}
                name="program_alias"
                onChange={(event) => setProgramAlias(event.target.value)}
                placeholder="synthetic_program"
                value={programAlias}
              />
            </Field>
            <Field label="Public HTTPS rule URL">
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
              {busy === "register" ? "Registering" : "Register source"}
            </button>
          </form>

          <div className="border border-[var(--line)] p-4">
            <div className="flex items-center justify-between gap-3">
              <h3 className="font-semibold">Sources</h3>
              <button
                className={secondaryButtonClassName}
                disabled={!selectedSource || busy !== null}
                onClick={() => void handleRefresh()}
                type="button"
              >
                {busy === "refresh" ? "Refreshing" : "Manual refresh"}
              </button>
            </div>
            <div className="mt-3 grid gap-2">
              {sources.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">No registered public rule sources.</p>
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
              No review snapshot is available yet. Studio must acquire and normalize the policy.
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
      <Status label="Fetch state" value={source.fetchStatus} />
      <Status label="Effective state" value={source.effectiveStatus} />
      <Status label="Review state" value={source.reviewPending ? "pending" : "none"} />
      <Status label="Next check" value={source.nextCheckAt ?? "unavailable"} />
      <Status label="Contract" value={source.contractStatus} />
      <Status label="Authority" value="fixed false" />
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
    <div className="flex flex-wrap gap-2" aria-label="Program rule snapshots">
      {snapshots.map((snapshot) => (
        <button
          className={snapshot.snapshotId === selectedSnapshotId
            ? primaryButtonClassName
            : secondaryButtonClassName}
          key={snapshot.snapshotId}
          onClick={() => onSelect(snapshot)}
          type="button"
        >
          {snapshot.fetchedAt ?? "unknown time"} · {snapshot.reviewStatus}
        </button>
      ))}
    </div>
  );
}

function SnapshotStatus({ snapshot }: { snapshot: ProgramRuleSnapshotView }) {
  return (
    <dl className="grid grid-cols-2 gap-2 border border-[var(--line)] p-4 text-xs md:grid-cols-4">
      <Status label="Review state" value={snapshot.reviewStatus} />
      <Status label="Fetch mode" value={snapshot.fetchMode} />
      <Status label="Language" value={snapshot.language} />
      <Status label="AI status" value={snapshot.aiStatus} />
    </dl>
  );
}

function ReviewPanel({
  busy,
  confirmed,
  enabled,
  onConfirm,
  onDecision,
  onReviewer,
  reviewerAlias,
  snapshot,
}: {
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
      <h3 className="font-semibold">Human snapshot review</h3>
      <Field label="Reviewer alias">
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
          I reviewed the current digest <code>{shortDigest(snapshot.reviewDigest)}</code> and
          understand approval only materializes review-gated scope rules.
        </span>
      </label>
      <div className="flex flex-wrap gap-2">
        <button
          className={primaryButtonClassName}
          disabled={!enabled}
          onClick={() => onDecision("approve")}
          type="button"
        >
          {busy === "approve" ? "Approving" : "Approve snapshot"}
        </button>
        <button
          className={secondaryButtonClassName}
          disabled={!enabled}
          onClick={() => onDecision("reject")}
          type="button"
        >
          {busy === "reject" ? "Rejecting" : "Reject snapshot"}
        </button>
      </div>
    </div>
  );
}

function DiffPanel({ diff }: { diff: ProgramRuleDiffView }) {
  return (
    <div className="grid gap-4 border border-[var(--line)] p-4 text-sm">
      <h3 className="font-semibold">Snapshot diff</h3>
      <RuleGroup label="Added rules" rules={diff.addedRules} />
      <RuleGroup label="Removed rules" rules={diff.removedRules} />
      <div>
        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Modified rules</p>
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
      <TextList label="Added prohibitions" values={diff.addedProhibitions} />
      <TextList label="Removed prohibitions" values={diff.removedProhibitions} />
      <div>
        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Linked artifacts</p>
        <ul className="mt-2 grid gap-1 font-mono text-xs">
          {[...diff.addedLinkedArtifacts, ...diff.removedLinkedArtifacts].map((artifact, index) => (
            <li key={`${artifact.normalizedSha256}:${index}`}>
              {shortDigest(artifact.normalizedSha256)} · promotion false
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
      <h3 className="font-semibold">Evidence excerpts</h3>
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
            linked {document.kind}: {shortDigest(document.normalizedSha256)}
          </span>
        ))}
        {snapshot.linkedArtifacts.map((artifact) => (
          <span key={artifact.normalizedSha256}>
            OpenAPI candidate: {shortDigest(artifact.normalizedSha256)} · promotion false
          </span>
        ))}
      </div>
    </div>
  );
}

function ScopeRulePanel({ rules }: { rules: ProgramScopeRuleView[] }) {
  return (
    <div className="grid gap-3 border border-[var(--line)] p-4 text-sm">
      <h3 className="font-semibold">Current effective rule projection</h3>
      {rules.length === 0 ? <EmptyValue /> : rules.map((rule) => (
        <div className="border border-[var(--line)] p-3" key={rule.ruleId}>
          <p className="font-mono text-xs">{rule.asset}</p>
          <p className="mt-1">
            {rule.scopeStatus} · automation {rule.automation} · {rule.rateLimit ?? "rate needs review"}
          </p>
          <p className="mt-1 text-xs text-[var(--muted)]">
            Effective {rule.effectiveStatus}; execution and submission authority fixed false.
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
                {rule.scopeStatus} · automation {rule.automation} · {rule.rateLimit ?? "rate needs review"}
              </p>
              {rule.prohibited.length > 0 ? (
                <p className="mt-1 text-xs text-[var(--warning)]">
                  Prohibited: {rule.prohibited.join(", ")}
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
      <p className="mt-1">{values.length > 0 ? values.join(", ") : "None"}</p>
    </div>
  );
}

function Status({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[var(--muted)]">{label}</dt>
      <dd className="mt-1 break-words font-semibold">{value}</dd>
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
  return <p className="mt-1 text-sm text-[var(--muted)]">None</p>;
}

function shortDigest(value: string) {
  return value === "unavailable" ? value : `${value.slice(0, 12)}…`;
}

const inputClassName = "min-h-10 border border-[var(--line)] bg-white px-3 py-2 outline-none focus:border-[var(--accent)]";
const primaryButtonClassName = "min-h-10 border border-[var(--accent)] bg-[var(--accent)] px-3 py-2 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-50";
const secondaryButtonClassName = "min-h-10 border border-[var(--line)] bg-white px-3 py-2 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50";
