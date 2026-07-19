import { Bot, UserRound } from "lucide-react";
import type { ReactNode } from "react";

import { toStudioConversationActorLabel } from "@/lib/studio-data";

interface ResearchConversationProps {
  actions?: ReactNode;
  children?: ReactNode;
  messages: Array<{
    actor?: "operator" | "system";
    message: string;
    tone: "blocked" | "info" | "safe";
  }>;
  runId: string;
}

export function ResearchConversation({ actions, children, messages, runId }: ResearchConversationProps) {
  return (
    <section aria-labelledby="conversation-title" className="mt-5" data-testid="studio-conversation">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-[var(--cc-border)] pb-3">
        <div>
          <p className="text-xs text-[var(--cc-text-muted)]">当前任务</p>
          <h2 className="mt-1 text-base font-semibold" id="conversation-title">研究会话</h2>
        </div>
        <span className="font-mono text-xs text-[var(--cc-text-muted)]">{runId}</span>
      </div>
      <div aria-live="polite" className="max-h-72 space-y-3 overflow-y-auto py-4">
        {messages.map((entry, index) => {
          const actorLabel = toStudioConversationActorLabel(entry.actor);
          return (
          <article className="grid grid-cols-[28px_minmax(0,1fr)] gap-3" key={`${entry.message}-${index}`}>
            <div className="grid size-7 place-items-center rounded-sm border border-[var(--cc-border)] bg-[var(--cc-surface-raised)]">
              {actorLabel === "研究员" ? <UserRound aria-hidden="true" className="size-3.5" /> : <Bot aria-hidden="true" className="size-3.5" />}
            </div>
            <div className="min-w-0 border-b border-[var(--cc-border)] pb-3">
              <p className="text-xs font-semibold">{actorLabel}</p>
              <p className="mt-1 text-sm leading-6 text-[var(--cc-text-muted)]">{entry.message}</p>
            </div>
          </article>
          );
        })}
      </div>
      {children ? <div className="border-t border-[var(--cc-border)] pt-4">{children}</div> : null}
      {actions ? <div className="sticky bottom-3 mt-4 border border-[var(--cc-border-strong)] bg-[var(--cc-surface-glass)] p-3 backdrop-blur-xl">{actions}</div> : null}
    </section>
  );
}
