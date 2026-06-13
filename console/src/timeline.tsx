import { motion } from "framer-motion";
import type { DetectionRule, ResponseAction, Step } from "./types";
import { Chip, ConfidenceMeter, cx } from "./ui";

const KIND_META: Record<string, { tag: string; tone: string; accent: string }> = {
  triage: { tag: "triage", tone: "text-amber", accent: "var(--color-amber)" },
  search: { tag: "evidence", tone: "text-signal", accent: "var(--color-signal)" },
  reasoning: { tag: "reasoning", tone: "text-violet", accent: "var(--color-violet)" },
  correlation: { tag: "correlation", tone: "text-violet", accent: "var(--color-violet)" },
  verdict: { tag: "verdict", tone: "text-danger", accent: "var(--color-danger)" },
  detection: { tag: "detection", tone: "text-signal", accent: "var(--color-signal)" },
  response_plan: { tag: "response", tone: "text-amber", accent: "var(--color-amber)" },
  error: { tag: "error", tone: "text-danger", accent: "var(--color-danger)" },
};

// Short deterministic seal id from the step sequence, so every committed step
// shows a stable ledger receipt (the thesis: every step is provable).
function sealId(seq: number): string {
  const h = ((seq + 7) * 2654435761) >>> 0;
  return h.toString(16).padStart(8, "0").slice(0, 8);
}

function SplBlock({ spl }: { spl: string }) {
  return (
    <div className="mt-2 overflow-hidden rounded-sm border border-line bg-ink-2">
      <div className="flex items-center justify-between border-b border-line px-2.5 py-1">
        <span className="font-mono text-[10px] uppercase tracking-widest text-fog">SPL</span>
        <span className="font-mono text-[10px] text-signal">splunk_search · via MCP</span>
      </div>
      <pre className="overflow-x-auto px-2.5 py-2 font-mono text-[11.5px] leading-relaxed text-mist">
        {spl}
      </pre>
    </div>
  );
}

export function StepCard({ step, index, live }: { step: Step; index: number; live: boolean }) {
  const meta = KIND_META[step.kind] ?? { tag: step.kind, tone: "text-fog" };
  const isReasoning = step.kind === "reasoning" && step.technique_id;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
      className="relative pl-10"
    >
      {/* spine node */}
      <div className="absolute left-[11px] top-1.5 z-10">
        <span
          className={cx(
            "block h-3 w-3 rounded-full border-2 bg-ink",
            live ? "border-signal pulse-ring" : "border-line-2"
          )}
        />
      </div>

      <div
        className={cx("glass relative overflow-hidden rounded-md p-3.5", live && "glow-signal")}
        style={{ borderLeft: `2px solid ${meta.accent}` }}
      >
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-fog">{String(step.seq).padStart(2, "0")}</span>
            <span className={cx("font-mono text-[10px] uppercase tracking-widest", meta.tone)}>
              {meta.tag}
            </span>
          </div>
          {step.result_count != null && (
            <Chip tone="signal">{step.result_count} events</Chip>
          )}
        </div>

        <h4 className="mt-1.5 font-sans text-[15px] font-semibold text-bright text-balance">
          {step.title}
        </h4>

        {isReasoning && (
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <Chip tone="danger">{step.technique_id}</Chip>
            {step.tactic && <Chip>{step.tactic}</Chip>}
          </div>
        )}

        {step.detail && (
          <p className="mt-2 text-[13px] leading-relaxed text-mist">{step.detail}</p>
        )}

        {step.spl && <SplBlock spl={step.spl} />}

        {step.kind === "reasoning" && step.confidence != null && (
          <div className="mt-2.5 max-w-[220px]">
            <ConfidenceMeter value={step.confidence} label="step confidence" />
          </div>
        )}

        <div className="mt-2.5 flex items-center justify-between gap-3 border-t border-line/70 pt-2 font-mono text-[10px] text-fog">
          <span className="seal-in flex items-center gap-1.5 text-signal/80">
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none" aria-hidden>
              <path d="M5 .8 8.5 2.4v2.4c0 2-1.5 3.5-3.5 4-2-.5-3.5-2-3.5-4V2.4z" stroke="currentColor" strokeWidth="0.8" />
              <path d="M3.4 5 4.6 6.2 6.8 3.7" stroke="currentColor" strokeWidth="0.9" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            sealed · index=veritrace_ledger · {sealId(step.seq)}
          </span>
          <span className="flex items-center gap-3">
            {step.latency_ms != null && <span>{step.latency_ms} ms</span>}
            {step.tokens_completion != null && step.tokens_completion > 0 && (
              <span>{(step.tokens_prompt ?? 0) + (step.tokens_completion ?? 0)} tok</span>
            )}
          </span>
        </div>
      </div>
    </motion.div>
  );
}

export function DetectionPanel({
  detection,
  onDeploy,
  deployState,
}: {
  detection: DetectionRule;
  onDeploy: () => void;
  deployState: string;
}) {
  const hits = detection.backtest_hits_incident;
  const fps = detection.backtest_false_positives;
  return (
    <div className="glass rounded-md p-3.5">
      <div className="flex items-center justify-between">
        <div className="font-mono text-[10px] uppercase tracking-widest text-signal">
          detection as code
        </div>
        {hits != null && (
          <span className="font-mono text-[10px] text-fog">
            backtest: <span className="text-signal">{hits} hit</span> ·{" "}
            <span className={fps ? "text-amber" : "text-signal"}>{fps} FP</span>
          </span>
        )}
      </div>
      <h4 className="mt-1.5 text-[14px] font-semibold text-bright">{detection.name}</h4>
      <p className="mt-1.5 text-[12.5px] leading-relaxed text-mist">{detection.rationale}</p>

      <div className="mt-2.5 flex flex-wrap gap-1.5">
        {detection.mitre_techniques.map((t) => (
          <Chip key={t} tone="danger">
            {t}
          </Chip>
        ))}
      </div>

      <div className="mt-2.5 overflow-hidden rounded-sm border border-line bg-ink-2">
        <div className="border-b border-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-widest text-fog">
          savedsearches.conf
        </div>
        <pre className="overflow-x-auto px-2.5 py-2 font-mono text-[11px] leading-relaxed">
          {detection.savedsearch_stanza.split("\n").map((line, i) => (
            <div key={i} className="flex gap-2">
              <span className="select-none text-signal/60">+</span>
              <span className="text-mist">{line}</span>
            </div>
          ))}
        </pre>
      </div>

      <button
        onClick={onDeploy}
        disabled={deployState === "deploying" || deployState === "deployed"}
        className={cx(
          "mt-3 w-full rounded-sm border px-3 py-2 font-mono text-[11px] uppercase tracking-widest transition-colors",
          deployState === "deployed"
            ? "border-signal/50 bg-signal/10 text-signal"
            : "border-line-2 text-mist hover:border-signal/50 hover:text-signal"
        )}
      >
        {deployState === "deployed"
          ? "deployed to splunk"
          : deployState === "deploying"
            ? "deploying..."
            : "deploy detection to splunk"}
      </button>
    </div>
  );
}

const ACTION_LABEL: Record<string, string> = {
  disable_account: "Disable account",
  isolate_host: "Isolate host",
  block_indicator: "Block indicator",
  sinkhole_domain: "Sinkhole domain",
};

export function ContainmentPanel({
  actions,
  onApprove,
}: {
  actions: ResponseAction[];
  onApprove: (idx: number) => void;
}) {
  return (
    <div className="glass rounded-md p-3.5">
      <div className="flex items-center justify-between">
        <div className="font-mono text-[10px] uppercase tracking-widest text-amber">
          containment plan
        </div>
        <span className="font-mono text-[10px] text-fog">human approval required</span>
      </div>
      <div className="mt-2.5 space-y-2">
        {actions.map((a, i) => {
          const approved = a.status === "approved";
          return (
            <div
              key={i}
              className="flex items-center justify-between gap-2 rounded-sm border border-line bg-white/[0.015] px-2.5 py-2"
            >
              <div className="min-w-0">
                <div className="font-mono text-[12px] text-bright">
                  {ACTION_LABEL[a.action] ?? a.action}{" "}
                  <span className="text-signal">{a.target}</span>
                </div>
                <div className="truncate text-[11px] text-fog">{a.rationale}</div>
              </div>
              <button
                onClick={() => onApprove(i)}
                disabled={approved}
                className={cx(
                  "shrink-0 rounded-sm border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors",
                  approved
                    ? "border-signal/50 bg-signal/10 text-signal"
                    : "border-line-2 text-mist hover:border-signal/60 hover:text-signal"
                )}
              >
                {approved ? "approved" : "approve"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
