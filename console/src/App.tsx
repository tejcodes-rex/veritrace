import { useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { api, openStream, type LedgerVerification, type Scenario } from "./api";
import type {
  AttackStage,
  DetectionRule,
  Investigation,
  InvestigationSummary,
  ResponseAction,
  Step,
} from "./types";
import {
  ConfidenceMeter,
  EntityGraph,
  KillChain,
  SeverityBadge,
  StatTile,
  VerdictBadge,
  cx,
} from "./ui";
import { ContainmentPanel, DetectionPanel, StepCard } from "./timeline";

const PACE_MS = 900;

interface ActiveState {
  id: string | null;
  steps: Step[];
  detection: DetectionRule | null;
  summary: any | null;
}

export default function App() {
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [health, setHealth] = useState<Record<string, string>>({});
  const [list, setList] = useState<InvestigationSummary[]>([]);

  const storeRef = useRef<Map<string, ActiveState>>(new Map());
  const awaitingRef = useRef(false);
  const knownAtRunRef = useRef<Set<string>>(new Set());

  const [activeId, setActiveId] = useState<string | null>(null);
  const [revealCount, setRevealCount] = useState(0);
  const [running, setRunning] = useState(false);
  const [, force] = useState(0);
  const bump = () => force((n) => n + 1);
  const [deployState, setDeployState] = useState("idle");

  // bootstrap
  useEffect(() => {
    api.scenario().then(setScenario).catch(() => {});
    api.health().then(setHealth).catch(() => {});
    refreshList();
  }, []);

  function refreshList() {
    api.list().then((d) => setList(d.investigations)).catch(() => {});
  }

  // single SSE connection
  const esOpened = useRef(false);
  useEffect(() => {
    if (esOpened.current) return;
    esOpened.current = true;
    const es = openStream((kind, payload) => {
      const id: string = payload.investigation_id;
      if (!id) return;
      const store = storeRef.current;
      if (!store.has(id)) store.set(id, { id, steps: [], detection: null, summary: null });
      const entry = store.get(id)!;

      if (kind === "step") {
        if (!entry.steps.some((s) => s.seq === payload.seq)) entry.steps.push(payload as Step);
        if (awaitingRef.current && !knownAtRunRef.current.has(id)) {
          awaitingRef.current = false;
          setActiveId(id);
          setRevealCount(0);
          setRunning(true);
        }
      } else if (kind === "detection") {
        entry.detection = payload as DetectionRule;
      } else if (kind === "investigation") {
        entry.summary = payload;
        refreshList();
      }
      bump();
    });
    return () => es.close();
  }, []);

  // paced reveal of steps for the active running investigation
  useEffect(() => {
    if (!running || !activeId) return;
    const entry = storeRef.current.get(activeId);
    if (!entry) return;
    const visibleKinds = entry.steps.filter((s) => s.kind !== "detection" && s.kind !== "response_plan" && s.kind !== "verdict");
    if (revealCount < visibleKinds.length) {
      const t = setTimeout(() => setRevealCount((c) => c + 1), PACE_MS);
      return () => clearTimeout(t);
    }
    if (entry.summary && revealCount >= visibleKinds.length) {
      const t = setTimeout(() => setRunning(false), 400);
      return () => clearTimeout(t);
    }
  }, [running, activeId, revealCount, force]);

  function runInvestigation() {
    knownAtRunRef.current = new Set(storeRef.current.keys());
    awaitingRef.current = true;
    setActiveId(null);
    setRevealCount(0);
    setDeployState("idle");
    setRunning(true);
    api.start(scenario?.alert).catch(() => setRunning(false));
  }

  async function selectInvestigation(id: string) {
    setRunning(false);
    const inv: Investigation = await api.get(id);
    storeRef.current.set(id, {
      id,
      steps: inv.steps,
      detection: inv.detection,
      summary: {
        verdict: inv.verdict,
        severity: inv.severity,
        confidence: inv.confidence,
        summary: inv.summary,
        response_actions: inv.response_actions,
        attack_chain: inv.attack_chain,
        mttr_seconds: inv.mttr_seconds,
        total_tokens: inv.total_tokens,
        model_name: inv.model_name,
        model_provider: inv.model_provider,
        ledger_root: (inv as any).ledger_root,
      },
    });
    // Paced playback of a completed investigation: reveal its real recorded
    // steps one at a time, the same cinematic reveal as a live run. The summary
    // is set up front, so the reveal stops cleanly on the verdict.
    setActiveId(id);
    setDeployState("idle");
    setRevealCount(0);
    setRunning(true);
  }

  async function approve(idx: number) {
    if (!activeId) return;
    await api.approve(activeId, idx).catch(() => {});
    const entry = storeRef.current.get(activeId);
    if (entry?.summary?.response_actions?.[idx]) {
      entry.summary.response_actions[idx].status = "approved";
      bump();
    }
  }

  async function deploy() {
    if (!activeId) return;
    setDeployState("deploying");
    const r: any = await api.deployDetection(activeId).catch(() => ({ status: "error" }));
    setDeployState(r.status === "deployed" ? "deployed" : "idle");
  }

  const entry = activeId ? storeRef.current.get(activeId) : null;
  const allSteps = entry?.steps ?? [];
  const visibleSteps = allSteps.filter(
    (s) => s.kind !== "detection" && s.kind !== "response_plan" && s.kind !== "verdict"
  );
  const shown = visibleSteps.slice(0, revealCount);
  const summary = entry?.summary ?? null;
  const summaryReady = summary && !running;

  const liveChain: AttackStage[] = useMemo(() => {
    if (summaryReady && summary.attack_chain?.length) return summary.attack_chain;
    return shown
      .filter((s) => s.technique_id)
      .map((s, i) => ({
        order: i + 1,
        tactic: s.tactic,
        technique_id: s.technique_id,
        technique_name: s.technique_name,
        narrative: s.detail,
        confidence: s.confidence ?? 0,
        evidence_labels: [],
      }));
  }, [shown, summaryReady, summary]);

  const reached = liveChain.length;

  return (
    <div className="relative z-10 mx-auto flex min-h-screen max-w-[1480px] flex-col">
      <Header health={health} running={running} />

      <div className="grid flex-1 grid-cols-[230px_minmax(0,1fr)_360px] gap-4 px-5 pb-8">
        {/* left: incident queue */}
        <aside className="flex flex-col gap-3">
          <button
            onClick={runInvestigation}
            disabled={running}
            className={cx(
              "group relative overflow-hidden rounded-md border px-3 py-2.5 font-mono text-[11px] uppercase tracking-widest transition-colors",
              running
                ? "border-signal/40 text-signal sweep"
                : "border-signal/50 bg-signal/10 text-signal hover:bg-signal/20"
            )}
          >
            {running ? "investigating..." : "run investigation"}
          </button>

          <div className="font-mono text-[10px] uppercase tracking-widest text-fog">incident queue</div>
          <div className="flex flex-col gap-2 overflow-y-auto">
            {scenario && (
              <QueueCard
                title={scenario.alert.name}
                severity={scenario.alert.severity}
                meta={scenario.alert.alert_id}
                active={false}
                onClick={runInvestigation}
                pending
              />
            )}
            {list.map((s) => (
              <QueueCard
                key={s.investigation_id}
                title={s.alert_name}
                severity={(s.severity ?? "high") as any}
                meta={`${s.investigation_id} · ${s.mttr_seconds}s`}
                verdict={s.verdict}
                active={s.investigation_id === activeId}
                onClick={() => selectInvestigation(s.investigation_id)}
              />
            ))}
          </div>
        </aside>

        {/* center: reasoning spine */}
        <main className="flex min-w-0 flex-col gap-4">
          {!entry && <EmptyState onRun={runInvestigation} scenario={scenario} />}

          {entry && (
            <>
              <CaseHeader
                title={scenario?.alert.name ?? "Investigation"}
                summary={summary}
                running={running}
              />
              <KillChain stages={liveChain} />

              <div className="relative mt-1">
                <div className="absolute bottom-2 left-[16px] top-2 w-px spine" />
                <div className="flex flex-col gap-3">
                  <AnimatePresence initial={false}>
                    {shown.map((s, i) => (
                      <StepCard
                        key={s.seq}
                        step={s}
                        index={i}
                        live={running && i === shown.length - 1}
                      />
                    ))}
                  </AnimatePresence>
                  {running && shown.length < visibleSteps.length && (
                    <div className="relative pl-10">
                      <div className="absolute left-[11px] top-2 h-3 w-3 rounded-full border-2 border-signal bg-ink pulse-ring" />
                      <div className="font-mono text-[11px] text-fog">
                        <span className="text-signal">querying splunk over MCP</span>
                        <span className="blink"> _</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {summaryReady && <VerdictPanel summary={summary} sealed={allSteps.length} iid={activeId} />}
            </>
          )}
        </main>

        {/* right: context */}
        <aside className="flex flex-col gap-4">
          {scenario && <EntityGraph entities={scenario.entities} reached={reached} />}
          {summaryReady && entry?.detection && (
            <DetectionPanel detection={entry.detection} onDeploy={deploy} deployState={deployState} />
          )}
          {summaryReady && summary.response_actions?.length > 0 && (
            <ContainmentPanel actions={summary.response_actions as ResponseAction[]} onApprove={approve} />
          )}
        </aside>
      </div>
    </div>
  );
}

function Header({ health, running }: { health: Record<string, string>; running: boolean }) {
  return (
    <header className="flex items-center justify-between border-b border-line px-5 py-3.5">
      <div className="flex items-center gap-3">
        <div className="grid h-8 w-8 place-items-center rounded-sm border border-signal/40 bg-signal/10">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M8 1L14 4v4c0 3.5-2.6 6.3-6 7-3.4-.7-6-3.5-6-7V4l6-3z" stroke="#34e3c4" strokeWidth="1.2" />
            <path d="M5 8l2 2 4-4.5" stroke="#34e3c4" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <div>
          <div className="font-sans text-[17px] font-bold leading-none tracking-tight text-bright">
            Veritrace
          </div>
          <div className="font-mono text-[10px] uppercase tracking-widest text-fog">
            autonomous soc analyst
          </div>
        </div>
      </div>
      <div className="flex items-center gap-4 font-mono text-[11px] text-fog">
        <span className="flex items-center gap-1.5">
          <span className={cx("h-1.5 w-1.5 rounded-full", running ? "bg-amber blink" : "bg-signal")} />
          {running ? "live investigation" : "ready"}
        </span>
        <span className="hidden sm:inline">
          model <span className="text-mist">{health.model_provider ?? "..."}</span>
        </span>
        <span className="hidden md:inline">
          mcp <span className="text-signal">connected</span>
        </span>
      </div>
    </header>
  );
}

function QueueCard({
  title,
  severity,
  meta,
  verdict,
  active,
  pending,
  onClick,
}: {
  title: string;
  severity: any;
  meta: string;
  verdict?: string | null;
  active: boolean;
  pending?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cx(
        "rounded-md border p-2.5 text-left transition-colors",
        active ? "border-signal/50 bg-signal/5" : "border-line hover:border-line-2 bg-white/[0.012]"
      )}
    >
      <div className="flex items-center justify-between">
        <SeverityBadge severity={severity} />
        {pending && <span className="font-mono text-[9px] uppercase tracking-wider text-amber blink">new</span>}
        {verdict === "true_positive" && (
          <span className="font-mono text-[9px] uppercase tracking-wider text-danger">breach</span>
        )}
      </div>
      <div className="mt-1.5 text-[12.5px] font-medium leading-snug text-mist">{title}</div>
      <div className="mt-1 font-mono text-[10px] text-fog">{meta}</div>
    </button>
  );
}

function CaseHeader({ title, summary, running }: { title: string; summary: any; running: boolean }) {
  return (
    <div className="glass rounded-md p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="font-mono text-[10px] uppercase tracking-widest text-fog">active case</div>
          <h2 className="mt-0.5 font-sans text-xl font-bold tracking-tight text-bright text-balance">
            {title}
          </h2>
        </div>
        {summary?.verdict && !running && <VerdictBadge verdict={summary.verdict} />}
      </div>
      {summary && !running && (
        <div className="mt-3.5 grid grid-cols-4 gap-2.5">
          <StatTile label="severity" value={(summary.severity ?? "-").toUpperCase()} />
          <StatTile label="confidence" value={`${Math.round((summary.confidence ?? 0) * 100)}%`} accent />
          <StatTile label="mttr" value={`${summary.mttr_seconds ?? 0}s`} />
          <StatTile label="reasoning tok" value={`${summary.total_tokens ?? 0}`} />
        </div>
      )}
    </div>
  );
}

function VerdictPanel({ summary, sealed, iid }: { summary: any; sealed: number; iid: string | null }) {
  const breach = summary.verdict === "true_positive" || summary.verdict === "escalate";
  const stages = summary.attack_chain?.length ?? 0;
  const [verif, setVerif] = useState<LedgerVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const root = summary.ledger_root as string | undefined;

  async function verify() {
    if (!iid) return;
    setVerifying(true);
    setVerif(null);
    try {
      setVerif(await api.verifyLedger(iid));
    } catch {
      setVerif(null);
    } finally {
      setVerifying(false);
    }
  }
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className={cx(
        "verdict-impact glass scanline relative overflow-hidden rounded-md p-5",
        breach ? "border-danger/40" : "border-signal/40"
      )}
      style={{
        boxShadow: breach
          ? "0 0 0 1px rgba(255,93,107,0.25), 0 0 48px -16px rgba(255,93,107,0.5)"
          : "0 0 0 1px rgba(52,227,196,0.25), 0 0 48px -16px rgba(52,227,196,0.5)",
      }}
    >
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5">
          <span className={cx("font-mono text-[10px] uppercase tracking-[0.3em]", breach ? "text-danger" : "text-signal")}>
            verdict
          </span>
          {summary.verdict && <VerdictBadge verdict={summary.verdict} />}
        </div>
        <span className="font-mono text-[10px] uppercase tracking-wider text-fog">
          {stages}-stage kill chain reconstructed
        </span>
      </div>

      {breach && (
        <div className="mt-3 font-sans text-[26px] font-bold leading-none tracking-tight text-danger text-balance">
          Breach confirmed.
        </div>
      )}

      <p className="mt-3 font-serif text-[16px] leading-relaxed text-bright text-balance">
        {summary.summary}
      </p>

      <div className="mt-4 grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end">
        <div className="max-w-sm">
          <ConfidenceMeter value={summary.confidence ?? 0} label="overall confidence" />
        </div>
        <div className="flex items-center gap-2 rounded-sm border border-signal/30 bg-signal/[0.06] px-3 py-1.5">
          <svg width="12" height="12" viewBox="0 0 10 10" fill="none" className="text-signal" aria-hidden>
            <path d="M5 .8 8.5 2.4v2.4c0 2-1.5 3.5-3.5 4-2-.5-3.5-2-3.5-4V2.4z" stroke="currentColor" strokeWidth="0.8" />
            <path d="M3.4 5 4.6 6.2 6.8 3.7" stroke="currentColor" strokeWidth="0.9" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span className="font-mono text-[11px] text-signal">
            {sealed} steps sealed to Splunk ledger
          </span>
        </div>
      </div>

      {/* tamper-evident chain of custody */}
      <div className="mt-4 rounded-sm border border-line bg-ink-2/60 p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="font-mono text-[10px] uppercase tracking-widest text-fog">
            chain of custody
            {root && <span className="ml-2 text-signal/70">root {root.slice(0, 12)}</span>}
          </div>
          <button
            onClick={verify}
            disabled={verifying}
            className={cx(
              "rounded-sm border px-2.5 py-1 font-mono text-[10px] uppercase tracking-wider transition-colors",
              verifying
                ? "border-line-2 text-fog"
                : "border-signal/50 bg-signal/10 text-signal hover:bg-signal/20"
            )}
          >
            {verifying ? "verifying..." : "verify ledger integrity"}
          </button>
        </div>
        {verif && (
          <div
            className={cx(
              "seal-in mt-2.5 flex items-start gap-2 rounded-sm border p-2.5",
              verif.ok ? "border-signal/40 bg-signal/[0.06]" : "border-danger/50 bg-danger/10"
            )}
          >
            <span className={cx("mt-0.5 font-mono text-[13px]", verif.ok ? "text-signal" : "text-danger")}>
              {verif.ok ? "✓" : "✗"}
            </span>
            <div className="min-w-0">
              <div className={cx("font-mono text-[11.5px]", verif.ok ? "text-signal" : "text-danger")}>
                {verif.detail}
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-fog">
                recomputed from {verif.source === "splunk" ? "the Splunk ledger" : "the sealed chain"} ·{" "}
                {verif.step_count} steps · root {verif.computed_root.slice(0, 16)}
              </div>
            </div>
          </div>
        )}
      </div>
    </motion.div>
  );
}

function EmptyState({ onRun, scenario }: { onRun: () => void; scenario: Scenario | null }) {
  return (
    <div className="glass flex min-h-[420px] flex-col items-center justify-center rounded-md p-10 text-center">
      <div className="font-mono text-[11px] uppercase tracking-[0.3em] text-signal">glass-box soc</div>
      <h2 className="mt-3 max-w-xl font-sans text-2xl font-bold tracking-tight text-bright text-balance">
        An autonomous Tier-1 analyst that investigates, proves every step, and ships the fix.
      </h2>
      <p className="mt-3 max-w-md text-[13.5px] leading-relaxed text-fog">
        Veritrace pulls evidence from Splunk over the MCP Server, reasons with the Foundation-Sec model,
        and writes its full chain of evidence and reasoning back into Splunk as a verifiable ledger.
      </p>
      {scenario && (
        <div className="mt-5 flex items-center gap-2 rounded-md border border-line bg-white/[0.012] px-3 py-2">
          <SeverityBadge severity={scenario.alert.severity} />
          <span className="text-[12.5px] text-mist">{scenario.alert.name}</span>
        </div>
      )}
      <button
        onClick={onRun}
        className="mt-6 rounded-sm border border-signal/50 bg-signal/10 px-5 py-2.5 font-mono text-[11px] uppercase tracking-widest text-signal transition-colors hover:bg-signal/20"
      >
        run investigation
      </button>
    </div>
  );
}
