import type { AttackStage, Severity, Verdict } from "./types";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

const SEV_STYLE: Record<Severity, string> = {
  critical: "text-danger border-danger/40 bg-danger/10",
  high: "text-danger border-danger/40 bg-danger/10",
  medium: "text-amber border-amber/40 bg-amber/10",
  low: "text-signal border-signal/40 bg-signal/10",
  info: "text-fog border-line-2 bg-white/5",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-sm border px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider",
        SEV_STYLE[severity]
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

const VERDICT_LABEL: Record<Verdict, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign: "Benign",
  escalate: "Escalate",
  inconclusive: "Inconclusive",
};

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const danger = verdict === "true_positive" || verdict === "escalate";
  return (
    <span
      className={cx(
        "inline-flex items-center gap-2 rounded-sm border px-2.5 py-1 font-mono text-xs uppercase tracking-wider",
        danger
          ? "border-danger/50 bg-danger/10 text-danger"
          : "border-signal/50 bg-signal/10 text-signal"
      )}
    >
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function Chip({
  children,
  tone = "default",
}: {
  children: React.ReactNode;
  tone?: "default" | "signal" | "amber" | "danger" | "violet";
}) {
  const tones = {
    default: "border-line-2 text-fog",
    signal: "border-signal/40 text-signal",
    amber: "border-amber/40 text-amber",
    danger: "border-danger/40 text-danger",
    violet: "border-violet/40 text-violet",
  };
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 font-mono text-[11px]",
        tones[tone]
      )}
    >
      {children}
    </span>
  );
}

export function ConfidenceMeter({
  value,
  label = "confidence",
}: {
  value: number;
  label?: string;
}) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  const tone = pct >= 80 ? "var(--color-signal)" : pct >= 50 ? "var(--color-amber)" : "var(--color-danger)";
  return (
    <div className="w-full">
      <div className="mb-1 flex items-center justify-between font-mono text-[11px] text-fog">
        <span className="uppercase tracking-wider">{label}</span>
        <span style={{ color: tone }}>{pct}%</span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-line">
        <div
          className="meter-fill h-full rounded-full"
          style={{ width: `${pct}%`, backgroundColor: tone, boxShadow: `0 0 12px -2px ${tone}` }}
        />
      </div>
    </div>
  );
}

export function StatTile({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="glass rounded-md px-3 py-2">
      <div className="font-mono text-[10px] uppercase tracking-widest text-fog">{label}</div>
      <div className={cx("mt-0.5 font-mono text-lg", accent ? "text-signal" : "text-bright")}>{value}</div>
    </div>
  );
}

/* ---- MITRE ATT&CK kill-chain ribbon ---- */

const TACTIC_ORDER = [
  "Initial Access",
  "Execution",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Command and Control",
  "Exfiltration",
];

export function KillChain({ stages }: { stages: AttackStage[] }) {
  const byTactic = new Map<string, AttackStage>();
  for (const s of stages) byTactic.set(s.tactic, s);
  const tactics = TACTIC_ORDER.filter((t) => byTactic.has(t) || true);

  return (
    <div className="glass rounded-md p-3">
      <div className="mb-2.5 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-fog">
        <span className="text-signal">MITRE ATT&CK</span> kill chain
      </div>
      <div className="flex items-stretch gap-1.5 overflow-x-auto">
        {tactics.map((t, i) => {
          const stage = byTactic.get(t);
          const active = Boolean(stage);
          return (
            <div key={t} className="flex items-center gap-1.5">
              <div
                className={cx(
                  "min-w-[112px] rounded-sm border px-2 py-1.5 transition-colors",
                  active
                    ? "border-danger/50 bg-danger/10"
                    : "border-line bg-white/[0.015] opacity-50"
                )}
              >
                <div className="font-mono text-[9px] uppercase tracking-wider text-fog">{t}</div>
                {stage ? (
                  <div className="mt-0.5 font-mono text-[11px] text-danger">{stage.technique_id}</div>
                ) : (
                  <div className="mt-0.5 font-mono text-[11px] text-fog">.</div>
                )}
              </div>
              {i < tactics.length - 1 && (
                <span className={cx("font-mono text-xs", active ? "text-danger/60" : "text-line-2")}>
                  &rsaquo;
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---- blast-radius entity graph ---- */

interface Node {
  id: string;
  label: string;
  sub: string;
  x: number;
  y: number;
  compromised?: boolean;
  attacker?: boolean;
}

const STAGE_CAPTION = [
  "perimeter intact",
  "perimeter breached",
  "account compromised",
  "endpoint under control",
  "lateral movement to crown jewels",
  "command and control established",
  "data exfiltration in progress",
];

export function EntityGraph({
  entities,
  reached,
}: {
  entities: Record<string, string>;
  reached: number; // 0..6, how far the chain has progressed
}) {
  const nodes: Node[] = [
    { id: "att", label: entities.attacker_ip ?? "attacker", sub: "external actor", x: 64, y: 130, attacker: true },
    { id: "vpn", label: entities.gateway ?? "vpn-gw-01", sub: "gateway", x: 214, y: 130, compromised: reached >= 1 },
    { id: "user", label: entities.victim_user ?? "user", sub: "account", x: 350, y: 56, compromised: reached >= 2 },
    { id: "entry", label: entities.host_entry ?? "host", sub: "endpoint", x: 500, y: 56, compromised: reached >= 3 },
    { id: "db", label: entities.host_db ?? "db", sub: "database", x: 500, y: 204, compromised: reached >= 4 },
    { id: "c2", label: entities.c2_domain ?? "c2", sub: "C2 domain", x: 214, y: 204, compromised: reached >= 5 },
  ];
  const pos = (id: string) => nodes.find((n) => n.id === id)!;
  const edges: { a: string; b: string; label: string; step: number; curve?: boolean }[] = [
    { a: "att", b: "vpn", label: "brute force", step: 1 },
    { a: "vpn", b: "user", label: "takeover", step: 2 },
    { a: "user", b: "entry", label: "discovery", step: 3 },
    { a: "entry", b: "db", label: "SMB lateral", step: 4 },
    { a: "db", b: "c2", label: "beacon", step: 5 },
    { a: "db", b: "att", label: "exfil 4.8 GB", step: 6, curve: true },
  ];
  const newest = reached; // the stage that just activated
  const caption = STAGE_CAPTION[Math.min(reached, 6)];

  return (
    <div className="glass relative overflow-hidden rounded-md p-3">
      <div className="mb-1 flex items-center justify-between">
        <span className="font-mono text-[10px] uppercase tracking-widest text-fog">live attack map</span>
        <span className={cx("font-mono text-[9px] uppercase tracking-wider", reached >= 1 ? "text-danger" : "text-signal")}>
          {reached}/6 stages
        </span>
      </div>
      <svg viewBox="0 0 564 268" className="w-full" style={{ maxHeight: 268 }}>
        <defs>
          <marker id="arrow" markerWidth="9" markerHeight="9" refX="7" refY="4.5" orient="auto">
            <path d="M0,0 L9,4.5 L0,9 z" fill="#ff5d6b" />
          </marker>
          <marker id="arrowdim" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" fill="#28344a" />
          </marker>
          <radialGradient id="attglow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#ff5d6b" stopOpacity="0.16" />
            <stop offset="100%" stopColor="#ff5d6b" stopOpacity="0" />
          </radialGradient>
        </defs>

        {/* radar rings behind the attacker */}
        {[26, 46, 68].map((r) => (
          <circle key={r} cx={64} cy={130} r={r} fill="none" stroke="#28344a" strokeWidth="0.6" opacity="0.4" />
        ))}
        <circle cx={64} cy={130} r={70} fill="url(#attglow)" />

        {edges.map((e, i) => {
          const A = pos(e.a);
          const B = pos(e.b);
          const on = reached >= e.step;
          const len = Math.hypot(B.x - A.x, B.y - A.y);
          const mx = (A.x + B.x) / 2;
          const my = (A.y + B.y) / 2;
          // curved exfil edge dips below
          const d = e.curve
            ? `M${A.x},${A.y} Q${mx},${my + 74} ${B.x},${B.y}`
            : `M${A.x},${A.y} L${B.x},${B.y}`;
          return (
            <g key={i}>
              {!on && (
                <path d={d} fill="none" stroke="#28344a" strokeWidth="1" strokeDasharray="3 4" opacity="0.45" markerEnd="url(#arrowdim)" />
              )}
              {on && (
                <>
                  {/* base edge draws in once when it activates */}
                  <path
                    key={`base-${e.step}`}
                    d={d} fill="none" stroke="#ff5d6b" strokeWidth="1.7" opacity="0.9"
                    markerEnd="url(#arrow)"
                    className="edge-draw"
                    style={{ ["--len" as any]: len + 90 }}
                  />
                  {/* flowing packets along the active edge */}
                  <path d={d} fill="none" stroke="#ff9aa3" strokeWidth="1.4" className="flow-dash" opacity={0.85} />
                </>
              )}
              <text
                x={mx} y={e.curve ? my + 50 : my - 5}
                fill={on ? "#ff8088" : "#4a566e"}
                fontSize="9" fontFamily="IBM Plex Mono, monospace" textAnchor="middle"
              >
                {e.label}
              </text>
            </g>
          );
        })}

        {nodes.map((n) => {
          const justIgnited = n.compromised && n.id === ["", "vpn", "user", "entry", "db", "c2"][newest];
          return (
            <g key={n.id}>
              {(n.compromised || n.attacker) && (
                <circle cx={n.x} cy={n.y} r={n.attacker ? 14 : 12} fill="none" stroke="#ff5d6b" strokeWidth="1" opacity="0.5" className="node-ignite" />
              )}
              <circle
                cx={n.x} cy={n.y} r={n.attacker ? 14 : 12}
                fill={n.attacker ? "#1a0d10" : n.compromised ? "#1c0f12" : "#0f1520"}
                stroke={n.attacker ? "#ff5d6b" : n.compromised ? "#ff5d6b" : "#28344a"}
                strokeWidth={n.attacker || n.compromised ? 1.9 : 1.2}
                style={n.compromised || n.attacker ? { filter: "drop-shadow(0 0 5px rgba(255,93,107,0.55))" } : undefined}
              />
              <circle cx={n.x} cy={n.y} r={3.4} fill={n.attacker || n.compromised ? "#ff5d6b" : "#34e3c4"} />
              {justIgnited && (
                <circle cx={n.x} cy={n.y} r={12} fill="none" stroke="#ff5d6b" strokeWidth="1.4" className="pulse-ring" />
              )}
              <text x={n.x} y={n.y + 27} fill="#cdd6e6" fontSize="9.5" fontFamily="IBM Plex Mono, monospace" textAnchor="middle">
                {n.label}
              </text>
              <text x={n.x} y={n.y + 38} fill="#7e889c" fontSize="8" fontFamily="IBM Plex Mono, monospace" textAnchor="middle">
                {n.sub}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="mt-1 flex items-center gap-2 border-t border-line pt-2">
        <span className={cx("h-1.5 w-1.5 rounded-full", reached >= 1 ? "bg-danger blink" : "bg-signal")} />
        <span className={cx("font-mono text-[10px] tracking-wide", reached >= 1 ? "text-danger" : "text-fog")}>
          {caption}
        </span>
      </div>
    </div>
  );
}
