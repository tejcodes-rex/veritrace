import type { Alert, Investigation, InvestigationSummary } from "./types";

async function j<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export interface Scenario {
  alert: Alert;
  entities: Record<string, string>;
}

export const api = {
  health: () => fetch("/api/health").then((r) => j<Record<string, string>>(r)),
  scenario: () => fetch("/api/scenario").then((r) => j<Scenario>(r)),
  list: () =>
    fetch("/api/investigations").then((r) =>
      j<{ investigations: InvestigationSummary[] }>(r)
    ),
  get: (id: string) =>
    fetch(`/api/investigations/${id}`).then((r) => j<Investigation>(r)),
  start: (alert?: Alert) =>
    fetch("/api/investigations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ alert: alert ?? null }),
    }).then((r) => j<{ status: string; alert: Alert }>(r)),
  approve: (id: string, idx: number) =>
    fetch(`/api/investigations/${id}/actions/${idx}/approve`, {
      method: "POST",
    }).then((r) => j<Record<string, unknown>>(r)),
  deployDetection: (id: string) =>
    fetch(`/api/investigations/${id}/deploy_detection`, { method: "POST" }).then(
      (r) => j<Record<string, unknown>>(r)
    ),
  verifyLedger: (id: string) =>
    fetch(`/api/investigations/${id}/verify`, { method: "POST" }).then(
      (r) => j<LedgerVerification>(r)
    ),
};

export interface LedgerVerification {
  ok: boolean;
  step_count: number;
  computed_root: string;
  expected_root: string | null;
  broken_at: number | null;
  detail: string;
  source: string;
  investigation_id: string;
}

export type StreamHandler = (kind: string, payload: any) => void;

export function openStream(onEvent: StreamHandler): EventSource {
  const es = new EventSource("/api/stream");
  for (const kind of [
    "step",
    "investigation",
    "detection",
    "action_approved",
  ]) {
    es.addEventListener(kind, (e) => {
      try {
        onEvent(kind, JSON.parse((e as MessageEvent).data));
      } catch {
        /* ignore malformed frame */
      }
    });
  }
  return es;
}
