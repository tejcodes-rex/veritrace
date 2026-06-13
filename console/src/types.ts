export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "escalate"
  | "inconclusive";

export interface EvidenceRef {
  label: string;
  index: string;
  sourcetype: string;
  spl: string;
  result_count: number;
  sample: Record<string, unknown>[];
}

export interface Step {
  investigation_id?: string;
  seq: number;
  kind: string;
  title: string;
  detail: string;
  spl: string;
  tool: string;
  result_count: number | null;
  evidence: EvidenceRef[];
  tactic: string;
  technique_id: string;
  technique_name: string;
  model_reasoning: string;
  confidence: number | null;
  latency_ms: number | null;
  tokens_prompt: number | null;
  tokens_completion: number | null;
  ts: string;
}

export interface AttackStage {
  order: number;
  tactic: string;
  technique_id: string;
  technique_name: string;
  narrative: string;
  confidence: number;
  evidence_labels: string[];
}

export interface ResponseAction {
  action: string;
  target: string;
  rationale: string;
  reversible: boolean;
  requires_approval: boolean;
  status: string;
}

export interface DetectionRule {
  name: string;
  description: string;
  spl: string;
  rationale: string;
  severity: Severity;
  mitre_techniques: string[];
  schedule_cron: string;
  backtest_hits_incident: number | null;
  backtest_false_positives: number | null;
  savedsearch_stanza: string;
}

export interface Alert {
  alert_id: string;
  name: string;
  description: string;
  severity: Severity;
  entity: string;
  src: string;
  dest: string;
  user: string;
  index: string;
}

export interface Investigation {
  investigation_id: string;
  alert: Alert;
  status: string;
  started_at: string;
  completed_at: string;
  steps: Step[];
  attack_chain: AttackStage[];
  verdict: Verdict | null;
  severity: Severity | null;
  confidence: number;
  summary: string;
  response_actions: ResponseAction[];
  detection: DetectionRule | null;
  model_provider: string;
  model_name: string;
  total_tokens: number;
  total_latency_ms: number;
  mttr_seconds: number;
}

export interface InvestigationSummary {
  investigation_id: string;
  alert_name: string;
  status: string;
  verdict: Verdict | null;
  severity: Severity | null;
  confidence: number;
  started_at: string;
  mttr_seconds: number;
}
