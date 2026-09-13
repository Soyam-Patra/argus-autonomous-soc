export type InvestigationStatus = 'CLOSED' | 'ACTIVE' | 'INVESTIGATING' | string;

export interface Decision {
  decision?: string;
  action?: string;
  target?: string;
  rationale?: string;
  confidence?: number;
  [key: string]: unknown;
}

export interface EventItem {
  event_type: string;
  message: string;
  rationale?: string | null;
  timestamp?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface InvestigationState {
  incident_id: string;
  scenario_id: string;
  alert_id: string;
  status: InvestigationStatus;
  attack_outcome: string;
  attack_confidence: number;
  response_status: string;
  containment_status: string;
  active_threat: boolean;
  final_assessment: Record<string, unknown> | null;
  evidence: Record<string, unknown>;
  actions_taken: Array<Record<string, unknown>>;
  events: EventItem[];
  current_step: number;
  current_decision: Decision | null;
}

export interface Scenario {
  scenario_id: string;
  name: string;
  incident_id: string;
  alert_id: string;
  expected_outcome: string;
  description: string;
}
