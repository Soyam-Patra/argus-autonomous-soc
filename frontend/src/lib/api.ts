import type { InvestigationState, Scenario } from '../types/argus';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? 'http://127.0.0.1:8000';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options?.headers ?? {}) },
    ...options,
  });

  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      detail = body.detail ?? detail;
    } catch {
      // Keep HTTP status when the response is not JSON.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; service: string }>('/health'),
  scenarios: () => request<Scenario[]>('/scenarios'),
  createInvestigation: (scenarioId = 'scenario-003') =>
    request<{ state: InvestigationState }>('/investigations', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioId, max_steps: 1 }),
    }).then((body) => body.state),
  continueInvestigation: (incidentId: string, maxSteps = 1) =>
    request<InvestigationState>(`/investigations/${incidentId}/continue`, {
      method: 'POST',
      body: JSON.stringify({ max_steps: maxSteps }),
    }),
  getInvestigation: (incidentId: string) =>
    request<InvestigationState>(`/investigations/${incidentId}`),
  override: (incidentId: string, action: string, target: string, decision: 'APPROVE' | 'DENY', reason: string) =>
    request(`/investigations/${incidentId}/override`, {
      method: 'POST',
      body: JSON.stringify({ action, target, decision, reason: reason || null }),
    }),
};

export { API_BASE };
