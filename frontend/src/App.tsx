import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Ban,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Crosshair,
  Database,
  Eye,
  FileSearch,
  Fingerprint,
  Globe,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Skull,
  TerminalSquare,
  UserRoundCheck,
  XCircle,
  Zap,
} from 'lucide-react';
import { api, API_BASE } from './lib/api';
import type { EventItem, InvestigationState, Scenario } from './types/argus';

const eventLabels: Record<string, { label: string; icon: typeof Activity }> = {
  ALERT_RECEIVED: { label: 'Alert received', icon: ShieldAlert },
  EVIDENCE_GATHERED: { label: 'Evidence gathered', icon: FileSearch },
  DECISION: { label: 'Agent decision', icon: Crosshair },
  RESPONSE_ATTEMPTED: { label: 'Response attempted', icon: Zap },
  VERIFICATION_FAILED: { label: 'Verification failed', icon: XCircle },
  CONTAINMENT_FAILURE_DETECTED: { label: 'Containment failure', icon: AlertTriangle },
  NEW_EVIDENCE_FOUND: { label: 'New evidence found', icon: Network },
  HYPOTHESIS_REVISED: { label: 'Hypothesis revised', icon: RefreshCw },
  ADAPTIVE_RESPONSE_SELECTED: { label: 'Adaptive response', icon: ShieldAlert },
  RESPONSE_VERIFIED: { label: 'Response verified', icon: ShieldCheck },
  HUMAN_OVERRIDE: { label: 'Human override', icon: UserRoundCheck },
  CLOSE: { label: 'Incident closed', icon: CheckCircle2 },
};

function App() {
  const [connected, setConnected] = useState(false);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState('scenario-003');
  const [investigation, setInvestigation] = useState<InvestigationState | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideStatus, setOverrideStatus] = useState('');
  const [autoRunning, setAutoRunning] = useState(false);

  const checkConnection = useCallback(async () => {
    try {
      await api.health();
      setConnected(true);
    } catch {
      setConnected(false);
    }
  }, []);

  useEffect(() => {
    checkConnection();
    api.scenarios().then(setScenarios).catch(() => undefined);
  }, [checkConnection]);

  const runFirstStep = async () => {
    setLoading(true);
    setError('');
    setOverrideStatus('');
    try {
      const state = await api.createInvestigation(selectedScenario);
      setInvestigation(state);
      await checkConnection();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to start investigation');
    } finally {
      setLoading(false);
    }
  };

  const nextStep = async () => {
    if (!investigation || investigation.status === 'CLOSED') return;
    setLoading(true);
    setError('');
    try {
      const state = await api.continueInvestigation(investigation.incident_id, 1);
      setInvestigation(state);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to continue investigation');
    } finally {
      setLoading(false);
    }
  };

  const runToClosure = async () => {
    if (!investigation) {
      await runFirstStep();
      return;
    }
    setAutoRunning(true);
    setError('');
    try {
      let state = investigation;
      for (let i = 0; i < 24 && state.status !== 'CLOSED'; i += 1) {
        state = await api.continueInvestigation(state.incident_id, 1);
        setInvestigation({ ...state });
        await new Promise((resolve) => setTimeout(resolve, 220));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to complete investigation');
    } finally {
      setAutoRunning(false);
    }
  };

  const submitOverride = async () => {
    if (!investigation) return;
    setLoading(true);
    setError('');
    try {
      await api.override(
        investigation.incident_id,
        'quarantine_host',
        '10.0.1.25',
        'DENY',
        overrideReason || 'Analyst requested manual denial of quarantine.',
      );
      const state = await api.getInvestigation(investigation.incident_id);
      setInvestigation(state);
      setOverrideStatus('Quarantine denial recorded in the incident audit trail.');
      setOverrideReason('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to record override');
    } finally {
      setLoading(false);
    }
  };

  const selected = scenarios.find((scenario) => scenario.scenario_id === selectedScenario);
  const evidenceScore = getEvidenceScore(investigation);
  const lastDecision = investigation?.current_decision;
  const statusText = investigation?.active_threat ? 'ACTIVE THREAT' : investigation?.status ?? 'READY';

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <div className="brand-mark"><Eye size={20} /></div>
          <div>
            <div className="brand-name">ARGUS</div>
            <div className="brand-subtitle">AUTONOMOUS EVIDENCE-DRIVEN SOC</div>
          </div>
        </div>
        <div className="topbar-right">
          <div className="api-status">
            <span className={`status-dot ${connected ? 'online' : 'offline'}`} />
            API {connected ? 'CONNECTED' : 'OFFLINE'}
          </div>
          <div className="api-endpoint">{API_BASE}</div>
          <button className="icon-button" onClick={checkConnection} title="Refresh API connection"><RefreshCw size={16} /></button>
        </div>
      </header>

      <main className="workspace">
        <aside className="incident-sidebar">
          <div className="sidebar-heading">
            <span>INCIDENT QUEUE</span>
            <span className="count-badge">{scenarios.length || 0}</span>
          </div>
          <div className="queue-list">
            {(scenarios.length ? scenarios : [{ scenario_id: 'scenario-003', name: 'Primary adaptive intrusion', incident_id: 'INC-003', alert_id: 'ALERT-003', expected_outcome: 'SUCCESS', description: 'Adaptive containment demonstration.' }]).map((scenario) => (
              <button
                key={scenario.scenario_id}
                className={`queue-item ${selectedScenario === scenario.scenario_id ? 'selected' : ''}`}
                onClick={() => setSelectedScenario(scenario.scenario_id)}
              >
                <div className="queue-item-top">
                  <span className="severity-dot critical" />
                  <span className="mono">{scenario.alert_id}</span>
                  <ChevronRight size={14} />
                </div>
                <strong>{scenario.name}</strong>
                <span>{scenario.description}</span>
              </button>
            ))}
          </div>
          <div className="sidebar-footer">
            <div className="legend-row"><span className="severity-dot critical" /> Critical</div>
            <div className="legend-row"><span className="severity-dot medium" /> Investigating</div>
            <div className="legend-row"><span className="severity-dot safe" /> Contained</div>
          </div>
        </aside>

        <section className="main-content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">AUTONOMOUS INVESTIGATION CONSOLE</div>
              <h1>{investigation ? investigation.incident_id : selected?.incident_id ?? 'INC-003'}</h1>
              <p>{selected?.name ?? 'Primary adaptive intrusion scenario'}</p>
            </div>
            <div className="action-group">
              {!investigation && <button className="primary-button" onClick={runFirstStep} disabled={loading || !connected}><Play size={16} /> Run Investigation</button>}
              {investigation && investigation.status !== 'CLOSED' && <button className="secondary-button" onClick={nextStep} disabled={loading || autoRunning}><ChevronRight size={16} /> Next Step</button>}
              {investigation && investigation.status !== 'CLOSED' && <button className="primary-button" onClick={runToClosure} disabled={loading || autoRunning}><Zap size={16} /> {autoRunning ? 'Executing…' : 'Run to Closure'}</button>}
              {investigation && investigation.status === 'CLOSED' && <div className="closed-pill"><CheckCircle2 size={15} /> INCIDENT CLOSED</div>}
            </div>
          </div>

          {error && <div className="error-banner"><AlertTriangle size={17} /> {error}</div>}

          <div className="metrics-grid">
            <MetricCard label="Attack Outcome" value={investigation?.attack_outcome ?? 'PENDING'} tone={investigation?.attack_outcome === 'SUCCESS' ? 'danger' : 'neutral'} icon={<Skull size={17} />} />
            <MetricCard label="Attack Confidence" value={investigation ? `${Math.round(investigation.attack_confidence * 100)}%` : '—'} tone="neutral" icon={<Fingerprint size={17} />} />
            <MetricCard label="Evidence Score" value={investigation ? `${evidenceScore}/100` : '—'} tone="neutral" icon={<Database size={17} />} />
            <MetricCard label="Containment" value={investigation?.containment_status ?? 'NOT STARTED'} tone={investigation?.containment_status === 'SUCCESS' ? 'safe' : investigation?.containment_status === 'FAILED' ? 'danger' : 'neutral'} icon={<ShieldCheck size={17} />} />
          </div>

          <div className="status-strip">
            <div><span className="strip-label">RESPONSE</span><strong>{investigation?.response_status ?? 'NOT STARTED'}</strong></div>
            <div><span className="strip-label">THREAT STATE</span><strong className={investigation?.active_threat ? 'danger-text' : 'safe-text'}>{statusText}</strong></div>
            <div><span className="strip-label">EXECUTION STEP</span><strong>{investigation?.current_step ?? 0}</strong></div>
            <div><span className="strip-label">TARGET</span><strong className="mono">10.0.1.25</strong></div>
          </div>

          <div className="content-grid">
            <section className="panel timeline-panel">
              <PanelHeader icon={<Activity size={17} />} title="Investigation timeline" meta={investigation ? `${investigation.events.length} events` : 'Awaiting alert'} />
              <div className="timeline">
                {investigation?.events.length ? investigation.events.map((event, index) => <TimelineItem key={`${event.event_type}-${index}`} event={event} />) : <EmptyState icon={<CircleDot size={22} />} title="No investigation running" text="Launch the primary scenario to watch ARGUS reason through evidence and response." />}
              </div>
            </section>

            <section className="panel decision-panel">
              <PanelHeader icon={<Crosshair size={17} />} title="Agent decision" meta="bounded autonomy" />
              {lastDecision ? <>
                <div className="decision-kicker">NEXT ACTION</div>
                <div className="decision-action">{String(lastDecision.decision ?? lastDecision.action ?? 'ASSESS')}</div>
                <div className="decision-target"><TerminalSquare size={14} /> {String(lastDecision.target ?? 'environment')}</div>
                <div className="decision-divider" />
                <div className="decision-kicker">RATIONALE</div>
                <p className="rationale">{String(lastDecision.rationale ?? 'Evidence threshold evaluated by the policy guard.')}</p>
                <div className="decision-foot"><span>Policy guarded</span><span className="safe-text">YES</span></div>
              </> : <EmptyState icon={<Crosshair size={22} />} title="Decision engine idle" text="ARGUS will expose its current action and backend rationale here." />}
            </section>
          </div>

          <div className="content-grid lower-grid">
            <EvidencePanel evidence={investigation?.evidence} />
            <EnvironmentPanel investigation={investigation} />
          </div>

          <div className="content-grid lower-grid">
            <section className="panel override-panel">
              <PanelHeader icon={<LockKeyhole size={17} />} title="Human override" meta="audit trail" />
              <p className="panel-copy">An analyst can deny a bounded response. ARGUS records the decision and reason without hiding the original autonomous recommendation.</p>
              <div className="override-form">
                <div className="override-target"><Ban size={15} /><span>DENY</span><strong>quarantine_host</strong><code>10.0.1.25</code></div>
                <input value={overrideReason} onChange={(event) => setOverrideReason(event.target.value)} placeholder="Reason for analyst denial…" disabled={!investigation || loading} />
                <button className="danger-outline" onClick={submitOverride} disabled={!investigation || loading}><UserRoundCheck size={15} /> Record Denial</button>
              </div>
              {overrideStatus && <div className="override-success"><CheckCircle2 size={15} /> {overrideStatus}</div>}
            </section>
          </div>
        </section>
      </main>
    </div>
  );
}

function MetricCard({ label, value, tone, icon }: { label: string; value: string; tone: string; icon: React.ReactNode }) {
  return <div className={`metric-card ${tone}`}><div className="metric-icon">{icon}</div><div><div className="metric-label">{label}</div><div className="metric-value">{value}</div></div></div>;
}

function PanelHeader({ icon, title, meta }: { icon: React.ReactNode; title: string; meta: string }) {
  return <div className="panel-header"><div className="panel-title"><span className="panel-icon">{icon}</span>{title}</div><span className="panel-meta">{meta}</span></div>;
}

function TimelineItem({ event }: { event: EventItem }) {
  const config = eventLabels[event.event_type] ?? { label: event.event_type.replaceAll('_', ' '), icon: Activity };
  const Icon = config.icon;
  const isFailure = event.event_type.includes('FAILED') || event.event_type.includes('FAILURE');
  const isSuccess = event.event_type.includes('VERIFIED') || event.event_type === 'CLOSE';
  return <div className={`timeline-item ${isFailure ? 'failure' : ''} ${isSuccess ? 'success' : ''}`}>
    <div className="timeline-marker"><Icon size={14} /></div>
    <div className="timeline-body">
      <div className="timeline-top"><strong>{config.label}</strong><span className="timeline-time">{formatTime(event.timestamp)}</span></div>
      <div className="timeline-message">{event.message}</div>
      {event.rationale && <div className="timeline-rationale">{event.rationale}</div>}
    </div>
  </div>;
}

function EvidencePanel({ evidence }: { evidence?: Record<string, unknown> }) {
  const entries = Object.entries(evidence ?? {});
  return <section className="panel"><PanelHeader icon={<FileSearch size={17} />} title="Collected evidence" meta={`${entries.length} sources`} />
    {entries.length ? <div className="evidence-list">{entries.map(([key, value]) => <EvidenceRow key={key} label={key} value={value} />)}</div> : <EmptyState icon={<Database size={22} />} title="Evidence store empty" text="Evidence collected by the agent will appear here." />}
  </section>;
}

function EvidenceRow({ label, value }: { label: string; value: unknown }) {
  const pretty = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  const icon = label.toLowerCase().includes('network') ? <Network size={15} /> : label.toLowerCase().includes('vulner') ? <AlertTriangle size={15} /> : label.toLowerCase().includes('log') ? <TerminalSquare size={15} /> : label.toLowerCase().includes('alert') ? <ShieldAlert size={15} /> : <Database size={15} />;
  return <details className="evidence-row"><summary><span className="evidence-name"><span className="evidence-icon">{icon}</span>{label.replaceAll('_', ' ')}</span><span className="evidence-chevron"><ChevronRight size={14} /></span></summary><pre>{pretty}</pre></details>;
}

function EnvironmentPanel({ investigation }: { investigation: InvestigationState | null }) {
  const blocked = investigation?.actions_taken?.some((action) => String(action.action ?? '').includes('block'));
  const quarantined = investigation?.actions_taken?.some((action) => String(action.action ?? '').includes('quarantine'));
  return <section className="panel"><PanelHeader icon={<Globe size={17} />} title="Environment" meta="simulated SOC" />
    <div className="env-grid">
      <EnvField label="Target service" value="payments-api" />
      <EnvField label="Target IP" value="10.0.1.25" mono />
      <EnvField label="Original source" value="185.22.91.14" mono />
      <EnvField label="Rotated source" value="185.22.91.17" mono />
    </div>
    <div className="env-state"><div><span>FIREWALL BLOCK</span><strong className={blocked ? 'safe-text' : ''}>{blocked ? 'APPLIED' : 'NOT APPLIED'}</strong></div><ArrowRight size={15} /><div><span>HOST QUARANTINE</span><strong className={quarantined ? 'safe-text' : ''}>{quarantined ? 'APPLIED' : 'NOT APPLIED'}</strong></div></div>
  </section>;
}

function EnvField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="env-field"><span>{label}</span><strong className={mono ? 'mono' : ''}>{value}</strong></div>;
}

function EmptyState({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return <div className="empty-state"><div className="empty-icon">{icon}</div><strong>{title}</strong><span>{text}</span></div>;
}

function formatTime(timestamp?: string) {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function getEvidenceScore(investigation: InvestigationState | null) {
  const assessment = investigation?.final_assessment;
  const direct = assessment?.evidence_score;
  if (typeof direct === 'number') return Math.round(direct);
  const evidence = investigation?.evidence ?? {};
  return Math.min(
    100,
    Object.values(evidence).reduce<number>(
      (score, value) => score + (value ? 20 : 0),
      0
    )
  );
}

export default App;
