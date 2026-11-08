import { useCallback, useEffect, useRef, useState } from 'react';

export interface WorkflowState {
  status: string;
  ready: boolean;
  storage_durable: boolean;
  storage_revision: number;
  highest_revision: number;
  active_bundle?: { bundle_id: string; revision: number; digest: string; signer_key_id: string; expires_at: string };
  session_count: number;
  revoked_session_ids: string[];
  stale_window_seconds: number;
  issuer_mode: string;
  upstream?: { ready: boolean; status_code?: number; latency_ms?: number };
  providers?: { ready: boolean; status: string; verification?: string }[];
}

interface SimulateResult {
  fixture_ref: string;
  fixture_id?: string;
  expected_allow?: boolean;
  observed_allow: boolean;
  expected_matched: boolean;
  observed_reasons?: string[];
  decision?: Decision;
  error_code?: string;
  error_message?: string;
}

interface SessionResult {
  valid: boolean;
  session_id?: string;
  subject_id?: string;
  roles?: string[];
  expires_at?: string;
  issuer_mode?: string;
  storage_durable?: boolean;
  error_code?: string;
  error_message?: string;
}

interface BundleResult {
  status: string;
  accepted: boolean;
  active: boolean;
  revision?: number;
  highest_revision?: number;
  digest?: string;
  signature_verified: boolean;
  durable: boolean;
  issued_at?: string;
  expires_at?: string;
  error_code?: string;
  message?: string;
  active_bundle_retained?: boolean;
}

interface Decision {
  allow: boolean;
  reasons?: string[];
  revision?: number;
  policy_digest?: string;
  classification?: string;
  obligations?: string[];
  error?: { code: string; message: string };
}

interface ProxyResult {
  allow: boolean;
  valid: boolean;
  forwarded_to_upstream: boolean;
  status_code: number;
  error_code?: string;
  error_message?: string;
  upstream_status_code?: number;
  upstream_response_body?: string;
  decision?: Decision;
  stripped_headers?: string[];
}

interface SpoofResult {
  spoofed_allow: boolean;
  spoofed_error_code?: string;
  spoofed_error_message?: string;
  spoofed_forwarded_to_upstream: boolean;
  direct_origin_blocked: boolean;
  direct_origin_status_code: number;
}

interface RevokeResult {
  revoked: boolean;
  stopped_within_bound: boolean;
  subsequent_allow: boolean;
  subsequent_error_code?: string;
  subsequent_error_message?: string;
  side_effects_executed: boolean;
  error_code?: string;
  error_message?: string;
}

interface OutageResult {
  decision_outage_allow: boolean;
  decision_outage_error_code?: string;
  decision_outage_message?: string;
  idp_outage_allow: boolean;
  idp_outage_error_code?: string;
  expired_bundle_accepted: boolean;
  expired_bundle_error_code?: string;
  expired_bundle_message?: string;
  active_bundle_retained: boolean;
  active_revision: number;
  public_health_bypass_ok: boolean;
}

type StageId = 'fixture' | 'bundle' | 'protected' | 'spoof' | 'revoke' | 'outage';
type StageOutcome = 'idle' | 'running' | 'passed' | 'failed';

const stageOrder: StageId[] = ['fixture', 'bundle', 'protected', 'spoof', 'revoke', 'outage'];

const stageCopy: Record<StageId, { title: string; description: string; invariant: string }> = {
  fixture: {
    title: 'Simulator fixture',
    description: 'Evaluate the synthetic C01 decision fixture against the signed policy and report the explicit allow reason.',
    invariant: 'Default deny and normalized identity',
  },
  bundle: {
    title: 'Sign and verify bundle',
    description: 'Sign a deterministic Ed25519 policy bundle, verify its digest and activate the next monotonic revision durably.',
    invariant: 'Signature, freshness and monotonic revision',
  },
  protected: {
    title: 'Protect owned upstream',
    description: 'Forward an authenticated request through the allowlisted gateway to the owned synthetic upstream and inspect the decision.',
    invariant: 'Private resources fail closed',
  },
  spoof: {
    title: 'Spoofed header and direct origin',
    description: 'Send forged identity headers and contact the origin directly; both must fail closed before the upstream.',
    invariant: 'Only authenticated normalized identity enters policy',
  },
  revoke: {
    title: 'Revoke session',
    description: 'Revoke the active session epoch and prove the next request is denied within the bounded stale window.',
    invariant: 'Private resources fail closed',
  },
  outage: {
    title: 'Outage and expired policy',
    description: 'Simulate decision-engine and IdP outages and attempt an expired bundle activation; the active authority must be retained.',
    invariant: 'Fail closed and bundle freshness',
  },
};

async function callWorkflow<T>(path: string, body?: unknown, method = 'POST'): Promise<{ status: number; data: T }> {
  const response = await fetch(path, {
    method,
    headers: method === 'POST' ? { 'Content-Type': 'application/json' } : undefined,
    body: method === 'POST' ? JSON.stringify(body ?? {}) : undefined,
    cache: 'no-store',
  });
  let data: T;
  try {
    data = (await response.json()) as T;
  } catch {
    throw new Error(`The engine returned an unreadable response (${response.status}).`);
  }
  return { status: response.status, data };
}

function shortId(value?: string) {
  return value && value.length > 18 ? `${value.slice(0, 10)}…${value.slice(-6)}` : value ?? '—';
}

type StageResult = { passed: boolean; error?: string };

function extractErrorMessage(data: unknown, fallback: string): string {
  if (data && typeof data === 'object') {
    const record = data as Record<string, unknown>;
    const candidates = [
      record.error_message,
      record.message,
      record.error_code,
      record.error,
    ];
    for (const c of candidates) {
      if (typeof c === 'string' && c.trim()) {
        return c;
      }
    }
  }
  return fallback;
}

export function ReferenceWorkflow() {
  const [state, setState] = useState<WorkflowState | null>(null);
  const [loading, setLoading] = useState(true);
  const [session, setSession] = useState<SessionResult | null>(null);
  const [simulation, setSimulation] = useState<SimulateResult | null>(null);
  const [bundle, setBundle] = useState<BundleResult | null>(null);
  const [proxy, setProxy] = useState<ProxyResult | null>(null);
  const [spoof, setSpoof] = useState<SpoofResult | null>(null);
  const [revoke, setRevoke] = useState<RevokeResult | null>(null);
  const [outage, setOutage] = useState<OutageResult | null>(null);
  const [outcomes, setOutcomes] = useState<Record<StageId, StageOutcome>>({
    fixture: 'idle', bundle: 'idle', protected: 'idle', spoof: 'idle', revoke: 'idle', outage: 'idle',
  });
  const [error, setError] = useState('');
  const [runningAll, setRunningAll] = useState(false);
  const activeSession = useRef<string>('');
  const busy = useRef(false);

  const refreshState = useCallback(async () => {
    try {
      const { data } = await callWorkflow<WorkflowState>('/api/v1/reference/state', undefined, 'GET');
      setState(data);
      return data;
    } catch {
      setState(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshState();
  }, [refreshState]);

  function mark(stage: StageId, outcome: StageOutcome) {
    setOutcomes(previous => ({ ...previous, [stage]: outcome }));
  }

  async function runFixture(): Promise<StageResult> {
    mark('fixture', 'running');
    const { status, data } = await callWorkflow<SimulateResult>('/api/v1/reference/simulate', {
      fixture_ref: 'tests/fixtures/policyhelix/C01/positive-decision.json',
    });
    setSimulation(data);
    const passed = status === 200 && Boolean(data.expected_matched && data.observed_allow);
    mark('fixture', passed ? 'passed' : 'failed');
    let err: string | undefined;
    if (!passed) {
      err = extractErrorMessage(data, 'Simulator fixture did not match expected allow decision.');
    }
    return { passed, error: err };
  }

  async function runBundle(): Promise<StageResult> {
    mark('bundle', 'running');
    const { status, data } = await callWorkflow<BundleResult>('/api/v1/reference/bundle', {});
    setBundle(data);
    const passed = status === 200 && Boolean(data.accepted && data.signature_verified && data.durable);
    mark('bundle', passed ? 'passed' : 'failed');
    await refreshState();
    let err: string | undefined;
    if (!passed) {
      err = extractErrorMessage(data, 'Bundle signing or atomic activation failed.');
    }
    return { passed, error: err };
  }

  async function runProtected(): Promise<StageResult> {
    mark('protected', 'running');
    const issued = await callWorkflow<SessionResult>('/api/v1/reference/session', {});
    setSession(issued.data);
    if (!issued.data.valid || !issued.data.session_id) {
      mark('protected', 'failed');
      const err = extractErrorMessage(issued.data, 'The local engine did not issue a reference session.');
      return { passed: false, error: err };
    }
    activeSession.current = issued.data.session_id;
    const { status, data } = await callWorkflow<ProxyResult>('/api/v1/reference/proxy', { session_id: issued.data.session_id });
    setProxy(data);
    const passed = status === 200 && Boolean(data.allow && data.forwarded_to_upstream && data.upstream_status_code === 200);
    mark('protected', passed ? 'passed' : 'failed');
    let err: string | undefined;
    if (!passed) {
      const defaultErr = data.upstream_status_code ? `Upstream returned HTTP ${data.upstream_status_code}` : 'Protected upstream proxy request was not allowed.';
      err = extractErrorMessage(data, defaultErr);
    }
    return { passed, error: err };
  }

  async function runSpoof(): Promise<StageResult> {
    mark('spoof', 'running');
    const { status, data } = await callWorkflow<SpoofResult>('/api/v1/reference/spoof', {
      session_id: activeSession.current,
      forged_headers: { 'X-Remote-User': 'admin' },
    });
    setSpoof(data);
    const passed = status === 200 && Boolean(!data.spoofed_allow && !data.spoofed_forwarded_to_upstream && data.direct_origin_blocked);
    mark('spoof', passed ? 'passed' : 'failed');
    let err: string | undefined;
    if (!passed) {
      const spoofErr = data.spoofed_error_message || data.spoofed_error_code;
      err = extractErrorMessage(data, spoofErr || (!data.direct_origin_blocked ? 'Direct origin access was not blocked.' : 'Spoofed identity header was not denied.'));
    }
    return { passed, error: err };
  }

  async function runRevoke(): Promise<StageResult> {
    mark('revoke', 'running');
    const { status, data } = await callWorkflow<RevokeResult>('/api/v1/reference/revoke', { session_id: activeSession.current });
    setRevoke(data);
    const passed = status === 200 && Boolean(data.revoked && !data.subsequent_allow && data.stopped_within_bound);
    mark('revoke', passed ? 'passed' : 'failed');
    await refreshState();
    let err: string | undefined;
    if (!passed) {
      const revErr = !data.stopped_within_bound ? 'Revocation was not enforced within bound.' : 'Subsequent access was unexpectedly allowed after revocation.';
      err = extractErrorMessage(data, revErr);
    }
    return { passed, error: err };
  }

  async function runOutage(): Promise<StageResult> {
    mark('outage', 'running');
    const issued = await callWorkflow<SessionResult>('/api/v1/reference/session', {});
    if (!issued.data.valid || !issued.data.session_id) {
      mark('outage', 'failed');
      const err = extractErrorMessage(issued.data, 'The local engine did not issue an outage session.');
      return { passed: false, error: err };
    }
    const { status, data } = await callWorkflow<OutageResult>('/api/v1/reference/outage', { session_id: issued.data.session_id });
    setOutage(data);
    const passed = status === 200 && Boolean(!data.decision_outage_allow && !data.idp_outage_allow && !data.expired_bundle_accepted && data.active_bundle_retained);
    mark('outage', passed ? 'passed' : 'failed');
    await refreshState();
    let err: string | undefined;
    if (!passed) {
      const outageErr = data.expired_bundle_message || data.expired_bundle_error_code || data.decision_outage_message || data.decision_outage_error_code;
      err = extractErrorMessage(data, outageErr || 'Outage simulation did not fail closed.');
    }
    return { passed, error: err };
  }

  const runners: Record<StageId, () => Promise<StageResult>> = {
    fixture: runFixture,
    bundle: runBundle,
    protected: runProtected,
    spoof: runSpoof,
    revoke: runRevoke,
    outage: runOutage,
  };

  async function runStage(stage: StageId) {
    if (busy.current) return;
    busy.current = true;
    setError('');
    try {
      const result = await runners[stage]();
      if (!result.passed && result.error) {
        setError(result.error);
      }
    } catch (reason) {
      mark(stage, 'failed');
      setError(reason instanceof Error ? reason.message : 'The workflow stage could not be completed.');
    } finally {
      busy.current = false;
    }
  }

  async function runAll() {
    if (busy.current) return;
    busy.current = true;
    setRunningAll(true);
    setError('');
    setSimulation(null); setBundle(null); setProxy(null); setSpoof(null); setRevoke(null); setOutage(null);
    setOutcomes({ fixture: 'idle', bundle: 'idle', protected: 'idle', spoof: 'idle', revoke: 'idle', outage: 'idle' });
    try {
      for (const stage of stageOrder) {
        try {
          const result = await runners[stage]();
          if (!result.passed) {
            const detail = result.error ? `: ${result.error}` : ' because the engine did not produce the required invariant outcome.';
            setError(`The reference workflow stopped at "${stageCopy[stage].title}"${detail}`);
            break;
          }
        } catch (reason) {
          mark(stage, 'failed');
          const msg = reason instanceof Error ? reason.message : 'The workflow stage could not be completed.';
          setError(`The reference workflow stopped at "${stageCopy[stage].title}": ${msg}`);
          break;
        }
      }
    } finally {
      busy.current = false;
      setRunningAll(false);
      await refreshState();
    }
  }

  const ready = Boolean(!loading && state?.ready && state?.storage_durable);
  const passedCount = stageOrder.filter(stage => outcomes[stage] === 'passed').length;

  return <div className="reference-page" tabIndex={-1}>
    <header className="page-header">
      <div className="eyebrow">Clone-to-value reference workflow</div>
      <h2>Complete the six-stage local workflow.</h2>
      <p className="intro">
        Every stage runs against the supervised loopback engine, the durable local storage adapter, a signed Ed25519 policy bundle and an owned synthetic upstream.
        No cloud account, public domain or sibling repository is required.
      </p>
    </header>

    <section className="panel" aria-label="Live engine status">
      <div className="workflow-summary">
        <div><span className="metric-label">Engine</span><span className="metric-value">{loading ? 'loading…' : state ? (ready ? 'ready' : 'degraded') : 'unavailable'}</span></div>
        <div><span className="metric-label">Durable storage</span><span className="metric-value">{loading ? 'loading…' : state?.storage_durable ? `revision ${state.storage_revision}` : 'not durable'}</span></div>
        <div><span className="metric-label">Active bundle</span><span className="metric-value">{loading ? 'loading…' : state?.active_bundle ? `rev ${state.active_bundle.revision}` : 'none'}</span></div>
        <div><span className="metric-label">Owned upstream</span><span className="metric-value">{loading ? 'loading…' : state?.upstream?.ready ? `ready · ${Math.round(state.upstream.latency_ms ?? 0)}ms` : 'not ready'}</span></div>
        <div><span className="metric-label">Stages passed</span><span className="metric-value">{passedCount} of {stageOrder.length}</span></div>
      </div>
      <div className="workflow-actions">
        <button type="button" onClick={() => void runAll()} disabled={loading || runningAll || !ready}>{runningAll ? 'Running reference workflow…' : 'Run full workflow'}</button>
        <button type="button" className="button-secondary" onClick={() => void refreshState()} disabled={loading || runningAll} aria-label="Refresh engine state">Refresh engine state</button>
        <span className="muted" role="status" aria-live="polite">
          {loading ? 'Checking local engine state…' : runningAll ? 'Executing the ordered workflow stages.' : ready ? 'The local engine is ready for the workflow.' : 'Start the local supervisor with npm start to run the workflow.'}
        </span>
      </div>
      {state && <p className="muted workflow-note">
        Session revocation bound: {state.stale_window_seconds}s · sessions persisted: {state.session_count} · revoked epochs: {state.revoked_session_ids.length} ·
        issuer mode: {state.issuer_mode.replaceAll('_', ' ')}
      </p>}
      {state?.providers && state.providers.length > 0 && <ul className="workflow-providers" aria-label="Provider verification">
        {state.providers.map((provider, index) => <li key={`${provider.verification ?? 'provider'}-${index}`}>
          <span className={`dot ${provider.ready ? '' : 'dot-error'}`} aria-hidden="true" />
          <span>{provider.verification?.replaceAll('_', ' ') ?? 'provider'}</span>
          <code>{provider.status}</code>
        </li>)}
      </ul>}
    </section>

    {error && <section className="notice notice-error" role="alert"><span className="dot dot-error" aria-hidden="true" /><p>{error}</p></section>}

    <ol className="workflow-stages">
      {stageOrder.map((stage, index) => {
        const copy = stageCopy[stage];
        const outcome = outcomes[stage];
        return <li key={stage} className={`workflow-stage stage-${outcome}`}>
          <div className="workflow-stage-head">
            <span className="task-id">{String(index + 1).padStart(2, '0')}</span>
            <div>
              <h3>{copy.title}</h3>
              <p>{copy.description}</p>
              <p className="muted">Invariant: {copy.invariant}</p>
            </div>
            <div className="workflow-stage-controls">
              <span className={`state ${outcome === 'passed' ? 'state-allow' : outcome === 'failed' ? 'state-deny' : ''}`} role="status" aria-label={`Stage ${index + 1} status: ${outcome === 'idle' ? 'not run' : outcome}`}>{outcome === 'idle' ? 'not run' : outcome}</span>
              <button type="button" className="button-secondary" onClick={() => void runStage(stage)} disabled={loading || runningAll || !ready} aria-label={`Run stage ${index + 1}: ${copy.title}`}>Run stage</button>
            </div>
          </div>
          <div className="workflow-stage-result" role="region" aria-label={`${copy.title} result`}>
            {stage === 'fixture' && (simulation ? <dl className="result-grid">
              <div><dt>Fixture</dt><dd><code>{simulation.fixture_id ?? simulation.fixture_ref}</code></dd></div>
              <div><dt>Expected allow</dt><dd>{String(simulation.expected_allow)}</dd></div>
              <div><dt>Observed allow</dt><dd>{String(simulation.observed_allow)}</dd></div>
              <div><dt>Reason</dt><dd><code>{simulation.observed_reasons?.join(', ') || simulation.error_code || '—'}</code></dd></div>
            </dl> : <p className="muted">Not executed in this browser session.</p>)}
            {stage === 'bundle' && (bundle ? <dl className="result-grid">
              <div><dt>Status</dt><dd>{bundle.status}</dd></div>
              <div><dt>Revision</dt><dd>{bundle.revision ?? '—'} (highest {bundle.highest_revision ?? '—'})</dd></div>
              <div><dt>Signature verified</dt><dd>{String(bundle.signature_verified)}</dd></div>
              <div><dt>Durable</dt><dd>{String(bundle.durable)}</dd></div>
              <div><dt>Digest</dt><dd><code>{shortId(bundle.digest)}</code></dd></div>
              <div><dt>Expires</dt><dd><code>{bundle.expires_at ?? '—'}</code></dd></div>
              {bundle.error_code && <div><dt>Rejected</dt><dd><code>{bundle.error_code}</code></dd></div>}
            </dl> : <p className="muted">Not executed in this browser session.</p>)}
            {stage === 'protected' && (proxy ? <dl className="result-grid">
              <div><dt>Allowed</dt><dd>{String(proxy.allow)}</dd></div>
              <div><dt>Forwarded</dt><dd>{String(proxy.forwarded_to_upstream)}</dd></div>
              <div><dt>Upstream</dt><dd>{proxy.upstream_status_code ?? '—'}</dd></div>
              <div><dt>Policy reason</dt><dd><code>{proxy.decision?.reasons?.join(', ') || proxy.error_code || '—'}</code></dd></div>
              <div><dt>Session</dt><dd><code>{session?.session_id ? `${session.session_id.slice(0, 8)}…` : '—'} (fingerprint bound)</code></dd></div>
              <div><dt>Roles</dt><dd><code>{session?.roles?.join(', ') ?? '—'}</code></dd></div>
            </dl> : <p className="muted">Not executed in this browser session.</p>)}
            {stage === 'spoof' && (spoof ? <dl className="result-grid">
              <div><dt>Forged header allowed</dt><dd>{String(spoof.spoofed_allow)}</dd></div>
              <div><dt>Forged header error</dt><dd><code>{spoof.spoofed_error_code ?? '—'}</code></dd></div>
              <div><dt>Forged request forwarded</dt><dd>{String(spoof.spoofed_forwarded_to_upstream)}</dd></div>
              <div><dt>Direct origin</dt><dd>{spoof.direct_origin_blocked ? 'blocked' : 'reachable'} ({spoof.direct_origin_status_code})</dd></div>
            </dl> : <p className="muted">Not executed in this browser session.</p>)}
            {stage === 'revoke' && (revoke ? <dl className="result-grid">
              <div><dt>Revoked</dt><dd>{String(revoke.revoked)}</dd></div>
              <div><dt>Stopped within bound</dt><dd>{String(revoke.stopped_within_bound)}</dd></div>
              <div><dt>Next request</dt><dd><code>{revoke.subsequent_error_code ?? (revoke.subsequent_allow ? 'allowed' : 'denied')}</code></dd></div>
              <div><dt>Side effects</dt><dd>{String(revoke.side_effects_executed)}</dd></div>
            </dl> : <p className="muted">Not executed in this browser session.</p>)}
            {stage === 'outage' && (outage ? <dl className="result-grid">
              <div><dt>Decision outage</dt><dd>{outage.decision_outage_allow ? 'allowed' : 'denied'} <code>{outage.decision_outage_error_code ?? ''}</code></dd></div>
              <div><dt>IdP outage</dt><dd>{outage.idp_outage_allow ? 'allowed' : 'denied'} <code>{outage.idp_outage_error_code ?? ''}</code></dd></div>
              <div><dt>Expired bundle</dt><dd>{outage.expired_bundle_accepted ? 'accepted' : 'rejected'} <code>{outage.expired_bundle_error_code ?? ''}</code></dd></div>
              <div><dt>Active authority retained</dt><dd>{String(outage.active_bundle_retained)} (rev {outage.active_revision})</dd></div>
              <div><dt>Public health bypass</dt><dd>{String(outage.public_health_bypass_ok)}</dd></div>
            </dl> : <p className="muted">Not executed in this browser session.</p>)}
          </div>
        </li>;
      })}
    </ol>

    <section className="panel" aria-label="Restart and restore">
      <div className="eyebrow">Restart and restore</div>
      <h3>Durable state survives a restart.</h3>
      <p>
        The active bundle revision, the monotonic revision floor, issued sessions and revocation epochs are written through the
        authoritative storage adapter. Restarting the supervisor keeps them in force; <code>npm run test:clone</code> asserts that
        proof automatically on a clean clone.
      </p>
      <p className="muted" role="status" aria-live="polite">
        {loading
          ? 'Checking restored bundle state…'
          : state?.active_bundle
          ? `Restored bundle ${state.active_bundle.bundle_id} at revision ${state.active_bundle.revision}, signer ${state.active_bundle.signer_key_id}.`
          : 'No bundle has been activated yet, so there is nothing to restore.'}
      </p>
    </section>
  </div>;
}
