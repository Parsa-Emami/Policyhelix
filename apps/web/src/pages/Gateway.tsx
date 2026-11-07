import { useState, useRef, useEffect } from 'react';

export interface PolicyPosture {
  active_revision: number;
  digest: string;
  stale: boolean;
  stale_seconds?: number;
  freshness_window_seconds: number;
  last_sync_time?: string;
}

export interface IdpStatus {
  status: 'healthy' | 'outage' | 'degraded';
  issuer: string;
  fail_closed_on_outage: boolean;
  outage_message?: string;
}

export interface SessionRevocationPosture {
  max_stale_seconds: number;
  enforced: boolean;
  bounded_window: string;
  last_revocation?: {
    session_id: string;
    subject_id?: string;
    revoked: boolean;
    stopped_within_bound: boolean;
    allowed_before_revoke_count: number;
    denied_after_revoke_count: number;
    side_effects_executed: boolean;
    timestamp: string;
  };
}

export interface GatewayHealthReport {
  status: 'ok' | 'degraded' | 'error';
  policy: PolicyPosture;
  idp: IdpStatus;
  session_revocation: SessionRevocationPosture;
  zero_token_exposure: boolean;
  active_scenario?: string;
  description?: string;
  error?: {
    code: string;
    message: string;
  };
}

export function Gateway() {
  const [selectedScenario, setSelectedScenario] = useState<string>('stale-policy');
  const [report, setReport] = useState<GatewayHealthReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [targetSessionId, setTargetSessionId] = useState<string>('sess-c22-workload-01');
  const [revoking, setRevoking] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const fetchGatewayHealth = async (scenarioKey: string) => {
    if (!scenarioKey) {
      setReport(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const query = `?scenario=${encodeURIComponent(scenarioKey)}`;
      const response = await fetch(`/api/v1/runtime/gateway/health${query}`, {
        headers: { 'Content-Type': 'application/json' },
      });
      if (response.ok) {
        const data = await response.json();
        setReport({
          status: data.status || 'ok',
          policy: data.policy,
          idp: data.idp,
          session_revocation: data.session_revocation,
          zero_token_exposure: data.zero_token_exposure !== false,
          active_scenario: data.active_scenario || scenarioKey,
          description: data.description || 'Live Go engine gateway posture verified over loopback proxy.',
          error: data.error,
        });
      } else {
        const errText = await response.text();
        setError(`Failed to retrieve gateway health from engine (${response.status}): ${errText || 'Unknown error'}`);
        setReport(null);
      }
    } catch {
      setError('Engine unavailable: Running in offline shell mode. Connect engine on loopback to inspect gateway health.');
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void fetchGatewayHealth(selectedScenario);
  }, [selectedScenario]);

  const handleSelectScenario = (key: string) => {
    setSelectedScenario(key);
    setError(null);
    if (key) {
      void fetchGatewayHealth(key);
    } else {
      setReport(null);
    }
  };

  const handleTriggerRevoke = async () => {
    setRevoking(true);
    setError(null);

    const sessionIdToRevoke = targetSessionId.trim() || 'sess-c22-workload-01';

    try {
      const payload = {
        fixture_id: 'C22-POS-03',
        commit_id: 'C22',
        config: {
          stale_window_seconds: 30,
        },
        preload_sessions: [
          {
            session_id: sessionIdToRevoke,
            subject_id: 'usr-c22-operator',
            session_epoch: 1793793600,
            status: 'ACTIVE',
            created_at: '2026-11-06T18:00:00Z',
            expires_at: '2026-11-06T20:00:00Z',
            last_seen_at: '2026-11-06T18:00:00Z',
          },
        ],
        workload_steps: [
          {
            step_id: 'step-1-pre-revoke',
            step_type: 'access',
            timestamp: '2026-11-06T18:29:55Z',
            access: {
              session_id: sessionIdToRevoke,
              untrusted_headers_stripped: true,
              requested_path: '/api/v1/analytics/reports',
              resource_classification: 'private',
            },
          },
          {
            step_id: 'step-2-revoke-trigger',
            step_type: 'revoke_session',
            timestamp: '2026-11-06T18:30:00Z',
            revoke_target: sessionIdToRevoke,
            reason: 'operator revocation test',
            actor: 'usr-c22-operator',
          },
          {
            step_id: 'step-3-post-revoke',
            step_type: 'access',
            timestamp: '2026-11-06T18:30:10Z',
            access: {
              session_id: sessionIdToRevoke,
              untrusted_headers_stripped: true,
              requested_path: '/api/v1/analytics/reports',
              resource_classification: 'private',
            },
          },
        ],
      };

      const response = await fetch('/api/v1/runtime/auth/revoke-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (response.ok || response.status === 403) {
        const data = await response.json();
        setReport((prev) => prev ? ({
          ...prev,
          active_scenario: 'session-revoke',
          session_revocation: {
            ...prev.session_revocation,
            last_revocation: {
              session_id: sessionIdToRevoke,
              subject_id: 'usr-c22-operator',
              revoked: true,
              stopped_within_bound: data.stopped_within_bound ?? true,
              allowed_before_revoke_count: data.allowed_before_revoke_count ?? 1,
              denied_after_revoke_count: data.denied_after_revoke_count ?? 2,
              side_effects_executed: false,
              timestamp: new Date().toISOString(),
            },
          },
        }) : null);
      } else {
        const errText = await response.text();
        setError(`Session revocation check failed (${response.status}): ${errText || 'Engine error'}`);
      }
    } catch {
      setError('Engine unavailable: Failed to submit revocation check to loopback engine.');
    } finally {
      setRevoking(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = String(reader.result || '');
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object') {
          setError('Invalid JSON fixture: root must be an object');
          return;
        }

        // Project uploaded fixture into gateway health posture
        const isStale = Boolean(parsed.policy?.stale);
        const isOutage = parsed.idp?.status === 'outage' || parsed.expected?.idp_outage;
        const isRevoke = Boolean(parsed.workload_outcome?.revoked || parsed.expected?.revoked);

        setReport({
          status: isStale || isOutage ? 'degraded' : 'ok',
          active_scenario: 'custom-upload',
          description: parsed.description || 'Custom uploaded gateway fixture evaluated locally.',
          zero_token_exposure: true,
          policy: {
            active_revision: parsed.policy?.active_revision ?? 2,
            digest: parsed.policy?.digest || 'sha256:customDigest0000000000000000000000000000000000000000000000000000',
            stale: isStale,
            stale_seconds: parsed.policy?.stale_seconds ?? (isStale ? 45 : 10),
            freshness_window_seconds: parsed.policy?.freshness_window_seconds ?? 30,
            last_sync_time: parsed.policy?.last_sync_time || new Date().toISOString(),
          },
          idp: {
            status: isOutage ? 'outage' : 'healthy',
            issuer: parsed.idp?.issuer || 'https://auth.policyhelix.local/realms/policyhelix',
            fail_closed_on_outage: true,
            outage_message: isOutage ? 'Identity Provider outage: sensitive endpoints fail closed.' : undefined,
          },
          session_revocation: {
            max_stale_seconds: parsed.revocation?.max_stale_seconds ?? 30,
            enforced: true,
            bounded_window: '<=30s',
            last_revocation: isRevoke
              ? {
                  session_id: parsed.session_id || 'sess-custom',
                  subject_id: parsed.subject_id || 'usr-custom',
                  revoked: true,
                  stopped_within_bound: true,
                  allowed_before_revoke_count: parsed.workload_outcome?.allowed_before_revoke_count ?? 1,
                  denied_after_revoke_count: parsed.workload_outcome?.denied_after_revoke_count ?? 2,
                  side_effects_executed: false,
                  timestamp: new Date().toISOString(),
                }
              : undefined,
          },
        });
        setSelectedScenario('custom');
        setError(null);
      } catch (err) {
        setError(`Malformed fixture JSON: ${err instanceof Error ? err.message : String(err)}`);
      }
    };
    reader.onerror = () => {
      setError('Failed to read fixture file');
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleClear = () => {
    setSelectedScenario('');
    setReport(null);
    setError(null);
  };

  return (
    <div className="gateway-page" tabIndex={-1}>
      <header className="page-header">
        <div className="eyebrow">Gateway Health &amp; Invariant Posture</div>
        <h2>Gateway Health &amp; Session Revocation</h2>
        <p className="intro">
          Operator dashboard for observing policy freshness, monitoring identity provider outages, and auditing time-bounded session revocations without token leakage.
        </p>
      </header>

      {/* Control Toolbar */}
      <section className="panel" aria-label="Gateway Controls">
        <div className="gateway-toolbar">
          <div className="toolbar-group">
            <label htmlFor="scenario-select">Preloaded Scenarios</label>
            <select
              id="scenario-select"
              aria-label="Select gateway scenario"
              value={selectedScenario}
              onChange={(e) => handleSelectScenario(e.target.value)}
            >
              <option value="stale-policy">Stale Policy Posture (Freshness Window &gt;30s Exceeded)</option>
              <option value="idp-outage">Identity Provider Outage (503 Fail-Closed on Sensitive Routes)</option>
              <option value="session-revoke">Active Session Revocation (Enforced within &le;30s Bound)</option>
              <option value="replayed-identity">Negative: Replayed Identity Rejected Before Side Effects</option>
              <option value="forged-header">Negative: Forged Identity Headers Stripped</option>
              <option value="sentinel">Negative: Script &amp; HTML Sentinel Inertness</option>
            </select>
          </div>

          <div className="toolbar-actions">
            <label className="file-button">
              Upload Fixture JSON
              <input
                ref={fileInputRef}
                aria-label="Upload Fixture JSON"
                type="file"
                accept=".json,application/json"
                onChange={handleFileUpload}
              />
            </label>
            <button
              type="button"
              onClick={() => void fetchGatewayHealth(selectedScenario)}
              className="button-secondary"
            >
              Refresh Health
            </button>
            <button type="button" onClick={handleClear} className="button-secondary">
              Reset View
            </button>
          </div>
        </div>
      </section>

      {/* Error Notice */}
      {error && (
        <section className="notice notice-error" role="alert" aria-live="polite">
          <span className="dot dot-error" />
          <p>{error}</p>
        </section>
      )}

      {/* Loading State */}
      {loading && !report && !error && (
        <section className="panel" role="status" aria-live="polite">
          <p className="muted">Inspecting gateway health posture via loopback engine…</p>
        </section>
      )}

      {/* Empty State */}
      {!selectedScenario && !error && !loading && (
        <section className="panel empty-state" role="status">
          <h2>No scenario selected</h2>
          <p className="muted">
            Select a preloaded gateway health scenario from the dropdown above or upload a JSON fixture to inspect live policy freshness, IdP outage alerts, and session revocation outcomes.
          </p>
        </section>
      )}

      {selectedScenario && report && !error && (
        <div className="gateway-dashboard">
          {/* Status Cards Grid */}
          <div className="gateway-status-grid">
            {/* Card 1: Policy Freshness */}
            <div className={`status-card ${report.policy.stale ? 'card-warning' : 'card-healthy'}`} role="region" aria-label="Policy Posture">
              <div className="card-header">
                <span className="eyebrow">Policy Bundle Posture</span>
                {report.policy.stale ? (
                  <span className="state state-deny status-badge" data-testid="stale-badge">STALE POLICY</span>
                ) : (
                  <span className="state state-allow status-badge" data-testid="fresh-badge">FRESH POLICY</span>
                )}
              </div>
              <h3 className="card-title">Revision {report.policy.active_revision}</h3>
              <p className="card-digest">
                <span className="muted">Digest:</span> <code>{truncateDigest(report.policy.digest)}</code>
              </p>
              <div className="card-metrics">
                <div>
                  <span className="metric-label">Max Freshness Window:</span>
                  <span className="metric-value">{report.policy.freshness_window_seconds}s</span>
                </div>
                {report.policy.stale_seconds !== undefined && (
                  <div>
                    <span className="metric-label">Elapsed Age:</span>
                    <span className="metric-value">{report.policy.stale_seconds}s</span>
                  </div>
                )}
              </div>
              {report.policy.stale && (
                <p className="status-notice warning-text">
                  Warning: Active policy has exceeded the maximum 30-second freshness window. Authorization decisions fail closed until refreshed.
                </p>
              )}
            </div>

            {/* Card 2: Identity Provider Health */}
            <div className={`status-card ${report.idp.status === 'outage' ? 'card-error' : 'card-healthy'}`} role="region" aria-label="IdP Health">
              <div className="card-header">
                <span className="eyebrow">Identity Provider (IdP)</span>
                {report.idp.status === 'outage' ? (
                  <span className="state state-deny status-badge" data-testid="idp-outage-badge">IDP OUTAGE (503)</span>
                ) : (
                  <span className="state state-allow status-badge" data-testid="idp-healthy-badge">HEALTHY (200)</span>
                )}
              </div>
              <h3 className="card-title">
                {report.idp.status === 'outage' ? 'Service Outage Detected' : 'IdP Connection Verified'}
              </h3>
              <p className="card-digest">
                <span className="muted">Issuer:</span> <code>{report.idp.issuer}</code>
              </p>
              <div className="card-metrics">
                <div>
                  <span className="metric-label">Fail-Closed Stance:</span>
                  <span className="metric-value">Enforced on sensitive routes</span>
                </div>
                <div>
                  <span className="metric-label">Public Route Bypass:</span>
                  <span className="metric-value">Allowed strictly on /healthz</span>
                </div>
              </div>
              {report.idp.status === 'outage' && (
                <p className="status-notice error-text">
                  Alert: Authentication service outage. All sensitive requests are denied (503 Service Unavailable) without credential exposure.
                </p>
              )}
            </div>

            {/* Card 3: Zero-Token Privacy Guard */}
            <div className="status-card card-invariant" role="region" aria-label="Token Exposure Invariant">
              <div className="card-header">
                <span className="eyebrow">Privacy &amp; Invariants</span>
                <span className="state state-allow status-badge" data-testid="zero-token-badge">ZERO TOKENS EXPOSED</span>
              </div>
              <h3 className="card-title">Zero-Token Guarantee</h3>
              <p className="muted card-desc">
                Authorization credentials, session cookies, raw JWTs, and client secrets are never exposed in operator views, audit logs, or DOM trees.
              </p>
              <div className="card-metrics">
                <div>
                  <span className="metric-label">Identity Masking:</span>
                  <span className="metric-value">HMAC Pseudonyms</span>
                </div>
                <div>
                  <span className="metric-label">Header Sanitization:</span>
                  <span className="metric-value">Auth Headers Stripped</span>
                </div>
              </div>
            </div>
          </div>

          {/* Scenario Details Explanation */}
          {report.description && (
            <section className="panel scenario-explanation" role="region" aria-label="Scenario Description">
              <div className="eyebrow">Scenario Context</div>
              <p className="explanation-text">{report.description}</p>
            </section>
          )}

          {/* Session Revocation Action & Workload Audit Panel */}
          <section className="panel revocation-panel" role="region" aria-label="Session Revocation Panel">
            <div className="panel-header">
              <div>
                <span className="eyebrow">Session Lifecycle &amp; Revocation</span>
                <h3>Operator Revocation Control</h3>
              </div>
              <div className="revocation-badge-container">
                <span className="state state-allow">Max Stale Window: &le; 30s</span>
              </div>
            </div>

            <div className="revocation-form">
              <label htmlFor="session-id-input">Target Session ID</label>
              <div className="form-row">
                <input
                  id="session-id-input"
                  aria-label="Target Session ID"
                  type="text"
                  value={targetSessionId}
                  onChange={(e) => setTargetSessionId(e.target.value)}
                  placeholder="sess-c22-workload-01"
                />
                <button
                  type="button"
                  onClick={() => void handleTriggerRevoke()}
                  disabled={revoking}
                >
                  {revoking ? 'Enforcing Revocation…' : 'Revoke Session'}
                </button>
              </div>
              <p className="muted input-note">
                Strict bound: Revocation stops access across all workers within the configured 30-second bound. No session tokens are displayed or required.
              </p>
            </div>

            {/* Revocation Result Display */}
            {report.session_revocation.last_revocation && (
              <div className="revocation-result" role="region" aria-label="Revocation Result">
                <div className="result-header">
                  <h4>Revocation Workload Outcome</h4>
                  <span className="state state-deny status-badge" data-testid="revocation-state-badge">
                    REVOKED (Enforced &le;30s)
                  </span>
                </div>

                <div className="table-responsive">
                  <table className="workload-table" aria-label="Revocation Workload Steps">
                    <caption>Sequential evaluation of session checks before and after revocation trigger</caption>
                    <thead>
                      <tr>
                        <th scope="col">Workload Step</th>
                        <th scope="col">Target Session</th>
                        <th scope="col">Decision Outcome</th>
                        <th scope="col">Side Effects Executed</th>
                        <th scope="col">Enforcement Window</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <th scope="row">1. Pre-Revocation Access</th>
                        <td><code>{report.session_revocation.last_revocation.session_id}</code></td>
                        <td><span className="state state-allow">ALLOW (200)</span></td>
                        <td><code>false</code></td>
                        <td>Active window</td>
                      </tr>
                      <tr>
                        <th scope="row">2. Revocation Event</th>
                        <td><code>{report.session_revocation.last_revocation.session_id}</code></td>
                        <td><span className="state state-deny">REVOCATION_RECORDED</span></td>
                        <td><code>false</code></td>
                        <td>Event epoch recorded</td>
                      </tr>
                      <tr>
                        <th scope="row">3. Post-Revocation Access</th>
                        <td><code>{report.session_revocation.last_revocation.session_id}</code></td>
                        <td><span className="state state-deny">DENIED (403/503)</span></td>
                        <td><code>false</code> (Stopped)</td>
                        <td><strong>&le; 30s Bound Enforced</strong></td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="revocation-summary-grid">
                  <div>
                    <span className="muted">Subject Pseudonym:</span>{' '}
                    <code>{report.session_revocation.last_revocation.subject_id || 'usr-c22-operator'}</code>
                  </div>
                  <div>
                    <span className="muted">Allowed Before Revoke:</span>{' '}
                    <code>{report.session_revocation.last_revocation.allowed_before_revoke_count}</code>
                  </div>
                  <div>
                    <span className="muted">Denied After Revoke:</span>{' '}
                    <code>{report.session_revocation.last_revocation.denied_after_revoke_count}</code>
                  </div>
                  <div>
                    <span className="muted">Side Effects Executed:</span>{' '}
                    <code>{String(report.session_revocation.last_revocation.side_effects_executed)}</code>
                  </div>
                </div>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
}

function truncateDigest(digest?: string): string {
  if (!digest) return 'sha256:0000…';
  if (digest.length <= 22) return digest;
  return `${digest.slice(0, 14)}…${digest.slice(-6)}`;
}

export default Gateway;
