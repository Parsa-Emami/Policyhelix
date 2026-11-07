import { useState, useRef, useEffect } from 'react';

export interface DecisionSummary {
  allow: boolean;
  policy_digest?: string;
  revision?: number;
  reasons?: string[];
  classification?: string;
}

export interface SimulationReport {
  status: 'passed' | 'failed' | 'error';
  fixture_id?: string;
  commit_id?: string;
  description?: string;
  changed: boolean;
  transition?: 'deny_to_allow' | 'allow_to_deny' | 'unchanged' | 'reasons_or_digest_changed' | string;
  baseline_decision?: DecisionSummary;
  candidate_decision?: DecisionSummary;
  decision?: DecisionSummary;
  reasons?: string[];
  policy_digest?: string;
  revision?: number;
  match_expected?: boolean;
  error?: {
    code?: string;
    message?: string;
  };
  elapsed_ms?: number;
}

export interface SimulationFixture {
  schema_version?: string;
  fixture_id: string;
  description?: string;
  baseline_bundle?: {
    revision?: number;
    digest?: string;
    bundle_id?: string;
  };
  candidate_bundle?: {
    revision?: number;
    digest?: string;
    bundle_id?: string;
  };
  input?: {
    request_id?: string;
    subject?: {
      id?: string;
      roles?: string[];
      authenticated?: boolean;
    };
    resource?: {
      id?: string;
      classification?: string;
    };
    action?: string;
  };
  expected?: {
    allow?: boolean;
    changed?: boolean;
    transition?: string;
  };
}

// Built-in accessible sample fixtures for immediate local simulation
const SAMPLE_FIXTURES: Record<string, SimulationFixture> = {
  'deny-to-allow': {
    fixture_id: 'C21-POS-01',
    description: 'Baseline policy rev 1 denies operator; candidate policy rev 2 grants read access to analytics reports yielding changed deny_to_allow decision',
    baseline_bundle: {
      revision: 1,
      digest: 'sha256:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff',
      bundle_id: 'bundle-analytics-v1',
    },
    candidate_bundle: {
      revision: 2,
      digest: 'sha256:222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111',
      bundle_id: 'bundle-analytics-v2',
    },
    input: {
      request_id: 'req-sim-01',
      subject: {
        id: 'usr-ops-pat-901',
        roles: ['operator'],
        authenticated: true,
      },
      resource: {
        id: '/api/v1/analytics/reports',
        classification: 'private',
      },
      action: 'read',
    },
    expected: {
      allow: true,
      changed: true,
      transition: 'deny_to_allow',
    },
  },
  'allow-to-deny': {
    fixture_id: 'C21-POS-02',
    description: 'Baseline policy rev 2 allows operator; candidate policy rev 3 restricts endpoint strictly to auditor yielding changed allow_to_deny decision',
    baseline_bundle: {
      revision: 2,
      digest: 'sha256:33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222',
      bundle_id: 'bundle-finance-v2',
    },
    candidate_bundle: {
      revision: 3,
      digest: 'sha256:4444555566667777888899990000aaaabbbbccccddddeeeeffff111122223333',
      bundle_id: 'bundle-finance-v3',
    },
    input: {
      request_id: 'req-sim-02',
      subject: {
        id: 'usr-ops-dan-442',
        roles: ['operator'],
        authenticated: true,
      },
      resource: {
        id: '/api/v1/finance/ledger',
        classification: 'restricted',
      },
      action: 'read',
    },
    expected: {
      allow: false,
      changed: true,
      transition: 'allow_to_deny',
    },
  },
  'unchanged': {
    fixture_id: 'C21-POS-03',
    description: 'Baseline rev 1 and candidate rev 2 both allow public health endpoint yielding unchanged decision',
    baseline_bundle: {
      revision: 1,
      digest: 'sha256:555566667777888899990000aaaabbbbccccddddeeeeffff1111222233334444',
      bundle_id: 'bundle-core-v1',
    },
    candidate_bundle: {
      revision: 2,
      digest: 'sha256:66667777888899990000aaaabbbbccccddddeeeeffff11112222333344445555',
      bundle_id: 'bundle-core-v2',
    },
    input: {
      request_id: 'req-sim-03',
      subject: {
        id: 'anonymous',
        roles: [],
        authenticated: false,
      },
      resource: {
        id: '/healthz',
        classification: 'public',
      },
      action: 'read',
    },
    expected: {
      allow: true,
      changed: false,
      transition: 'unchanged',
    },
  },
  'sentinel': {
    fixture_id: 'C21-NEG-SENTINEL',
    description: "<script>alert('xss-sentinel')</script><img src=x onerror=alert('img-sentinel')> Sentinel inertness test on changed decision",
    baseline_bundle: {
      revision: 1,
      digest: 'sha256:7777888899990000aaaabbbbccccddddeeeeffff111122223333444455556666',
      bundle_id: 'bundle-sentinel-v1',
    },
    candidate_bundle: {
      revision: 2,
      digest: 'sha256:888899990000aaaabbbbccccddddeeeeffff1111222233334444555566667777',
      bundle_id: 'bundle-sentinel-v2',
    },
    input: {
      request_id: 'req-c21-sentinel',
      subject: {
        id: "usr-<script>alert('sub')</script>",
        roles: ['operator'],
        authenticated: true,
      },
      resource: {
        id: '/api/v1/sentinel',
        classification: 'private',
      },
      action: 'read',
    },
    expected: {
      allow: true,
      changed: true,
      transition: 'deny_to_allow',
    },
  },
  'fail-closed': {
    fixture_id: 'C21-NEG-FAILCLOSED',
    description: 'Private sensitive resource without authenticated identity fails closed with deny decision in both revisions',
    baseline_bundle: {
      revision: 1,
      digest: 'sha256:99990000aaaabbbbccccddddeeeeffff11112222333344445555666677778888',
      bundle_id: 'bundle-sec-v1',
    },
    candidate_bundle: {
      revision: 2,
      digest: 'sha256:0000aaaabbbbccccddddeeeeffff111122223333444455556666777788889999',
      bundle_id: 'bundle-sec-v2',
    },
    input: {
      request_id: 'req-c21-failclosed',
      subject: {
        id: '',
        roles: [],
        authenticated: false,
      },
      resource: {
        id: '/api/v1/vault/keys',
        classification: 'private',
      },
      action: 'read',
    },
    expected: {
      allow: false,
      changed: false,
      transition: 'unchanged',
    },
  },
};

export function Simulator() {
  const [selectedSample, setSelectedSample] = useState<string>('deny-to-allow');
  const [activeFixture, setActiveFixture] = useState<SimulationFixture | null>(SAMPLE_FIXTURES['deny-to-allow']);
  const [report, setReport] = useState<SimulationReport | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Helper to run simulation via engine API
  const runSimulation = async (fixture: SimulationFixture) => {
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('/api/v1/runtime/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(fixture),
      });

      if (response.ok || response.status === 422) {
        const data: SimulationReport = await response.json();
        setReport(data);
      } else if (response.status === 503) {
        setError('Engine or policy provider unavailable (503 Service Unavailable) — fail closed');
        setReport(null);
      } else {
        const errorText = await response.text();
        setError(`Simulation failed (${response.status}): ${errorText || 'Unknown engine error'}`);
        setReport(null);
      }
    } catch {
      setError('Engine unavailable: Running in offline shell mode. Connect engine on loopback to simulate.');
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (activeFixture) {
      void runSimulation(activeFixture);
    }
  }, [activeFixture]);

  const handleSelectSample = (sampleKey: string) => {
    setSelectedSample(sampleKey);
    const fx = SAMPLE_FIXTURES[sampleKey];
    if (fx) {
      setActiveFixture(fx);
      setError(null);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const text = String(reader.result || '');
        const parsed = JSON.parse(text) as SimulationFixture;
        if (!parsed || typeof parsed !== 'object' || !parsed.fixture_id) {
          setError('Invalid simulation fixture: missing fixture_id or malformed schema');
          setActiveFixture(null);
          setReport(null);
          return;
        }
        setSelectedSample('custom');
        setActiveFixture(parsed);
        setError(null);
        void runSimulation(parsed);
      } catch (err) {
        setError(`Malformed fixture JSON: ${err instanceof Error ? err.message : String(err)}`);
        setActiveFixture(null);
        setReport(null);
      }
    };
    reader.onerror = () => {
      setError('Failed to read fixture file');
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleClear = () => {
    setActiveFixture(null);
    setReport(null);
    setError(null);
    setSelectedSample('');
  };

  // Derive human-readable explanation of changed decision
  const renderDecisionExplanation = (rep: SimulationReport, fx: SimulationFixture | null) => {
    const baseline = rep.baseline_decision;
    const candidate = rep.candidate_decision || rep.decision;
    const isChanged = rep.changed;
    const transition = rep.transition || (isChanged ? (candidate?.allow ? 'deny_to_allow' : 'allow_to_deny') : 'unchanged');

    const subjectStr = fx?.input?.subject?.id || 'anonymous';
    const rolesStr = (fx?.input?.subject?.roles || []).join(', ') || 'none';
    const resourceStr = fx?.input?.resource?.id || '/resource';
    const classStr = fx?.input?.resource?.classification || candidate?.classification || 'private';
    const actionStr = fx?.input?.action || 'read';

    let explanationText = '';
    if (transition === 'deny_to_allow') {
      explanationText = `Policy revision ${candidate?.revision ?? 2} added or expanded permissions for subject '${subjectStr}' (roles: [${rolesStr}]), transitioning the decision on resource '${resourceStr}' from DENIED to ALLOWED.`;
    } else if (transition === 'allow_to_deny') {
      explanationText = `Policy revision ${candidate?.revision ?? 3} revoked access or tightened constraints for subject '${subjectStr}', transitioning the decision on resource '${resourceStr}' from ALLOWED to DENIED.`;
    } else {
      explanationText = `Policy revision ${candidate?.revision ?? 1} maintains the same outcome (${candidate?.allow ? 'ALLOWED' : 'DENIED'}) for subject '${subjectStr}' on ${classStr} resource '${resourceStr}'.`;
    }

    return (
      <div className="explanation-card" role="region" aria-label="Decision Explanation">
        <div className="eyebrow">Decision Diff Explanation</div>
        <h3 className="explanation-title">{explanationText}</h3>
        <p className="explanation-details">
          <strong>Fixture Context:</strong> {fx?.description || 'Synthetic decision fixture'}
        </p>
        <div className="explanation-grid">
          <div>
            <span className="muted">Subject:</span> <code>{subjectStr}</code>
          </div>
          <div>
            <span className="muted">Roles:</span> <code>{rolesStr}</code>
          </div>
          <div>
            <span className="muted">Action:</span> <code>{actionStr}</code>
          </div>
          <div>
            <span className="muted">Classification:</span> <code>{classStr}</code>
          </div>
        </div>
        {rep.reasons && rep.reasons.length > 0 && (
          <div className="reasons-block">
            <span className="muted">Policy Reasons:</span>
            <ul>
              {rep.reasons.map((r, i) => (
                <li key={i}>
                  <code>{r}</code>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="simulator-page" tabIndex={-1}>
      <header className="page-header">
        <div className="eyebrow">Local-First Authorization</div>
        <h2>Policy Simulator &amp; Decision Diffs</h2>
        <p className="intro">
          Inspect and compare offline authorization decisions between policy revisions. Observe changed outcomes and verify explainability using fixture context.
        </p>
      </header>

      {/* Control Toolbar */}
      <section className="panel" aria-label="Simulator Controls">
        <div className="simulator-toolbar">
          <div className="toolbar-group">
            <label htmlFor="sample-select">Preloaded Fixtures</label>
            <select
              id="sample-select"
              aria-label="Select sample fixture"
              value={selectedSample}
              onChange={(e) => handleSelectSample(e.target.value)}
            >
              <option value="deny-to-allow">Changed: Deny → Allow (Rev 1 → 2)</option>
              <option value="allow-to-deny">Changed: Allow → Deny (Rev 2 → 3)</option>
              <option value="unchanged">Unchanged: Allow (Rev 1 → 2)</option>
              <option value="sentinel">Negative: Script Sentinel Inertness</option>
              <option value="fail-closed">Negative: Private Resource Fail-Closed</option>
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
            {activeFixture && (
              <button
                type="button"
                onClick={() => activeFixture && void runSimulation(activeFixture)}
                disabled={loading}
              >
                {loading ? 'Simulating…' : 'Re-run Simulation'}
              </button>
            )}
            <button type="button" onClick={handleClear} className="button-secondary">
              Clear
            </button>
          </div>
        </div>
      </section>

      {/* Error / Alert Display */}
      {error && (
        <section className="notice notice-error" role="alert" aria-live="polite">
          <span className="dot dot-error" />
          <p>{error}</p>
        </section>
      )}

      {/* Loading State */}
      {loading && !report && !error && (
        <section className="panel" role="status" aria-live="polite">
          <p className="muted">Evaluating decision simulation via loopback engine…</p>
        </section>
      )}

      {/* Empty State */}
      {!activeFixture && !error && (
        <section className="panel empty-state" role="status">
          <h2>No simulation loaded</h2>
          <p className="muted">
            Select a preloaded fixture from the dropdown above or upload a JSON simulation file to evaluate decision diffs across policy revisions.
          </p>
        </section>
      )}

      {/* Loaded Simulation Diff and Explanation */}
      {activeFixture && report && (
        <div className="simulator-results">
          {/* Revision and Status Banner */}
          <section className="panel diff-banner">
            <div className="banner-header">
              <div>
                <span className="eyebrow">Fixture: {activeFixture.fixture_id}</span>
                <h2>
                  Policy Revision {report.candidate_decision?.revision ?? report.revision ?? 2} Diff
                </h2>
              </div>
              <div className="transition-tag-container">
                {report.changed ? (
                  report.candidate_decision?.allow ? (
                    <span className="state transition-badge state-allow">DENY → ALLOW</span>
                  ) : (
                    <span className="state transition-badge state-deny">ALLOW → DENY</span>
                  )
                ) : (
                  <span className="state transition-badge state-unchanged">UNCHANGED</span>
                )}
              </div>
            </div>

            {/* Decision Comparison Table */}
            <div className="table-responsive">
              <table className="diff-table" aria-label="Policy Revision Decision Diff">
                <caption>Comparison of authorization attributes between baseline and candidate policy revisions</caption>
                <thead>
                  <tr>
                    <th scope="col">Evaluation Attribute</th>
                    <th scope="col">
                      Baseline Policy (Rev {report.baseline_decision?.revision ?? 1})
                    </th>
                    <th scope="col">
                      Candidate Policy (Rev {report.candidate_decision?.revision ?? report.revision ?? 2})
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <th scope="row">Outcome</th>
                    <td>
                      <span className={`state ${report.baseline_decision?.allow ? 'state-allow' : 'state-deny'}`}>
                        {report.baseline_decision?.allow ? 'ALLOW (200)' : 'DENY (403)'}
                      </span>
                    </td>
                    <td>
                      <span className={`state ${report.candidate_decision?.allow ? 'state-allow' : 'state-deny'}`}>
                        {report.candidate_decision?.allow ? 'ALLOW (200)' : 'DENY (403)'}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Policy Revision</th>
                    <td>
                      <span className="revision-badge">Rev {report.baseline_decision?.revision ?? 1}</span>
                    </td>
                    <td>
                      <span className="revision-badge">
                        Rev {report.candidate_decision?.revision ?? report.revision ?? 2}
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Policy Digest</th>
                    <td>
                      <code>{truncateDigest(report.baseline_decision?.policy_digest || activeFixture.baseline_bundle?.digest)}</code>
                    </td>
                    <td>
                      <code>{truncateDigest(report.candidate_decision?.policy_digest || activeFixture.candidate_bundle?.digest || report.policy_digest)}</code>
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Resource Target</th>
                    <td>
                      <code>{activeFixture.input?.resource?.id || '/resource'}</code>
                    </td>
                    <td>
                      <code>{activeFixture.input?.resource?.id || '/resource'}</code>
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Classification</th>
                    <td>
                      <span className="classification-tag">
                        {report.baseline_decision?.classification || activeFixture.input?.resource?.classification || 'private'}
                      </span>
                    </td>
                    <td>
                      <span className="classification-tag">
                        {report.candidate_decision?.classification || activeFixture.input?.resource?.classification || 'private'}
                      </span>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Explanation in Context */}
          <section className="panel">
            {renderDecisionExplanation(report, activeFixture)}
          </section>
        </div>
      )}
    </div>
  );
}

// Helpers
function truncateDigest(digest?: string): string {
  if (!digest) return 'sha256:0000…';
  if (digest.length <= 22) return digest;
  return `${digest.slice(0, 14)}…${digest.slice(-6)}`;
}

export default Simulator;
