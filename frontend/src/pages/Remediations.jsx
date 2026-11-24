import React, { useState, useEffect } from 'react';
import { api } from '../api/client.js';
import { useAsync } from '../hooks/useApi.js';

export default function RemediationsPage() {
  const [history, setHistory] = useState([]);
  const [expandedId, setExpandedId] = useState(null);
  const { run: fetchHistory, loading } = useAsync(() => api.remediationHistory(100));
  const { run: rollback, loading: rollingBack, error: rollbackError } = useAsync((id) => api.rollbackRemediation(id));

  const load = async () => {
    const r = await fetchHistory();
    if (r) setHistory(r);
  };

  useEffect(() => { load(); }, []);

  const handleRollback = async (changeId) => {
    if (!confirm(`Roll back change ${changeId}? The original profile settings will be restored.`)) return;
    const r = await rollback(changeId);
    if (r) load();
  };

  const statusTag = (s) => {
    const map = { applied: 'tag-applied', rolled_back: 'tag-rolled-back', failed: 'tag-failed' };
    return <span className={`tag ${map[s] || ''}`}>{s}</span>;
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <h1 className="section-title" style={{ marginBottom: 0 }}>Remediation History</h1>
        <button className="btn btn-secondary btn-sm" onClick={load} disabled={loading}>
          {loading ? 'Loading…' : '↺ Refresh'}
        </button>
      </div>

      {rollbackError && <div className="banner banner-error mb-2">{rollbackError}</div>}

      <div className="card" style={{ padding: 0 }}>
        <div className="table-wrapper" style={{ border: 'none' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>BIG-IP</th>
                <th>Virtual Server</th>
                <th>Protocol</th>
                <th>Context</th>
                <th>Profile Applied</th>
                <th>Changes</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.length === 0 && !loading && (
                <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>
                  No remediation history yet.
                </td></tr>
              )}
              {history.map(r => {
                const entries = Object.entries(r.parameter_changes || {});
                const isOpen = expandedId === r.change_id;
                return (
                  <React.Fragment key={r.change_id}>
                    <tr>
                      <td className="text-mono">{new Date(r.applied_at).toLocaleString()}</td>
                      <td>{r.bigip_host}</td>
                      <td className="text-mono" style={{ maxWidth: 180 }}>
                        <span className="truncate" style={{ display: 'block' }}>{r.virtual_server}</span>
                      </td>
                      <td><span className="tag tag-protocol">{r.protocol.toUpperCase()}</span></td>
                      <td>{r.context}</td>
                      <td className="text-mono" style={{ fontSize: 11, maxWidth: 180 }}>
                        <span className="truncate" style={{ display: 'block' }}>{r.applied_profile_full_path}</span>
                        {r.created_child_profile && <span className="tag tag-medium" style={{ fontSize: 10 }}>child</span>}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary btn-sm"
                          title={entries.map(([k, v]) => `${k}: ${v.before} → ${v.after}`).join(', ')}
                          onClick={() => setExpandedId(isOpen ? null : r.change_id)}
                        >
                          {entries.length} param{entries.length !== 1 ? 's' : ''} {isOpen ? '▲' : '▼'}
                        </button>
                      </td>
                      <td>{statusTag(r.status)}</td>
                      <td>
                        {r.status === 'applied' && (
                          <button className="btn btn-secondary btn-sm" onClick={() => handleRollback(r.change_id)}
                            disabled={rollingBack}>
                            Rollback
                          </button>
                        )}
                        {r.rolled_back_at && (
                          <span className="text-muted text-sm">{new Date(r.rolled_back_at).toLocaleDateString()}</span>
                        )}
                      </td>
                    </tr>
                    {isOpen && (
                      <tr>
                        <td colSpan={9} style={{ background: 'var(--input-bg)' }}>
                          <div className="text-sm" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                            <div>
                              <strong>Original Profile:</strong> <code>{r.original_profile_full_path}</code>{' '}
                              → <strong>Applied:</strong> <code>{r.applied_profile_full_path}</code>
                              {r.f5_kb_id && <span style={{ marginLeft: 12 }}><strong>KB:</strong> {r.f5_kb_id}</span>}
                            </div>
                            {r.operator_note && <div><strong>Operator Note:</strong> {r.operator_note}</div>}
                            {r.error_message && <div style={{ color: 'var(--chip-error)' }}><strong>Error:</strong> {r.error_message}</div>}
                            <div className="text-mono" style={{ marginTop: 4 }}>
                              {entries.map(([k, v]) => (
                                <div key={k}>
                                  {k}: <span className="diff-current">{String(v.before)}</span> →{' '}
                                  <span className="diff-recommended">{String(v.after)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
