import React, { useState } from 'react';
import { api } from '../api/client.js';
import { useAsync } from '../hooks/useApi.js';

function RecommendationCard({ rec, onApply, onApplied, applied }) {
  const [expanded, setExpanded] = useState(false);
  const confidenceClass = { High: 'tag-high', Medium: 'tag-medium', Low: 'tag-low' }[rec.confidence] || 'tag-low';

  return (
    <div className="card" style={{ marginBottom: 10, padding: 14 }}>
      <div className="flex items-center justify-between gap-2" style={{ flexWrap: 'wrap' }}>
        <div className="flex items-center gap-2" style={{ flexWrap: 'wrap' }}>
          <span className={`tag ${confidenceClass}`}>{rec.confidence}</span>
          <span className="tag tag-protocol">{rec.protocol.toUpperCase()}</span>
          <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}>{rec.virtual_server}</span>
          <span className="text-muted text-sm">({rec.context})</span>
          <span className="text-muted text-sm">{rec.profile_name}</span>
          {rec.is_system_default_profile && (
            <span className="tag tag-medium">will create child profile</span>
          )}
        </div>
        <div className="flex gap-2">
          <button className="btn btn-secondary btn-sm" onClick={() => setExpanded(e => !e)}>
            {expanded ? 'Hide Details' : `${rec.parameter_diffs.length} Changes`}
          </button>
          {!applied && (
            <button className="btn btn-primary btn-sm" onClick={() => onApply(rec)}>
              Apply
            </button>
          )}
          {applied && <span className="tag tag-applied">Applied ✓</span>}
        </div>
      </div>

      {rec.supporting_evidence && (
        <p className="text-sm text-muted mt-1">{rec.supporting_evidence}</p>
      )}

      {expanded && (
        <div className="mt-2">
          <div className="diff-panel">
            <div className="diff-row" style={{ fontWeight: 600, fontSize: 11, background: 'transparent', border: 'none', paddingBottom: 2 }}>
              <span>Parameter</span><span>Current</span><span>Recommended</span>
            </div>
            {rec.parameter_diffs.map((d, i) => (
              <div key={i} className="diff-row">
                <span className="diff-param">{d.parameter}</span>
                <span className="diff-current">{String(d.current_value)}{d.unit ? ` ${d.unit}` : ''}</span>
                <span className="diff-recommended">{String(d.recommended_value)}{d.unit ? ` ${d.unit}` : ''}</span>
              </div>
            ))}
          </div>
          <div className="mt-2 text-sm">
            <strong>F5 Reference:</strong>{' '}
            <a href={rec.f5_kb_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
              {rec.f5_kb_id}: {rec.f5_kb_title}
            </a>
          </div>
          {Object.keys(rec.metrics_snapshot || {}).length > 0 && (
            <div className="mt-1 text-sm text-muted text-mono">
              {Object.entries(rec.metrics_snapshot).map(([k, v]) => `${k}: ${v}`).join('  |  ')}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AnalysisPage({ bigips }) {
  const [form, setForm] = useState({
    bigip_ids: [],
    virtual_servers: [],
    protocols: ['tcp', 'udp', 'http'],
    window: '24h',
  });
  const [vsInput, setVsInput] = useState('');
  const [results, setResults] = useState(null);
  const [appliedIds, setAppliedIds] = useState(new Set());
  const [applyNote, setApplyNote] = useState('');
  const { run: runAnalysis, loading: analyzing, error: analysisError } = useAsync(() => api.runAnalysis(form));
  const { run: runApply, loading: applying, error: applyError } = useAsync(
    (recs) => api.applyRemediation(recs, applyNote || null)
  );

  const toggleProtocol = (p) => setForm(f => ({
    ...f,
    protocols: f.protocols.includes(p) ? f.protocols.filter(x => x !== p) : [...f.protocols, p],
  }));

  const toggleBigIp = (id) => setForm(f => ({
    ...f,
    bigip_ids: f.bigip_ids.includes(id) ? f.bigip_ids.filter(x => x !== id) : [...f.bigip_ids, id],
  }));

  const handleAnalyze = async () => {
    const payload = {
      ...form,
      virtual_servers: vsInput.trim() ? vsInput.split('\n').map(s => s.trim()).filter(Boolean) : [],
    };
    const r = await runAnalysis();
    if (r) { setResults(r); setAppliedIds(new Set()); }
  };

  const handleApplySingle = async (rec) => {
    const r = await runApply([rec]);
    if (r?.applied?.length > 0) {
      setAppliedIds(prev => new Set([...prev, rec.id]));
    }
  };

  const handleApplyAll = async () => {
    if (!results) return;
    const toApply = results.recommendations.filter(r => !appliedIds.has(r.id));
    const r = await runApply(toApply);
    if (r?.applied) setAppliedIds(prev => new Set([...prev, ...toApply.map(x => x.id)]));
  };

  const PROTOCOLS = ['tcp', 'udp', 'http'];
  const WINDOWS = ['1h', '6h', '24h', '7d', '30d'];

  return (
    <div>
      <h1 className="section-title">Analysis & Remediation Studio</h1>

      <div className="card">
        <p className="card__title" style={{ marginBottom: 12 }}>Analysis Parameters</p>
        <div className="form-row">
          <div className="field" style={{ flex: 2 }}>
            <label>Target BIG-IP(s)</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 4 }}>
              <label className="checkbox-row">
                <input type="checkbox"
                  checked={form.bigip_ids.length === 0}
                  onChange={() => setForm(f => ({ ...f, bigip_ids: [] }))} />
                <span>All devices</span>
              </label>
              {bigips.map(b => (
                <label key={b.id} className="checkbox-row">
                  <input type="checkbox"
                    checked={form.bigip_ids.includes(b.id)}
                    onChange={() => toggleBigIp(b.id)} />
                  <span>{b.label || b.host}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="field">
            <label>Protocols</label>
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              {PROTOCOLS.map(p => (
                <label key={p} className="checkbox-row">
                  <input type="checkbox"
                    checked={form.protocols.includes(p)}
                    onChange={() => toggleProtocol(p)} />
                  <span>{p.toUpperCase()}</span>
                </label>
              ))}
            </div>
          </div>
          <div className="field">
            <label>Historical Window</label>
            <select value={form.window} onChange={e => setForm(f => ({ ...f, window: e.target.value }))}>
              {WINDOWS.map(w => <option key={w} value={w}>{w}</option>)}
            </select>
          </div>
        </div>
        <div className="form-row mt-2">
          <div className="field w-full">
            <label>Filter Virtual Servers (one full path per line, blank = all enrolled)</label>
            <textarea rows={3} value={vsInput} onChange={e => setVsInput(e.target.value)}
              placeholder="/Common/vip_web&#10;/Common/vip_api" style={{ fontFamily: 'monospace', fontSize: 12 }} />
          </div>
        </div>
        <div className="mt-2 flex gap-2 items-center">
          <button className="btn btn-primary" onClick={handleAnalyze} disabled={analyzing || form.protocols.length === 0}>
            {analyzing ? <><span className="spinner" /> Analyzing…</> : '▶ Run Analysis'}
          </button>
          {analyzing && <span className="text-sm text-muted">Querying VictoriaMetrics and BIG-IP profiles…</span>}
        </div>
        {analysisError && <div className="banner banner-error mt-2">{analysisError}</div>}
      </div>

      {results && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <div>
              <span className="card__title">
                {results.recommendations.length} Recommendation{results.recommendations.length !== 1 ? 's' : ''}
              </span>
              <span className="text-muted text-sm" style={{ marginLeft: 10 }}>
                {results.bigip_count} BIG-IP{results.bigip_count !== 1 ? 's' : ''} ·{' '}
                {results.virtual_server_count} VS · window: {results.window} · src: {results.telemetry_source}
              </span>
            </div>
            {results.recommendations.length > 0 && (
              <div className="flex gap-2 items-center">
                <div className="field" style={{ marginBottom: 0 }}>
                  <input value={applyNote} onChange={e => setApplyNote(e.target.value)}
                    placeholder="Operator note…" style={{ fontSize: 12, padding: '4px 8px' }} />
                </div>
                <button className="btn btn-primary btn-sm" onClick={handleApplyAll} disabled={applying}>
                  {applying ? 'Applying…' : `Apply All (${results.recommendations.filter(r => !appliedIds.has(r.id)).length})`}
                </button>
              </div>
            )}
          </div>
          {applyError && <div className="banner banner-error mb-2">{applyError}</div>}
          {results.recommendations.length === 0 && (
            <div className="banner banner-success">
              No tuning recommendations needed — current profile configuration is well-optimized for the observed traffic pattern.
            </div>
          )}
          {results.recommendations.map(rec => (
            <RecommendationCard key={rec.id} rec={rec}
              onApply={handleApplySingle}
              applied={appliedIds.has(rec.id)} />
          ))}
        </div>
      )}
    </div>
  );
}
