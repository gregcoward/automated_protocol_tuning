import React, { useState, useEffect } from 'react';
import { api } from '../api/client.js';
import { useAsync } from '../hooks/useApi.js';

function RecommendationCard({ rec, onApply, applied, applying }) {
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
            <span className="tag tag-medium">child → {rec.suggested_profile_name}</span>
          )}
          <span className={`tag ${rec.safe_auto_apply ? 'tag-low' : 'tag-high'}`}>
            {rec.safe_auto_apply ? 'Auto-Safe' : 'Operator Review'}
          </span>
          {rec.settings_evaluated > 0 && (
            <span className="text-muted text-sm">({rec.settings_evaluated} settings checked)</span>
          )}
        </div>
        <div className="flex gap-2">
          <button className="btn btn-secondary btn-sm" onClick={() => setExpanded(e => !e)}>
            {expanded ? 'Hide Details' : `${rec.parameter_diffs.length} Change${rec.parameter_diffs.length !== 1 ? 's' : ''}`}
          </button>
          {!applied && (
            <button className="btn btn-primary btn-sm" onClick={() => onApply(rec)} disabled={applying}>
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
          {rec.recommended_parent_profile && rec.is_system_default_profile && (
            <div className="text-sm mb-2">
              <strong>Parent Profile (defaultsFrom):</strong>{' '}
              <code>{rec.recommended_parent_profile}</code>
            </div>
          )}
          <div className="diff-panel">
            <div className="diff-row" style={{ fontWeight: 600, fontSize: 11, background: 'transparent', border: 'none', paddingBottom: 2 }}>
              <span>Parameter / Section</span><span>Current</span><span>Recommended & Rationale</span>
            </div>
            {rec.parameter_diffs.map((d, i) => (
              <div key={i} className="diff-row">
                <div>
                  <div className="diff-param">{d.gui_name || d.parameter}</div>
                  <div className="text-muted" style={{ fontSize: 11, fontFamily: 'monospace' }}>{d.parameter}</div>
                  {d.section && <div className="text-muted" style={{ fontSize: 10 }}>{d.section} · {d.category || 'telemetry'}</div>}
                </div>
                <span className="diff-current">
                  {Array.isArray(d.current_value) ? d.current_value.join(' ') : String(d.current_value)}
                  {d.unit ? ` ${d.unit}` : ''}
                </span>
                <div>
                  <div className="diff-recommended">
                    {Array.isArray(d.recommended_value) ? d.recommended_value.join(' ') : String(d.recommended_value)}
                    {d.unit ? ` ${d.unit}` : ''}
                    {!d.safe_auto_apply && (
                      <span className="tag tag-high" style={{ marginLeft: 6, fontSize: 10 }}>confirm</span>
                    )}
                  </div>
                  {d.rationale && <div className="text-muted" style={{ fontSize: 11, marginTop: 2 }}>{d.rationale}</div>}
                </div>
              </div>
            ))}
          </div>

          {rec.advisories?.length > 0 && (
            <div className="banner banner-warn mt-2" style={{ marginBottom: 0 }}>
              <strong>Topology & Policy Advisories:</strong>
              <ul style={{ margin: '4px 0 0 18px', padding: 0 }}>
                {rec.advisories.map((adv, idx) => <li key={idx} className="text-sm">{adv}</li>)}
              </ul>
            </div>
          )}

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

function SettingsCatalogCard() {
  const [open, setOpen] = useState(false);
  const [catalog, setCatalog] = useState([]);
  const [protoFilter, setProtoFilter] = useState('all');
  const [search, setSearch] = useState('');
  const { run: fetchCatalog, loading } = useAsync(() => api.profileSettings());

  useEffect(() => {
    if (open && catalog.length === 0) {
      fetchCatalog().then(r => { if (r) setCatalog(r); });
    }
  }, [open, catalog.length, fetchCatalog]);

  const filtered = catalog.filter(item => {
    if (protoFilter !== 'all' && item.protocol !== protoFilter) return false;
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      item.gui_name.toLowerCase().includes(q) ||
      item.rest_key.toLowerCase().includes(q) ||
      item.section.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q)
    );
  });

  return (
    <div className="card">
      <div className="collapsible-header" onClick={() => setOpen(o => !o)}>
        <div>
          <p className="card__title">Evaluated BIG-IP Profile Settings Catalog (TCP · UDP · HTTP)</p>
          <p className="card__subtitle">All profile parameters evaluated across Timer, Memory, Connection, Congestion, Loss Recovery, MPTCP, Enforcement, sFlow & HSTS</p>
        </div>
        <span className={`chevron ${open ? 'open' : ''}`}>▼</span>
      </div>
      {open && (
        <div className="mt-2">
          <div className="form-row mb-2">
            <div className="field" style={{ maxWidth: 160 }}>
              <label>Protocol</label>
              <select value={protoFilter} onChange={e => setProtoFilter(e.target.value)}>
                <option value="all">All ({catalog.length})</option>
                <option value="tcp">TCP ({catalog.filter(x => x.protocol === 'tcp').length})</option>
                <option value="udp">UDP ({catalog.filter(x => x.protocol === 'udp').length})</option>
                <option value="http">HTTP ({catalog.filter(x => x.protocol === 'http').length})</option>
              </select>
            </div>
            <div className="field" style={{ flex: 2 }}>
              <label>Filter Settings</label>
              <input value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search GUI name, REST key, section, or behavior (e.g. bbr, chunking, mptcp, hsts)…" />
            </div>
          </div>
          {loading && <p className="text-sm text-muted">Loading settings catalog…</p>}
          {!loading && (
            <div className="table-wrapper" style={{ maxHeight: 360, overflowY: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Section</th>
                    <th>Setting (GUI / REST Key)</th>
                    <th>Default</th>
                    <th>Mode / Tier</th>
                    <th>Behavior & Interactions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((s) => (
                    <tr key={`${s.protocol}:${s.rest_key}`}>
                      <td><span className="tag tag-protocol">{s.protocol.toUpperCase()}</span></td>
                      <td className="text-sm">{s.section}</td>
                      <td>
                        <div style={{ fontWeight: 600, fontSize: 12 }}>{s.gui_name}</div>
                        <div className="text-mono text-muted" style={{ fontSize: 11 }}>{s.rest_key}</div>
                      </td>
                      <td className="text-mono" style={{ fontSize: 11 }}>{String(s.default_value)}</td>
                      <td>
                        <span className={`tag ${s.safe_auto_apply ? 'tag-low' : 'tag-medium'}`}>
                          {s.evaluation_mode}
                        </span>
                      </td>
                      <td className="text-sm text-muted">
                        <div>{s.description}</div>
                        {s.interactions && <div style={{ fontSize: 11, marginTop: 2 }}><em>Interactions:</em> {s.interactions}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
    protocols: ['tcp', 'udp', 'http'],
    window: '24h',
  });
  const [vsInput, setVsInput] = useState('');
  const [results, setResults] = useState(null);
  const [appliedIds, setAppliedIds] = useState(new Set());
  const [applyNote, setApplyNote] = useState('');
  const [itemErrors, setItemErrors] = useState([]);

  const { run: runAnalysis, loading: analyzing, error: analysisError } = useAsync(
    (payload) => api.runAnalysis(payload)
  );
  const { run: runApply, loading: applying, error: applyError } = useAsync(
    (recs, note) => api.applyRemediation(recs, note)
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
    const r = await runAnalysis(payload);
    if (r) {
      setResults(r);
      setAppliedIds(new Set());
      setItemErrors([]);
    }
  };

  const handleApplySingle = async (rec) => {
    setItemErrors([]);
    const r = await runApply([rec], applyNote || null);
    if (r?.applied?.length > 0) {
      setAppliedIds(prev => new Set([...prev, ...r.applied]));
    }
    if (r?.errors?.length > 0) {
      setItemErrors(r.errors);
    }
  };

  const handleApplyAll = async () => {
    if (!results) return;
    setItemErrors([]);
    const toApply = results.recommendations.filter(r => !appliedIds.has(r.id));
    if (toApply.length === 0) return;
    const r = await runApply(toApply, applyNote || null);
    if (r?.applied?.length > 0) {
      setAppliedIds(prev => new Set([...prev, ...r.applied]));
    }
    if (r?.errors?.length > 0) {
      setItemErrors(r.errors);
    }
  };

  const PROTOCOLS = ['tcp', 'udp', 'http'];
  const WINDOWS = ['1h', '6h', '24h', '7d', '30d'];
  const remainingCount = results ? results.recommendations.filter(r => !appliedIds.has(r.id)).length : 0;

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
          {analyzing && <span className="text-sm text-muted">Evaluating telemetry and all TCP/UDP/HTTP profile settings…</span>}
        </div>
        {analysisError && <div className="banner banner-error mt-2">{analysisError}</div>}
      </div>

      {results && (
        <div className="mb-2">
          <div className="flex items-center justify-between mb-2" style={{ flexWrap: 'wrap', gap: 8 }}>
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
                <button className="btn btn-primary btn-sm" onClick={handleApplyAll}
                  disabled={applying || remainingCount === 0}>
                  {applying ? 'Applying…' : `Apply All (${remainingCount})`}
                </button>
              </div>
            )}
          </div>
          {applyError && <div className="banner banner-error mb-2">{applyError}</div>}
          {itemErrors.length > 0 && (
            <div className="banner banner-error mb-2">
              <strong>{itemErrors.length} remediation(s) failed:</strong>
              <ul style={{ margin: '4px 0 0 18px', padding: 0 }}>
                {itemErrors.map((err, i) => (
                  <li key={i}>{err.recommendation_id}: {err.error}</li>
                ))}
              </ul>
            </div>
          )}
          {results.recommendations.length === 0 && (
            <div className="banner banner-success">
              No tuning recommendations needed — all evaluated TCP, UDP, and HTTP profile settings are optimal for the observed traffic pattern.
            </div>
          )}
          {results.recommendations.map(rec => (
            <RecommendationCard
              key={rec.id}
              rec={rec}
              onApply={handleApplySingle}
              applying={applying}
              applied={appliedIds.has(rec.id)}
            />
          ))}
        </div>
      )}

      <SettingsCatalogCard />
    </div>
  );
}
