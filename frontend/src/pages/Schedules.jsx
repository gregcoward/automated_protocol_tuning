import React, { useState, useEffect } from 'react';
import { api } from '../api/client.js';
import { useAsync } from '../hooks/useApi.js';

function ScheduleForm({ bigips, onCreated }) {
  const [form, setForm] = useState({
    name: '', schedule_type: 'interval', interval_hours: 6, cron_expression: '',
    protocols: ['tcp', 'udp', 'http'], analysis_window: '6h',
    mode: 'recommend_only', min_confidence: 'High', enabled: true,
    bigip_ids: [], virtual_servers: [],
  });
  const { run, loading, error } = useAsync(() => api.createSchedule(form));

  const submit = async (e) => {
    e.preventDefault();
    const r = await run();
    if (r) onCreated(r);
  };

  const toggleProtocol = (p) => setForm(f => ({
    ...f, protocols: f.protocols.includes(p) ? f.protocols.filter(x => x !== p) : [...f.protocols, p]
  }));

  return (
    <form onSubmit={submit}>
      {error && <div className="banner banner-error mb-2">{error}</div>}
      <div className="form-row">
        <div className="field" style={{ flex: 2 }}>
          <label>Schedule Name</label>
          <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            placeholder="Nightly TCP Analysis" required />
        </div>
        <div className="field">
          <label>Type</label>
          <select value={form.schedule_type} onChange={e => setForm(f => ({ ...f, schedule_type: e.target.value }))}>
            <option value="interval">Interval</option>
            <option value="cron">Cron Expression</option>
          </select>
        </div>
        {form.schedule_type === 'interval' ? (
          <div className="field">
            <label>Every (hours)</label>
            <input type="number" min={1} max={168} value={form.interval_hours}
              onChange={e => setForm(f => ({ ...f, interval_hours: +e.target.value }))} />
          </div>
        ) : (
          <div className="field">
            <label>Cron (DoW H D M Y)</label>
            <input value={form.cron_expression} onChange={e => setForm(f => ({ ...f, cron_expression: e.target.value }))}
              placeholder="0 2 * * *" style={{ fontFamily: 'monospace' }} />
          </div>
        )}
        <div className="field">
          <label>Analysis Window</label>
          <select value={form.analysis_window} onChange={e => setForm(f => ({ ...f, analysis_window: e.target.value }))}>
            {['1h','6h','24h','7d','30d'].map(w => <option key={w} value={w}>{w}</option>)}
          </select>
        </div>
      </div>
      <div className="form-row mt-2">
        <div className="field">
          <label>Mode</label>
          <select value={form.mode} onChange={e => setForm(f => ({ ...f, mode: e.target.value }))}>
            <option value="recommend_only">Recommend Only</option>
            <option value="auto_remediate">Auto-Remediate</option>
          </select>
        </div>
        <div className="field">
          <label>Min Confidence (auto-apply)</label>
          <select value={form.min_confidence} onChange={e => setForm(f => ({ ...f, min_confidence: e.target.value }))}>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
        <div className="field">
          <label>Protocols</label>
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            {['tcp','udp','http'].map(p => (
              <label key={p} className="checkbox-row">
                <input type="checkbox" checked={form.protocols.includes(p)} onChange={() => toggleProtocol(p)} />
                <span>{p.toUpperCase()}</span>
              </label>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'flex-end' }}>
          <label className="checkbox-row">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
            <span>Enabled</span>
          </label>
        </div>
      </div>
      <button type="submit" className="btn btn-primary mt-2" disabled={loading}>
        {loading ? 'Creating…' : 'Create Schedule'}
      </button>
    </form>
  );
}

export default function SchedulesPage({ bigips }) {
  const [schedules, setSchedules] = useState([]);
  const [audit, setAudit] = useState([]);
  const [showAudit, setShowAudit] = useState(false);
  const { run: fetchSchedules } = useAsync(() => api.listSchedules());
  const { run: fetchAudit } = useAsync(() => api.scheduleAudit());
  const { run: deleteSchedule } = useAsync((id) => api.deleteSchedule(id));
  const { run: toggleSchedule } = useAsync((id, enabled) => api.updateSchedule(id, { enabled }));

  const load = async () => {
    const r = await fetchSchedules();
    if (r) setSchedules(r);
  };
  const loadAudit = async () => {
    const r = await fetchAudit();
    if (r) setAudit(r);
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (id) => {
    if (!confirm('Delete this schedule?')) return;
    await deleteSchedule(id);
    load();
  };

  const handleToggle = async (sched) => {
    await toggleSchedule(sched.id, !sched.enabled);
    load();
  };

  return (
    <div>
      <h1 className="section-title">Automated Tuning Scheduler</h1>

      <div className="card">
        <p className="card__title" style={{ marginBottom: 12 }}>Create Schedule</p>
        <ScheduleForm bigips={bigips} onCreated={() => load()} />
      </div>

      <div className="card">
        <div className="card__header">
          <p className="card__title">Active Schedules ({schedules.length})</p>
          <button className="btn btn-secondary btn-sm" onClick={load}>↺ Refresh</button>
        </div>
        {schedules.length === 0 && <p className="text-muted text-sm">No schedules configured.</p>}
        {schedules.map(s => (
          <div key={s.id} style={{ borderBottom: '1px solid var(--border)', paddingBottom: 10, marginBottom: 10 }}>
            <div className="flex items-center justify-between gap-2" style={{ flexWrap: 'wrap' }}>
              <div>
                <span style={{ fontWeight: 600 }}>{s.name}</span>
                <span className={`tag ${s.mode === 'auto_remediate' ? 'tag-high' : 'tag-medium'}`} style={{ marginLeft: 8 }}>
                  {s.mode === 'auto_remediate' ? '⚡ Auto-Remediate' : '📋 Recommend Only'}
                </span>
                {!s.enabled && <span className="tag tag-low" style={{ marginLeft: 4 }}>Paused</span>}
              </div>
              <div className="flex gap-2">
                <button className="btn btn-secondary btn-sm" onClick={() => handleToggle(s)}>
                  {s.enabled ? 'Pause' : 'Resume'}
                </button>
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete(s.id)}>Delete</button>
              </div>
            </div>
            <div className="text-sm text-muted mt-1 flex gap-3" style={{ flexWrap: 'wrap' }}>
              <span>{s.schedule_type === 'cron' ? `cron: ${s.cron_expression}` : `every ${s.interval_hours}h`}</span>
              <span>window: {s.analysis_window}</span>
              <span>protocols: {s.protocols.join(', ')}</span>
              <span>min confidence: {s.min_confidence}</span>
              {s.last_run_at && <span>last run: {new Date(s.last_run_at).toLocaleString()}</span>}
              {s.next_run_at && <span>next: {new Date(s.next_run_at).toLocaleString()}</span>}
              {s.last_recommendations_count > 0 && (
                <span>{s.last_recommendations_count} recs / {s.last_applied_count} applied</span>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="collapsible-header" onClick={() => { setShowAudit(a => !a); if (!showAudit) loadAudit(); }}>
          <p className="card__title">Schedule Audit Trail</p>
          <span className={`chevron ${showAudit ? 'open' : ''}`}>▼</span>
        </div>
        {showAudit && (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr><th>Time</th><th>Schedule</th><th>Mode</th><th>Recs Found</th><th>Applied</th><th>Summary</th></tr>
              </thead>
              <tbody>
                {audit.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No audit entries.</td></tr>
                )}
                {audit.map((e, i) => (
                  <tr key={i}>
                    <td className="text-mono">{new Date(e.timestamp).toLocaleString()}</td>
                    <td>{e.schedule_name}</td>
                    <td><span className={`tag ${e.mode === 'auto_remediate' ? 'tag-high' : 'tag-medium'}`}>{e.mode}</span></td>
                    <td>{e.recommendations_found}</td>
                    <td>{e.remediations_applied}</td>
                    <td className="text-sm text-muted">{e.summary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
