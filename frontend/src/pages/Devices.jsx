import React, { useState } from 'react';
import { api } from '../api/client.js';
import { useAsync } from '../hooks/useApi.js';

function ConnectForm({ onConnected }) {
  const [form, setForm] = useState({
    host: '', port: 443, username: 'admin', password: '',
    verify_ssl: false, enable_tmctl: false, demo_mode: false, label: '',
  });
  const { run, loading, error } = useAsync(() => api.connect(form));

  const submit = async (e) => {
    e.preventDefault();
    const result = await run();
    if (result) onConnected(result);
  };

  return (
    <form onSubmit={submit}>
      {error && <div className="banner banner-error mb-2">{error}</div>}
      <div className="form-row">
        <div className="field">
          <label>Host / IP</label>
          <input value={form.host} onChange={e => setForm(f => ({ ...f, host: e.target.value }))}
            placeholder="192.168.1.245" required />
        </div>
        <div className="field" style={{ maxWidth: 100 }}>
          <label>Port</label>
          <input type="number" value={form.port} onChange={e => setForm(f => ({ ...f, port: +e.target.value }))} />
        </div>
        <div className="field">
          <label>Username</label>
          <input value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required />
        </div>
        <div className="field">
          <label>Password</label>
          <input type="password" value={form.password}
            onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
        </div>
        <div className="field">
          <label>Label (optional)</label>
          <input value={form.label} onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
            placeholder="Production LB" />
        </div>
      </div>
      <div className="form-row mt-2 gap-3">
        <label className="checkbox-row">
          <input type="checkbox" checked={form.verify_ssl}
            onChange={e => setForm(f => ({ ...f, verify_ssl: e.target.checked }))} />
          <span>Verify SSL</span>
        </label>
        <label className="checkbox-row">
          <input type="checkbox" checked={form.enable_tmctl}
            onChange={e => setForm(f => ({ ...f, enable_tmctl: e.target.checked }))} />
          <span>Enable tmctl metrics</span>
        </label>
        <label className="checkbox-row">
          <input type="checkbox" checked={form.demo_mode}
            onChange={e => setForm(f => ({ ...f, demo_mode: e.target.checked }))} />
          <span>Demo mode (simulated)</span>
        </label>
      </div>
      <div className="mt-2">
        <button type="submit" className="btn btn-primary" disabled={loading}>
          {loading ? <><span className="spinner" /> Connecting…</> : 'Connect BIG-IP'}
        </button>
      </div>
    </form>
  );
}

function EnrollPanel({ device, onUpdated }) {
  const [enrolled, setEnrolled] = useState(
    device.virtual_servers.filter(v => v.enrolled).map(v => v.full_path)
  );
  const { run, loading, error } = useAsync(() => api.updateEnrollment(device.id, enrolled));

  const toggle = (fp) => setEnrolled(prev =>
    prev.includes(fp) ? prev.filter(x => x !== fp) : [...prev, fp]
  );

  const save = async () => {
    const r = await run();
    if (r) onUpdated(device.id, r.enrolled);
  };

  return (
    <div>
      {error && <div className="banner banner-error mb-2">{error}</div>}
      <p className="text-sm text-muted mb-2">Select Virtual Servers to monitor and tune:</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 240, overflowY: 'auto' }}>
        {device.virtual_servers.map(vs => (
          <label key={vs.full_path} className="checkbox-row">
            <input type="checkbox" checked={enrolled.includes(vs.full_path)}
              onChange={() => toggle(vs.full_path)} />
            <span style={{ fontFamily: 'monospace', fontSize: 12 }}>{vs.full_path}</span>
            <span className="text-muted text-sm">{vs.destination}</span>
            {vs.profiles.map(p => (
              <span key={p.full_path} className="tag tag-protocol" style={{ marginLeft: 4 }}>{p.protocol}</span>
            ))}
          </label>
        ))}
        {device.virtual_servers.length === 0 && (
          <span className="text-muted text-sm">No virtual servers discovered</span>
        )}
      </div>
      <button className="btn btn-primary btn-sm mt-2" onClick={save} disabled={loading}>
        {loading ? 'Saving…' : `Save Enrollment (${enrolled.length} selected)`}
      </button>
    </div>
  );
}

export default function DevicesPage({ bigips, onRefresh }) {
  const [expanded, setExpanded] = useState(null);
  const { run: removeRun, loading: removing } = useAsync((id) => api.removeSession(id));

  const handleRemove = async (id) => {
    if (!confirm('Remove this BIG-IP session?')) return;
    await removeRun(id);
    onRefresh();
  };

  const handleConnected = () => onRefresh();
  const handleEnrolled = () => onRefresh();

  return (
    <div>
      <h1 className="section-title">BIG-IP Devices</h1>

      <div className="card">
        <div className="card__header">
          <div>
            <p className="card__title">Connect a BIG-IP</p>
            <p className="card__subtitle">Credentials are encrypted at rest with Fernet</p>
          </div>
        </div>
        <ConnectForm onConnected={handleConnected} />
      </div>

      <div className="card">
        <div className="card__header">
          <p className="card__title">Registered Devices ({bigips.length})</p>
        </div>
        {bigips.length === 0 && <p className="text-muted text-sm">No devices registered. Connect a BIG-IP above.</p>}
        {bigips.map(b => (
          <div key={b.id} style={{ borderBottom: '1px solid var(--border)', paddingBottom: 12, marginBottom: 12 }}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={`dot`} style={{
                  display: 'inline-block', width: 9, height: 9, borderRadius: '50%',
                  background: b.connected ? 'var(--chip-connected)' : 'var(--chip-error)', flexShrink: 0
                }} />
                <div>
                  <span style={{ fontWeight: 600 }}>{b.label || b.host}</span>
                  {b.hostname && <span className="text-muted text-sm" style={{ marginLeft: 8 }}>{b.hostname}</span>}
                  {b.version && <span className="text-muted text-sm" style={{ marginLeft: 8 }}>v{b.version}</span>}
                  {b.demo_mode && <span className="tag tag-medium" style={{ marginLeft: 8 }}>demo</span>}
                </div>
              </div>
              <div className="flex gap-2">
                <button className="btn btn-secondary btn-sm"
                  onClick={() => setExpanded(expanded === b.id ? null : b.id)}>
                  {expanded === b.id ? 'Collapse' : `Enroll VSes (${b.enrolled_count})`}
                </button>
                <button className="btn btn-danger btn-sm" onClick={() => handleRemove(b.id)} disabled={removing}>
                  Remove
                </button>
              </div>
            </div>
            {b.last_error && <div className="banner banner-error mt-1 text-sm">{b.last_error}</div>}
            {expanded === b.id && (
              <div style={{ marginTop: 12, paddingLeft: 20 }}>
                <EnrollPanel device={b} onUpdated={handleEnrolled} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
