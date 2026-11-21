import React, { useState, useEffect } from 'react';
import { api } from '../api/client.js';
import { useAsync } from '../hooks/useApi.js';

export default function SettingsPage({ onStorageUpdated }) {
  const [status, setStatus] = useState(null);
  const [form, setForm] = useState(null);
  const { run: fetchStatus, loading } = useAsync(() => api.storageStatus());
  const { run: saveSettings, loading: saving, error: saveError } = useAsync((s) => api.updateStorageSettings(s));

  const load = async () => {
    const r = await fetchStatus();
    if (r) {
      setStatus(r);
      setForm(r.settings);
    }
  };

  useEffect(() => { load(); }, []);

  const handleSave = async () => {
    const r = await saveSettings(form);
    if (r) { await load(); onStorageUpdated && onStorageUpdated(); }
  };

  const pct = status?.utilization_pct ?? 0;
  const barClass = pct >= 90 ? 'crit' : pct >= 70 ? 'warn' : '';

  return (
    <div>
      <h1 className="section-title">Storage & Telemetry Settings</h1>

      {status && (
        <div className="card">
          <p className="card__title" style={{ marginBottom: 12 }}>Storage Utilization</p>
          <div className="flex gap-4 items-center mb-2" style={{ flexWrap: 'wrap' }}>
            <div>
              <span style={{ fontSize: 24, fontWeight: 700 }}>{status.used_mb.toFixed(0)} MB</span>
              <span className="text-muted text-sm"> / {status.max_gb} GB configured</span>
            </div>
            <div style={{ flex: 1, minWidth: 200 }}>
              <div className="progress-bar">
                <div className={`progress-bar__fill ${barClass}`} style={{ width: `${Math.min(pct, 100)}%` }} />
              </div>
              <div className="text-sm text-muted mt-1">{pct.toFixed(1)}% used</div>
            </div>
          </div>
          <div className="flex gap-3" style={{ flexWrap: 'wrap' }}>
            <span className={`storage-badge ${status.vm_healthy ? '' : 'warn'}`}>
              VictoriaMetrics {status.vm_healthy ? '● Healthy' : '○ Unreachable'}
            </span>
            <span className={`storage-badge ${status.otel_healthy ? '' : 'warn'}`}>
              OTLP Collector {status.otel_healthy ? '● Healthy' : '○ Unreachable'}
            </span>
            {status.active_series > 0 && (
              <span className="storage-badge">{status.active_series.toLocaleString()} active metric series</span>
            )}
            {status.last_enforced_at && (
              <span className="storage-badge">Last enforced: {new Date(status.last_enforced_at).toLocaleString()}</span>
            )}
          </div>
          {status.enforcement_actions?.length > 0 && (
            <details className="mt-2">
              <summary className="text-sm text-muted" style={{ cursor: 'pointer' }}>
                Enforcement log ({status.enforcement_actions.length} entries)
              </summary>
              <div style={{ fontFamily: 'monospace', fontSize: 11, marginTop: 6 }}>
                {status.enforcement_actions.map((a, i) => <div key={i}>{a}</div>)}
              </div>
            </details>
          )}
        </div>
      )}

      {form && (
        <div className="card">
          <p className="card__title" style={{ marginBottom: 16 }}>Configuration</p>
          {saveError && <div className="banner banner-error mb-2">{saveError}</div>}
          <div className="form-row">
            <div className="field">
              <label>Retention Period</label>
              <input value={form.retention_period}
                onChange={e => setForm(f => ({ ...f, retention_period: e.target.value }))}
                placeholder="30d" style={{ fontFamily: 'monospace' }} />
              <span className="text-muted text-sm">e.g. 7d, 2w, 1m, 1y</span>
            </div>
            <div className="field">
              <label>Max Storage Capacity (GB)</label>
              <input type="number" min={0.25} step={0.5} value={form.max_storage_gb}
                onChange={e => setForm(f => ({ ...f, max_storage_gb: +e.target.value }))} />
            </div>
            <div className="field">
              <label>Telemetry Poll Interval (seconds)</label>
              <input type="number" min={5} max={3600} value={form.poll_interval_seconds}
                onChange={e => setForm(f => ({ ...f, poll_interval_seconds: +e.target.value }))} />
            </div>
            <div className="field">
              <label>Dedup Min Scrape Interval</label>
              <input value={form.dedup_min_scrape_interval}
                onChange={e => setForm(f => ({ ...f, dedup_min_scrape_interval: e.target.value }))}
                placeholder="15s" style={{ fontFamily: 'monospace' }} />
              <span className="text-muted text-sm">e.g. 15s, 1m</span>
            </div>
          </div>
          <div className="form-row mt-2">
            <div className="field" style={{ flex: 2 }}>
              <label>OTLP Endpoint</label>
              <input value={form.otel_endpoint}
                onChange={e => setForm(f => ({ ...f, otel_endpoint: e.target.value }))}
                style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </div>
            <div className="field" style={{ flex: 2 }}>
              <label>Grafana External URL</label>
              <input value={form.grafana_external_url}
                onChange={e => setForm(f => ({ ...f, grafana_external_url: e.target.value }))}
                style={{ fontFamily: 'monospace', fontSize: 12 }} />
            </div>
            <div className="field" style={{ justifyContent: 'flex-end' }}>
              <label className="checkbox-row" style={{ marginTop: 'auto' }}>
                <input type="checkbox" checked={form.auto_prune_enabled}
                  onChange={e => setForm(f => ({ ...f, auto_prune_enabled: e.target.checked }))} />
                <span>Auto-prune when over capacity</span>
              </label>
            </div>
          </div>
          <div className="mt-2 flex gap-2">
            <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
              {saving ? 'Saving…' : 'Save Settings'}
            </button>
            <button className="btn btn-secondary" onClick={load} disabled={loading}>
              Reset
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <p className="card__title" style={{ marginBottom: 8 }}>Architecture Overview</p>
        <div style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.8 }}>
          <div>BIG-IP(s) ──▶ FastAPI Backend ──▶ OTLP Collector ──▶ VictoriaMetrics (MetricsQL)</div>
          <div style={{ paddingLeft: 32 }}>↑ iControl REST polls (every {form?.poll_interval_seconds}s)</div>
          <div>VictoriaMetrics ◀── Protocol Analyzer ◀── On-Demand Analysis / Scheduler</div>
          <div>Grafana ◀── VictoriaMetrics · Embeds in React UI via /d-solo panels</div>
        </div>
      </div>
    </div>
  );
}
