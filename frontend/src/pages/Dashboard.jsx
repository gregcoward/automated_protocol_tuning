import React, { useState, useEffect } from 'react';
import { api } from '../api/client.js';

const PANELS = [
  { title: 'Throughput In/Out', panelId: 1 },
  { title: 'Active Connections', panelId: 2 },
  { title: 'TCP Retransmission Rate', panelId: 3 },
  { title: 'TCP Zero-Window Events', panelId: 4 },
  { title: 'TCP RTT (ms)', panelId: 5 },
  { title: 'Buffer Exhaustion', panelId: 6 },
  { title: 'UDP Drop Rate', panelId: 7 },
  { title: 'HTTP Keep-Alive Reuse', panelId: 8 },
];

function GrafanaPanel({ baseUrl, dashboardUid, panelId, vars, timeRange, title }) {
  const params = new URLSearchParams({
    orgId: '1',
    panelId: String(panelId),
    theme: document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
    from: timeRange.from,
    to: timeRange.to,
    'var-bigip_host': vars.bigip_host || 'All',
    'var-virtual_server': vars.virtual_server || 'All',
  });

  const src = `${baseUrl}/d-solo/${dashboardUid}/bigip-protocol-performance-before-after-tuning?${params.toString()}`;

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>{title}</span>
      </div>
      <iframe
        src={src}
        className="grafana-embed"
        title={title}
        style={{ minHeight: 240 }}
        allowFullScreen
      />
    </div>
  );
}

export default function DashboardPage({ bigips, storage }) {
  const grafanaUrl = storage?.settings?.grafana_external_url || 'http://localhost:3000';
  const dashUid = 'bigip-protocol-tuning';

  const [vars, setVars] = useState({ bigip_host: '', virtual_server: '' });
  const [timeRange, setTimeRange] = useState({ from: 'now-24h', to: 'now' });
  const [grafanaOk, setGrafanaOk] = useState(null);

  useEffect(() => {
    // Probe Grafana availability
    fetch(`${grafanaUrl}/api/health`, { mode: 'no-cors' })
      .then(() => setGrafanaOk(true))
      .catch(() => setGrafanaOk(false));
  }, [grafanaUrl]);

  const TIME_RANGES = [
    { label: '1h', from: 'now-1h', to: 'now' },
    { label: '6h', from: 'now-6h', to: 'now' },
    { label: '24h', from: 'now-24h', to: 'now' },
    { label: '7d', from: 'now-7d', to: 'now' },
    { label: '30d', from: 'now-30d', to: 'now' },
  ];

  return (
    <div>
      <h1 className="section-title">Before/After Performance Dashboard</h1>

      <div className="card" style={{ padding: '12px 20px' }}>
        <div className="flex items-center gap-3" style={{ flexWrap: 'wrap' }}>
          <div className="field" style={{ marginBottom: 0, minWidth: 180 }}>
            <label>BIG-IP Host</label>
            <select value={vars.bigip_host}
              onChange={e => setVars(v => ({ ...v, bigip_host: e.target.value }))}>
              <option value="">All</option>
              {bigips.map(b => <option key={b.id} value={b.host}>{b.label || b.host}</option>)}
            </select>
          </div>
          <div className="field" style={{ marginBottom: 0, flex: 1, minWidth: 180 }}>
            <label>Virtual Server</label>
            <input value={vars.virtual_server}
              onChange={e => setVars(v => ({ ...v, virtual_server: e.target.value }))}
              placeholder="/Common/vip_app (blank = all)" style={{ fontFamily: 'monospace', fontSize: 12 }} />
          </div>
          <div style={{ marginBottom: 0 }}>
            <label style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', display: 'block', marginBottom: 4 }}>Time Range</label>
            <div className="flex gap-1">
              {TIME_RANGES.map(tr => (
                <button key={tr.label}
                  className={`btn btn-secondary btn-sm ${timeRange.from === tr.from ? 'btn-primary' : ''}`}
                  onClick={() => setTimeRange({ from: tr.from, to: tr.to })}>
                  {tr.label}
                </button>
              ))}
            </div>
          </div>
          <div style={{ marginBottom: 0 }}>
            <a href={`${grafanaUrl}/d/${dashUid}`} target="_blank" rel="noreferrer"
              className="btn btn-secondary btn-sm" style={{ marginTop: 20 }}>
              Open Full Dashboard ↗
            </a>
          </div>
        </div>
      </div>

      {grafanaOk === false && (
        <div className="banner banner-warn">
          Grafana is not reachable at <code>{grafanaUrl}</code>. Ensure the Grafana container is running.
          Panels will display once connected.
        </div>
      )}

      <div className="grafana-panel-row">
        {PANELS.map(p => (
          <GrafanaPanel
            key={p.panelId}
            baseUrl={grafanaUrl}
            dashboardUid={dashUid}
            panelId={p.panelId}
            vars={vars}
            timeRange={timeRange}
            title={p.title}
          />
        ))}
      </div>

      <div className="banner banner-info mt-2" style={{ fontSize: 12 }}>
        Vertical annotation markers in each panel indicate exact tuning events.
        Remediations emit Grafana annotations automatically via the API.
        {grafanaUrl.includes('localhost') && ' In production, set GRAFANA_EXTERNAL_URL to the public hostname.'}
      </div>
    </div>
  );
}
