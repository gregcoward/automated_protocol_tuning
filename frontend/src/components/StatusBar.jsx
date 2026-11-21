import React from 'react';

export default function StatusBar({ bigips, storage, theme, setTheme, onRefresh }) {
  const usedMb = storage?.used_mb ?? 0;
  const maxGb = storage?.max_gb ?? 10;
  const pct = storage?.utilization_pct ?? 0;
  const storageClass = pct >= 90 ? 'crit' : pct >= 70 ? 'warn' : '';
  const retention = storage?.settings?.retention_period ?? '30d';

  return (
    <div className="status-bar">
      <span className="status-bar__logo">⚡ BIG-IP Protocol Tuner</span>
      <div className="status-bar__sep" />
      <div className="status-bar__chips">
        {bigips.length === 0 && (
          <span style={{ color: '#64748b', fontSize: 12 }}>No devices connected</span>
        )}
        {bigips.map(b => (
          <span key={b.id} className={`connected-chip ${b.connected ? '' : 'disconnected'}`}>
            <span className="dot" />
            <span className="connected-chip__label">{b.label || b.host}</span>
            <span style={{ fontSize: 11, color: '#64748b' }}>
              {b.enrolled_count}VS
            </span>
          </span>
        ))}
      </div>
      <div className="status-bar__right">
        <span className={`storage-badge ${storageClass}`}>
          {usedMb.toFixed(0)} MB / {maxGb} GB — Ret: {retention}
          {storageClass && ` ⚠`}
        </span>
        <span className={`storage-badge ${storage?.vm_healthy ? '' : 'warn'}`}>
          VM {storage?.vm_healthy ? '●' : '○'}
        </span>
        <div className="theme-segment">
          <button className={theme === 'light' ? 'active' : ''} onClick={() => setTheme('light')}>☀</button>
          <button className={theme === 'dark' ? 'active' : ''} onClick={() => setTheme('dark')}>☾</button>
        </div>
        <button className="btn btn-icon btn-sm" onClick={onRefresh} title="Refresh all">↺</button>
      </div>
    </div>
  );
}
