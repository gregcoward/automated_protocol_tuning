import React, { useState, useEffect, useCallback } from 'react';
import StatusBar from './components/StatusBar.jsx';
import DevicesPage from './pages/Devices.jsx';
import AnalysisPage from './pages/Analysis.jsx';
import RemediationsPage from './pages/Remediations.jsx';
import SchedulesPage from './pages/Schedules.jsx';
import DashboardPage from './pages/Dashboard.jsx';
import SettingsPage from './pages/Settings.jsx';
import { api } from './api/client.js';

const NAV_ITEMS = [
  { id: 'devices', icon: '🔌', label: 'Devices' },
  { id: 'analysis', icon: '🔬', label: 'Analysis' },
  { id: 'remediations', icon: '🛠️', label: 'Remediations' },
  { id: 'schedules', icon: '📅', label: 'Schedules' },
  { id: 'dashboard', icon: '📊', label: 'Dashboard' },
  { id: 'settings', icon: '⚙️', label: 'Settings' },
];

export default function App() {
  const [page, setPage] = useState('devices');
  const [bigips, setBigIps] = useState([]);
  const [storage, setStorage] = useState(null);
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark');

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem('theme', theme);
  }, [theme]);

  const refreshBigIps = useCallback(async () => {
    try {
      const r = await api.listBigIps();
      setBigIps(r || []);
    } catch {}
  }, []);

  const refreshStorage = useCallback(async () => {
    try {
      const r = await api.storageStatus();
      setStorage(r);
    } catch {}
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.allSettled([refreshBigIps(), refreshStorage()]);
  }, [refreshBigIps, refreshStorage]);

  // Initial load + periodic refresh
  useEffect(() => {
    refreshAll();
    const interval = setInterval(refreshAll, 30_000);
    return () => clearInterval(interval);
  }, [refreshAll]);

  const renderPage = () => {
    switch (page) {
      case 'devices': return <DevicesPage bigips={bigips} onRefresh={refreshBigIps} />;
      case 'analysis': return <AnalysisPage bigips={bigips} />;
      case 'remediations': return <RemediationsPage />;
      case 'schedules': return <SchedulesPage bigips={bigips} />;
      case 'dashboard': return <DashboardPage bigips={bigips} storage={storage} />;
      case 'settings': return <SettingsPage onStorageUpdated={refreshStorage} />;
      default: return null;
    }
  };

  return (
    <>
      <StatusBar
        bigips={bigips}
        storage={storage}
        theme={theme}
        setTheme={setTheme}
        onRefresh={refreshAll}
      />
      <div className="app-layout">
        <nav className="sidebar">
          {NAV_ITEMS.map(item => (
            <div
              key={item.id}
              className={`nav-item ${page === item.id ? 'active' : ''}`}
              onClick={() => setPage(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </div>
          ))}
        </nav>
        <main className="main-content">
          {renderPage()}
        </main>
      </div>
    </>
  );
}
