const BASE = '/api';

async function request(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(`${BASE}${path}`, opts);
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const json = await res.json();
      detail = typeof json.detail === 'string' ? json.detail : JSON.stringify(json.detail) || detail;
    } catch {}
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  // BIG-IP sessions
  connect: (data) => request('POST', '/connect', data),
  listBigIps: () => request('GET', '/bigips'),
  removeSession: (id) => request('DELETE', `/session/${id}`),
  updateEnrollment: (id, paths) => request('PUT', `/session/${id}/enrollment`, { enrolled_virtual_servers: paths }),

  // Analysis & Reference Catalogs
  runAnalysis: (params) => request('POST', '/analyze/run', params),
  knowledgeBase: () => request('GET', '/knowledge-base'),
  profileSettings: (protocol) => request('GET', protocol ? `/profile-settings?protocol=${protocol}` : '/profile-settings'),

  // Remediation
  applyRemediation: (recommendations, note) => request('POST', '/remediate/apply', { recommendations, operator_note: note }),
  rollbackRemediation: (changeId) => request('POST', `/remediate/rollback/${changeId}`),
  remediationHistory: (limit = 100) => request('GET', `/remediate/history?limit=${limit}`),

  // Schedules
  createSchedule: (data) => request('POST', '/schedules', data),
  listSchedules: () => request('GET', '/schedules'),
  updateSchedule: (id, updates) => request('PATCH', `/schedules/${id}`, updates),
  deleteSchedule: (id) => request('DELETE', `/schedules/${id}`),
  scheduleAudit: () => request('GET', '/schedules/audit'),

  // Storage
  storageStatus: () => request('GET', '/storage/status'),
  updateStorageSettings: (settings) => request('PUT', '/storage/settings', settings),

  // Health
  health: () => request('GET', '/health'),
};
