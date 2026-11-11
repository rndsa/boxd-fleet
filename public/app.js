// Boxd Fleet Manager - Ultra Clean Console Controller

// State
let appState = {
  authenticated: false,
  accounts: [],
  machines: [],
  machinesLoaded: false,
  telemetry: null,
  currentTab: 'overview',
  selectedAccountId: 'all',
  execTarget: null,
  sshPassTarget: null,
  sshPassStatus: null,
  sshSavedRevealed: false,
  manageTarget: null,
  manageState: null,
  manageActiveTab: 'update',
  manageJobPoller: null,
  liveSyncEnabled: localStorage.getItem('boxd_live_sync') !== '0',
  liveSyncTimer: null,
  statusFilter: 'all',
  searchQuery: ''
};

// Init
document.addEventListener('DOMContentLoaded', () => {
  initNeoTheme();
  updateLiveSyncBtnUI();
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && appState.authenticated && appState.liveSyncEnabled) {
      fetchDashboardData({ silent: true });
    }
  });
  checkAuth();
});

// ================= FETCH HELPER WITH AUTH GUARD =================

async function apiFetch(url, options = {}) {
  const res = await fetch(url, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...options
  });
  if (res.status === 403) {
    try {
      const errData = await res.clone().json();
      if (errData && errData.code === 'IP_NOT_ALLOWED') {
        window.location.reload();
        return res;
      }
    } catch (e) {}
  }
  if (res.status === 401 && appState.authenticated) {
    showPinGate();
    showToast('Sesi berakhir, silakan masukkan PIN akses lagi.', 'error');
  }
  return res;
}

// ================= THEME MANAGEMENT =================

function initNeoTheme() {
  const savedTheme = localStorage.getItem('boxd_neo_theme') || 'light';
  applyNeoTheme(savedTheme);
}

function applyNeoTheme(theme) {
  const isDark = theme === 'dark';
  document.body.classList.toggle('dark-theme', isDark);
  localStorage.setItem('boxd_neo_theme', theme);
  const icon = document.getElementById('themeToggleIcon');
  const label = document.getElementById('themeToggleLabel');
  if (icon && label) {
    icon.innerHTML = isDark
      ? '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>'
      : '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>';
    label.textContent = isDark ? 'Dark' : 'Light';
  }
}

function toggleNeoTheme() {
  const currentTheme = localStorage.getItem('boxd_neo_theme') || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  applyNeoTheme(newTheme);
}

// ================= AUTHENTICATION =================

async function checkAuth(retry = true) {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const keyParam = urlParams.get('key');
    let endpoint = '/api/auth/status';
    if (keyParam) {
      endpoint += `?key=${encodeURIComponent(keyParam)}`;
    }

    const res = await fetch(endpoint, {
      credentials: 'same-origin',
      cache: 'no-store'
    });
    if (res.status === 403) {
      try {
        const blockData = await res.json();
        if (blockData && blockData.code === 'IP_NOT_ALLOWED') {
          window.location.reload();
          return;
        }
      } catch (e) {}
    }
    if (!res.ok && res.status >= 500 && retry) {
      await new Promise(r => setTimeout(r, 450));
      return checkAuth(false);
    }

    const data = await res.json();
    if (res.ok && data.authenticated) {
      if (keyParam) {
        window.history.replaceState({}, document.title, window.location.pathname);
      }
      showDashboard();
      return;
    }
  } catch (err) {
    if (retry) {
      await new Promise(r => setTimeout(r, 450));
      return checkAuth(false);
    }
    console.error('Auth check error:', err);
  }
  showPinGate();
}

function showDashboard() {
  appState.authenticated = true;
  const gate = document.getElementById('securityGate');
  const app = document.getElementById('appContainer');
  if (gate) gate.classList.add('hidden');
  if (app) app.classList.remove('hidden');
  fetchDashboardData();
  scheduleLiveAutoRefresh();
}

function showPinGate() {
  appState.authenticated = false;
  stopLiveAutoRefresh();
  const gate = document.getElementById('securityGate');
  const app = document.getElementById('appContainer');
  if (gate) gate.classList.remove('hidden');
  if (app) app.classList.add('hidden');
  const input = document.getElementById('pinInput');
  const toggleBtn = document.getElementById('pinToggleBtn');
  if (input) {
    input.type = 'password';
    input.value = '';
    setTimeout(() => input.focus(), 100);
  }
  if (toggleBtn) toggleBtn.textContent = 'Lihat';
}

function togglePinInputVisibility() {
  const input = document.getElementById('pinInput');
  const btn = document.getElementById('pinToggleBtn');
  if (!input || !btn) return;
  const reveal = input.type === 'password';
  input.type = reveal ? 'text' : 'password';
  btn.textContent = reveal ? 'Sembunyi' : 'Lihat';
}

async function handleLogin(e) {
  e.preventDefault();
  const input = document.getElementById('pinInput');
  const submitBtn = document.getElementById('pinSubmitBtn');
  const errorEl = document.getElementById('pinError');
  const pin = input ? input.value.trim() : '';
  if (!pin) return;

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span>Memverifikasi...</span>';
  }
  if (errorEl) errorEl.classList.add('hidden');

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin })
    });
    if (res.status === 403) {
      window.location.reload();
      return;
    }
    const data = await res.json();

    if (res.ok && data.success) {
      showDashboard();
    } else {
      if (errorEl) {
        errorEl.textContent = data.error || 'PIN Akses tidak valid';
        errorEl.classList.remove('hidden');
      }
      const card = document.querySelector('.security-gate-card');
      if (card) {
        card.classList.add('shake-anim');
        setTimeout(() => card.classList.remove('shake-anim'), 450);
      }
      if (input) input.select();
    }
  } catch (err) {
    if (errorEl) {
      errorEl.textContent = 'Gagal menghubungi server';
      errorEl.classList.remove('hidden');
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = '<span>Buka Konsol →</span>';
    }
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
  } catch (e) {}
  closeSecurityCenterModal();
  showPinGate();
  showToast('Konsol berhasil dikunci (Logged out).', 'info');
}

// ================= SECURITY & AUDIT TRAIL =================

function openSecurityCenterModal() {
  const modal = document.getElementById('securityCenterModal');
  if (modal) modal.classList.remove('hidden');
  fetchAuditLogs();
  fetchIpWhitelist();
}

function closeSecurityCenterModal() {
  const modal = document.getElementById('securityCenterModal');
  if (modal) modal.classList.add('hidden');
}

let ipWhitelistState = {
  enabled: false,
  currentIp: '-',
  allowedIps: []
};

async function fetchIpWhitelist() {
  try {
    const res = await apiFetch('/api/security/ip-whitelist');
    const data = await res.json();
    if (res.ok && data.success) {
      ipWhitelistState = data;
      renderIpWhitelist();
    }
  } catch (err) {
    console.error('Failed to fetch IP whitelist:', err);
  }
}

function renderIpWhitelist() {
  const badge = document.getElementById('ipWhitelistStatusBadge');
  const toggleBtn = document.getElementById('ipWhitelistToggleBtn');
  const detectedIpEl = document.getElementById('currentDetectedIp');
  const allowBtn = document.getElementById('allowCurrentIpBtn');
  const tbody = document.getElementById('allowedIpsTableBody');

  if (detectedIpEl) {
    detectedIpEl.textContent = ipWhitelistState.currentIp || '-';
  }

  const allowedList = Array.isArray(ipWhitelistState.allowedIps) ? ipWhitelistState.allowedIps : [];
  const currentAlreadyAllowed = allowedList.some(
    item => Boolean(item.matchesCurrent) || item.ip === ipWhitelistState.currentIp
  );

  if (allowBtn) {
    if (currentAlreadyAllowed) {
      allowBtn.textContent = '✓ Sudah Diizinkan';
      allowBtn.className = 'stat-subpill badge-green-soft font-mono';
      allowBtn.disabled = true;
    } else {
      allowBtn.textContent = '+ Izinkan IP Ini';
      allowBtn.className = 'btn-stark-cta btn-sm-cta';
      allowBtn.disabled = false;
    }
  }

  if (badge) {
    badge.textContent = ipWhitelistState.enabled ? 'AKTIF' : 'NONAKTIF';
    badge.className = `stat-subpill font-mono ${ipWhitelistState.enabled ? 'badge-green-soft' : ''}`;
  }

  if (toggleBtn) {
    toggleBtn.textContent = ipWhitelistState.enabled ? 'Matikan' : 'Aktifkan';
    toggleBtn.className = `action-btn ${ipWhitelistState.enabled ? 'danger' : 'primary'}`;
  }

  if (tbody) {
    if (allowedList.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 10px; color: var(--text-muted);">Belum ada IP terdaftar.</td></tr>';
      return;
    }

    tbody.innerHTML = allowedList.map(item => {
      const isCurrent = Boolean(item.matchesCurrent) || item.ip === ipWhitelistState.currentIp;
      return `
        <tr>
          <td style="font-weight: 700; color: var(--text-primary); font-size: 11px;">
            ${escapeHTML(item.ip)}
            ${isCurrent ? '<span class="stat-subpill badge-green-soft" style="font-size: 9.5px; margin-left: 5px;">INI</span>' : ''}
          </td>
          <td style="color: var(--text-secondary); font-size: 11px;">${escapeHTML(item.label || '-')}</td>
          <td style="text-align: right;">
            <button class="ep-btn danger" onclick="handleDeleteAllowedIp(${Number(item.id)}, '${escapeAttr(item.ip)}', ${isCurrent ? 'true' : 'false'})">Hapus</button>
          </td>
        </tr>
      `;
    }).join('');
  }
}

async function toggleIpWhitelist() {
  const newStatus = !ipWhitelistState.enabled;
  try {
    const res = await apiFetch('/api/security/ip-whitelist/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: newStatus })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(newStatus ? 'Filter IP aktif — hanya IP terdaftar yang bisa akses web.' : 'Filter IP dimatikan — semua IP bisa buka halaman login.', 'info');
      fetchIpWhitelist();
    } else {
      showToast('Gagal mengubah status: ' + (data.error || 'Server error'), 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function allowMyCurrentIp() {
  try {
    const res = await apiFetch('/api/security/ip-whitelist/allow-my-ip', { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`IP Anda (${data.currentIp}) berhasil didaftarkan!`, 'success');
      fetchIpWhitelist();
    } else {
      showToast('Gagal menambahkan IP: ' + (data.error || 'Server error'), 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleAddAllowedIp(e) {
  e.preventDefault();
  const inputIp = document.getElementById('newAllowedIpInput');
  const inputLabel = document.getElementById('newAllowedIpLabel');
  if (!inputIp || !inputIp.value.trim()) return;

  const ip = inputIp.value.trim();
  const label = inputLabel ? inputLabel.value.trim() : '';

  try {
    const res = await apiFetch('/api/security/ip-whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, label })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`IP ${ip} berhasil ditambahkan ke whitelist!`, 'success');
      inputIp.value = '';
      if (inputLabel) inputLabel.value = '';
      fetchIpWhitelist();
    } else {
      showToast('Gagal: ' + (data.error || 'Server error'), 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleDeleteAllowedIp(id, ip, isCurrent = false) {
  const msg = isCurrent && ipWhitelistState.enabled
    ? `PERINGATAN: "${ip}" adalah IP yang sedang kamu pakai dan Filter IP sedang AKTIF. Menghapusnya akan langsung memblokir akses kamu ke konsol. Yakin lanjut?`
    : `Hapus IP "${ip}" dari daftar izin?`;
  if (!confirm(msg)) return;

  try {
    const res = await apiFetch(`/api/security/ip-whitelist/${encodeURIComponent(id)}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`IP ${ip} dihapus dari whitelist`, 'info');
      fetchIpWhitelist();
    } else {
      showToast('Gagal menghapus: ' + (data.error || 'Server error'), 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function fetchAuditLogs() {
  const tbody = document.getElementById('auditTableBody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 16px;">Mengambil log audit...</td></tr>';

  try {
    const res = await apiFetch('/api/audit-logs?limit=15');
    const data = await res.json();
    if (res.ok && data.logs && data.logs.length > 0) {
      tbody.innerHTML = data.logs.map(log => {
        const d = new Date(log.timestamp);
        const timeStr = d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = d.toLocaleDateString('id-ID', { day: '2-digit', month: '2-digit' });
        const isFail = log.action.includes('FAIL') || log.action.includes('LOCK') || log.action.includes('BLOCKED');
        const badgeClass = isFail ? 'badge-rose' : 'badge-green';
        const statusText = isFail ? 'BLOCKED' : 'SUCCESS';

        const rawIp = String(log.ip || '-');
        const cleanIp = rawIp.includes(',') ? rawIp.split(',').pop().trim() : rawIp;

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 10px;">${dateStr} ${timeStr}</td>
            <td style="font-weight: 700; color: var(--text-primary); font-size: 10.5px; overflow: hidden; text-overflow: ellipsis;">${escapeHTML(log.action)}</td>
            <td style="color: var(--text-secondary); font-size: 10px; overflow: hidden; text-overflow: ellipsis;" title="${escapeAttr(cleanIp)}">${escapeHTML(cleanIp)}</td>
            <td style="text-align: right;"><span class="stat-subpill ${isFail ? 'badge-rose-soft' : 'badge-green-soft'}" style="font-size: 8.5px;">${statusText}</span></td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 16px; color: var(--text-muted);">Belum ada log audit tercatat.</td></tr>';
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 16px; color: #F43F5E;">Gagal memuat log: ${escapeHTML(err.message)}</td></tr>`;
  }
}

// ================= TWO-STEP DESTRUCTIVE ACTION SAFETY =================

let pendingDelete = null;

function confirmDeleteMachine(accountId, machineId, name, region) {
  pendingDelete = { accountId, machineId, name, region };
  const modal = document.getElementById('deleteMachineSafetyModal');
  const nameEl = document.getElementById('safetyDelVmName');
  const promptEl = document.getElementById('safetyDelPromptName');
  const inputEl = document.getElementById('safetyDelInput');
  const btn = document.getElementById('safetyDelConfirmBtn');

  if (nameEl) nameEl.textContent = name;
  if (promptEl) promptEl.textContent = name;
  if (inputEl) {
    inputEl.value = '';
    setTimeout(() => inputEl.focus(), 150);
  }
  if (btn) {
    btn.style.opacity = '0.4';
    btn.style.pointerEvents = 'none';
  }
  if (modal) modal.classList.remove('hidden');
}

function closeDeleteSafetyModal() {
  const modal = document.getElementById('deleteMachineSafetyModal');
  if (modal) modal.classList.add('hidden');
  pendingDelete = null;
}

function checkSafetyDeleteMatch() {
  const inputEl = document.getElementById('safetyDelInput');
  const btn = document.getElementById('safetyDelConfirmBtn');
  if (!pendingDelete || !inputEl || !btn) return;

  const isMatch = inputEl.value.trim().toLowerCase() === pendingDelete.name.toLowerCase();
  if (isMatch) {
    btn.style.opacity = '1';
    btn.style.pointerEvents = 'auto';
  } else {
    btn.style.opacity = '0.4';
    btn.style.pointerEvents = 'none';
  }
}

async function executeSafetyDelete() {
  if (!pendingDelete) return;
  const { accountId, machineId, name, region } = pendingDelete;
  closeDeleteSafetyModal();

  showToast(`Menghapus instance ${name}...`, 'info');

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`Mesin ${name} berhasil dihapus permanen`, 'info');
      await fetchDashboardData();
    } else {
      showToast(`Gagal menghapus: ${data.error || 'Server error'}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

// ================= TAB NAVIGATION =================

function switchTab(tabId) {
  appState.currentTab = tabId;

  const tabs = ['overview', 'machines', 'panduan', 'accounts', 'telemetry', 'api'];
  tabs.forEach(t => {
    const btn = document.getElementById(`tabBtn-${t}`);
    const content = document.getElementById(`tabContent-${t}`);

    if (btn) btn.classList.toggle('active', t === tabId);
    if (content) content.classList.toggle('active', t === tabId);
  });

  if (tabId === 'telemetry' || tabId === 'accounts' || tabId === 'overview') {
    fetchTelemetryData();
  }
  if (tabId === 'api') {
    loadApiWorkspace();
  }
}

// ================= DATA FETCHING & RECONCILIATION =================

function updateLiveSyncBtnUI() {
  const btn = document.getElementById('liveSyncToggleBtn');
  const lbl = document.getElementById('liveSyncLabel');
  if (btn) btn.classList.toggle('is-live', !!appState.liveSyncEnabled);
  if (lbl) lbl.textContent = appState.liveSyncEnabled ? 'Live' : 'Paused';
}

function toggleLiveAutoRefresh() {
  appState.liveSyncEnabled = !appState.liveSyncEnabled;
  localStorage.setItem('boxd_live_sync', appState.liveSyncEnabled ? '1' : '0');
  updateLiveSyncBtnUI();
  if (appState.liveSyncEnabled) {
    fetchDashboardData({ silent: true });
    scheduleLiveAutoRefresh();
    showToast('Auto-refresh live diaktifkan', 'info');
  } else {
    stopLiveAutoRefresh();
    showToast('Auto-refresh dijeda', 'info');
  }
}

function stopLiveAutoRefresh() {
  if (appState.liveSyncTimer) {
    clearTimeout(appState.liveSyncTimer);
    appState.liveSyncTimer = null;
  }
}

function scheduleLiveAutoRefresh() {
  stopLiveAutoRefresh();
  if (!appState.authenticated || !appState.liveSyncEnabled) return;
  const hasTransitioning = (appState.machines || []).some(m =>
    ['pending', 'starting', 'stopping', 'migrating', 'resuming', 'waking'].includes(String(m.status || '').toLowerCase())
  );
  const delayMs = hasTransitioning ? 5000 : 15000;
  appState.liveSyncTimer = setTimeout(async () => {
    if (!document.hidden && appState.authenticated && appState.liveSyncEnabled) {
      await fetchDashboardData({ silent: true });
    }
    scheduleLiveAutoRefresh();
  }, delayMs);
}

async function fetchDashboardData(options = {}) {
  const silent = !!(options && options.silent);
  const syncBtn = document.getElementById('syncTelemetryBtn');
  if (syncBtn && !silent) syncBtn.classList.add('is-spinning');

  try {
    await Promise.allSettled([
      fetchAccounts({ silent }),
      fetchMachines({ silent }),
      fetchTelemetryData()
    ]);
    renderOverviewWidgets();
  } finally {
    if (syncBtn && !silent) {
      setTimeout(() => syncBtn.classList.remove('is-spinning'), 500);
    }
  }
}

async function fetchAccounts(options = {}) {
  const silent = !!(options && options.silent);
  try {
    const res = await apiFetch('/api/accounts');
    const data = await res.json();
    if (data.success) {
      appState.accounts = data.accounts || [];
      renderAccountSelectors();
      updateAccountStats();
      renderOverviewWidgets();
    }
  } catch (err) {
    if (!silent) showToast('Gagal memuat akun: ' + err.message, 'error');
  }
}

async function fetchMachines(options = {}) {
  const silent = !!(options && options.silent);
  const grid = document.getElementById('machinesGrid');
  const emptyState = document.getElementById('emptyMachinesState');

  if (emptyState && !silent) emptyState.classList.add('hidden');
  if (grid && !silent && !appState.machinesLoaded) {
    grid.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 24px; text-align: center; color: var(--text-dim); font-family: var(--font-mono); font-size: 12px;">
        Memuat daftar microVM...
      </div>
    `;
  }

  try {
    const url = `/api/machines?accountId=${encodeURIComponent(appState.selectedAccountId)}`;
    const res = await apiFetch(url);
    const data = await res.json();

    appState.machinesLoaded = true;
    if (data.success) {
      appState.machines = (data.machines || []).filter(m => m.accessible !== false);
      renderMachines();
      updateMachineStats();
    } else {
      if (grid && !silent) grid.innerHTML = '';
      if (!silent) showToast('Gagal memuat mesin: ' + data.error, 'error');
    }
  } catch (err) {
    appState.machinesLoaded = true;
    if (grid && !silent) grid.innerHTML = '';
    if (!silent) showToast('Gagal memuat mesin: ' + err.message, 'error');
  }
}

/**
 * Sync in-memory appState.accounts from live telemetry response
 * so Overview, Accounts Hub, and Selectors always reflect fresh balances/scopes/quotas.
 */
function syncAccountsStateFromTelemetry(telemetryData) {
  if (!telemetryData || !Array.isArray(telemetryData.accounts)) return;
  const byId = new Map();
  for (const item of telemetryData.accounts) {
    if (item.account && item.account.id) {
      byId.set(item.account.id, item);
    }
  }
  appState.accounts = appState.accounts.map(acc => {
    const live = byId.get(acc.id);
    if (!live) return acc;
    return {
      ...acc,
      user_id: live.account.userId || acc.user_id,
      display_name: live.account.displayName || acc.display_name,
      org_id: (live.org && live.org.id) || acc.org_id,
      org_name: (live.org && live.org.name) || acc.org_name,
      org_slug: (live.org && live.org.slug) || acc.org_slug,
      key_scope: live.account.keyScope || acc.key_scope,
      home_region: live.account.homeRegion || acc.home_region,
      enabled_regions: live.account.enabledRegions || acc.enabled_regions,
      balance_micro: live.billing && live.billing.balanceMicro !== undefined ? live.billing.balanceMicro : acc.balance_micro,
      currency: (live.billing && live.billing.currency) || acc.currency,
      max_vms: live.account.maxVms || acc.max_vms,
      status: live.account.status || acc.status,
      last_error: live.error || null
    };
  });
}

async function fetchTelemetryData() {
  try {
    const res = await apiFetch('/api/accounts/telemetry');
    const data = await res.json();
    if (data.success) {
      appState.telemetry = data;
      syncAccountsStateFromTelemetry(data);
      updateAccountStats();
      renderAccountSelectors();
      renderAccountsHub();
      renderTelemetryView();
      renderOverviewWidgets();
    }
  } catch (err) {
    console.error('Telemetry fetch error:', err.message);
  }
}

// ================= STATS & COUNTERS =================

function updateAccountStats() {
  const total = appState.accounts.length;
  const badgeAccounts = document.getElementById('tabBadgeAccounts');
  if (badgeAccounts) badgeAccounts.textContent = total;

  const countPill = document.getElementById('accountsCountPill');
  if (countPill) countPill.textContent = `${total} akun`;
}

function updateMachineStats() {
  const total = appState.machines.length;
  const badgeMachines = document.getElementById('tabBadgeMachines');
  if (badgeMachines) badgeMachines.textContent = total;

  renderOverviewWidgets();
}

function onGlobalSearch() {
  const input = document.getElementById('searchInput');
  if (!input) return;
  appState.searchQuery = input.value.toLowerCase().trim();
  renderOverviewWidgets();
  renderMachines();
  renderAccountsHub();
}

function getFilteredMachinesList(applyStatusFilter = true) {
  let list = (appState.machines || []).filter(m => m.accessible !== false);

  if (applyStatusFilter && appState.statusFilter !== 'all') {
    list = list.filter(m => {
      if (appState.statusFilter === 'running') return m.status === 'running';
      if (appState.statusFilter === 'hibernated') return m.status === 'hibernated';
      if (appState.statusFilter === 'suspended') return ['suspended', 'paused'].includes(m.status);
      if (appState.statusFilter === 'stopped') return ['stopped', 'failed'].includes(m.status);
      return true;
    });
  }

  if (appState.searchQuery) {
    list = list.filter(m =>
      (m.name && m.name.toLowerCase().includes(appState.searchQuery)) ||
      (m.id && m.id.toLowerCase().includes(appState.searchQuery)) ||
      (m.region && m.region.toLowerCase().includes(appState.searchQuery)) ||
      (m.accountLabel && m.accountLabel.toLowerCase().includes(appState.searchQuery)) ||
      (m.status && m.status.toLowerCase().includes(appState.searchQuery))
    );
  }

  return list;
}

function openMachinesWithFilter(statusVal = 'all') {
  const filterEl = document.getElementById('statusFilter');
  const nextFilter = statusVal || 'all';
  if (filterEl) filterEl.value = nextFilter;
  appState.statusFilter = nextFilter;
  switchTab('machines');
  renderMachines();
}

function toggleOverviewAccountFilter(accountId) {
  const nextId = appState.selectedAccountId === accountId ? 'all' : accountId;
  const filterSelect = document.getElementById('accountFilter');
  if (filterSelect) filterSelect.value = nextId;
  appState.selectedAccountId = nextId;
  fetchMachines();
  renderOverviewWidgets();
  renderTelemetryView();
}

function renderOverviewWidgets() {
  const machines = (appState.machines || []).filter(m => m.accessible !== false);
  const accounts = appState.accounts || [];
  const telemetry = appState.telemetry || {};
  const telemetryAccounts = telemetry.accounts || [];
  const selectedAccId = appState.selectedAccountId;

  // Scope accounts & telemetry to current ACC filter
  const scopedAccounts = selectedAccId === 'all'
    ? accounts
    : accounts.filter(a => a.id === selectedAccId);

  const scopedTelemetry = selectedAccId === 'all'
    ? telemetryAccounts
    : telemetryAccounts.filter(t => t.account && t.account.id === selectedAccId);

  // 1. Machine & Resource metrics (controllable VMs only)
  const totalVms = machines.length;

  let totalAllocatedVcpu = 0;
  let totalAllocatedRamBytes = 0;
  let runningCount = 0;
  let standbyCount = 0;
  let hibernatedCount = 0;
  let stoppedCount = 0;
  let alwaysOnCount = 0;
  let sshPassCount = 0;
  let nonStoppedCount = 0;
  let autoUpdReadyCount = 0;
  const regionCounts = new Map();

  machines.forEach(m => {
    totalAllocatedVcpu += (m.resources && m.resources.vcpu) || 0;
    totalAllocatedRamBytes += (m.resources && m.resources.memoryBytes) || 0;

    if (m.status === 'running') runningCount++;
    else if (['suspended', 'paused'].includes(m.status)) standbyCount++;
    else if (m.status === 'hibernated') hibernatedCount++;
    else stoppedCount++;

    if (m.status !== 'stopped' && m.status !== 'failed') {
      nonStoppedCount++;
      if (m.vmConfig && m.vmConfig.autoUpdateEnabled) autoUpdReadyCount++;
    }
    if (m.alwaysOn) alwaysOnCount++;
    if (m.sshAccess && m.sshAccess.enabled) sshPassCount++;

    const reg = String(m.region || 'fra').toUpperCase();
    regionCounts.set(reg, (regionCounts.get(reg) || 0) + 1);
  });
  const totalRamGb = Math.round(totalAllocatedRamBytes / (1024 * 1024 * 1024));

  // 2. Balance, Quota Cap & Total Spend synced across scoped accounts
  let totalBalance = 0;
  let totalExpenditure = 0;
  let quotaCap = 0;

  if (scopedTelemetry.length > 0) {
    scopedTelemetry.forEach(t => {
      if (t.billing && typeof t.billing.balance === 'number') totalBalance += t.billing.balance;
      if (t.usage && typeof t.usage.totalCost === 'number') totalExpenditure += t.usage.totalCost;
      if (!t.error && t.account && typeof t.account.maxVms === 'number') quotaCap += t.account.maxVms;
    });
  } else {
    scopedAccounts.forEach(a => {
      if (a.balance_micro) totalBalance += a.balance_micro / 1e6;
      if (a.status === 'active') quotaCap += (a.max_vms || 100);
    });
  }
  if (quotaCap === 0 && scopedAccounts.length > 0) {
    quotaCap = scopedAccounts.reduce((acc, a) => acc + (a.max_vms || 100), 0);
  }

  // 3. Regions strip
  const regionSet = new Set();
  machines.forEach(m => { if (m.region) regionSet.add(m.region.toUpperCase()); });
  scopedAccounts.forEach(a => {
    if (a.home_region) regionSet.add(String(a.home_region).toUpperCase());
  });
  const elRegions = document.getElementById('overviewRegionsLabel');
  if (elRegions) {
    elRegions.textContent = regionSet.size > 0 ? Array.from(regionSet).sort().join(' · ') : 'FRA · NYC';
  }

  const elSyncMeta = document.getElementById('overviewSyncMeta');
  if (elSyncMeta) {
    elSyncMeta.textContent = appState.machinesLoaded
      ? `${totalVms} VM · ${scopedAccounts.length} Akun`
      : `${scopedAccounts.length} Akun`;
  }

  // Update KPI Cards
  const elQuota = document.getElementById('overviewStatQuota');
  if (elQuota) elQuota.textContent = appState.machinesLoaded ? `${totalVms} / ${quotaCap}` : `${quotaCap} VM`;

  const elQuotaBadge = document.getElementById('overviewStatQuotaBadge');
  if (elQuotaBadge) elQuotaBadge.textContent = appState.machinesLoaded ? 'VM terkelola' : 'Memuat…';

  const elVcpu = document.getElementById('overviewStatVcpu');
  if (elVcpu) elVcpu.textContent = appState.machinesLoaded ? `${totalAllocatedVcpu} vCPU` : '—';

  const elRamBadge = document.getElementById('overviewStatRamBadge');
  if (elRamBadge) elRamBadge.textContent = appState.machinesLoaded ? `${totalRamGb} GB RAM` : '—';

  const elBalance = document.getElementById('statBalance');
  if (elBalance) elBalance.textContent = `$${totalBalance.toFixed(2)}`;

  const elAccBadge = document.getElementById('overviewStatAccBadge');
  if (elAccBadge) elAccBadge.textContent = `${scopedAccounts.length} akun`;

  const elSpend = document.getElementById('overviewStatSpend');
  if (elSpend) {
    elSpend.textContent = totalExpenditure > 0 && totalExpenditure < 0.01
      ? `$${totalExpenditure.toFixed(4)}`
      : `$${totalExpenditure.toFixed(2)}`;
  }

  // 4. Overview Fleet Status Summary (No individual instance list)
  const fleetBody = document.getElementById('overviewFleetStatusBody');
  if (fleetBody) {
    if (!appState.machinesLoaded && machines.length === 0) {
      fleetBody.innerHTML = `<div style="padding: 18px; text-align: center; color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">Memuat ringkasan fleet…</div>`;
    } else {
      const regionBreakdown = regionCounts.size > 0
        ? Array.from(regionCounts.entries()).sort((a, b) => a[0].localeCompare(b[0])).map(([r, c]) => `${escapeHTML(r)} (${c})`).join(' · ')
        : '—';

      let autoUpdPill = `<span class="status-pill status-neutral font-mono">—</span>`;
      if (nonStoppedCount > 0) {
        const cls = autoUpdReadyCount === nonStoppedCount ? 'status-green' : 'status-amber';
        autoUpdPill = `<span class="status-pill ${cls} font-mono">${autoUpdReadyCount} / ${nonStoppedCount} VM siap</span>`;
      }

      fleetBody.innerHTML = `
        <div class="ov-status-grid">
          <button type="button" class="ov-status-tile is-green ${runningCount > 0 ? 'is-nonzero' : ''}" onclick="openMachinesWithFilter('running')">
            <span class="ov-status-label">Running</span>
            <span class="ov-status-count font-mono">${runningCount}</span>
          </button>
          <button type="button" class="ov-status-tile is-amber ${standbyCount > 0 ? 'is-nonzero' : ''}" onclick="openMachinesWithFilter('suspended')">
            <span class="ov-status-label">Standby</span>
            <span class="ov-status-count font-mono">${standbyCount}</span>
          </button>
          <button type="button" class="ov-status-tile ${hibernatedCount > 0 ? 'is-nonzero' : ''}" onclick="openMachinesWithFilter('hibernated')">
            <span class="ov-status-label">Hibernated</span>
            <span class="ov-status-count font-mono">${hibernatedCount}</span>
          </button>
          <button type="button" class="ov-status-tile ${stoppedCount > 0 ? 'is-nonzero' : ''}" onclick="openMachinesWithFilter('stopped')">
            <span class="ov-status-label">Stopped</span>
            <span class="ov-status-count font-mono">${stoppedCount}</span>
          </button>
        </div>

        <div class="ov-kv-list">
          <div class="ov-kv-row">
            <span class="ov-kv-key">Auto-Update &amp; APT</span>
            <span class="ov-kv-val">${autoUpdPill}</span>
          </div>
          <div class="ov-kv-row">
            <span class="ov-kv-key">Mode Always-On</span>
            <span class="ov-kv-val font-mono">${totalVms > 0 ? `${alwaysOnCount} / ${totalVms} VM` : '—'}</span>
          </div>
          <div class="ov-kv-row">
            <span class="ov-kv-key">SSH Password</span>
            <span class="ov-kv-val font-mono">${totalVms > 0 ? `${sshPassCount} / ${totalVms} VM` : '—'}</span>
          </div>
          <div class="ov-kv-row">
            <span class="ov-kv-key">Distribusi Region</span>
            <span class="ov-kv-val font-mono">${regionBreakdown}</span>
          </div>
        </div>

        <div class="ov-card-actions">
          <button type="button" class="btn-stark-cta btn-sm-cta" onclick="openNewMachineModal()">+ Deploy VM</button>
          <button type="button" class="action-btn" onclick="openMachinesWithFilter('all')">Buka Machines →</button>
          <button type="button" class="action-btn" onclick="switchTab('panduan')">Panduan</button>
        </div>
      `;
    }
  }

  // 5. Overview Accounts Summary
  const accSummaryBody = document.getElementById('overviewAccountsSummaryBody');
  if (accSummaryBody) {
    const rawItems = scopedTelemetry.length > 0
      ? scopedTelemetry
      : scopedAccounts.map(a => ({
          account: {
            id: a.id,
            label: a.label,
            homeRegion: a.home_region || 'fra',
            status: a.status
          },
          billing: { balance: (a.balance_micro || 0) / 1e6 },
          usage: { totalCost: 0 },
          error: a.last_error || null
        }));

    const q = appState.searchQuery || '';
    const filteredItems = q
      ? rawItems.filter(item => {
          const acc = item.account || {};
          return (acc.label && acc.label.toLowerCase().includes(q)) ||
                 (acc.homeRegion && acc.homeRegion.toLowerCase().includes(q));
        })
      : rawItems;

    if (rawItems.length === 0) {
      accSummaryBody.innerHTML = `<div style="padding: 18px; text-align: center; color: var(--text-muted); font-size: 12px;">Belum ada akun terhubung.</div>`;
    } else if (filteredItems.length === 0) {
      accSummaryBody.innerHTML = `<div style="padding: 18px; text-align: center; color: var(--text-muted); font-size: 12px;">Tidak ada akun yang cocok dengan "${escapeHTML(q)}".</div>`;
    } else {
      const activeAccCount = rawItems.filter(item => !item.error && item.account && item.account.status !== 'invalid' && item.account.status !== 'error').length;
      const rowsHtml = filteredItems.map(item => {
        const acc = item.account || {};
        const bal = item.billing && typeof item.billing.balance === 'number' ? item.billing.balance : 0;
        const cost = item.usage && typeof item.usage.totalCost === 'number' ? item.usage.totalCost : 0;
        const costText = cost > 0 && cost < 0.01 ? `$${cost.toFixed(4)}` : `$${cost.toFixed(2)}`;
        const region = String(acc.homeRegion || 'fra').toUpperCase();
        const hasError = !!item.error || acc.status === 'invalid' || acc.status === 'error';
        const isSelected = appState.selectedAccountId === acc.id;
        const safeId = escapeAttr(acc.id);

        return `
          <tr class="ov-acc-row ${isSelected ? 'is-selected' : ''}" onclick="toggleOverviewAccountFilter('${safeId}')" title="Klik untuk filter akun ini">
            <td>
              <div class="ov-acc-name-wrap">
                <span class="ov-acc-name">${escapeHTML(acc.label || '-')}</span>
                <span class="ov-acc-region font-mono">${escapeHTML(region)}</span>
                ${hasError ? `<span class="status-pill status-rose font-mono" style="font-size: 9px; padding: 1px 5px;">ERR</span>` : ''}
              </div>
            </td>
            <td class="num font-mono text-emerald" style="font-weight: 800;">$${bal.toFixed(2)}</td>
            <td class="num font-mono text-muted">${costText}</td>
          </tr>
        `;
      }).join('');

      accSummaryBody.innerHTML = `
        <div class="ov-acc-table-wrap">
          <table class="ov-acc-table">
            <thead>
              <tr>
                <th>Akun</th>
                <th class="num">Saldo</th>
                <th class="num">Terpakai</th>
              </tr>
            </thead>
            <tbody>${rowsHtml}</tbody>
          </table>
        </div>
        <div class="ov-card-footer">
          <span class="ov-card-footer-meta font-mono">${activeAccCount} / ${rawItems.length} akun aktif</span>
          <button type="button" class="action-btn" onclick="openAddAccountModal()">+ Tambah Akun</button>
        </div>
      `;
    }
  }
}

// ================= RENDERING =================

function renderAccountSelectors() {
  const filterSelect = document.getElementById('accountFilter');
  const vmSelect = document.getElementById('vmAccountSelect');
  if (!filterSelect || !vmSelect) return;

  const prevFilter = appState.selectedAccountId;
  const prevDeploy = vmSelect.value;

  filterSelect.innerHTML = `<option value="all">Semua Akun (${appState.accounts.length})</option>`;
  vmSelect.innerHTML = '';

  appState.accounts.forEach(acc => {
    const scopeTag = acc.key_scope && acc.key_scope !== 'unknown' ? ` · ${acc.key_scope.toUpperCase()}` : '';
    const opt = document.createElement('option');
    opt.value = acc.id;
    opt.textContent = `${acc.label}${scopeTag}`;
    filterSelect.appendChild(opt);

    const vmOpt = document.createElement('option');
    vmOpt.value = acc.id;
    const cleanMask = String(acc.masked_key || '').replace(/\s*\.\.\.\s*/g, '…');
    vmOpt.textContent = `${acc.label} · ${cleanMask}${scopeTag}`;
    vmSelect.appendChild(vmOpt);
  });

  if (appState.accounts.some(a => a.id === prevFilter)) {
    filterSelect.value = prevFilter;
  } else {
    filterSelect.value = 'all';
    appState.selectedAccountId = 'all';
  }

  if (prevDeploy && appState.accounts.some(a => a.id === prevDeploy)) {
    vmSelect.value = prevDeploy;
  }
  onDeployAccountChange();
}

function onAccountFilterChange() {
  const select = document.getElementById('accountFilter');
  appState.selectedAccountId = select.value;
  fetchMachines();
  renderOverviewWidgets();
  renderTelemetryView();
}

function filterMachines() {
  const searchEl = document.getElementById('searchInput');
  appState.searchQuery = searchEl ? searchEl.value.toLowerCase().trim() : '';
  appState.statusFilter = document.getElementById('statusFilter').value;
  renderMachines();
}

function renderMachines() {
  const grid = document.getElementById('machinesGrid');
  const emptyState = document.getElementById('emptyMachinesState');
  if (!grid || !emptyState) return;

  updateFleetAutoUpdateBanner();
  const list = getFilteredMachinesList(true);

  if (list.length === 0) {
    grid.innerHTML = '';
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  grid.innerHTML = renderMachineCollectionsHTML(list);
}

function updateFleetAutoUpdateBanner() {
  const banner = document.getElementById('machinesAutoUpdateBanner');
  const countEl = document.getElementById('fleetAutoUpdPendingCount');
  if (!banner || !countEl) return;

  const controllable = (appState.machines || []).filter(m => m.accessible !== false && m.status !== 'stopped');
  const pending = controllable.filter(m => !(m.vmConfig && m.vmConfig.autoUpdateEnabled));
  if (pending.length > 0) {
    countEl.textContent = String(pending.length);
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
  }
}

async function handleBatchPrepareAutoUpdate(runUpgrade = false) {
  const prepBtn = document.getElementById('fleetPrepareAutoUpdBtn');
  const upgBtn = document.getElementById('fleetUpgradeAllBtn');
  const prevPrep = prepBtn ? prepBtn.textContent : '';
  const prevUpg = upgBtn ? upgBtn.textContent : '';
  if (prepBtn) {
    prepBtn.disabled = true;
    prepBtn.textContent = runUpgrade ? 'Memproses...' : 'Mengaktifkan...';
  }
  if (upgBtn) upgBtn.disabled = true;

  showToast(runUpgrade ? 'Menyiapkan Auto-Update & Upgrade OS semua VM aktif/standby...' : 'Mengaktifkan Auto-Update & mengisi cache APT semua VM...', 'info');

  try {
    const res = await apiFetch('/api/machines/autoupdate-all', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: appState.selectedAccountId || 'all',
        runUpgrade: !!runUpgrade,
        wakeStandby: true,
        intervalHours: 12,
        updateRuntimes: true
      })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      const msg = runUpgrade
        ? `${data.configured} VM diaktifkan Auto-Update & ${data.upgradedJobs} upgrade OS berjalan!`
        : `${data.configured} VM siap pakai (Auto-Update & cache APT aktif)!`;
      showToast(data.failed > 0 ? `${msg} (${data.failed} gagal)` : msg, data.failed > 0 ? 'error' : 'success');
      await fetchDashboardData({ silent: true });
    } else {
      showToast(`Gagal menyiapkan semua VM: ${data.error || 'Error'}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    if (prepBtn) {
      prepBtn.disabled = false;
      prepBtn.textContent = prevPrep || '⚡ Aktifkan Auto-Update Semua';
    }
    if (upgBtn) {
      upgBtn.disabled = false;
      upgBtn.textContent = prevUpg || '+ Upgrade OS Semua';
    }
  }
}

function renderMachineCollectionsHTML(list) {
  const controllable = list.filter(m => m.accessible !== false);

  let html = '';
  if (controllable.length > 0) {
    const showDeployCue = !appState.searchQuery && appState.statusFilter === 'all';
    const isBanner = controllable.length % 3 === 0;
    const ghostCard = showDeployCue && !isBanner ? `
      <button type="button" class="machine-deploy-ghost" onclick="openNewMachineModal()">
        <span class="ghost-plus">+</span>
        <span class="ghost-title">Deploy MicroVM Baru</span>
        <span class="ghost-sub font-mono">Ubuntu 24.04 · Auto-Update &amp; SSH siap pakai</span>
      </button>
    ` : '';
    const ghostBanner = showDeployCue && isBanner ? `
      <button type="button" class="machine-deploy-ghost is-banner" onclick="openNewMachineModal()">
        <span class="ghost-plus">+</span>
        <span class="ghost-banner-copy">
          <span class="ghost-title">Deploy MicroVM Baru</span>
          <span class="ghost-sub font-mono">Ubuntu 24.04 · Auto-Update &amp; SSH siap pakai</span>
        </span>
      </button>
    ` : '';
    html += `<div class="machines-grid">${controllable.map(m => createMachineCardHTML(m)).join('')}${ghostCard}</div>${ghostBanner}`;
  }
  return html;
}

function getMachineStatusInfo(m) {
  const isRunning = m.status === 'running';
  const isSuspended = ['suspended', 'paused'].includes(m.status);
  const isHibernated = m.status === 'hibernated';
  const isRemote = m.status === 'remote';

  if (isRunning) return { statusText: 'RUNNING', badgeClass: 'status-green' };
  if (isSuspended) return { statusText: 'STANDBY', badgeClass: 'status-amber' };
  if (isHibernated) return { statusText: 'HIBERNATED', badgeClass: 'status-neutral' };
  if (isRemote) return { statusText: 'ACTIVE', badgeClass: 'status-sky' };
  return { statusText: 'STOPPED', badgeClass: 'status-neutral' };
}

function createMachineCardHTML(m) {
  if (m.accessible === false) return '';

  const isRunning = m.status === 'running';
  const isSuspended = ['suspended', 'paused'].includes(m.status);
  const isHibernated = m.status === 'hibernated';
  const region = (m.region || 'fra').toUpperCase();
  const { statusText, badgeClass } = getMachineStatusInfo(m);

  const domain = (m.access && m.access.domain) || `${region.toLowerCase()}.boxd.sh`;
  const sshPort = m.access ? m.access.sshPort : null;
  const sshAccess = m.sshAccess || null;
  const hasSshPass = !!(sshAccess && sshAccess.enabled && sshAccess.publicPort && sshAccess.dns);
  const primarySshUser = hasSshPass ? (sshAccess.sshUser === 'boxd' ? 'boxd' : 'root') : 'boxd';
  const sshCmd = hasSshPass
    ? `ssh -p ${sshAccess.publicPort} ${primarySshUser}@${sshAccess.dns}`
    : (sshPort ? `ssh -p ${sshPort} boxd@${domain}` : `boxd machine ssh ${m.name}`);
  const url = (m.access && m.access.url) || `https://${m.name}.${domain}`;
  const vcpu = (m.resources && m.resources.vcpu) || 1;
  const memHuman = (m.resources && m.resources.memoryHuman) || '4 GB';
  const rawCost = typeof m.cost === 'number' ? m.cost : 0;
  const costText = rawCost >= 0.01 ? `$${rawCost.toFixed(2)}` : rawCost > 0 ? `$${rawCost.toFixed(4)}` : '$0.00';
  const costChip = `<span class="mc-cost-inline font-mono">${costText}</span>`;

  const safeAccId = escapeAttr(m.accountId);
  const safeId = escapeAttr(m.id);
  const safeName = escapeAttr(m.name);
  const safeLabel = escapeAttr(m.accountLabel);
  const safeRegion = escapeAttr(m.region || 'fra');
  const keySvg = `<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`;
  const isAlwaysOn = !!m.alwaysOn;
  const isAutoUpd = !!(m.vmConfig && m.vmConfig.autoUpdateEnabled);
  const modeChips = [
    isAlwaysOn ? `<span class="mc-mode-chip is-always-on" title="Auto-Suspend & Hibernate Nonaktif">ALWAYS-ON</span>` : '',
    isAutoUpd ? `<span class="mc-mode-chip is-autoupd" title="Auto-Update Terjadwal Aktif">AUTO-UPD</span>` : ''
  ].filter(Boolean).join('');

  return `
    <div class="machine-card is-ctrl" id="card-${escapeHTML(m.id)}">
      <div class="mc-top">
        <div class="mc-title-area">
          <span class="mc-name font-mono">${escapeHTML(m.name)}</span>
          <div style="display: flex; align-items: center; gap: 6px; flex-shrink: 0;">
            ${costChip}
            <span class="status-pill ${badgeClass} font-mono">${escapeHTML(statusText)}</span>
          </div>
        </div>
        <div class="mc-meta-line font-mono">
          <span class="mc-meta-text"><span class="mc-acc-label" title="${escapeHTML(m.accountLabel)}">${escapeHTML(m.accountLabel)}</span> <span class="nowrap-spec">· ${escapeHTML(region)} · ${vcpu} vCPU · ${escapeHTML(memHuman)}</span></span>
          ${modeChips ? `<span class="mc-meta-chips">${modeChips}</span>` : ''}
        </div>
      </div>

      <div class="mc-endpoints">
        <div class="endpoint-item endpoint-item-ssh ${hasSshPass ? 'has-pass' : ''}">
          <span class="endpoint-protocol">SSH</span>
          <span class="endpoint-value font-mono" style="cursor: pointer;" onclick="${hasSshPass ? `copyToClipboard('${escapeAttr(sshCmd)}', 'SSH disalin')` : `openSshPasswordModal('${safeAccId}', '${safeId}', '${safeName}', '${safeLabel}', '${safeRegion}')`}" title="${escapeHTML(hasSshPass ? sshCmd : 'Klik Set Pass untuk atur password SSH (port 22)')}">${escapeHTML(hasSshPass ? sshCmd : `root@${m.name}.boxd.sh`)}</span>
          <div class="ep-actions">
            <button type="button" class="ep-btn ep-btn-pass ${hasSshPass ? 'is-active' : 'needs-setup'}" onclick="openSshPasswordModal('${safeAccId}', '${safeId}', '${safeName}', '${safeLabel}', '${safeRegion}')" title="Atur Password SSH">${keySvg}<span>${hasSshPass ? 'Pass' : 'Set Pass'}</span></button>
            ${hasSshPass ? `<button type="button" class="ep-btn" onclick="copyToClipboard('${escapeAttr(sshCmd)}', 'SSH disalin')">Copy</button>` : `<button type="button" class="ep-btn" onclick="copyToClipboard('${escapeAttr(sshCmd)}', 'SSH key command disalin')" title="Copy perintah SSH Key Boxd">SSH Key</button>`}
          </div>
        </div>

        <div class="endpoint-item">
          <span class="endpoint-protocol">WEB</span>
          <a href="${escapeHTML(url)}" target="_blank" rel="noopener" class="endpoint-link">
            <span class="endpoint-value font-mono">${escapeHTML(m.name)}.${escapeHTML(domain)}</span>
          </a>
          <a href="${escapeHTML(url)}" target="_blank" rel="noopener" class="ep-btn">Visit ↗</a>
        </div>

        ${m.access && m.access.desktopUrl ? `
          <div class="endpoint-item">
            <span class="endpoint-protocol">GUI</span>
            <a href="${escapeHTML(m.access.desktopUrl)}" target="_blank" rel="noopener" class="endpoint-link">
              <span class="endpoint-value font-mono">Desktop Web Shell</span>
            </a>
            <a href="${escapeHTML(m.access.desktopUrl)}" target="_blank" rel="noopener" class="ep-btn">Open ↗</a>
          </div>
        ` : ''}
      </div>

      <div class="mc-bottom">
        <div class="mc-actions-left">
          ${isRunning ? `
            <button class="action-btn" onclick="doMachineAction('${safeAccId}', '${safeId}', 'pause', '${safeRegion}')">Pause</button>
            <button class="action-btn" onclick="doMachineAction('${safeAccId}', '${safeId}', 'hibernate', '${safeRegion}')">Hibernate</button>
          ` : `
            <button class="action-btn start-ready" onclick="doMachineAction('${safeAccId}', '${safeId}', '${isSuspended ? 'resume' : isHibernated ? 'wake' : 'start'}', '${safeRegion}')">▶ Start</button>
          `}
          <button class="action-btn" onclick="openExecModal('${safeAccId}', '${safeId}', '${safeName}', '${safeLabel}', '${safeRegion}')">&gt;_ Console</button>
          <button class="action-btn" onclick="openVmManageModal('${safeAccId}', '${safeId}', '${safeName}', '${safeLabel}', '${safeRegion}')">Kelola</button>
        </div>
        <button class="action-btn danger" onclick="confirmDeleteMachine('${safeAccId}', '${safeId}', '${safeName}', '${safeRegion}')">Hapus</button>
      </div>
    </div>
  `;
}

// ================= RENDER MULTI-ACCOUNT HUB =================

function filterAccountsHub() {
  renderAccountsHub();
}

function renderAccountsHub() {
  const container = document.getElementById('accountsHubGrid');
  if (!container) return;

  const sourceList = (appState.telemetry && Array.isArray(appState.telemetry.accounts))
    ? appState.telemetry.accounts
    : appState.accounts.map(a => ({
        account: {
          id: a.id,
          label: a.label,
          userId: a.user_id,
          displayName: a.display_name,
          maxVms: a.max_vms || 100,
          status: a.status,
          keyScope: a.key_scope || 'unknown',
          homeRegion: a.home_region || 'fra',
          maskedKey: a.masked_key
        },
        org: { id: a.org_id, name: a.org_name || 'Personal' },
        billing: { balance: (a.balance_micro || 0) / 1e6 },
        usage: { totalCost: 0 },
        machinesCount: 0,
        controllableCount: 0,
        privateLockedCount: 0,
        error: a.last_error || null
      }));

  if (sourceList.length === 0) {
    container.innerHTML = `<div class="text-dim" style="padding: 20px; font-size: 12px;">Belum ada akun. Klik "+ Tambah Akun" untuk menghubungkan Boxd API Key.</div>`;
    return;
  }

  const query = appState.searchQuery || '';
  let list = sourceList;
  if (query) {
    list = list.filter(item => {
      const acc = item.account || {};
      const org = item.org || {};
      return (acc.label && acc.label.toLowerCase().includes(query)) ||
             (acc.displayName && acc.displayName.toLowerCase().includes(query)) ||
             (acc.userId && acc.userId.toLowerCase().includes(query)) ||
             (acc.maskedKey && acc.maskedKey.toLowerCase().includes(query)) ||
             (org.name && org.name.toLowerCase().includes(query));
    });
  }

  if (list.length === 0) {
    container.innerHTML = `<div class="text-dim" style="padding: 24px;">Tidak ada akun yang cocok dengan kata kunci pencarian.</div>`;
    return;
  }

  container.innerHTML = list.map((item) => {
    const acc = item.account || {};
    const billing = item.billing || {};
    const usage = item.usage || {};
    const machinesCount = item.controllableCount !== undefined ? item.controllableCount : (item.machinesCount || 0);
    const maxVms = acc.maxVms || 100;
    const quotaPct = maxVms > 0 ? Math.min(100, Math.round((machinesCount / maxVms) * 100)) : 0;

    const balanceVal = typeof billing.balance === 'number' ? billing.balance : 0;
    const costVal = typeof usage.totalCost === 'number' ? usage.totalCost : 0;
    const balanceFormatted = balanceVal.toFixed(2);
    const totalCostFormatted = costVal > 0 && costVal < 0.01 ? costVal.toFixed(4) : costVal.toFixed(2);

    const hasError = !!item.error || acc.status === 'invalid' || acc.status === 'error';
    const statusText = acc.status === 'invalid' ? 'INVALID' : 'ERROR';
    const scope = (acc.keyScope || 'unknown').toUpperCase();
    const scopeText = scope === 'ORG' || scope === 'MEMBER' ? `${scope} · ` : '';

    const regionsStr = Array.isArray(acc.enabledRegions) && acc.enabledRegions.length > 0
      ? acc.enabledRegions.map(r => r.toUpperCase()).join(', ')
      : String(acc.homeRegion || 'fra').toUpperCase();

    const safeId = escapeAttr(acc.id);
    const safeLabel = escapeAttr(acc.label);

    const cleanMask = String(acc.maskedKey || '').replace(/\s*\.\.\.\s*/g, '…');
    const metaLine = `${acc.displayName || acc.userId || '-'} · ${scopeText}${cleanMask} · ${regionsStr}`;

    return `
      <div class="account-card ${hasError ? 'has-error' : ''}">
        <div class="acc-card-top">
          <div style="min-width: 0; flex: 1;">
            <div class="acc-label">${escapeHTML(acc.label)}</div>
            <div class="acc-user-id font-mono" title="${escapeAttr(metaLine)}">${escapeHTML(metaLine)}</div>
          </div>
          ${hasError ? `<span class="status-pill status-rose font-mono">${statusText}</span>` : ''}
        </div>

        ${hasError ? `
          <div class="mc-lock-notice" style="border-color: #F43F5E; color: var(--text-primary); background-color: rgba(244, 63, 94, 0.1);">
            ${escapeHTML(item.error || acc.lastError || 'Gagal sinkronisasi akun')}
          </div>
        ` : ''}

        <div class="acc-metrics-split">
          <div class="acc-metric-col">
            <span class="acc-metric-lbl">SALDO</span>
            <span class="acc-metric-val text-emerald font-mono">$${balanceFormatted}</span>
          </div>
          <div class="acc-metric-col" style="text-align: right;">
            <span class="acc-metric-lbl">PEMAKAIAN</span>
            <span class="acc-metric-val font-mono">$${totalCostFormatted}</span>
          </div>
        </div>

        <div class="quota-track-wrap">
          <div class="quota-track-header">
            <span>Kuota VM</span>
            <strong class="font-mono">${machinesCount} / ${maxVms}</strong>
          </div>
          <div class="quota-track-bg">
            <div class="quota-track-fill" style="width: ${quotaPct === 0 ? 0 : Math.max(3, quotaPct)}%;"></div>
          </div>
        </div>

        <div class="acc-actions">
          <div style="display: flex; gap: 6px;">
            <button class="btn-mc-action" onclick="selectAndFilterAccount('${safeId}')">Lihat VM</button>
            <button class="btn-mc-action" onclick="syncAccount('${safeId}')">Sync</button>
          </div>
          <button class="btn-mc-action delete" onclick="deleteAccount('${safeId}', '${safeLabel}')">Hapus</button>
        </div>
      </div>
    `;
  }).join('');
}

function selectAndFilterAccount(accountId) {
  const filterSelect = document.getElementById('accountFilter');
  if (filterSelect) {
    filterSelect.value = accountId;
    appState.selectedAccountId = accountId;
  }
  switchTab('machines');
  fetchMachines();
  renderOverviewWidgets();
  renderTelemetryView();
}

// ================= RENDER TELEMETRY VIEW =================

function renderTelemetryView() {
  if (!appState.telemetry) return;

  const summary = appState.telemetry.summary || {};
  const rates = summary.rates || { vcpuHour: 0.047, ramHour: 0.014, diskHour: 0.000096 };

  const elVcpuRate = document.getElementById('telemVcpuRate');
  const elRamRate = document.getElementById('telemRamRate');
  const elStorageRate = document.getElementById('telemStorageRate');
  const elSyncedBadge = document.getElementById('telemLastSyncedBadge');

  if (elVcpuRate) elVcpuRate.textContent = `$${rates.vcpuHour.toFixed(4)}`;
  if (elRamRate) elRamRate.textContent = `$${rates.ramHour.toFixed(4)}`;
  if (elStorageRate) elStorageRate.textContent = `$${rates.diskHour.toFixed(6)}`;
  if (elSyncedBadge && appState.telemetry.syncedAt) {
    const tStr = new Date(appState.telemetry.syncedAt).toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    elSyncedBadge.textContent = `Synced ${tStr}`;
  }

  const scopedAccounts = appState.selectedAccountId === 'all'
    ? (appState.telemetry.accounts || [])
    : (appState.telemetry.accounts || []).filter(a => a.account && a.account.id === appState.selectedAccountId);

  const scopedTotalCost = scopedAccounts.reduce((acc, item) => {
    const cost = item.usage && typeof item.usage.totalCost === 'number' ? item.usage.totalCost : 0;
    return acc + cost;
  }, 0);

  const elTotalCost = document.getElementById('telemTotalCost');
  if (elTotalCost) {
    elTotalCost.textContent = scopedTotalCost > 0 && scopedTotalCost < 0.01
      ? `$${scopedTotalCost.toFixed(4)}`
      : `$${scopedTotalCost.toFixed(2)}`;
  }

  const tbody = document.getElementById('telemetryTableBody');
  const countMeta = document.getElementById('telemRowCountMeta');
  if (!tbody) return;

  const rows = [];
  scopedAccounts.forEach(accItem => {
    if (accItem.usage && Array.isArray(accItem.usage.machines)) {
      accItem.usage.machines.forEach(m => {
        if (!m.accessible && !m.shared) return;
        const hours = (m.runningSeconds / 3600).toFixed(2);
        const exactCost = m.cost !== undefined ? `$${m.cost.toFixed(6)}` : '$0.000000';
        const costStr = m.cost !== undefined ? `$${m.cost.toFixed(4)}` : '$0.0000';
        const ramHuman = `${Math.round((m.memoryBytes || 0) / (1024 * 1024 * 1024))} GB`;
        const statusRaw = String(m.status || 'active').toUpperCase();
        const regionStr = String(m.region || 'fra').toUpperCase();
        const scopeStr = m.isDeleted ? ' · TERHAPUS' : '';

        let badgeClass = 'status-green';
        if (m.isDeleted || statusRaw === 'HIBERNATED' || statusRaw === 'STOPPED') badgeClass = 'status-neutral';
        else if (statusRaw === 'REMOTE' || statusRaw === 'ACTIVE') badgeClass = 'status-sky';
        else if (statusRaw === 'SUSPENDED' || statusRaw === 'STANDBY' || statusRaw === 'PAUSED') badgeClass = 'status-amber';

        const uptimeSec = (m.runningSeconds || 0).toLocaleString('en-US');

        rows.push(`
          <tr>
            <td data-label="VM" class="telem-cell-vm">
              <strong class="font-mono" style="color: var(--text-primary);">${escapeHTML(m.name)}</strong>
              <div class="telem-vm-sub">${escapeHTML(accItem.account.label)}${escapeHTML(scopeStr)}</div>
            </td>
            <td data-label="Status" class="telem-cell-status">
              <span class="status-pill ${badgeClass} font-mono">${escapeHTML(statusRaw)}</span>
              <span class="font-mono telem-region-tag">${escapeHTML(regionStr)}</span>
            </td>
            <td data-label="Spek" class="telem-cell-spec">
              <span class="font-mono nowrap-spec">${m.vcpu} vCPU · ${ramHuman}</span>
            </td>
            <td data-label="Uptime" class="num">
              <span class="font-mono" title="${uptimeSec} detik"><span class="telem-uptime-hours">${hours}j</span><span class="telem-sec-sub">(${uptimeSec}s)</span></span>
            </td>
            <td data-label="vCPU·hr" class="num">
              <span class="font-mono">${m.vcpuHours ? m.vcpuHours.toFixed(4) : '0.0000'}</span>
            </td>
            <td data-label="RAM GiB·hr" class="num">
              <span class="font-mono">${m.ramGibHours ? m.ramGibHours.toFixed(4) : '0.0000'}</span>
            </td>
            <td data-label="Biaya" class="num">
              <strong class="font-mono text-emerald" title="${exactCost}">${costStr}</strong>
            </td>
          </tr>
        `);
      });
    }
  });

  if (countMeta) countMeta.textContent = `${rows.length} microVM`;

  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">Belum ada riwayat komputasi aktif.</td></tr>`;
  } else {
    tbody.innerHTML = rows.join('');
  }
}

// ================= MACHINE ACTIONS =================

async function doMachineAction(accountId, machineId, action, region) {
  const card = document.getElementById(`card-${machineId}`);
  if (card) {
    card.style.opacity = '0.5';
    card.style.pointerEvents = 'none';
  }

  showToast(`Menjalankan ${action} pada mesin...`, 'info');

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, action, region })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`Aksi ${action} berhasil!`, 'success');
      setTimeout(fetchDashboardData, 1200);
    } else {
      showToast(`Aksi gagal: ${data.error}`, 'error');
      if (card) {
        card.style.opacity = '1';
        card.style.pointerEvents = 'auto';
      }
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
    if (card) {
      card.style.opacity = '1';
      card.style.pointerEvents = 'auto';
    }
  }
}

// ================= NEW MACHINE MODAL =================

function onDeployAccountChange() {
  const accSelect = document.getElementById('vmAccountSelect');
  const hintEl = document.getElementById('vmAccountScopeHint');
  const sharedInput = document.getElementById('vmSharedInput');
  if (!accSelect) return;

  const acc = appState.accounts.find(a => a.id === accSelect.value);
  if (!acc) {
    if (hintEl) hintEl.textContent = '';
    return;
  }

  const scope = acc.key_scope || 'unknown';
  const home = (acc.home_region || 'fra').toUpperCase();
  if (scope === 'org') {
    if (sharedInput) sharedInput.checked = true;
    if (hintEl) {
      hintEl.textContent = `ORG key · Home region: ${home}`;
    }
  } else if (scope === 'member') {
    if (hintEl) {
      hintEl.textContent = `Member key · Home region: ${home}`;
    }
  } else {
    if (hintEl) hintEl.textContent = `Home region: ${home}`;
  }
}

function onDeployUsagePresetChange() {
  const preset = (document.getElementById('vmUsagePreset') || {}).value || 'balanced';
  const customRow = document.getElementById('vmCustomIdleRow');
  const suspInput = document.getElementById('vmSuspendInput');
  const hibInput = document.getElementById('vmHibernateInput');
  if (customRow) customRow.classList.toggle('hidden', preset !== 'custom');

  if (preset === 'balanced') {
    if (suspInput) suspInput.value = '300';
    if (hibInput) hibInput.value = '14400';
  } else if (preset === 'standby') {
    if (suspInput) suspInput.value = '1800';
    if (hibInput) hibInput.value = '0';
  } else if (preset === 'always_on') {
    if (suspInput) suspInput.value = '0';
    if (hibInput) hibInput.value = '0';
  }
}

function openNewMachineModal() {
  if (appState.accounts.length === 0) {
    showToast('Harap hubungkan akun Boxd terlebih dahulu', 'error');
    openAddAccountModal();
    return;
  }
  const vmSelect = document.getElementById('vmAccountSelect');
  if (vmSelect && appState.selectedAccountId !== 'all') {
    vmSelect.value = appState.selectedAccountId;
  }
  onDeployAccountChange();
  onDeployUsagePresetChange();
  document.getElementById('newMachineModal').classList.remove('hidden');
}

function closeNewMachineModal() {
  document.getElementById('newMachineModal').classList.add('hidden');
}

async function generateRandomName() {
  const nameInput = document.getElementById('vmNameInput');
  const accSelect = document.getElementById('vmAccountSelect');
  nameInput.value = 'generating...';

  try {
    const res = await apiFetch(`/api/machines/suggest-name?accountId=${encodeURIComponent(accSelect.value)}`);
    const data = await res.json();
    nameInput.value = data.name || `boxd-vm-${Math.floor(100 + Math.random() * 900)}`;
  } catch (e) {
    nameInput.value = `boxd-vm-${Math.floor(100 + Math.random() * 900)}`;
  }
}

async function handleCreateMachine(e) {
  e.preventDefault();
  const btn = document.getElementById('createMachineBtn');

  const accountId = document.getElementById('vmAccountSelect').value;
  const name = document.getElementById('vmNameInput').value.trim();
  const sizeVal = document.querySelector('input[name="vmSize"]:checked').value;
  const [vcpuStr, memStr] = sizeVal.split('x');
  const region = document.getElementById('vmRegionSelect').value;
  const usagePreset = (document.getElementById('vmUsagePreset') || {}).value || 'balanced';

  let autoSuspendTimeout = 300;
  let autoHibernateTimeout = 14400;
  if (usagePreset === 'standby') {
    autoSuspendTimeout = 1800;
    autoHibernateTimeout = 0;
  } else if (usagePreset === 'always_on') {
    autoSuspendTimeout = 0;
    autoHibernateTimeout = 0;
  } else if (usagePreset === 'custom') {
    autoSuspendTimeout = Math.max(0, parseInt((document.getElementById('vmSuspendInput') || {}).value, 10) || 0);
    autoHibernateTimeout = Math.max(0, parseInt((document.getElementById('vmHibernateInput') || {}).value, 10) || 0);
  }

  const autoUpdEl = document.getElementById('vmAutoUpdateCheck');
  const botOffEl = document.getElementById('vmBotOffCheck');
  const upgradeNowEl = document.getElementById('vmUpgradeNowCheck');
  const starterKits = Array.from(document.querySelectorAll('input[name="deployStarterKit"]:checked')).map(el => el.value);

  const sharedEl = document.getElementById('vmSharedInput');
  const shared = sharedEl ? !!sharedEl.checked : true;
  const sshPasswordEl = document.getElementById('vmSshPasswordInput');
  const sshUserEl = document.getElementById('vmSshUserSelect');
  const sshPassword = sshPasswordEl ? sshPasswordEl.value : '';
  const sshUser = sshUserEl ? sshUserEl.value : 'root';

  if (sshPassword && sshPassword.length < 6) {
    showToast('Password SSH minimal 6 karakter (atau kosongkan)', 'error');
    return;
  }

  const hasAutoSetup = !!(autoUpdEl && autoUpdEl.checked) || !!(upgradeNowEl && upgradeNowEl.checked) || starterKits.length > 0;
  btn.disabled = true;
  btn.innerHTML = (sshPassword || hasAutoSetup) ? '<span>Deploying + Setup...</span>' : '<span>Deploying ~2s...</span>';

  try {
    const res = await apiFetch('/api/machines', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId,
        name: name || undefined,
        vcpu: parseInt(vcpuStr, 10),
        memory: `${memStr}G`,
        region,
        shared,
        autoSuspendTimeout,
        autoHibernateTimeout,
        botProtectionMode: botOffEl && botOffEl.checked ? 'off' : 'on',
        autoSetup: hasAutoSetup ? {
          enableAutoUpdate: !!(autoUpdEl && autoUpdEl.checked),
          intervalHours: 12,
          updateRuntimes: true,
          upgradeNow: !!(upgradeNowEl && upgradeNowEl.checked),
          starterKits
        } : undefined,
        sshPassword: sshPassword || undefined,
        sshUser: sshPassword ? sshUser : undefined
      })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      const m = data.machine;
      if (m && m.sshSetupError) {
        showToast(`VM "${m.name}" dideploy, tapi SSH gagal: ${m.sshSetupError}`, 'error');
      } else if (m && m.provisionJobId) {
        showToast(`VM "${m.name}" dideploy! Setup stack & update berjalan...`, 'success');
      } else if (m && m.sshAccess && m.sshAccess.enabled) {
        showToast(`VM "${m.name}" + Password SSH siap dipakai!`, 'success');
      } else {
        showToast(`VM "${m.name}" berhasil dideploy!`, 'success');
      }
      closeNewMachineModal();
      document.getElementById('newMachineForm').reset();
      if (sharedEl) sharedEl.checked = true;
      if (autoUpdEl) autoUpdEl.checked = true;
      if (botOffEl) botOffEl.checked = true;
      onDeployAccountChange();
      onDeployUsagePresetChange();
      await fetchDashboardData({ silent: true });

      if (m && m.provisionJobId) {
        openVmManageModal(accountId, m.id, m.name, m.accountLabel || '', m.region || 'fra', {
          initialTab: 'update',
          initialJobId: m.provisionJobId
        });
      }
    } else {
      showToast(`Gagal membuat VM: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Deploy MicroVM</span>';
  }
}

function generateSecurePassword(length = 16) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789@#_-';
  const out = [];
  if (window.crypto && window.crypto.getRandomValues) {
    const arr = new Uint32Array(length);
    window.crypto.getRandomValues(arr);
    for (let i = 0; i < length; i++) {
      out.push(chars[arr[i] % chars.length]);
    }
  } else {
    for (let i = 0; i < length; i++) {
      out.push(chars[Math.floor(Math.random() * chars.length)]);
    }
  }
  return out.join('');
}

function generateDeploySshPassword() {
  const input = document.getElementById('vmSshPasswordInput');
  if (input) {
    input.value = generateSecurePassword(14);
  }
}

// ================= SSH PASSWORD MODAL =================

async function openSshPasswordModal(accountId, machineId, name, accountLabel, region) {
  appState.sshPassTarget = { accountId, machineId, name, accountLabel, region };
  appState.sshPassStatus = null;
  appState.sshSavedRevealed = false;

  document.getElementById('sshPassTargetName').textContent = name;
  document.getElementById('sshPassTargetAccount').textContent = `${accountLabel} · ${(region || 'fra').toUpperCase()}`;
  document.getElementById('sshPassInput').value = '';
  document.getElementById('sshPassInput').type = 'password';
  document.getElementById('sshPassInputToggleBtn').textContent = 'Lihat';

  const badge = document.getElementById('sshPassStatusBadge');
  badge.textContent = 'MEMUAT...';
  badge.className = 'stat-subpill font-mono';
  document.getElementById('sshPassStatusHint').textContent = 'Memeriksa port forward & status sshd VM...';
  document.getElementById('sshPassStatusHint').classList.remove('hidden');
  document.getElementById('sshPassConnectionInfo').classList.add('hidden');
  document.getElementById('sshPassServiceWarn').classList.add('hidden');
  document.getElementById('sshPassDisableBtn').classList.add('hidden');

  document.getElementById('sshPasswordModal').classList.remove('hidden');
  await refreshSshPasswordStatus();
}

function closeSshPasswordModal() {
  document.getElementById('sshPasswordModal').classList.add('hidden');
  appState.sshPassTarget = null;
  appState.sshPassStatus = null;
  appState.sshSavedRevealed = false;
}

async function refreshSshPasswordStatus() {
  if (!appState.sshPassTarget) return;
  const { accountId, machineId, region } = appState.sshPassTarget;

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/ssh-password?accountId=${encodeURIComponent(accountId)}&region=${encodeURIComponent(region || 'fra')}`);
    const data = await res.json();
    if (!appState.sshPassTarget || appState.sshPassTarget.machineId !== machineId) return;

    if (res.ok && data.success) {
      appState.sshPassStatus = data;
      renderSshPasswordStatus(data);
    } else {
      document.getElementById('sshPassStatusBadge').textContent = 'ERROR';
      document.getElementById('sshPassStatusHint').textContent = data.error || 'Gagal memeriksa status SSH';
    }
  } catch (err) {
    document.getElementById('sshPassStatusBadge').textContent = 'ERROR';
    document.getElementById('sshPassStatusHint').textContent = 'Koneksi gagal: ' + err.message;
  }
}

function renderSshPasswordStatus(st) {
  const badge = document.getElementById('sshPassStatusBadge');
  const hint = document.getElementById('sshPassStatusHint');
  const infoBox = document.getElementById('sshPassConnectionInfo');
  const warnBox = document.getElementById('sshPassServiceWarn');
  const disableBtn = document.getElementById('sshPassDisableBtn');

  // Preselect active sshUser radio
  const targetUser = st.sshUser || 'root';
  const radio = document.querySelector(`input[name="sshPassUser"][value="${targetUser}"]`);
  if (radio) radio.checked = true;

  if (st.portExposed && st.publicPort) {
    const isHealthy = st.sshServiceActive !== false;
    badge.textContent = isHealthy ? `AKTIF · PORT ${st.publicPort}` : `PORT ${st.publicPort}`;
    badge.className = isHealthy ? 'stat-subpill badge-green-soft font-mono' : 'stat-subpill font-mono';
    hint.classList.add('hidden');
    infoBox.classList.remove('hidden');
    disableBtn.classList.remove('hidden');

    document.getElementById('sshPassCommandText').textContent = st.command || `ssh -p ${st.publicPort} root@${st.dns}`;
    document.getElementById('sshPassHostText').textContent = st.dns || '-';
    document.getElementById('sshPassPortText').textContent = String(st.publicPort);
    document.getElementById('sshPassUserText').textContent = st.sshUser === 'both' ? 'root & boxd' : (st.sshUser || 'root');

    appState.sshSavedRevealed = false;
    const savedText = document.getElementById('sshPassSavedText');
    const revealBtn = document.getElementById('sshPassRevealSavedBtn');
    const copyBtn = document.getElementById('sshPassCopySavedBtn');

    if (st.password) {
      savedText.textContent = '••••••••••••';
      revealBtn.textContent = 'Lihat';
      revealBtn.classList.remove('hidden');
      copyBtn.classList.remove('hidden');
    } else {
      savedText.textContent = st.hasPassword ? '(Terkunci / secret berubah)' : '(Belum tersimpan di panel)';
      revealBtn.classList.add('hidden');
      copyBtn.classList.add('hidden');
    }

    if (st.sshServiceActive === false) {
      warnBox.classList.remove('hidden');
    } else {
      warnBox.classList.add('hidden');
    }
  } else {
    badge.textContent = 'BELUM AKTIF';
    badge.className = 'stat-subpill font-mono';
    infoBox.classList.add('hidden');
    warnBox.classList.add('hidden');
    disableBtn.classList.add('hidden');
    hint.classList.remove('hidden');
    hint.textContent = st.status === 'stopped'
      ? 'VM sedang STOPPED. Nyalakan VM terlebih dahulu sebelum mengatur password SSH.'
      : 'Belum ada port SSH password yang dibuka. Atur password di bawah untuk mengaktifkan akses SSH.';
  }
}

function toggleSshInputVisibility() {
  const input = document.getElementById('sshPassInput');
  const btn = document.getElementById('sshPassInputToggleBtn');
  if (!input || !btn) return;
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = 'Sembunyi';
  } else {
    input.type = 'password';
    btn.textContent = 'Lihat';
  }
}

function generateModalSshPassword() {
  const input = document.getElementById('sshPassInput');
  const btn = document.getElementById('sshPassInputToggleBtn');
  if (input) {
    input.value = generateSecurePassword(16);
    input.type = 'text';
    if (btn) btn.textContent = 'Sembunyi';
    input.focus();
  }
}

function toggleSavedSshPass() {
  if (!appState.sshPassStatus || !appState.sshPassStatus.password) return;
  const savedText = document.getElementById('sshPassSavedText');
  const revealBtn = document.getElementById('sshPassRevealSavedBtn');
  appState.sshSavedRevealed = !appState.sshSavedRevealed;
  if (appState.sshSavedRevealed) {
    savedText.textContent = appState.sshPassStatus.password;
    revealBtn.textContent = 'Tutup';
  } else {
    savedText.textContent = '••••••••••••';
    revealBtn.textContent = 'Lihat';
  }
}

function copySavedSshPass() {
  if (!appState.sshPassStatus || !appState.sshPassStatus.password) return;
  copyToClipboard(appState.sshPassStatus.password, 'Password SSH disalin');
}

function copySshCommandFromModal() {
  const cmd = document.getElementById('sshPassCommandText').textContent;
  if (cmd && cmd !== '-') {
    copyToClipboard(cmd, 'Perintah SSH disalin');
  }
}

async function handleSaveSshPassword(e) {
  e.preventDefault();
  if (!appState.sshPassTarget) return;

  const password = document.getElementById('sshPassInput').value;
  const userEl = document.querySelector('input[name="sshPassUser"]:checked');
  const sshUser = userEl ? userEl.value : 'root';

  if (!password || password.length < 6) {
    showToast('Password minimal 6 karakter', 'error');
    return;
  }

  const btn = document.getElementById('sshPassSubmitBtn');
  btn.disabled = true;
  btn.innerHTML = '<span>Mengaktifkan SSH...</span>';

  try {
    const { accountId, machineId, region } = appState.sshPassTarget;
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/ssh-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, password, sshUser })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`SSH aktif di port ${data.publicPort} (${data.sshUser})!`, 'success');
      document.getElementById('sshPassInput').value = '';
      await refreshSshPasswordStatus();
      await fetchDashboardData();
    } else {
      showToast(`Gagal atur SSH: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Simpan &amp; Aktifkan</span>';
  }
}

async function handleDisableSshPassword() {
  if (!appState.sshPassTarget) return;
  const { accountId, machineId, name, region } = appState.sshPassTarget;
  if (!confirm(`Matikan login password SSH dan tutup port 22 untuk VM "${name}"?`)) {
    return;
  }

  const disableBtn = document.getElementById('sshPassDisableBtn');
  disableBtn.disabled = true;
  disableBtn.textContent = 'Mematikan...';

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/ssh-password?accountId=${encodeURIComponent(accountId)}&region=${encodeURIComponent(region || 'fra')}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Akses password SSH untuk "${name}" dimatikan`, 'info');
      await refreshSshPasswordStatus();
      await fetchDashboardData();
    } else {
      showToast(`Gagal mematikan: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    disableBtn.disabled = false;
    disableBtn.textContent = 'Matikan SSH Pass';
  }
}

// ================= KELOLA & AUTO-UPDATE VM MODAL =================

function clearManageJobPoller() {
  if (appState.manageJobPoller) {
    clearInterval(appState.manageJobPoller);
    appState.manageJobPoller = null;
  }
}

function switchManageTab(tabId) {
  appState.manageActiveTab = tabId;
  ['update', 'power', 'network', 'snapshot'].forEach(t => {
    const btn = document.getElementById(`manageTabBtn-${t}`);
    const pane = document.getElementById(`managePane-${t}`);
    if (btn) btn.classList.toggle('active', t === tabId);
    if (pane) pane.classList.toggle('hidden', t !== tabId);
  });
}

async function openVmManageModal(accountId, machineId, name, accountLabel, region, options = {}) {
  clearManageJobPoller();
  appState.manageTarget = { accountId, machineId, name, accountLabel, region: region || 'fra' };
  appState.manageState = null;

  document.getElementById('manageTargetName').textContent = name || machineId;
  document.getElementById('manageTargetMeta').textContent = `${accountLabel || accountId} · ${(region || 'fra').toUpperCase()}`;
  document.getElementById('manageOsSummary').textContent = 'Memeriksa kondisi VM…';
  const badge = document.getElementById('manageAutoUpdBadge');
  badge.textContent = 'MEMUAT…';
  badge.className = 'stat-subpill font-mono';
  document.getElementById('manageUpgradableCount').textContent = '-';
  document.getElementById('manageLastUpdateInfo').textContent = '-';
  document.getElementById('manageDiskUptime').textContent = '-';
  document.getElementById('manageInstalledTools').classList.add('hidden');
  document.getElementById('vmManageJobCard').classList.add('hidden');
  document.getElementById('manageStarterKitsGrid').innerHTML = '<div class="font-mono text-dim" style="font-size: 11px;">Memuat…</div>';
  document.getElementById('managePortsList').innerHTML = '';
  document.getElementById('manageProxiesList').innerHTML = '';
  document.getElementById('manageSnapshotsList').innerHTML = '';

  switchManageTab(options.initialTab || 'update');
  document.getElementById('vmManageModal').classList.remove('hidden');

  await refreshVmManageState();

  if (options.initialJobId) {
    startManageJobPolling(options.initialJobId);
  }
}

function closeVmManageModal() {
  clearManageJobPoller();
  document.getElementById('vmManageModal').classList.add('hidden');
  appState.manageTarget = null;
  appState.manageState = null;
}

async function refreshVmManageState() {
  if (!appState.manageTarget) return;
  const { accountId, machineId, region } = appState.manageTarget;
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/manage?accountId=${encodeURIComponent(accountId)}&region=${encodeURIComponent(region || 'fra')}`);
    const data = await res.json();
    if (!appState.manageTarget || appState.manageTarget.machineId !== machineId) return;

    if (res.ok && data.success) {
      appState.manageState = data;
      renderVmManageState(data);
    } else {
      document.getElementById('manageOsSummary').textContent = data.error || 'Gagal memuat status VM';
      document.getElementById('manageAutoUpdBadge').textContent = 'ERROR';
    }
  } catch (err) {
    document.getElementById('manageOsSummary').textContent = 'Koneksi gagal: ' + err.message;
  }
}

function syncQuickIdleChips() {
  const suspVal = String(document.getElementById('manageSuspendInput')?.value ?? '').trim();
  const hibVal = String(document.getElementById('manageHibernateInput')?.value ?? '').trim();
  document.querySelectorAll('.quick-sec-chips .cmd-pill').forEach(btn => {
    const target = btn.getAttribute('data-target');
    const val = btn.getAttribute('data-val');
    const cur = target === 'manageSuspendInput' ? suspVal : target === 'manageHibernateInput' ? hibVal : '';
    btn.classList.toggle('is-active', cur !== '' && cur === val);
  });
}

function syncResizeButtonState() {
  const btn = document.getElementById('manageResizeBtn');
  const hint = document.getElementById('manageResizeHint');
  const checked = document.querySelector('input[name="manageResizeTier"]:checked');
  const m = (appState.manageState && appState.manageState.machine) || {};
  const curVcpu = Number((m.resources && m.resources.vcpu) || 0);
  const selVcpu = checked ? Number(checked.value) : 0;

  document.querySelectorAll('[data-tier-now]').forEach(el => {
    const t = Number(el.getAttribute('data-tier-now'));
    el.classList.toggle('hidden', t !== curVcpu);
  });

  const memMap = { 1: '4 GB', 2: '8 GB', 4: '16 GB', 8: '32 GB' };
  if (btn) {
    const sameTier = curVcpu > 0 && selVcpu === curVcpu;
    btn.disabled = !checked || sameTier;
    if (hint) {
      hint.textContent = sameTier
        ? `VM sudah memakai spek ${curVcpu} vCPU · ${memMap[curVcpu] || ''}. Pilih ukuran lain untuk resize.`
        : `Siap ubah spek ke ${selVcpu} vCPU · ${memMap[selVcpu] || ''} (efektif saat running/stopped).`;
    }
  }
}

function renderVmManageState(data) {
  const m = data.machine || {};
  const cfg = data.vmConfig || m.vmConfig || {};
  const insp = data.inspection || null;
  const statusInfo = getMachineStatusInfo(m);
  const statusUpper = statusInfo.statusText || String(m.status || 'unknown').toUpperCase();

  document.getElementById('manageTargetName').textContent = m.name || '-';
  document.getElementById('manageTargetMeta').textContent = `${m.accountLabel || ''} · ${String(m.region || 'fra').toUpperCase()} · ${statusUpper}`;

  const badge = document.getElementById('manageAutoUpdBadge');
  const autoOn = !!(cfg.autoUpdateEnabled || (insp && (insp.timerEnabled || insp.timerActive)));
  const intervalHrs = cfg.autoUpdateIntervalHours || 12;

  if (autoOn) {
    badge.textContent = `AKTIF · TIAP ${intervalHrs}J`;
    badge.className = 'stat-subpill badge-green-soft font-mono';
  } else if (insp && insp.reachable && !insp.aptCacheReady) {
    badge.textContent = 'APT CACHE KOSONG';
    badge.className = 'stat-subpill badge-amber font-mono';
  } else {
    badge.textContent = 'NONAKTIF';
    badge.className = 'stat-subpill font-mono';
  }

  document.getElementById('manageAutoUpdateToggle').checked = autoOn;
  const intervalSel = document.getElementById('manageAutoUpdateInterval');
  if (intervalSel) {
    const targetVal = String(intervalHrs);
    if (Array.from(intervalSel.options).some(o => o.value === targetVal)) {
      intervalSel.value = targetVal;
    }
  }
  document.getElementById('manageAutoUpdateRuntimes').checked = cfg.autoUpdateRuntimes !== false;

  const osSummaryEl = document.getElementById('manageOsSummary');
  const upgEl = document.getElementById('manageUpgradableCount');
  const lastUpdEl = document.getElementById('manageLastUpdateInfo');
  const diskUptimeEl = document.getElementById('manageDiskUptime');
  const toolsEl = document.getElementById('manageInstalledTools');

  if (insp && insp.reachable) {
    osSummaryEl.textContent = `${insp.os || 'Linux'} · Kernel ${insp.kernel || '-'}`;
    if (!insp.aptCacheReady) {
      upgEl.textContent = 'Cache kosong (perlu refresh)';
    } else if (insp.upgradableCount === 0) {
      upgEl.textContent = '0 (Mutakhir)';
    } else {
      upgEl.textContent = `${insp.upgradableCount} paket`;
    }
    diskUptimeEl.textContent = `${insp.disk || '-'} · ${insp.uptime || '-'}`;
    if (Array.isArray(insp.tools) && insp.tools.length > 0) {
      toolsEl.textContent = `Tools aktif: ${insp.tools.join(', ')}`;
      toolsEl.classList.remove('hidden');
    } else {
      toolsEl.classList.add('hidden');
    }
  } else {
    osSummaryEl.textContent = m.status === 'running'
      ? 'VM running tetapi agen inspeksi belum merespons.'
      : `VM berstatus ${statusUpper}. Klik "Update Sekarang" atau simpan jadwal untuk menyalakan VM otomatis & update.`;
    upgEl.textContent = '-';
    diskUptimeEl.textContent = '-';
    toolsEl.classList.add('hidden');
  }

  if (cfg.lastUpdateAt) {
    const tStr = new Date(cfg.lastUpdateAt).toLocaleString('id-ID', {
      day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
    });
    lastUpdEl.textContent = `${tStr}${cfg.lastUpdateSummary ? ' · ' + cfg.lastUpdateSummary : ''}`;
  } else {
    lastUpdEl.textContent = 'Belum pernah';
  }

  // Starter kits
  const kits = Array.isArray(data.starterKits) ? data.starterKits : [];
  const installedKits = Array.isArray(cfg.starterKits) ? cfg.starterKits : [];
  const kitsGrid = document.getElementById('manageStarterKitsGrid');
  kitsGrid.innerHTML = kits.map(kit => {
    const isInstalled = installedKits.includes(kit.id);
    return `
      <label class="kit-card">
        <input type="checkbox" name="manageStarterKit" value="${escapeAttr(kit.id)}">
        <div style="min-width: 0; flex: 1;">
          <div class="kit-card-title">
            <span>${escapeHTML(kit.label)}</span>
            ${isInstalled ? '<span class="mc-mode-chip is-always-on">TERPASANG</span>' : ''}
          </div>
          <div class="kit-card-desc font-mono">${escapeHTML(kit.desc)}</div>
        </div>
      </label>
    `;
  }).join('');

  // Power & Spec tab
  const alwaysOnPill = document.getElementById('manageAlwaysOnStatusPill');
  const isAlwaysOn = !!m.alwaysOn && String(m.botProtectionMode || '').toLowerCase() === 'off';
  if (alwaysOnPill) {
    alwaysOnPill.textContent = isAlwaysOn ? 'AKTIF' : 'OFF';
    alwaysOnPill.className = isAlwaysOn ? 'stat-subpill badge-green-soft font-mono' : 'stat-subpill font-mono';
  }
  document.getElementById('manageSuspendInput').value = m.autoSuspendTimeout !== undefined ? m.autoSuspendTimeout : 300;
  document.getElementById('manageHibernateInput').value = m.autoHibernateTimeout !== undefined ? m.autoHibernateTimeout : 14400;
  document.getElementById('manageBotProtectionSelect').value = m.botProtectionMode || 'on';
  document.getElementById('manageIdleIgnoreOutbound').checked = !!m.idleIgnoreOutbound;
  syncQuickIdleChips();
  const vcpuVal = String((m.resources && m.resources.vcpu) || 1);
  const tierRadio = document.querySelector(`input[name="manageResizeTier"][value="${vcpuVal}"]`);
  if (tierRadio) tierRadio.checked = true;
  syncResizeButtonState();

  // Network tab
  const domain = (m.access && m.access.domain) || `${m.region || 'fra'}.boxd.sh`;
  const proxies = Array.isArray(data.proxies) ? data.proxies : [];
  const defaultProxy = proxies.find(p => p.isDefault || !p.name);
  const defaultPortInput = document.getElementById('manageDefaultProxyPortInput');
  if (defaultPortInput) {
    if (defaultProxy) {
      defaultPortInput.value = defaultProxy.portMode === 'auto' ? 'auto' : String(defaultProxy.port || 'auto');
    } else {
      defaultPortInput.value = 'auto';
    }
  }

  const proxiesListEl = document.getElementById('manageProxiesList');
  if (proxies.length === 0) {
    proxiesListEl.innerHTML = `<div class="font-mono text-muted" style="font-size: 10.5px;">Belum ada subdomain proxy tambahan. Default URL: https://${escapeHTML(m.name)}.${escapeHTML(domain)}</div>`;
  } else {
    proxiesListEl.innerHTML = proxies.map(p => {
      const pDomain = p.domain || (p.name ? `${p.name}.${m.name}.${domain}` : `${m.name}.${domain}`);
      const pUrl = p.url || `https://${pDomain}`;
      const isDef = !!(p.isDefault || !p.name);
      const portLabel = p.portMode === 'auto'
        ? `auto${p.port ? ` (aktif :${p.port})` : ''}`
        : String(p.port || '-');
      return `
        <div class="manage-item-row">
          <div class="manage-item-info">
            <div class="manage-item-main font-mono">${escapeHTML(pUrl)}</div>
            <div class="manage-item-sub font-mono">Target port: ${escapeHTML(portLabel)}${isDef ? ' · Default' : ` · Subdomain "${escapeHTML(p.name)}"`}</div>
          </div>
          <div class="manage-item-actions">
            <a href="${escapeAttr(pUrl)}" target="_blank" rel="noopener" class="ep-btn">Visit ↗</a>
            ${!isDef && p.name ? `<button type="button" class="ep-btn danger" onclick="handleDeleteNamedProxy('${escapeAttr(p.name)}')">Hapus</button>` : ''}
          </div>
        </div>
      `;
    }).join('');
  }

  const ports = Array.isArray(data.ports) ? data.ports : [];
  const portsListEl = document.getElementById('managePortsList');
  if (ports.length === 0) {
    portsListEl.innerHTML = `<div class="font-mono text-muted" style="font-size: 10.5px;">Belum ada port TCP/UDP yang diekspos.</div>`;
  } else {
    portsListEl.innerHTML = ports.map(pt => {
      const vmPort = Number(pt.machinePort !== undefined ? pt.machinePort : (pt.internalPort !== undefined ? pt.internalPort : 0));
      const targetStr = `${pt.dns || `${m.name}.${domain}`}:${pt.publicPort}`;
      const isSsh = vmPort === 22;
      return `
        <div class="manage-item-row">
          <div class="manage-item-info">
            <div class="manage-item-main font-mono">:${escapeHTML(String(vmPort))} (${escapeHTML(String(pt.protocol || 'tcp').toUpperCase())}) → ${escapeHTML(targetStr)}</div>
            <div class="manage-item-sub font-mono">${isSsh ? 'Port SSH VM' : 'Port Forward Aktif'}</div>
          </div>
          <div class="manage-item-actions">
            <button type="button" class="ep-btn" onclick="copyToClipboard('${escapeAttr(targetStr)}', 'Endpoint disalin')">Copy</button>
            <button type="button" class="ep-btn danger" onclick="handleUnexposePort(${vmPort}, ${isSsh})">Tutup</button>
          </div>
        </div>
      `;
    }).join('');
  }

  // Snapshots tab
  const snaps = Array.isArray(data.snapshots) ? data.snapshots : [];
  const snapsListEl = document.getElementById('manageSnapshotsList');
  if (snaps.length === 0) {
    snapsListEl.innerHTML = `<div class="font-mono text-muted" style="font-size: 10.5px;">Belum ada snapshot di region ${escapeHTML(String(m.region || 'fra').toUpperCase())}.</div>`;
  } else {
    snapsListEl.innerHTML = snaps.map(sn => {
      const sName = sn.name || sn.id;
      const sizeStr = sn.sizeBytes ? `${(sn.sizeBytes / (1024 * 1024 * 1024)).toFixed(2)} GB` : '';
      const statusStr = sn.status ? ` · ${String(sn.status).toUpperCase()}` : '';
      const canDeploy = !sn.archived && (!sn.status || sn.status === 'ready');
      return `
        <div class="manage-item-row">
          <div class="manage-item-info">
            <div class="manage-item-main font-mono">${escapeHTML(sName)}</div>
            <div class="manage-item-sub font-mono">${escapeHTML(String(sn.region || m.region || 'fra').toUpperCase())}${sizeStr ? ' · ' + escapeHTML(sizeStr) : ''}${escapeHTML(statusStr)}</div>
          </div>
          <div class="manage-item-actions">
            <button type="button" class="ep-btn" ${canDeploy ? '' : 'disabled style="opacity:0.5;cursor:not-allowed;"'} onclick="handleDeployFromSnapshot('${escapeAttr(sName)}')">Deploy VM</button>
            <button type="button" class="ep-btn danger" onclick="handleDeleteVmSnapshot('${escapeAttr(sName)}')">Hapus</button>
          </div>
        </div>
      `;
    }).join('');
  }

  // Active or latest job
  const jobs = Array.isArray(data.jobs) ? data.jobs : [];
  const runningJob = jobs.find(j => j.status === 'running');
  if (runningJob) {
    renderManageJob(runningJob);
    startManageJobPolling(runningJob.id);
  } else if (jobs.length > 0 && !appState.manageJobPoller) {
    renderManageJob(jobs[0]);
  }
}

function renderManageJob(job) {
  if (!job) return;
  const card = document.getElementById('vmManageJobCard');
  const title = document.getElementById('manageJobTitle');
  const meta = document.getElementById('manageJobMeta');
  const badge = document.getElementById('manageJobStatusBadge');
  const logBox = document.getElementById('manageJobLogBox');

  card.classList.remove('hidden');
  title.textContent = job.title || 'VM TASK LOG';
  const elapsed = Math.max(0, Math.round(((job.finishedAt || Date.now()) - job.startedAt) / 1000));
  meta.textContent = `Fase: ${job.phase || '-'} · Durasi: ${elapsed}s${job.error ? ' · ' + job.error : ''}`;

  const st = String(job.status || 'running').toUpperCase();
  badge.textContent = st;
  badge.className = st === 'SUCCESS'
    ? 'stat-subpill badge-green-soft font-mono'
    : st === 'ERROR'
      ? 'stat-subpill status-rose font-mono'
      : 'stat-subpill status-amber font-mono';

  logBox.textContent = job.output || (job.status === 'running' ? 'Menjalankan di dalam VM...' : '(Tidak ada output)');
  logBox.scrollTop = logBox.scrollHeight;
}

function startManageJobPolling(jobId) {
  clearManageJobPoller();
  const poll = async () => {
    if (!appState.manageTarget) {
      clearManageJobPoller();
      return;
    }
    try {
      const res = await apiFetch(`/api/jobs/${encodeURIComponent(jobId)}`);
      const data = await res.json();
      if (res.ok && data.success && data.job) {
        renderManageJob(data.job);
        if (data.job.status !== 'running') {
          clearManageJobPoller();
          showToast(
            data.job.status === 'success'
              ? `${data.job.title} selesai!`
              : `${data.job.title} gagal: ${data.job.error || 'error'}`,
            data.job.status === 'success' ? 'success' : 'error'
          );
          await refreshVmManageState();
          await fetchDashboardData({ silent: true });
        }
      }
    } catch (e) {}
  };
  poll();
  appState.manageJobPoller = setInterval(poll, 2000);
}

async function handleSaveVmAutoUpdate() {
  if (!appState.manageTarget) return;
  const btn = document.getElementById('manageSaveAutoUpdateBtn');
  const enabled = document.getElementById('manageAutoUpdateToggle').checked;
  const intervalHours = parseInt(document.getElementById('manageAutoUpdateInterval').value, 10) || 12;
  const updateRuntimes = document.getElementById('manageAutoUpdateRuntimes').checked;
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  btn.textContent = 'Menyimpan...';
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/autoupdate/config`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, enabled, intervalHours, updateRuntimes })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(enabled ? `Auto-update aktif tiap ${intervalHours} jam` : 'Auto-update dinonaktifkan', 'success');
      await refreshVmManageState();
      await fetchDashboardData({ silent: true });
    } else {
      showToast(`Gagal atur auto-update: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Simpan Jadwal';
  }
}

async function handleRunVmUpdateNow() {
  if (!appState.manageTarget) return;
  const btn = document.getElementById('manageRunUpdateNowBtn');
  const intervalHours = parseInt(document.getElementById('manageAutoUpdateInterval').value, 10) || 12;
  const updateRuntimes = document.getElementById('manageAutoUpdateRuntimes').checked;
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  btn.textContent = 'Memulai...';
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/autoupdate/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, intervalHours, updateRuntimes })
    });
    const data = await res.json();
    if (res.ok && data.success && data.jobId) {
      showToast('Update OS & runtime dimulai di background', 'info');
      renderManageJob(data.job);
      startManageJobPolling(data.jobId);
    } else {
      showToast(`Gagal memulai update: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Update Sekarang';
  }
}

async function handleInstallStarterKits() {
  if (!appState.manageTarget) return;
  const starterKits = Array.from(document.querySelectorAll('input[name="manageStarterKit"]:checked')).map(el => el.value);
  if (starterKits.length === 0) {
    showToast('Centang minimal satu starter stack untuk di-install', 'error');
    return;
  }

  const btn = document.getElementById('manageInstallKitsBtn');
  const { accountId, machineId, region } = appState.manageTarget;
  btn.disabled = true;
  btn.textContent = 'Memulai...';

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/packages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, starterKits })
    });
    const data = await res.json();
    if (res.ok && data.success && data.jobId) {
      showToast('Instalasi starter stack dimulai', 'info');
      document.querySelectorAll('input[name="manageStarterKit"]:checked').forEach(el => { el.checked = false; });
      renderManageJob(data.job);
      startManageJobPolling(data.jobId);
    } else {
      showToast(`Gagal install stack: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Install Stack';
  }
}

async function handleInstallCustomPackages(e) {
  e.preventDefault();
  if (!appState.manageTarget) return;
  const pkgType = document.getElementById('manageCustomPkgType').value;
  const rawInput = document.getElementById('manageCustomPkgInput').value.trim();
  if (!rawInput) return;

  const btn = document.getElementById('manageInstallCustomBtn');
  const { accountId, machineId, region } = appState.manageTarget;
  btn.disabled = true;
  btn.textContent = 'Memulai...';

  try {
    const payload = {
      accountId,
      region,
      aptPackages: pkgType === 'apt' ? rawInput : [],
      npmPackages: pkgType === 'npm' ? rawInput : []
    };
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/packages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok && data.success && data.jobId) {
      showToast(`Instalasi paket ${pkgType.toUpperCase()} dimulai`, 'info');
      document.getElementById('manageCustomPkgInput').value = '';
      renderManageJob(data.job);
      startManageJobPolling(data.jobId);
    } else {
      showToast(`Gagal install paket: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Install';
  }
}

function setManageIdleVal(inputId, val) {
  const el = document.getElementById(inputId);
  if (el) el.value = String(val);
  syncQuickIdleChips();
}

async function handleEnableAlwaysOnMode() {
  if (!appState.manageTarget) return;
  const btn = document.getElementById('manageAlwaysOnBtn');
  const { accountId, machineId, region } = appState.manageTarget;
  btn.disabled = true;
  btn.textContent = 'Mengaktifkan...';

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/runtime-settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, alwaysOn: true })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Mode Sepuasnya (Always-On + Bot Off) aktif!', 'success');
      await refreshVmManageState();
      await fetchDashboardData({ silent: true });
    } else {
      showToast(`Gagal mengaktifkan Always-On: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Aktifkan Always-On';
  }
}

async function handleSaveRuntimeSettings(e) {
  e.preventDefault();
  if (!appState.manageTarget) return;
  const btn = document.getElementById('manageSaveRuntimeBtn');
  const { accountId, machineId, region } = appState.manageTarget;

  const autoSuspendTimeout = parseInt(document.getElementById('manageSuspendInput').value, 10) || 0;
  const autoHibernateTimeout = parseInt(document.getElementById('manageHibernateInput').value, 10) || 0;
  const botProtectionMode = document.getElementById('manageBotProtectionSelect').value;
  const idleIgnoreOutbound = document.getElementById('manageIdleIgnoreOutbound').checked;

  btn.disabled = true;
  btn.textContent = 'Menyimpan...';
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/runtime-settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId,
        region,
        autoSuspendTimeout,
        autoHibernateTimeout,
        botProtectionMode,
        idleIgnoreOutbound
      })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Pengaturan idle & proteksi web disimpan', 'success');
      await refreshVmManageState();
      await fetchDashboardData({ silent: true });
    } else {
      showToast(`Gagal menyimpan: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Simpan Pengaturan';
  }
}

async function handleResizeVm() {
  if (!appState.manageTarget) return;
  const checked = document.querySelector('input[name="manageResizeTier"]:checked');
  if (!checked) return;
  const vcpu = parseInt(checked.value, 10);
  const memMap = { 1: '4G', 2: '8G', 4: '16G', 8: '32G' };
  const memory = memMap[vcpu] || '4G';
  const btn = document.getElementById('manageResizeBtn');
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  btn.textContent = 'Mengubah spek...';
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/resize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, vcpu, memory })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`VM di-resize ke ${vcpu} vCPU · ${memory}`, 'success');
      await refreshVmManageState();
      await fetchDashboardData({ silent: true });
    } else {
      showToast(`Gagal resize: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Terapkan Resize';
  }
}

async function handleSetDefaultProxyPort(e) {
  e.preventDefault();
  if (!appState.manageTarget) return;
  const raw = document.getElementById('manageDefaultProxyPortInput').value.trim();
  const port = raw.toLowerCase() === 'auto' ? 'auto' : parseInt(raw, 10);
  const btn = document.getElementById('manageDefaultProxyPortBtn');
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/proxies/default-port`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, port })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Default web route diatur ke port ${port}`, 'success');
      await refreshVmManageState();
    } else {
      showToast(`Gagal atur route: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function handleCreateNamedProxy(e) {
  e.preventDefault();
  if (!appState.manageTarget) return;
  const name = document.getElementById('manageNewProxyName').value.trim().toLowerCase();
  const port = parseInt(document.getElementById('manageNewProxyPort').value, 10);
  const btn = document.getElementById('manageCreateProxyBtn');
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/proxies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, name, port })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Subdomain "${name}" -> port ${port} dibuat`, 'success');
      document.getElementById('manageNewProxyName').value = '';
      document.getElementById('manageNewProxyPort').value = '';
      await refreshVmManageState();
    } else {
      showToast(`Gagal membuat subdomain: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function handleDeleteNamedProxy(name) {
  if (!appState.manageTarget) return;
  const { accountId, machineId, region } = appState.manageTarget;
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/proxies/${encodeURIComponent(name)}?accountId=${encodeURIComponent(accountId)}&region=${encodeURIComponent(region || 'fra')}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Subdomain "${name}" dihapus`, 'info');
      await refreshVmManageState();
    } else {
      showToast(`Gagal hapus: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleExposePort(e) {
  e.preventDefault();
  if (!appState.manageTarget) return;
  const port = parseInt(document.getElementById('manageExposePortInput').value, 10);
  const protocol = document.getElementById('manageExposeProtoSelect').value;
  const btn = document.getElementById('manageExposePortBtn');
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/ports`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region, port, protocol })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Port ${port}/${protocol} diekspos!`, 'success');
      document.getElementById('manageExposePortInput').value = '';
      await refreshVmManageState();
    } else {
      showToast(`Gagal expose port: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
}

async function handleUnexposePort(port, isSsh) {
  if (!appState.manageTarget) return;
  if (isSsh && !confirm('Port 22 dipakai untuk SSH Password. Yakin ingin menutup port 22?')) {
    return;
  }
  const { accountId, machineId, region } = appState.manageTarget;
  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(machineId)}/ports/${encodeURIComponent(port)}?accountId=${encodeURIComponent(accountId)}&region=${encodeURIComponent(region || 'fra')}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Port ${port} ditutup`, 'info');
      await refreshVmManageState();
    } else {
      showToast(`Gagal tutup port: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleCreateVmSnapshot(e) {
  e.preventDefault();
  if (!appState.manageTarget) return;
  const name = document.getElementById('manageSnapNameInput').value.trim();
  if (!name) return;
  const btn = document.getElementById('manageCreateSnapBtn');
  const { accountId, machineId, region } = appState.manageTarget;

  btn.disabled = true;
  btn.textContent = 'Menyimpan...';
  try {
    const res = await apiFetch('/api/snapshots', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, machineId, name, region })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Snapshot "${name}" dibuat`, 'success');
      document.getElementById('manageSnapNameInput').value = '';
      await refreshVmManageState();
    } else {
      showToast(`Gagal buat snapshot: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = '+ Buat Snapshot';
  }
}

async function handleDeployFromSnapshot(snapshotName) {
  if (!appState.manageTarget) return;
  const { accountId, region } = appState.manageTarget;
  const defaultNewName = `${snapshotName}-${Math.floor(10 + Math.random() * 89)}`.slice(0, 32);
  const vmName = prompt(`Nama VM baru dari snapshot "${snapshotName}" (opsional):`, defaultNewName);
  if (vmName === null) return;

  showToast(`Mendeploy VM dari snapshot "${snapshotName}"...`, 'info');
  try {
    const res = await apiFetch('/api/machines/from-snapshot', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId,
        fromSnapshot: snapshotName,
        name: vmName.trim() || undefined,
        region,
        shared: true,
        alwaysOn: false
      })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`VM "${data.machine.name}" berhasil dideploy dari snapshot!`, 'success');
      closeVmManageModal();
      await fetchDashboardData({ silent: true });
    } else {
      showToast(`Gagal deploy snapshot: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleDeleteVmSnapshot(snapshotName) {
  if (!appState.manageTarget) return;
  if (!confirm(`Hapus snapshot "${snapshotName}" permanen?`)) return;
  const { accountId, region } = appState.manageTarget;
  try {
    const res = await apiFetch(`/api/snapshots/${encodeURIComponent(snapshotName)}?accountId=${encodeURIComponent(accountId)}&region=${encodeURIComponent(region || 'fra')}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Snapshot "${snapshotName}" dihapus`, 'info');
      await refreshVmManageState();
    } else {
      showToast(`Gagal hapus snapshot: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

// ================= EXEC / TERMINAL MODAL =================

function openExecModal(accountId, machineId, name, accountLabel, region) {
  appState.execTarget = { machineId, name, accountId, accountLabel, region };
  document.getElementById('execTargetName').textContent = name;
  document.getElementById('execTargetAccount').textContent = accountLabel;
  document.getElementById('execModal').classList.remove('hidden');
  document.getElementById('execCmdInput').focus();
}

function closeExecModal() {
  document.getElementById('execModal').classList.add('hidden');
  appState.execTarget = null;
}

function setExecCmd(cmd) {
  const input = document.getElementById('execCmdInput');
  input.value = cmd;
  input.focus();
}

async function handleRunExec(e) {
  e.preventDefault();
  if (!appState.execTarget) return;

  const input = document.getElementById('execCmdInput');
  const cmd = input.value.trim();
  if (!cmd) return;

  const btn = document.getElementById('execSubmitBtn');
  const screen = document.getElementById('execOutputScreen');

  btn.disabled = true;
  btn.innerHTML = '<span>Running...</span>';

  const cmdLine = document.createElement('div');
  cmdLine.style.color = '#7DB89E';
  cmdLine.style.marginTop = '6px';
  cmdLine.textContent = `$ ${cmd}`;
  screen.appendChild(cmdLine);

  try {
    const res = await apiFetch(`/api/machines/${encodeURIComponent(appState.execTarget.machineId)}/exec`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId: appState.execTarget.accountId,
        command: cmd,
        region: appState.execTarget.region
      })
    });
    const data = await res.json();

    const outParts = [];
    if (data.stdout) outParts.push(data.stdout.trimEnd());
    if (data.stderr) outParts.push(data.stderr.trimEnd());
    const combinedOut = outParts.join('\n');

    const resultBlock = document.createElement('div');
    resultBlock.style.color = data.success ? '#e2e8f0' : '#f87171';
    resultBlock.textContent = combinedOut || (data.success ? '(Selesai tanpa output)' : data.error);
    screen.appendChild(resultBlock);

    if (!data.success && combinedOut) {
      let fixLabel = null;
      let fixCmd = null;
      if (/Unable to locate package/i.test(combinedOut)) {
        fixLabel = '⚡ Cache APT kosong — Klik untuk isi sudo apt-get update';
        fixCmd = 'sudo apt-get update';
      } else if (/Permission denied|are you root/i.test(combinedOut) && !/^sudo\s+/i.test(cmd)) {
        fixLabel = '↻ Ulangi perintah pakai sudo';
        fixCmd = `sudo ${cmd}`;
      } else if (/Do you want to continue|Abort\./i.test(combinedOut) && !/\s-y\b/.test(cmd)) {
        fixLabel = '↻ Ulangi non-interaktif (-y)';
        fixCmd = `${/^sudo\s+/i.test(cmd) ? '' : 'sudo '}${cmd} -y`;
      }
      if (fixLabel && fixCmd) {
        const hintBtn = document.createElement('button');
        hintBtn.type = 'button';
        hintBtn.className = 'cmd-pill';
        hintBtn.style.marginTop = '6px';
        hintBtn.textContent = fixLabel;
        hintBtn.onclick = () => {
          setExecCmd(fixCmd);
          document.getElementById('execForm').requestSubmit();
        };
        screen.appendChild(hintBtn);
      }
    }

    screen.scrollTop = screen.scrollHeight;
    input.value = '';
  } catch (err) {
    const errBlock = document.createElement('div');
    errBlock.style.color = '#f87171';
    errBlock.textContent = `Error: ${err.message}`;
    screen.appendChild(errBlock);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Jalankan</span>';
  }
}

// ================= ADD ACCOUNT MODAL =================

function openAddAccountModal() {
  document.getElementById('addAccountModal').classList.remove('hidden');
  document.getElementById('accLabelInput').focus();
}

function closeAddAccountModal() {
  document.getElementById('addAccountModal').classList.add('hidden');
}

async function handleAddAccount(e) {
  e.preventDefault();
  const btn = document.getElementById('addAccountBtn');
  btn.disabled = true;
  btn.innerHTML = '<span>Memverifikasi Key...</span>';

  const label = document.getElementById('accLabelInput').value.trim();
  const apiKey = document.getElementById('accKeyInput').value.trim();
  const notes = document.getElementById('accNotesInput').value.trim();

  try {
    const res = await apiFetch('/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, apiKey, notes })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`Akun "${label}" berhasil diverifikasi (${(data.account.key_scope || '').toUpperCase()} key)`, 'success');
      closeAddAccountModal();
      document.getElementById('addAccountForm').reset();
      await fetchDashboardData();
    } else {
      showToast(`Validasi gagal: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Simpan Akun</span>';
  }
}

async function syncAccount(id) {
  showToast('Menyinkronkan data akun dari Boxd...', 'info');
  try {
    const res = await apiFetch(`/api/accounts/${encodeURIComponent(id)}/sync`, { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Akun berhasil disinkronkan', 'success');
      await fetchDashboardData();
    } else {
      showToast(`Gagal sync: ${data.error}`, 'error');
      await fetchDashboardData();
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function deleteAccount(id, label) {
  if (!confirm(`Hapus akun "${label}" dari panel ini?\n(API Key akan dihapus dari server lokal)`)) {
    return;
  }

  try {
    const res = await apiFetch(`/api/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Akun "${label}" dihapus`, 'info');
      if (appState.selectedAccountId === id) {
        appState.selectedAccountId = 'all';
      }
      await fetchDashboardData();
    } else {
      showToast(`Gagal menghapus: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

// ================= UTILITIES =================

function copyToClipboard(text, msg = 'Tersalin!') {
  navigator.clipboard.writeText(text).then(() => {
    showToast(msg, 'success');
  }).catch(() => {
    showToast('Gagal menyalin otomatis', 'error');
  });
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const toast = document.createElement('div');
  toast.className = `toast ${type === 'success' ? 'success' : type === 'error' ? 'error' : ''}`;
  toast.textContent = message;
  toast.title = 'Klik untuk tutup';
  toast.onclick = () => toast.remove();
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-8px)';
    setTimeout(() => toast.remove(), 200);
  }, 2800);
}

function escapeHTML(str) {
  if (!str && str !== 0) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(str) {
  if (!str && str !== 0) return '';
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'")
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ================= EXTERNAL API WORKSPACE & KEYS =================

let apiWorkspaceState = {
  apiEnabled: true,
  ipWhitelistEnabled: false,
  currentIp: '-',
  allowedIps: [],
  keys: [],
  logs: [],
  activeDocTab: 'create'
};

function getApiBaseUrl() {
  return `${window.location.origin}/api/v1`;
}

async function loadApiWorkspace() {
  const baseEl = document.getElementById('apiBaseUrlDisplay');
  if (baseEl) baseEl.textContent = getApiBaseUrl();
  renderApiDocSnippet();

  try {
    const res = await apiFetch('/api/security/api-config');
    const data = await res.json();
    if (res.ok && data.success) {
      apiWorkspaceState = {
        ...apiWorkspaceState,
        apiEnabled: !!data.apiEnabled,
        ipWhitelistEnabled: !!data.ipWhitelistEnabled,
        currentIp: data.currentIp || '-',
        allowedIps: Array.isArray(data.allowedIps) ? data.allowedIps : [],
        keys: Array.isArray(data.keys) ? data.keys : [],
        logs: Array.isArray(data.logs) ? data.logs : []
      };
      renderApiWorkspace();
    }
  } catch (err) {
    console.error('Failed to load API workspace:', err);
  }
}

function renderApiWorkspace() {
  const masterBadge = document.getElementById('apiMasterStatusBadge');
  const masterBtn = document.getElementById('apiMasterToggleBtn');
  if (masterBadge) {
    masterBadge.textContent = apiWorkspaceState.apiEnabled ? 'AKTIF' : 'NONAKTIF';
    masterBadge.className = `stat-subpill font-mono ${apiWorkspaceState.apiEnabled ? 'badge-green-soft' : ''}`;
  }
  if (masterBtn) {
    masterBtn.textContent = apiWorkspaceState.apiEnabled ? 'Matikan' : 'Aktifkan';
    masterBtn.className = `action-btn ${apiWorkspaceState.apiEnabled ? 'danger' : 'primary'}`;
  }

  const ipBadge = document.getElementById('apiIpStatusBadge');
  const ipBtn = document.getElementById('apiIpToggleBtn');
  const curIpEl = document.getElementById('apiCurrentIpDisplay');
  const allowSelfBtn = document.getElementById('apiAllowMyIpBtn');

  if (curIpEl) curIpEl.textContent = apiWorkspaceState.currentIp || '-';
  const ips = apiWorkspaceState.allowedIps || [];
  const selfAllowed = ips.some(i => Boolean(i.matchesCurrent) || i.ip === apiWorkspaceState.currentIp);

  if (allowSelfBtn) {
    if (selfAllowed) {
      allowSelfBtn.textContent = '✓ Sudah Diizinkan';
      allowSelfBtn.className = 'stat-subpill badge-green-soft font-mono';
      allowSelfBtn.disabled = true;
    } else {
      allowSelfBtn.textContent = '+ Izinkan IP Ini';
      allowSelfBtn.className = 'btn-stark-cta btn-sm-cta';
      allowSelfBtn.disabled = false;
    }
  }

  if (ipBadge) {
    ipBadge.textContent = apiWorkspaceState.ipWhitelistEnabled ? 'AKTIF' : 'NONAKTIF';
    ipBadge.className = `stat-subpill font-mono ${apiWorkspaceState.ipWhitelistEnabled ? 'badge-green-soft' : ''}`;
  }
  if (ipBtn) {
    ipBtn.textContent = apiWorkspaceState.ipWhitelistEnabled ? 'Matikan' : 'Aktifkan';
    ipBtn.className = `action-btn ${apiWorkspaceState.ipWhitelistEnabled ? 'danger' : 'primary'}`;
  }

  // Allowed IPs Table
  const ipBody = document.getElementById('apiAllowedIpsBody');
  if (ipBody) {
    if (ips.length === 0) {
      ipBody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 12px; color: var(--text-muted);">Belum ada IP terdaftar untuk API.</td></tr>';
    } else {
      ipBody.innerHTML = ips.map(item => {
        const isCurrent = Boolean(item.matchesCurrent) || item.ip === apiWorkspaceState.currentIp;
        return `
          <tr>
            <td style="font-weight: 700; color: var(--text-primary); font-size: 11px;">
              ${escapeHTML(item.ip)}
              ${isCurrent ? '<span class="stat-subpill badge-green-soft" style="font-size: 9.5px; margin-left: 5px;">INI</span>' : ''}
            </td>
            <td style="color: var(--text-secondary); font-size: 11px;">${escapeHTML(item.label || '-')}</td>
            <td style="text-align: right;">
              <button type="button" class="ep-btn danger" onclick="handleDeleteApiIp(${Number(item.id)}, '${escapeAttr(item.ip)}')">Hapus</button>
            </td>
          </tr>
        `;
      }).join('');
    }
  }

  // Keys List
  const keys = apiWorkspaceState.keys || [];
  const countBadge = document.getElementById('apiKeysCountBadge');
  if (countBadge) countBadge.textContent = `${keys.length} key`;

  const keysList = document.getElementById('apiKeysList');
  if (keysList) {
    if (keys.length === 0) {
      keysList.innerHTML = `
        <div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 12px;">
          Belum ada API key. Klik <strong>+ Buat Key Baru</strong> untuk mulai mengotomatiskan deploy &amp; kontrol VM.
        </div>
      `;
    } else {
      keysList.innerHTML = keys.map(k => {
        const isExpired = k.expiresAt && Date.now() > k.expiresAt;
        let statusPill = '<span class="status-pill status-green font-mono">AKTIF</span>';
        if (isExpired) statusPill = '<span class="status-pill status-rose font-mono">EXPIRED</span>';
        else if (!k.enabled) statusPill = '<span class="status-pill status-neutral font-mono">PAUSED</span>';

        const ipBadgeText = Array.isArray(k.allowedIps) && k.allowedIps.length > 0
          ? `IP Lock: ${k.allowedIps.length} rule`
          : 'Ikuti Firewall Global';
        const accText = Array.isArray(k.allowedAccountIds) && !k.allowedAccountIds.includes('*')
          ? `${k.allowedAccountIds.length} akun`
          : 'Semua akun';
        const lastUsedText = k.lastUsedAt
          ? `${new Date(k.lastUsedAt).toLocaleString('id-ID')} · IP ${escapeHTML(k.lastUsedIp || '-')}`
          : 'Belum pernah dipakai';
        const expText = k.expiresAt
          ? `Exp: ${new Date(k.expiresAt).toLocaleDateString('id-ID')}`
          : 'Selamanya';

        return `
          <div class="api-key-card">
            <div class="api-key-top">
              <div class="api-key-title-wrap">
                <span class="api-key-name">${escapeHTML(k.name)}</span>
                <code class="api-key-prefix font-mono">${escapeHTML(k.keyPrefix)}</code>
                ${statusPill}
                ${k.requireHmac ? '<span class="status-pill status-amber font-mono">HMAC-SHA256</span>' : ''}
              </div>
              <div class="api-key-actions">
                <button type="button" class="ep-btn" onclick="openApiKeyModal('${escapeAttr(k.id)}')">Edit</button>
                <button type="button" class="ep-btn" onclick="toggleApiKeyEnabled('${escapeAttr(k.id)}', ${k.enabled ? 'false' : 'true'})">${k.enabled ? 'Pause' : 'Aktifkan'}</button>
                <button type="button" class="ep-btn" onclick="rotateApiKeySecret('${escapeAttr(k.id)}', '${escapeAttr(k.name)}')">Rotate</button>
                <button type="button" class="ep-btn danger" onclick="deleteApiKeyItem('${escapeAttr(k.id)}', '${escapeAttr(k.name)}')">Hapus</button>
              </div>
            </div>
            <div class="api-key-badges font-mono">
              <span class="stat-subpill">${escapeHTML(ipBadgeText)}</span>
              <span class="stat-subpill">${escapeHTML(accText)}</span>
              ${(k.scopes || []).map(sc => `<span class="stat-subpill badge-sky-soft">${escapeHTML(sc)}</span>`).join('')}
            </div>
            <div class="api-key-bottom font-mono">
              <span>${Number(k.rateLimitRpm || 60)} req/mnt · Max ${k.maxDeployPerHour === 0 ? '∞' : k.maxDeployPerHour} VM/jam · ≤${k.maxVcpuPerVm || 8} vCPU · ${escapeHTML(expText)}</span>
              <span>${Number(k.requestCount || 0)} req · ${lastUsedText}</span>
            </div>
          </div>
        `;
      }).join('');
    }
  }

  // Request Logs
  const logsBody = document.getElementById('apiLogsTableBody');
  const logs = apiWorkspaceState.logs || [];
  if (logsBody) {
    if (logs.length === 0) {
      logsBody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 14px; color: var(--text-muted);">Belum ada request masuk ke /api/v1.</td></tr>';
    } else {
      logsBody.innerHTML = logs.map(log => {
        const timeStr = new Date(log.timestamp).toLocaleString('id-ID', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const st = Number(log.status_code || 0);
        const cls = st >= 500 || st === 401 || st === 403 ? 'status-rose' : (st >= 400 ? 'status-amber' : 'status-green');
        const keyLabel = escapeHTML(log.key_name || '—');
        const ipLabel = escapeHTML(log.ip || '-');
        return `
          <tr>
            <td class="api-log-time-cell" style="font-size: 10.5px; color: var(--text-muted);">${escapeHTML(timeStr)}</td>
            <td class="api-log-hide-mob" style="font-size: 11px; font-weight: 700;">${keyLabel}</td>
            <td style="font-size: 11px; word-break: break-word;">
              <div><strong>${escapeHTML(log.method)}</strong> ${escapeHTML(log.path)}</div>
              <div class="api-log-mob-meta">${keyLabel} · ${ipLabel}</div>
            </td>
            <td class="api-log-hide-mob" style="font-size: 11px; color: var(--text-secondary); white-space: nowrap;">${ipLabel}</td>
            <td style="text-align: right; white-space: nowrap;"><span class="status-pill ${cls}" style="font-size: 10px;">${st}</span></td>
          </tr>
        `;
      }).join('');
    }
  }
}

function copyApiBaseUrl() {
  copyToClipboard(getApiBaseUrl(), 'Base URL API tersalin!');
}

function switchApiDocTab(tab) {
  apiWorkspaceState.activeDocTab = tab;
  ['create', 'control', 'hmac'].forEach(t => {
    const btn = document.getElementById(`apiDocTabBtn-${t}`);
    if (btn) btn.classList.toggle('active', t === tab);
  });
  renderApiDocSnippet();
}

function renderApiDocSnippet() {
  const base = getApiBaseUrl();
  const titleEl = document.getElementById('apiDocTitleLabel');
  const boxEl = document.getElementById('apiDocCodeBox');
  if (!boxEl) return;

  const tab = apiWorkspaceState.activeDocTab || 'create';
  if (tab === 'create') {
    if (titleEl) titleEl.textContent = 'POST /api/v1/vms (Generate VM + Auto SSH + Always-On)';
    boxEl.textContent = `curl -X POST "${base}/vms" \\
  -H "Authorization: Bearer bfk_live_YOUR_KEY" \\
  -H "Idempotency-Key: deploy-vm-001" \\
  -H "Content-Type: application/json" \\
  -d '{
    "name": "worker-01",
    "vcpu": 2,
    "memory": "8G",
    "region": "fra",
    "preset": "always_on",
    "autoGenerateSshPassword": true,
    "autoSetup": { "enableAutoUpdate": true }
  }'`;
  } else if (tab === 'control') {
    if (titleEl) titleEl.textContent = 'POST /api/v1/vms/:id/exec & /action';
    boxEl.textContent = `# Jalankan perintah di dalam VM
curl -X POST "${base}/vms/VM_ID/exec" \\
  -H "X-API-Key: bfk_live_YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{ "command": "uptime && uname -a" }'

# Kontrol lifecycle: start | stop | resume | pause | hibernate | reboot
curl -X POST "${base}/vms/VM_ID/action" \\
  -H "X-API-Key: bfk_live_YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{ "action": "reboot" }'`;
  } else {
    if (titleEl) titleEl.textContent = 'Keamanan Extra: HMAC-SHA256 Anti-Replay';
    boxEl.textContent = `TS=$(date +%s)
BODY='{"vcpu":1,"memory":"4G","preset":"always_on"}'
BODY_HASH=$(printf "%s" "$BODY" | sha256sum | awk '{print $1}')
CANON="\${TS}.POST./api/v1/vms.\${BODY_HASH}"
SIG=$(printf "%s" "$CANON" | openssl dgst -sha256 -hmac "bfk_sec_YOUR_SECRET" | awk '{print $2}')

curl -X POST "${base}/vms" \\
  -H "Authorization: Bearer bfk_live_YOUR_KEY" \\
  -H "X-API-Timestamp: $TS" \\
  -H "X-API-Signature: $SIG" \\
  -H "Content-Type: application/json" -d "$BODY"`;
  }
}

function copyApiDocSnippet() {
  const boxEl = document.getElementById('apiDocCodeBox');
  if (boxEl) copyToClipboard(boxEl.textContent, 'Contoh API tersalin!');
}

async function toggleApiMasterSwitch() {
  const next = !apiWorkspaceState.apiEnabled;
  try {
    const res = await apiFetch('/api/security/api-config/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(next ? 'API eksternal (/api/v1) diaktifkan.' : 'API eksternal (/api/v1) dimatikan.', 'info');
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal mengubah status API', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function toggleApiIpFirewall() {
  const next = !apiWorkspaceState.ipWhitelistEnabled;
  try {
    const res = await apiFetch('/api/security/api-ips/toggle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(next ? 'API Allowed IP Firewall aktif — hanya IP terdaftar yang bisa akses /api/v1.' : 'API Allowed IP Firewall dimatikan.', 'info');
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal mengubah filter IP API', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function allowMyApiIp() {
  try {
    const res = await apiFetch('/api/security/api-ips/allow-my-ip', { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`IP ${data.currentIp} diizinkan untuk API!`, 'success');
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal mendaftarkan IP', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleAddApiAllowedIp(e) {
  e.preventDefault();
  const ipEl = document.getElementById('newApiIpInput');
  const lblEl = document.getElementById('newApiIpLabel');
  if (!ipEl || !ipEl.value.trim()) return;
  try {
    const res = await apiFetch('/api/security/api-ips', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: ipEl.value.trim(), label: lblEl ? lblEl.value.trim() : '' })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`IP ${ipEl.value.trim()} ditambahkan ke API Allowed IP.`, 'success');
      ipEl.value = '';
      if (lblEl) lblEl.value = '';
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal menambah IP', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function handleDeleteApiIp(id, ip) {
  if (!confirm(`Hapus ${ip} dari daftar API Allowed IP?`)) return;
  try {
    const res = await apiFetch(`/api/security/api-ips/${Number(id)}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`IP ${ip} dihapus dari API Allowed IP.`, 'info');
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal menghapus IP', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

function renderApiKeyModalAccounts(selectedIds = ['*']) {
  const allCheck = document.getElementById('akAllAccountsCheck');
  const container = document.getElementById('akAccountsList');
  if (!allCheck || !container) return;

  const isAll = !Array.isArray(selectedIds) || selectedIds.length === 0 || selectedIds.includes('*');
  allCheck.checked = isAll;
  container.classList.toggle('hidden', isAll);

  const selectedSet = new Set(isAll ? [] : selectedIds);
  const accounts = appState.accounts || [];
  container.innerHTML = accounts.map(acc => `
    <label class="api-check-pill">
      <input type="checkbox" name="akAccountId" value="${escapeAttr(acc.id)}" ${selectedSet.has(acc.id) ? 'checked' : ''}>
      <span>${escapeHTML(acc.label)}</span>
    </label>
  `).join('') || '<span class="text-muted font-mono" style="font-size: 11px;">Belum ada akun terdaftar.</span>';
}

function onAkAllAccountsToggle() {
  const allCheck = document.getElementById('akAllAccountsCheck');
  const container = document.getElementById('akAccountsList');
  if (allCheck && container) {
    container.classList.toggle('hidden', allCheck.checked);
  }
}

function applyApiScopePreset(preset) {
  let scopes = ['vm:read', 'vm:create', 'vm:control'];
  if (preset === 'full') scopes = ['vm:read', 'vm:create', 'vm:control', 'vm:exec', 'vm:delete'];
  else if (preset === 'readonly') scopes = ['vm:read'];
  const set = new Set(scopes);
  document.querySelectorAll('input[name="akScope"]').forEach(cb => {
    cb.checked = set.has(cb.value);
  });
}

function openApiKeyModal(keyId = null) {
  const modal = document.getElementById('apiKeyModal');
  if (!modal) return;

  const existing = keyId ? (apiWorkspaceState.keys || []).find(k => k.id === keyId) : null;
  document.getElementById('apiKeyEditId').value = existing ? existing.id : '';
  document.getElementById('apiKeyModalTitle').textContent = existing ? `Edit API Key: ${existing.name}` : 'Buat API Key Baru';
  document.getElementById('akNameInput').value = existing ? existing.name : '';
  document.getElementById('akAllowedIpsInput').value = existing && Array.isArray(existing.allowedIps) ? existing.allowedIps.join('\n') : '';
  document.getElementById('akRequireHmacCheckbox').checked = existing ? !!existing.requireHmac : false;
  document.getElementById('akRateLimitInput').value = existing ? (existing.rateLimitRpm || 60) : 60;
  document.getElementById('akMaxDeployInput').value = existing && existing.maxDeployPerHour !== undefined ? existing.maxDeployPerHour : 10;
  document.getElementById('akMaxVcpuInput').value = String(existing ? (existing.maxVcpuPerVm || 8) : 8);
  document.getElementById('akExpiresSelect').value = 'never';

  const activeScopes = new Set(existing && Array.isArray(existing.scopes) ? existing.scopes : ['vm:read', 'vm:create', 'vm:control']);
  document.querySelectorAll('input[name="akScope"]').forEach(cb => {
    cb.checked = activeScopes.has(cb.value);
  });

  renderApiKeyModalAccounts(existing ? existing.allowedAccountIds : ['*']);
  modal.classList.remove('hidden');
}

function closeApiKeyModal() {
  const modal = document.getElementById('apiKeyModal');
  if (modal) modal.classList.add('hidden');
}

function openApiSecretRevealModal({ title, rawKey, rawHmacSecret }) {
  const modal = document.getElementById('apiSecretRevealModal');
  if (!modal) return;
  document.getElementById('apiRevealTitle').textContent = title || 'API Key Siap Digunakan';

  const keyGroup = document.getElementById('revealRawKeyGroup');
  const keyVal = document.getElementById('revealRawKeyVal');
  if (rawKey) {
    keyGroup.classList.remove('hidden');
    keyVal.textContent = rawKey;
  } else {
    keyGroup.classList.add('hidden');
  }

  const hmacGroup = document.getElementById('revealRawHmacGroup');
  const hmacVal = document.getElementById('revealRawHmacVal');
  if (rawHmacSecret) {
    hmacGroup.classList.remove('hidden');
    hmacVal.textContent = rawHmacSecret;
  } else {
    hmacGroup.classList.add('hidden');
  }

  modal.classList.remove('hidden');
}

function closeApiSecretRevealModal() {
  const modal = document.getElementById('apiSecretRevealModal');
  if (modal) modal.classList.add('hidden');
  document.getElementById('revealRawKeyVal').textContent = '-';
  document.getElementById('revealRawHmacVal').textContent = '-';
}

async function handleSaveApiKey(e) {
  e.preventDefault();
  const editId = document.getElementById('apiKeyEditId').value.trim();
  const scopes = Array.from(document.querySelectorAll('input[name="akScope"]:checked')).map(cb => cb.value);
  const allAccounts = document.getElementById('akAllAccountsCheck').checked;
  const allowedAccountIds = allAccounts
    ? ['*']
    : Array.from(document.querySelectorAll('input[name="akAccountId"]:checked')).map(cb => cb.value);

  const payload = {
    name: document.getElementById('akNameInput').value.trim(),
    scopes,
    allowedAccountIds,
    allowedIps: document.getElementById('akAllowedIpsInput').value,
    requireHmac: document.getElementById('akRequireHmacCheckbox').checked,
    rateLimitRpm: parseInt(document.getElementById('akRateLimitInput').value, 10) || 60,
    maxDeployPerHour: parseInt(document.getElementById('akMaxDeployInput').value, 10),
    maxVcpuPerVm: parseInt(document.getElementById('akMaxVcpuInput').value, 10) || 8
  };

  const expiresChoice = document.getElementById('akExpiresSelect').value;
  if (!editId || expiresChoice !== 'never') {
    payload.expiresDays = expiresChoice;
  }

  const saveBtn = document.getElementById('akSaveBtn');
  saveBtn.disabled = true;
  try {
    const url = editId ? `/api/api-keys/${encodeURIComponent(editId)}` : '/api/api-keys';
    const method = editId ? 'PATCH' : 'POST';
    const res = await apiFetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (res.ok && data.success) {
      closeApiKeyModal();
      await loadApiWorkspace();
      if (data.rawKey || data.rawHmacSecret) {
        openApiSecretRevealModal({
          title: editId ? 'HMAC Secret Baru Dibuat' : 'API Key Baru Berhasil Dibuat',
          rawKey: data.rawKey || null,
          rawHmacSecret: data.rawHmacSecret || null
        });
      } else {
        showToast('Pengaturan API Key berhasil diperbarui.', 'success');
      }
    } else {
      showToast(data.error || 'Gagal menyimpan API Key', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    saveBtn.disabled = false;
  }
}

async function toggleApiKeyEnabled(keyId, nextEnabled) {
  try {
    const res = await apiFetch(`/api/api-keys/${encodeURIComponent(keyId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !!nextEnabled })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(nextEnabled ? 'API Key diaktifkan.' : 'API Key dijeda.', 'info');
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal mengubah status key', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function rotateApiKeySecret(keyId, name) {
  if (!confirm(`Rotate key "${name}"?\nKey lama akan langsung tidak berlaku begitu diganti.`)) return;
  try {
    const res = await apiFetch(`/api/api-keys/${encodeURIComponent(keyId)}/rotate`, { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      await loadApiWorkspace();
      openApiSecretRevealModal({
        title: `Key "${name}" Berhasil Di-rotate`,
        rawKey: data.rawKey,
        rawHmacSecret: data.rawHmacSecret
      });
    } else {
      showToast(data.error || 'Gagal rotate key', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}

async function deleteApiKeyItem(keyId, name) {
  if (!confirm(`Hapus permanen API Key "${name}"? Semua script yang memakai key ini akan langsung gagal.`)) return;
  try {
    const res = await apiFetch(`/api/api-keys/${encodeURIComponent(keyId)}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`API Key "${name}" dihapus.`, 'info');
      loadApiWorkspace();
    } else {
      showToast(data.error || 'Gagal menghapus key', 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  }
}
