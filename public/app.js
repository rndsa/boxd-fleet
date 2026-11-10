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
  statusFilter: 'all',
  searchQuery: ''
};

// Init
document.addEventListener('DOMContentLoaded', () => {
  initNeoTheme();
  checkAuth();
});

// ================= FETCH HELPER WITH AUTH GUARD =================

async function apiFetch(url, options = {}) {
  const res = await fetch(url, options);
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
    icon.textContent = isDark ? '🌙' : '☀️';
    label.textContent = isDark ? 'DARK' : 'LIGHT';
  }
}

function toggleNeoTheme() {
  const currentTheme = localStorage.getItem('boxd_neo_theme') || 'light';
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  applyNeoTheme(newTheme);
}

// ================= AUTHENTICATION =================

async function checkAuth() {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const keyParam = urlParams.get('key');
    let endpoint = '/api/auth/status';
    if (keyParam) {
      endpoint += `?key=${encodeURIComponent(keyParam)}`;
    }

    const res = await fetch(endpoint);
    const data = await res.json();
    if (res.ok && data.authenticated) {
      if (keyParam) {
        window.history.replaceState({}, document.title, window.location.pathname);
      }
      showDashboard();
      return;
    }
  } catch (err) {
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
}

function showPinGate() {
  appState.authenticated = false;
  const gate = document.getElementById('securityGate');
  const app = document.getElementById('appContainer');
  if (gate) gate.classList.remove('hidden');
  if (app) app.classList.add('hidden');
  const input = document.getElementById('pinInput');
  if (input) {
    input.value = '';
    setTimeout(() => input.focus(), 100);
  }
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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pin })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast('Autentikasi berhasil! Sesi aktif 30 hari.', 'success');
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
      submitBtn.innerHTML = '<span>BUKA KONSOL →</span>';
    }
  }
}

async function handleLogout() {
  try {
    await fetch('/api/auth/logout', { method: 'POST' });
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
  const tbody = document.getElementById('allowedIpsTableBody');

  if (detectedIpEl) {
    detectedIpEl.textContent = ipWhitelistState.currentIp || '-';
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
    if (!ipWhitelistState.allowedIps || ipWhitelistState.allowedIps.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 10px; color: var(--text-muted);">Belum ada IP terdaftar.</td></tr>';
      return;
    }

    tbody.innerHTML = ipWhitelistState.allowedIps.map(item => {
      const isCurrent = item.ip === ipWhitelistState.currentIp;
      return `
        <tr>
          <td style="font-weight: 700; color: var(--text-primary); font-size: 11px;">
            ${escapeHTML(item.ip)}
            ${isCurrent ? '<span class="stat-subpill badge-green-soft" style="font-size: 8px; margin-left: 4px;">INI</span>' : ''}
          </td>
          <td style="color: var(--text-secondary); font-size: 10.5px;">${escapeHTML(item.label || '-')}</td>
          <td style="text-align: right;">
            <button class="action-btn danger" style="padding: 2px 8px; font-size: 9.5px;" onclick="handleDeleteAllowedIp(${Number(item.id)}, '${escapeAttr(item.ip)}')">Hapus</button>
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
      showToast(newStatus ? 'Batasan IP diaktifkan! Hanya IP terdaftar yang dapat mengakses.' : 'Batasan IP dinonaktifkan.', 'info');
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

async function handleDeleteAllowedIp(id, ip) {
  if (!confirm(`Hapus IP "${ip}" dari daftar izin?`)) return;

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

  const tabs = ['overview', 'machines', 'panduan', 'accounts', 'telemetry'];
  tabs.forEach(t => {
    const btn = document.getElementById(`tabBtn-${t}`);
    const content = document.getElementById(`tabContent-${t}`);

    if (btn) btn.classList.toggle('active', t === tabId);
    if (content) content.classList.toggle('active', t === tabId);
  });

  if (tabId === 'telemetry' || tabId === 'accounts' || tabId === 'overview') {
    fetchTelemetryData();
  }
}

// ================= DATA FETCHING & RECONCILIATION =================

async function fetchDashboardData() {
  const syncBtn = document.getElementById('syncTelemetryBtn');
  if (syncBtn) syncBtn.classList.add('is-spinning');

  try {
    await Promise.allSettled([
      fetchAccounts(),
      fetchMachines(),
      fetchTelemetryData()
    ]);
    renderOverviewWidgets();
  } finally {
    if (syncBtn) {
      setTimeout(() => syncBtn.classList.remove('is-spinning'), 500);
    }
  }
}

async function fetchAccounts() {
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
    showToast('Gagal memuat akun: ' + err.message, 'error');
  }
}

async function fetchMachines() {
  const grid = document.getElementById('machinesGrid');
  const emptyState = document.getElementById('emptyMachinesState');

  if (emptyState) emptyState.classList.add('hidden');
  if (grid) {
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
      appState.machines = data.machines || [];
      renderMachines();
      updateMachineStats();
    } else {
      if (grid) grid.innerHTML = '';
      showToast('Gagal memuat mesin: ' + data.error, 'error');
    }
  } catch (err) {
    appState.machinesLoaded = true;
    if (grid) grid.innerHTML = '';
    showToast('Gagal memuat mesin: ' + err.message, 'error');
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
}

function getFilteredMachinesList(applyStatusFilter = true) {
  let list = appState.machines || [];

  if (applyStatusFilter && appState.statusFilter !== 'all') {
    list = list.filter(m => {
      if (appState.statusFilter === 'running') return m.status === 'running';
      if (appState.statusFilter === 'hibernated') return m.status === 'hibernated';
      if (appState.statusFilter === 'suspended') return ['suspended', 'paused'].includes(m.status);
      if (appState.statusFilter === 'stopped') return ['stopped', 'failed'].includes(m.status);
      if (appState.statusFilter === 'private') return !m.accessible;
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

function renderOverviewWidgets() {
  const machines = appState.machines || [];
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

  // 1. Machine & Resource metrics
  const totalVms = machines.length;
  const controllableVms = machines.filter(m => m.accessible).length;
  const privateVms = machines.filter(m => !m.accessible).length;

  let totalAllocatedVcpu = 0;
  let totalAllocatedRamBytes = 0;
  machines.forEach(m => {
    totalAllocatedVcpu += (m.resources && m.resources.vcpu) || 0;
    totalAllocatedRamBytes += (m.resources && m.resources.memoryBytes) || 0;
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
    if (totalVms > 0) {
      elSyncMeta.textContent = privateVms > 0
        ? `${controllableVms} Shared · ${privateVms} Private`
        : `${controllableVms} VM Aktif`;
    } else {
      elSyncMeta.textContent = '';
    }
  }

  // Update KPI Cards
  const elQuota = document.getElementById('overviewStatQuota');
  if (elQuota) elQuota.textContent = `${quotaCap} VM`;

  const elQuotaBadge = document.getElementById('overviewStatQuotaBadge');
  if (elQuotaBadge) elQuotaBadge.textContent = appState.machinesLoaded ? `${totalVms} Terpakai` : 'Memuat...';

  const elVcpu = document.getElementById('overviewStatVcpu');
  if (elVcpu) elVcpu.textContent = appState.machinesLoaded ? `${totalAllocatedVcpu} vCPU` : '—';

  const elRamBadge = document.getElementById('overviewStatRamBadge');
  if (elRamBadge) elRamBadge.textContent = appState.machinesLoaded ? `${totalRamGb} GB RAM` : '—';

  const elBalance = document.getElementById('statBalance');
  if (elBalance) elBalance.textContent = `$${totalBalance.toFixed(2)}`;

  const elAccBadge = document.getElementById('overviewStatAccBadge');
  if (elAccBadge) elAccBadge.textContent = `${scopedAccounts.length} Akun`;

  const elSpend = document.getElementById('overviewStatSpend');
  if (elSpend) {
    elSpend.textContent = totalExpenditure > 0 && totalExpenditure < 0.01
      ? `$${totalExpenditure.toFixed(4)}`
      : `$${totalExpenditure.toFixed(2)}`;
  }

  updateScopeNotices(privateVms);

  // 4. Overview Machines List (respecting search query!)
  const overviewList = document.getElementById('overviewMachinesList');
  if (overviewList) {
    const filtered = getFilteredMachinesList(false);
    if (!appState.machinesLoaded && machines.length === 0) {
      overviewList.innerHTML = `<div style="padding: 18px; text-align: center; color: var(--text-muted); font-size: 12px; font-family: var(--font-mono);">Memuat data fleet...</div>`;
    } else if (machines.length === 0) {
      overviewList.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 12px; font-weight: 700;">Belum ada microVM. Buka tab Machines untuk deploy VM baru.</div>`;
    } else if (filtered.length === 0) {
      overviewList.innerHTML = `<div style="padding: 20px; text-align: center; color: var(--text-muted); font-size: 12px; font-weight: 700;">Tidak ada VM yang cocok dengan "${escapeHTML(appState.searchQuery)}".</div>`;
    } else {
      overviewList.innerHTML = `<div class="machines-grid">${filtered.map((m, idx) => createMachineCardHTML(m, idx)).join('')}</div>`;
    }
  }
}

function updateScopeNotices(privateCount) {
  const html = privateCount > 0
    ? `🔒 <strong>${privateCount} VM private read-only:</strong> API key tipe ORG tidak bisa mengontrol VM private. Pakai Member Key atau aktifkan <em>Share with Org</em> saat deploy.`
    : '';

  ['overviewScopeNotice', 'machinesScopeNotice'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    if (privateCount > 0) {
      el.className = 'scope-banner';
      el.innerHTML = html;
    } else {
      el.className = 'hidden';
      el.innerHTML = '';
    }
  });
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
    vmOpt.textContent = `${acc.label} (${acc.masked_key})${scopeTag}`;
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

  const list = getFilteredMachinesList(true);

  if (list.length === 0) {
    grid.innerHTML = '';
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  grid.innerHTML = list.map((m, idx) => createMachineCardHTML(m, idx)).join('');
}

function createMachineCardHTML(m) {
  const isAccessible = m.accessible !== false;
  const isRunning = m.status === 'running';
  const isSuspended = ['suspended', 'paused'].includes(m.status);
  const isHibernated = m.status === 'hibernated';
  const isRemote = m.status === 'remote';
  const region = (m.region || 'fra').toUpperCase();

  let statusClass = 'stopped';
  let statusText = 'STOPPED';
  let badgeClass = 'status-neutral';

  if (isRunning) {
    statusClass = 'running';
    statusText = 'RUNNING';
    badgeClass = 'status-green';
  } else if (isSuspended) {
    statusClass = 'suspended';
    statusText = 'STANDBY';
    badgeClass = 'status-amber';
  } else if (isHibernated) {
    statusClass = 'hibernated';
    statusText = 'HIBERNATED';
    badgeClass = 'status-neutral';
  } else if (isRemote) {
    statusClass = 'remote';
    statusText = 'ACTIVE';
    badgeClass = 'status-sky';
  }

  const domain = (m.access && m.access.domain) || `${region.toLowerCase()}.boxd.sh`;
  const sshPort = m.access ? m.access.sshPort : null;
  const sshCmd = sshPort ? `ssh -p ${sshPort} root@${domain}` : `boxd machine ssh ${m.name}`;
  const url = (m.access && m.access.url) || `https://${m.name}.${domain}`;
  const vcpu = (m.resources && m.resources.vcpu) || 1;
  const memHuman = (m.resources && m.resources.memoryHuman) || '4 GB';
  const scopeLabel = m.shared ? 'SHARED' : 'PRIVATE';
  const costText = m.cost > 0 ? `$${m.cost >= 0.01 ? m.cost.toFixed(2) : m.cost.toFixed(4)}` : '';
  const costChip = costText ? `<span class="mc-cost-inline font-mono">${costText}</span>` : '';

  const safeAccId = escapeAttr(m.accountId);
  const safeId = escapeAttr(m.id);
  const safeName = escapeAttr(m.name);
  const safeLabel = escapeAttr(m.accountLabel);
  const safeRegion = escapeAttr(m.region || 'fra');

  return `
    <div class="machine-card ${isAccessible ? 'is-ctrl' : 'is-readonly'}" id="card-${escapeHTML(m.id)}">
      <div class="mc-top">
        <div class="mc-title-area">
          <div style="display: flex; align-items: center; gap: 7px; min-width: 0;">
            <span class="status-indicator ${statusClass}"></span>
            <span class="mc-name font-mono">${escapeHTML(m.name)}</span>
          </div>
          <div style="display: flex; align-items: center; gap: 6px; flex-shrink: 0;">
            ${costChip}
            <span class="status-pill ${badgeClass} font-mono">${escapeHTML(statusText)}</span>
          </div>
        </div>
        <div class="mc-specs-row">
          <span class="spec-pill spec-acc" title="${escapeHTML(m.accountLabel)}">${escapeHTML(m.accountLabel)}</span>
          <span class="spec-pill font-mono">${escapeHTML(region)}</span>
          <span class="spec-pill font-mono">${scopeLabel}</span>
          <span class="spec-pill font-mono">${vcpu} vCPU · ${escapeHTML(memHuman)}</span>
        </div>
      </div>

      ${isAccessible ? `
        <div class="mc-endpoints">
          <div class="endpoint-item" onclick="copyToClipboard('${escapeAttr(sshCmd)}', 'SSH disalin')">
            <span class="endpoint-protocol">SSH</span>
            <span class="endpoint-value font-mono">${escapeHTML(sshCmd)}</span>
            <span class="ep-btn tag-blue">Copy</span>
          </div>

          <div class="endpoint-item">
            <span class="endpoint-protocol">WEB</span>
            <a href="${escapeHTML(url)}" target="_blank" rel="noopener" class="endpoint-link">
              <span class="endpoint-value font-mono">${escapeHTML(m.name)}.${escapeHTML(domain)}</span>
            </a>
            <a href="${escapeHTML(url)}" target="_blank" rel="noopener" class="ep-btn tag-amber">Visit ↗</a>
          </div>

          ${m.access && m.access.desktopUrl ? `
            <div class="endpoint-item">
              <span class="endpoint-protocol">GUI</span>
              <a href="${escapeHTML(m.access.desktopUrl)}" target="_blank" rel="noopener" class="endpoint-link">
                <span class="endpoint-value font-mono">Desktop Web Shell</span>
              </a>
              <a href="${escapeHTML(m.access.desktopUrl)}" target="_blank" rel="noopener" class="ep-btn tag-blue">Open ↗</a>
            </div>
          ` : ''}
        </div>

        <div class="mc-bottom">
          <div class="mc-actions-left">
            ${isRunning ? `
              <button class="action-btn" onclick="doMachineAction('${safeAccId}', '${safeId}', 'pause', '${safeRegion}')">⏸ Pause</button>
              <button class="action-btn" onclick="doMachineAction('${safeAccId}', '${safeId}', 'hibernate', '${safeRegion}')">❄ Hibernate</button>
            ` : `
              <button class="action-btn primary" onclick="doMachineAction('${safeAccId}', '${safeId}', '${isSuspended ? 'resume' : isHibernated ? 'wake' : 'start'}', '${safeRegion}')">▶ Start</button>
            `}
            <button class="action-btn" onclick="openExecModal('${safeAccId}', '${safeId}', '${safeName}', '${safeLabel}', '${safeRegion}')">&gt;_ Console</button>
          </div>
          <button class="action-btn danger" onclick="confirmDeleteMachine('${safeAccId}', '${safeId}', '${safeName}', '${safeRegion}')">✕ Delete</button>
        </div>
      ` : `
        <div class="mc-bottom mc-readonly-bar">
          <span class="mc-readonly-tag font-mono">🔒 Read-only · ORG Key</span>
          <button class="btn-mc-action" onclick="selectAndFilterAccount('${safeAccId}')">Akun →</button>
        </div>
      `}
    </div>
  `;
}

// ================= RENDER MULTI-ACCOUNT HUB =================

let accountSearchQuery = '';

function filterAccountsHub() {
  const input = document.getElementById('accountSearchInput');
  accountSearchQuery = input ? input.value.toLowerCase().trim() : '';
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

  let list = sourceList;
  if (accountSearchQuery) {
    list = list.filter(item => {
      const acc = item.account || {};
      const org = item.org || {};
      return (acc.label && acc.label.toLowerCase().includes(accountSearchQuery)) ||
             (acc.displayName && acc.displayName.toLowerCase().includes(accountSearchQuery)) ||
             (acc.userId && acc.userId.toLowerCase().includes(accountSearchQuery)) ||
             (acc.maskedKey && acc.maskedKey.toLowerCase().includes(accountSearchQuery)) ||
             (org.name && org.name.toLowerCase().includes(accountSearchQuery));
    });
  }

  if (list.length === 0) {
    container.innerHTML = `<div class="text-dim" style="padding: 24px;">Tidak ada akun yang cocok dengan kata kunci pencarian.</div>`;
    return;
  }

  container.innerHTML = list.map((item) => {
    const acc = item.account || {};
    const org = item.org || {};
    const billing = item.billing || {};
    const usage = item.usage || {};
    const machinesCount = item.machinesCount || 0;
    const maxVms = acc.maxVms || 100;
    const quotaPct = maxVms > 0 ? Math.min(100, Math.round((machinesCount / maxVms) * 100)) : 0;

    const balanceVal = typeof billing.balance === 'number' ? billing.balance : 0;
    const costVal = typeof usage.totalCost === 'number' ? usage.totalCost : 0;
    const balanceFormatted = balanceVal.toFixed(2);
    const totalCostFormatted = costVal > 0 && costVal < 0.01 ? costVal.toFixed(4) : costVal.toFixed(2);

    const hasError = !!item.error || acc.status === 'invalid' || acc.status === 'error';
    const statusClass = hasError ? 'status-rose' : 'status-green';
    const statusText = hasError ? (acc.status === 'invalid' ? 'INVALID' : 'ERROR') : 'AKTIF';

    const scope = (acc.keyScope || 'unknown').toUpperCase();
    const scopeBadge = scope === 'ORG'
      ? `<span class="status-pill status-amber font-mono">ORG</span>`
      : scope === 'MEMBER'
      ? `<span class="status-pill status-sky font-mono">MEMBER</span>`
      : '';

    const regionsStr = Array.isArray(acc.enabledRegions) && acc.enabledRegions.length > 0
      ? acc.enabledRegions.map(r => r.toUpperCase()).join(', ')
      : String(acc.homeRegion || 'fra').toUpperCase();

    const safeId = escapeAttr(acc.id);
    const safeLabel = escapeAttr(acc.label);

    const metaLine = `${acc.displayName || acc.userId || '-'} · ${acc.maskedKey || ''} · ${regionsStr}`;

    return `
      <div class="account-card">
        <div class="acc-card-top">
          <div style="min-width: 0; flex: 1;">
            <div class="acc-label">${escapeHTML(acc.label)}</div>
            <div class="acc-user-id font-mono" title="${escapeAttr(metaLine)}">${escapeHTML(metaLine)}</div>
          </div>
          <div style="display: flex; align-items: center; gap: 4px; flex-shrink: 0;">
            ${scopeBadge}
            <span class="status-pill ${statusClass} font-mono">${statusText}</span>
          </div>
        </div>

        ${hasError ? `
          <div class="mc-lock-notice" style="border-color: #F43F5E; color: var(--text-primary); background-color: rgba(244, 63, 94, 0.1);">
            ⚠️ ${escapeHTML(item.error || acc.lastError || 'Gagal sinkronisasi akun')}
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
  if (!tbody) return;

  const rows = [];
  scopedAccounts.forEach(accItem => {
    if (accItem.usage && Array.isArray(accItem.usage.machines)) {
      accItem.usage.machines.forEach(m => {
        const hours = (m.runningSeconds / 3600).toFixed(2);
        const costStr = m.cost !== undefined ? `$${m.cost.toFixed(6)}` : '$0.000000';
        const ramHuman = `${Math.round((m.memoryBytes || 0) / (1024 * 1024 * 1024))} GB`;
        const statusRaw = String(m.status || 'active').toUpperCase();
        const regionStr = String(m.region || 'fra').toUpperCase();
        const scopeStr = m.isDeleted ? '' : (m.shared ? ' · SHARED' : ' · PRIVATE');

        let statusClass = 'text-emerald';
        if (m.isDeleted) statusClass = 'text-dim';
        else if (statusRaw === 'REMOTE' || statusRaw === 'PRIVATE') statusClass = 'text-sky';
        else if (statusRaw === 'HIBERNATED' || statusRaw === 'SUSPENDED') statusClass = 'text-amber';

        const uptimeSec = (m.runningSeconds || 0).toLocaleString('en-US');

        rows.push(`
          <tr>
            <td>
              <strong class="font-mono" style="color: var(--text-primary);">${escapeHTML(m.name)}</strong>
              <div style="font-size: 10px; color: var(--text-dim);">${escapeHTML(accItem.account.label)}${escapeHTML(scopeStr)}</div>
            </td>
            <td>
              <span class="font-mono ${statusClass}" style="font-weight: 800;">${escapeHTML(statusRaw)}</span>
              <span style="color: var(--text-dim);"> · ${escapeHTML(regionStr)}</span>
            </td>
            <td>
              <span class="font-mono">${m.vcpu} vCPU · ${ramHuman}</span>
            </td>
            <td>
              <span class="font-mono">${uptimeSec}s (${hours}h)</span>
            </td>
            <td class="num">
              <span class="font-mono">${m.vcpuHours ? m.vcpuHours.toFixed(4) : '0.0000'}</span>
            </td>
            <td class="num">
              <span class="font-mono">${m.ramGibHours ? m.ramGibHours.toFixed(4) : '0.0000'}</span>
            </td>
            <td class="num">
              <strong class="font-mono text-emerald">${costStr}</strong>
            </td>
          </tr>
        `);
      });
    }
  });

  if (rows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">Belum ada riwayat komputasi aktif.</td></tr>`;
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
  btn.disabled = true;
  btn.innerHTML = '<span>Deploying ~2s...</span>';

  const accountId = document.getElementById('vmAccountSelect').value;
  const name = document.getElementById('vmNameInput').value.trim();
  const sizeVal = document.querySelector('input[name="vmSize"]:checked').value;
  const [vcpuStr, memStr] = sizeVal.split('x');
  const region = document.getElementById('vmRegionSelect').value;
  const autoSuspendTimeout = parseInt(document.getElementById('vmSuspendInput').value, 10) || 0;
  const sharedEl = document.getElementById('vmSharedInput');
  const shared = sharedEl ? !!sharedEl.checked : true;

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
        autoSuspendTimeout
      })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`VM "${data.machine.name}" berhasil dideploy!`, 'success');
      closeNewMachineModal();
      document.getElementById('newMachineForm').reset();
      if (sharedEl) sharedEl.checked = true;
      onDeployAccountChange();
      await fetchDashboardData();
    } else {
      showToast(`Gagal membuat VM: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Deploy VM</span>';
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

    const resultBlock = document.createElement('div');
    resultBlock.style.color = data.success ? '#e2e8f0' : '#f87171';
    resultBlock.textContent = data.stdout || data.stderr || (data.success ? '(Selesai tanpa output)' : data.error);
    screen.appendChild(resultBlock);

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
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => toast.remove(), 200);
  }, 3000);
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
