// Boxd Fleet Manager - Ultra Clean Console Controller

// State
let appState = {
  authenticated: false,
  accounts: [],
  machines: [],
  telemetry: null,
  currentTab: 'overview',
  selectedAccountId: 'all',
  execTarget: null,
  statusFilter: 'all',
  searchQuery: ''
};

// Elements
const pinGate = document.getElementById('pinGate');
const appContainer = document.getElementById('appContainer');
const pinInput = document.getElementById('pinInput');
const pinError = document.getElementById('pinError');
const pinSubmitBtn = document.getElementById('pinSubmitBtn');

// Init
document.addEventListener('DOMContentLoaded', () => {
  initNeoTheme();
  checkAuth();
});

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
        // Clean key param from browser address bar to protect against shoulder surfing
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
    const res = await fetch('/api/security/ip-whitelist');
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
    badge.textContent = ipWhitelistState.enabled ? 'AKTIF (TERFILTER)' : 'NONAKTIF';
    badge.className = `trend-badge font-mono ${ipWhitelistState.enabled ? 'badge-green' : 'badge-neutral'}`;
  }

  if (toggleBtn) {
    toggleBtn.textContent = ipWhitelistState.enabled ? 'Nonaktifkan Filter IP' : 'Aktifkan Filter IP';
    toggleBtn.className = `action-btn ${ipWhitelistState.enabled ? 'danger' : 'primary'}`;
  }

  if (tbody) {
    if (!ipWhitelistState.allowedIps || ipWhitelistState.allowedIps.length === 0) {
      tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; padding: 10px; color: var(--text-muted);">Belum ada IP yang terdaftar.</td></tr>';
      return;
    }

    tbody.innerHTML = ipWhitelistState.allowedIps.map(item => {
      const isCurrent = item.ip === ipWhitelistState.currentIp;
      return `
        <tr>
          <td style="font-weight: 700; color: var(--text-primary); font-size: 11px;">
            ${escapeHTML(item.ip)}
            ${isCurrent ? '<span class="trend-badge badge-green" style="font-size: 7px; margin-left: 4px;">IP SAYA</span>' : ''}
          </td>
          <td style="color: var(--text-secondary); font-size: 10.5px;">${escapeHTML(item.label || '-')}</td>
          <td style="text-align: right;">
            <button class="action-btn danger" style="padding: 2px 6px; font-size: 9px;" onclick="handleDeleteAllowedIp(${item.id}, '${escapeHTML(item.ip)}')">✕ Hapus</button>
          </td>
        </tr>
      `;
    }).join('');
  }
}

async function toggleIpWhitelist() {
  const newStatus = !ipWhitelistState.enabled;
  try {
    const res = await fetch('/api/security/ip-whitelist/toggle', {
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
    const res = await fetch('/api/security/ip-whitelist/allow-my-ip', { method: 'POST' });
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
    const res = await fetch('/api/security/ip-whitelist', {
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
    const res = await fetch(`/api/security/ip-whitelist/${encodeURIComponent(id)}`, {
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
    const res = await fetch('/api/audit-logs?limit=15');
    const data = await res.json();
    if (res.ok && data.logs && data.logs.length > 0) {
      tbody.innerHTML = data.logs.map(log => {
        const d = new Date(log.timestamp);
        const timeStr = d.toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const dateStr = d.toLocaleDateString('id-ID', { day: '2-digit', month: '2-digit' });
        const isFail = log.action.includes('FAIL') || log.action.includes('LOCK');
        const badgeClass = isFail ? 'badge-neutral' : 'badge-green';
        const statusText = isFail ? 'BLOCKED' : 'SUCCESS';

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 10px;">${dateStr} ${timeStr}</td>
            <td style="font-weight: 700; color: var(--text-primary); font-size: 11px;">${escapeHTML(log.action)}</td>
            <td style="color: var(--text-secondary); font-size: 10px;">${escapeHTML(log.ip || '-')}</td>
            <td><span class="trend-badge ${badgeClass}" style="font-size: 8px;">${statusText}</span></td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 16px; color: var(--text-muted);">Belum ada log audit tercatat.</td></tr>';
    }
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" style="text-align: center; padding: 16px; color: #F43F5E;">Gagal memuat log: ${err.message}</td></tr>`;
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
    const res = await fetch(`/api/machines/${encodeURIComponent(machineId)}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, region })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`Mesin ${name} berhasil dihapus permanen`, 'info');
      fetchMachines();
      fetchTelemetryData();
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

// ================= DATA FETCHING =================

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
    const res = await fetch('/api/accounts');
    const data = await res.json();
    if (data.success) {
      appState.accounts = data.accounts || [];
      renderAccountSelectors();
      updateAccountStats();
    }
  } catch (err) {
    showToast('Gagal memuat akun: ' + err.message, 'error');
  }
}

async function fetchMachines() {
  const grid = document.getElementById('machinesGrid');
  const emptyState = document.getElementById('emptyMachinesState');

  emptyState.classList.add('hidden');
  grid.innerHTML = `
    <div style="grid-column: 1 / -1; padding: 24px; text-align: center; color: var(--text-dim); font-family: var(--font-mono); font-size: 12px;">
      Memuat daftar microVM...
    </div>
  `;

  try {
    const url = `/api/machines?accountId=${encodeURIComponent(appState.selectedAccountId)}`;
    const res = await fetch(url);
    const data = await res.json();

    if (data.success) {
      appState.machines = data.machines || [];
      renderMachines();
      updateMachineStats();
    } else {
      grid.innerHTML = '';
      showToast('Gagal memuat mesin: ' + data.error, 'error');
    }
  } catch (err) {
    grid.innerHTML = '';
    showToast('Gagal memuat mesin: ' + err.message, 'error');
  }
}

async function fetchTelemetryData() {
  try {
    const res = await fetch('/api/accounts/telemetry');
    const data = await res.json();
    if (data.success) {
      appState.telemetry = data;
      renderAccountsHub();
      renderTelemetryView();
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
  if (countPill) countPill.textContent = `${total} Akun`;

  let totalBalanceMicro = 0;
  for (const acc of appState.accounts) {
    if (acc.balance_micro) {
      totalBalanceMicro += acc.balance_micro;
    }
  }
  const humanBalance = (totalBalanceMicro / 1000000).toFixed(2);
  const elBalance = document.getElementById('statBalance');
  if (elBalance) elBalance.textContent = `$${humanBalance}`;
}

function updateMachineStats() {
  const total = appState.machines.length;
  const running = appState.machines.filter(m => m.status === 'running').length;

  const elRunning = document.getElementById('statRunning');
  const elListCount = document.getElementById('machineListCount');
  const badgeMachines = document.getElementById('tabBadgeMachines');

  if (elRunning) elRunning.textContent = running;
  if (elListCount) elListCount.textContent = `${total} VM`;
  if (badgeMachines) badgeMachines.textContent = total;

  renderOverviewWidgets();
}

function onGlobalSearch() {
  const input = document.getElementById('searchInput');
  if (!input) return;
  const term = input.value.toLowerCase().trim();
  appState.searchQuery = term;
  
  // Filter overview items
  const pItems = document.querySelectorAll('#overviewMachinesList .project-item');
  pItems.forEach(el => {
    const text = el.innerText.toLowerCase();
    el.style.display = text.includes(term) || term === '' ? 'flex' : 'none';
  });

  // Also filter machines tab
  renderMachines();
}

function renderOverviewWidgets() {
  const machines = appState.machines || [];
  const accounts = appState.accounts || [];
  const telemetry = appState.telemetry || {};

  // 1. KPI cards
  const totalVms = machines.length;
  const runningVms = machines.filter(m => m.status === 'running').length;
  const hibernatedVms = machines.filter(m => m.status === 'hibernated').length;
  const standbyVms = machines.filter(m => ['suspended', 'paused'].includes(m.status)).length;
  const auditedCount = (telemetry.summary && telemetry.summary.activeVms !== undefined) ? 4 : (totalVms || 1);

  let totalAllocatedVcpu = 0;
  let totalAllocatedRam = 0;
  machines.forEach(m => {
    totalAllocatedVcpu += (m.resources && m.resources.vcpu) || 0;
    totalAllocatedRam += (m.resources && m.resources.memory) || 0;
  });
  const totalRamGb = Math.round(totalAllocatedRam / 1024);

  let totalBalance = 0;
  if (accounts.length > 0) {
    let b = 0;
    accounts.forEach(a => { if (a.balance_micro) b += a.balance_micro / 1000000; });
    totalBalance = b;
  }

  const quotaCap = accounts.length > 0 ? (accounts[0].max_vms || 100) : 100;

  const elQuota = document.getElementById('overviewStatQuota');
  if (elQuota) elQuota.textContent = `${quotaCap} VM`;

  const elQuotaBadge = document.getElementById('overviewStatQuotaBadge');
  if (elQuotaBadge) elQuotaBadge.textContent = `↗ ${totalVms} Active`;

  const elVcpu = document.getElementById('overviewStatVcpu');
  if (elVcpu) elVcpu.textContent = `${totalAllocatedVcpu} vCPU`;

  const elRamBadge = document.getElementById('overviewStatRamBadge');
  if (elRamBadge) elRamBadge.textContent = `↗ ${totalRamGb} GB RAM`;

  const elBalance = document.getElementById('statBalance');
  if (elBalance) elBalance.textContent = `$${totalBalance.toFixed(2)}`;

  let totalExpenditure = 0;
  if (telemetry.summary && telemetry.summary.totalExpenditure !== undefined) {
    totalExpenditure = telemetry.summary.totalExpenditure;
  }
  const elSpend = document.getElementById('overviewStatSpend');
  if (elSpend) elSpend.textContent = `$${totalExpenditure.toFixed(4)}`;

  // 2. Overview Machines List (Full microVM cards with SSH, Web, & controls)
  const overviewList = document.getElementById('overviewMachinesList');
  if (overviewList) {
    if (machines.length === 0) {
      overviewList.innerHTML = `<div style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 13px; font-weight: 700;">Belum ada microVM yang aktif. Klik "+ NEW VM" untuk deploy instance pertama.</div>`;
    } else {
      overviewList.innerHTML = `<div class="machines-grid">${machines.map((m, idx) => createMachineCardHTML(m, idx)).join('')}</div>`;
    }
  }
}

// ================= RENDERING =================

function renderAccountSelectors() {
  const filterSelect = document.getElementById('accountFilter');
  const vmSelect = document.getElementById('vmAccountSelect');

  const prevFilter = appState.selectedAccountId;
  filterSelect.innerHTML = `<option value="all">All Accounts</option>`;
  vmSelect.innerHTML = '';

  appState.accounts.forEach(acc => {
    const opt = document.createElement('option');
    opt.value = acc.id;
    opt.textContent = `${acc.label} (${acc.org_name || 'Personal'})`;
    filterSelect.appendChild(opt);

    const vmOpt = document.createElement('option');
    vmOpt.value = acc.id;
    vmOpt.textContent = `${acc.label} [${acc.masked_key}]`;
    vmSelect.appendChild(vmOpt);
  });

  if (appState.accounts.some(a => a.id === prevFilter)) {
    filterSelect.value = prevFilter;
  } else {
    filterSelect.value = 'all';
    appState.selectedAccountId = 'all';
  }
}

function onAccountFilterChange() {
  const select = document.getElementById('accountFilter');
  appState.selectedAccountId = select.value;
  fetchMachines();
}

function filterMachines() {
  appState.searchQuery = document.getElementById('searchInput').value.toLowerCase().trim();
  appState.statusFilter = document.getElementById('statusFilter').value;
  renderMachines();
}

function renderMachines() {
  const grid = document.getElementById('machinesGrid');
  const emptyState = document.getElementById('emptyMachinesState');

  let list = appState.machines;

  if (appState.statusFilter !== 'all') {
    list = list.filter(m => {
      if (appState.statusFilter === 'running') return m.status === 'running';
      if (appState.statusFilter === 'suspended') return ['suspended', 'paused'].includes(m.status);
      if (appState.statusFilter === 'hibernated') return m.status === 'hibernated';
      if (appState.statusFilter === 'stopped') return ['stopped', 'failed'].includes(m.status);
      return true;
    });
  }

  if (appState.searchQuery) {
    list = list.filter(m =>
      m.name.toLowerCase().includes(appState.searchQuery) ||
      m.id.toLowerCase().includes(appState.searchQuery) ||
      (m.region && m.region.toLowerCase().includes(appState.searchQuery)) ||
      (m.accountLabel && m.accountLabel.toLowerCase().includes(appState.searchQuery))
    );
  }

  if (list.length === 0) {
    grid.innerHTML = '';
    emptyState.classList.remove('hidden');
    return;
  }

  emptyState.classList.add('hidden');
  grid.innerHTML = list.map((m, idx) => createMachineCardHTML(m, idx)).join('');
}

function createMachineCardHTML(m, index = 0) {
  const isRunning = m.status === 'running';
  const isSuspended = ['suspended', 'paused'].includes(m.status);
  const isHibernated = m.status === 'hibernated';

  let statusClass = 'stopped';
  let statusText = 'STOPPED';
  if (isRunning) { statusClass = 'running'; statusText = 'RUNNING'; }
  else if (isSuspended) { statusClass = 'suspended'; statusText = 'STANDBY'; }
  else if (isHibernated) { statusClass = 'hibernated'; statusText = 'HIBERNATED'; }

  const sshPort = m.access.sshPort || 22;
  const sshCmd = `ssh -p ${sshPort} root@${m.access.domain || 'boxd.sh'}`;
  const url = m.access.url || `https://${m.name}.boxd.sh`;
  const region = (m.region || 'nyc').toUpperCase();

  return `
    <div class="machine-card" id="card-${m.id}">
      <div class="mc-top">
        <div class="mc-title-area">
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="status-indicator ${statusClass}"></span>
            <span class="mc-name font-mono">${escapeHTML(m.name)}</span>
          </div>
          <span class="trend-badge ${isRunning ? 'badge-green' : 'badge-neutral'} font-mono">${statusText}</span>
        </div>
        <div class="mc-specs-row">
          <span class="spec-pill">${escapeHTML(m.accountLabel)}</span>
          <span class="spec-pill font-mono">${escapeHTML(region)}</span>
          <span class="spec-pill font-mono">${m.resources.vcpu} vCPU</span>
          <span class="spec-pill font-mono">${m.resources.memoryHuman || '4 GB'}</span>
        </div>
      </div>

      <div class="mc-endpoints">
        <div class="endpoint-item" onclick="copyToClipboard('${escapeHTML(sshCmd)}', 'Perintah SSH disalin!')">
          <span class="endpoint-protocol">SSH</span>
          <span class="endpoint-value font-mono">${escapeHTML(sshCmd)}</span>
          <span class="time-left-tag tag-blue">[COPY]</span>
        </div>

        <div class="endpoint-item">
          <span class="endpoint-protocol">WEB</span>
          <a href="${escapeHTML(url)}" target="_blank" rel="noopener" class="endpoint-link">
            <span class="endpoint-value font-mono">${escapeHTML(m.name)}.${escapeHTML(m.access.domain || 'boxd.sh')}</span>
          </a>
          <a href="${escapeHTML(url)}" target="_blank" rel="noopener" class="time-left-tag tag-amber" style="text-decoration: none;">[VISIT ↗]</a>
        </div>

        ${m.access.desktopUrl ? `
          <div class="endpoint-item">
            <span class="endpoint-protocol">GUI</span>
            <a href="${escapeHTML(m.access.desktopUrl)}" target="_blank" rel="noopener" class="endpoint-link">
              <span class="endpoint-value font-mono">Desktop Web Shell</span>
            </a>
            <a href="${escapeHTML(m.access.desktopUrl)}" target="_blank" rel="noopener" class="time-left-tag tag-blue" style="text-decoration: none;">[OPEN ↗]</a>
          </div>
        ` : ''}
      </div>

      <div class="mc-bottom">
        ${isRunning ? `
          <button class="action-btn" onclick="doMachineAction('${m.accountId}', '${m.id}', 'pause', '${m.region}')">⏸ Pause</button>
          <button class="action-btn" onclick="openExecModal('${m.accountId}', '${m.id}', '${escapeHTML(m.name)}', '${escapeHTML(m.accountLabel)}', '${m.region}')">&gt;_ Console</button>
          <button class="action-btn danger" onclick="confirmDeleteMachine('${m.accountId}', '${m.id}', '${escapeHTML(m.name)}', '${m.region}')">✕ Delete</button>
        ` : `
          <button class="action-btn primary" onclick="doMachineAction('${m.accountId}', '${m.id}', '${isSuspended ? 'resume' : isHibernated ? 'wake' : 'start'}', '${m.region}')">▶ Start</button>
          <button class="action-btn" onclick="openExecModal('${m.accountId}', '${m.id}', '${escapeHTML(m.name)}', '${escapeHTML(m.accountLabel)}', '${m.region}')">&gt;_ Console</button>
          <button class="action-btn danger" onclick="confirmDeleteMachine('${m.accountId}', '${m.id}', '${escapeHTML(m.name)}', '${m.region}')">✕ Delete</button>
        `}
      </div>
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

  if (!appState.telemetry || !appState.telemetry.accounts || appState.telemetry.accounts.length === 0) {
    container.innerHTML = `<div class="text-dim" style="padding: 24px;">Belum ada akun terhubung.</div>`;
    return;
  }

  let list = appState.telemetry.accounts;
  if (accountSearchQuery) {
    list = list.filter(item => {
      const acc = item.account || {};
      return (acc.label && acc.label.toLowerCase().includes(accountSearchQuery)) ||
             (acc.displayName && acc.displayName.toLowerCase().includes(accountSearchQuery)) ||
             (acc.userId && acc.userId.toLowerCase().includes(accountSearchQuery));
    });
  }

  if (list.length === 0) {
    container.innerHTML = `<div class="text-dim" style="padding: 24px;">Tidak ada akun yang cocok dengan kata kunci pencarian.</div>`;
    return;
  }

  container.innerHTML = list.map((item, idx) => {
    const acc = item.account;
    const org = item.org || {};
    const billing = item.billing || {};
    const usage = item.usage || {};
    const machinesCount = item.machinesCount || 0;
    const maxVms = acc.maxVms || 100;
    const quotaPct = Math.min(100, Math.round((machinesCount / maxVms) * 100));

    const balanceFormatted = billing.balance !== undefined ? billing.balance.toFixed(2) : '0.00';
    const totalCostFormatted = usage.totalCost !== undefined ? usage.totalCost.toFixed(4) : '0.0000';
    const idxStr = String(idx + 1).padStart(2, '0');

    return `
      <div class="account-card">
        <div class="acc-card-top">
          <div>
            <div style="display: flex; align-items: center; gap: 6px;">
              <span class="mc-index-badge">[ACC-${idxStr}]</span>
              <span class="acc-label">${escapeHTML(acc.label)}</span>
            </div>
            <div class="acc-user-id">${escapeHTML(acc.displayName || acc.userId)} // ${escapeHTML(acc.maskedKey || '')}</div>
          </div>
          <span class="acc-status-tag">AUTHENTICATED</span>
        </div>

        <div class="acc-metrics-split">
          <div class="acc-metric-col">
            <span class="acc-metric-lbl">CREDIT BALANCE</span>
            <span class="acc-metric-val text-emerald">$${balanceFormatted}</span>
          </div>
          <div class="acc-metric-col">
            <span class="acc-metric-lbl">COMPUTE EXPENDITURE</span>
            <span class="acc-metric-val">$${totalCostFormatted}</span>
          </div>
        </div>

        <div class="quota-track-wrap">
          <div class="quota-track-header">
            <span>INSTANCE ALLOCATION</span>
            <strong class="font-mono">${machinesCount} / ${maxVms} UNITS (${quotaPct}%)</strong>
          </div>
          <div class="quota-track-bg">
            <div class="quota-track-fill" style="width: ${Math.max(4, quotaPct)}%;"></div>
          </div>
        </div>

        <div class="acc-actions">
          <div style="display: flex;">
            <button class="btn-mc-action" onclick="selectAndFilterAccount('${acc.id}')">
              <span>FILTER INSTANCES</span>
            </button>
            <button class="btn-mc-action" onclick="syncAccount('${acc.id}')">
              <span>SYNC TELEMETRY</span>
            </button>
          </div>
          <button class="btn-mc-action delete" onclick="deleteAccount('${acc.id}', '${escapeHTML(acc.label)}')">
            <span>REVOKE</span>
          </button>
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
}

// ================= RENDER TELEMETRY VIEW =================

function renderTelemetryView() {
  if (!appState.telemetry) return;

  const summary = appState.telemetry.summary || {};
  const elQuota = document.getElementById('telemMaxQuota');
  if (elQuota) elQuota.textContent = `${summary.totalMaxVms || 100} VM`;

  const tbody = document.getElementById('telemetryTableBody');
  if (!tbody) return;

  const rows = [];
  (appState.telemetry.accounts || []).forEach(accItem => {
    if (accItem.usage && Array.isArray(accItem.usage.machines)) {
      accItem.usage.machines.forEach(m => {
        const hours = (m.runningSeconds / 3600).toFixed(2);
        const costStr = m.cost !== undefined ? `$${m.cost.toFixed(6)}` : '$0.00';
        const ramHuman = `${Math.round((m.memoryBytes || 0) / (1024 * 1024 * 1024))} GB`;
        rows.push(`
          <tr>
            <td>
              <strong class="font-mono" style="color: #fff;">${escapeHTML(m.name)}</strong>
              <div style="font-size: 10px; color: var(--text-dim);">${escapeHTML(accItem.account.label)}</div>
            </td>
            <td>
              <span class="font-mono" style="color: var(--tech-green);">${escapeHTML(m.status ? m.status.toUpperCase() : 'ACTIVE')}</span>
              <span style="color: var(--text-dim);"> // ${escapeHTML(m.region ? m.region.toUpperCase() : 'NYC')}</span>
            </td>
            <td>
              <span class="font-mono">${m.vcpu} vCPU / ${ramHuman}</span>
            </td>
            <td>
              <span class="font-mono">${m.runningSeconds}s (${hours}h)</span>
            </td>
            <td>
              <span class="font-mono">${m.vcpuHours ? m.vcpuHours.toFixed(4) : '0.0000'}</span>
            </td>
            <td>
              <span class="font-mono">${m.ramGibHours ? m.ramGibHours.toFixed(4) : '0.0000'}</span>
            </td>
            <td>
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
    const res = await fetch(`/api/machines/${encodeURIComponent(machineId)}/action`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ accountId, action, region })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`Aksi ${action} berhasil!`, 'success');
      setTimeout(fetchMachines, 1200);
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

function openNewMachineModal() {
  if (appState.accounts.length === 0) {
    showToast('Harap hubungkan akun Boxd terlebih dahulu', 'error');
    openAddAccountModal();
    return;
  }
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
    const res = await fetch(`/api/machines/suggest-name?accountId=${encodeURIComponent(accSelect.value)}`);
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

  try {
    const res = await fetch('/api/machines', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        accountId,
        name: name || undefined,
        vcpu: parseInt(vcpuStr, 10),
        memory: `${memStr}G`,
        region,
        autoSuspendTimeout
      })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`VM "${data.machine.name}" berhasil dideploy!`, 'success');
      closeNewMachineModal();
      document.getElementById('newMachineForm').reset();
      fetchMachines();
      fetchTelemetryData();
    } else {
      showToast(`Gagal membuat VM: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Deploy Sekarang</span>';
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
    const res = await fetch(`/api/machines/${encodeURIComponent(appState.execTarget.machineId)}/exec`, {
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
    const res = await fetch('/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, apiKey, notes })
    });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(`Akun "${label}" berhasil diverifikasi`, 'success');
      closeAddAccountModal();
      document.getElementById('addAccountForm').reset();
      await fetchAccounts();
      fetchTelemetryData();
      fetchMachines();
    } else {
      showToast(`Validasi gagal: ${data.error}`, 'error');
    }
  } catch (err) {
    showToast('Koneksi gagal: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>Simpan & Verifikasi</span>';
  }
}

async function syncAccount(id) {
  showToast('Menyinkronkan data akun dari Boxd...', 'info');
  try {
    const res = await fetch(`/api/accounts/${encodeURIComponent(id)}/sync`, { method: 'POST' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast('Akun berhasil disinkronkan', 'success');
      await fetchAccounts();
      fetchTelemetryData();
      fetchMachines();
    } else {
      showToast(`Gagal sync: ${data.error}`, 'error');
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
    const res = await fetch(`/api/accounts/${encodeURIComponent(id)}`, { method: 'DELETE' });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Akun "${label}" dihapus`, 'info');
      await fetchAccounts();
      fetchTelemetryData();
      fetchMachines();
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
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
