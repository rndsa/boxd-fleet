require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const dbHelper = require('./db');
const auth = require('./auth');
const boxdService = require('./boxdService');

const app = express();
const PORT = process.env.PORT || 7070;

// Security Middleware: HTTP Headers (OWASP Defense-in-Depth)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; font-src 'self' https: data:; connect-src 'self' https: wss:; frame-ancestors 'self';");
  next();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logger for audit & troubleshooting
app.use((req, res, next) => {
  const ip = auth.extractClientIp(req);
  res.on('finish', () => {
    if (req.path.startsWith('/api') && !req.path.includes('/auth/status')) {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} - ${ip}`);
    }
  });
  next();
});

// Rate limiters for costly / sensitive operations
const deployRateLimiter = auth.createRateLimiter({ windowMs: 60000, max: 6, message: 'Terlalu sering deploy VM.' });
const actionRateLimiter = auth.createRateLimiter({ windowMs: 60000, max: 25, message: 'Terlalu sering mengubah status VM.' });
const execRateLimiter = auth.createRateLimiter({ windowMs: 60000, max: 15, message: 'Terlalu sering mengeksekusi perintah terminal.' });

// IP Whitelist / Allowed IPs Guard Middleware
app.use((req, res, next) => {
  const clientIp = auth.extractClientIp(req);
  req.clientIp = clientIp;

  // Static assets are always allowed to render styling
  if (req.path.match(/\.(css|js|png|jpg|jpeg|svg|ico|webp)$/i)) {
    return next();
  }

  const isEnabled = dbHelper.isIpWhitelistEnabled();
  if (!isEnabled) {
    return next();
  }

  // Check if client IP is whitelisted
  if (dbHelper.isIpWhitelisted(clientIp)) {
    return next();
  }

  // Emergency Safety Recovery: If accessed with Master Key (?key=... or x-access-pin)
  const directKey = (req.query && req.query.key) || req.headers['x-access-pin'];
  if (directKey && auth.verifyPin(directKey)) {
    dbHelper.addAllowedIp(clientIp, 'Auto-registered via Master Key');
    dbHelper.logAudit('IP_WHITELIST_AUTO_ADD', null, { ip: clientIp }, clientIp);
    return next();
  }

  // Blocked by IP filter
  dbHelper.logAudit('IP_BLOCKED', null, { ip: clientIp, path: req.path }, clientIp);

  if (req.path.startsWith('/api')) {
    return res.status(403).json({
      error: `Akses ditolak: IP [${clientIp}] tidak terdaftar dalam Allowed IPs.`,
      code: 'IP_NOT_ALLOWED',
      clientIp
    });
  }

  return res.status(403).send(`
    <!DOCTYPE html>
    <html lang="id">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>403 — IP Restricted | BOXD FLEET</title>
      <style>
        body { margin: 0; background: #0A0E17; color: #F8FAFC; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; box-sizing: border-box; }
        .card { background: #121826; border: 2px solid #F43F5E; border-radius: 8px; max-width: 440px; width: 100%; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.6); text-align: center; }
        .badge { display: inline-block; background: rgba(244,63,94,0.15); color: #FDA4AF; border: 1px solid #F43F5E; padding: 4px 10px; border-radius: 4px; font-weight: 800; font-size: 11px; margin-bottom: 12px; }
        h1 { font-size: 18px; margin: 0 0 10px 0; font-weight: 900; letter-spacing: -0.02em; }
        p { font-size: 12px; color: #94A3B8; line-height: 1.5; margin: 0 0 16px 0; }
        .ip-box { background: #080C14; border: 1.5px solid #334155; padding: 10px; border-radius: 6px; font-size: 13px; font-weight: 800; color: #FACC15; margin-bottom: 16px; word-break: break-all; }
        .hint { font-size: 11px; color: #64748B; line-height: 1.4; border-top: 1px solid #1E293B; padding-top: 12px; }
      </style>
    </head>
    <body>
      <div class="card">
        <div class="badge">FIREWALL: IP RESTRICTED</div>
        <h1>AKSES DITOLAK (403)</h1>
        <p>IP perangkat Anda tidak terdaftar dalam daftar IP yang diizinkan (Allowed IPs) untuk mengelola Boxd Fleet.</p>
        <div class="ip-box">IP PERANGKAT: ${clientIp}</div>
        <div class="hint">
          Buka konsol menggunakan tautan resmi dengan Master Key Anda (?key=...) untuk mendaftarkan IP ini secara instan.
        </div>
      </div>
    </body>
    </html>
  `);
});

// Serve frontend static files
app.use(express.static(path.join(__dirname, 'public')));

// Prevent stale HTTP/edge caching on ALL live auth, telemetry & fleet API responses
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// ================= AUTH ROUTES =================

app.get('/api/auth/status', (req, res) => {
  const token = req.cookies && req.cookies.boxd_session;
  const directKey = req.query && req.query.key;

  if (directKey && auth.verifyPin(directKey)) {
    const newToken = auth.signSession('admin');
    res.cookie('boxd_session', newToken, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    return res.json({ authenticated: true, user: 'admin', token: newToken });
  }

  if (token) {
    const session = auth.verifySession(token);
    if (session) {
      return res.json({ authenticated: true, user: session.u || 'admin', token });
    }
  }

  return res.json({ authenticated: false });
});

app.post('/api/auth/login', (req, res) => {
  const ip = auth.extractClientIp(req);
  const rateCheck = auth.checkRateLimit(ip);
  if (!rateCheck.allowed) {
    dbHelper.logAudit('LOGIN_LOCKED', null, { ip, reason: 'rate_limit_exceeded' }, ip);
    return res.status(429).json({
      error: `Terlalu banyak percobaan gagal. Coba lagi dalam ${rateCheck.remainingSecs} detik.`,
      code: 'RATE_LIMITED'
    });
  }

  const { pin } = req.body;
  if (!pin || !auth.verifyPin(pin)) {
    auth.recordLoginAttempt(ip, false);
    dbHelper.logAudit('LOGIN_FAILED', null, { ip }, ip);
    return res.status(401).json({
      error: 'PIN Akses salah!',
      code: 'INVALID_PIN'
    });
  }

  auth.recordLoginAttempt(ip, true);
  const token = auth.signSession('admin');

  // Set secure cookie (30 days, aligned with ?key= & auth.js)
  res.cookie('boxd_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  });

  dbHelper.logAudit('LOGIN_SUCCESS', null, { user: 'admin' }, ip);
  res.json({ success: true, token, user: 'admin' });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('boxd_session');
  res.json({ success: true });
});

// Protect all following /api/* routes
app.use('/api', auth.requireAuth);

// ================= ACCOUNTS ROUTES =================

app.get('/api/accounts', (req, res) => {
  try {
    const accounts = dbHelper.getAccounts();
    res.json({ success: true, accounts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/telemetry', async (req, res) => {
  try {
    const accounts = dbHelper.getAccounts();
    const fullAccounts = accounts.map(a => dbHelper.getAccountById(a.id)).filter(Boolean);

    const telemetryTasks = fullAccounts.map(acc =>
      boxdService.getAccountTelemetry(acc).catch(err => ({
        success: false,
        account: {
          id: acc.id,
          label: acc.label,
          userId: acc.user_id,
          displayName: acc.display_name || acc.label,
          maxVms: acc.max_vms || 100,
          status: 'error',
          keyScope: acc.key_scope || 'unknown',
          homeRegion: acc.home_region || 'fra',
          error: err.message
        },
        org: { id: acc.org_id, name: acc.org_name || 'Personal', slug: acc.org_slug || '' },
        billing: { balanceMicro: acc.balance_micro || 0, balance: (acc.balance_micro || 0) / 1e6, currency: (acc.currency || 'USD').toUpperCase(), entries: [] },
        usage: null,
        error: err.message,
        machinesCount: 0,
        controllableCount: 0,
        privateLockedCount: 0,
        machines: []
      }))
    );

    const results = await Promise.all(telemetryTasks);

    let activeAccounts = 0;
    let totalBalance = 0;
    let totalMachines = 0;
    let controllableMachines = 0;
    let privateLockedMachines = 0;
    let totalCost = 0;
    let totalMaxVms = 0;
    let totalAllocatedVcpu = 0;
    let totalAllocatedRamBytes = 0;
    let rates = null;
    let currency = 'USD';

    for (const t of results) {
      if (!t.error) activeAccounts++;
      if (t.billing && typeof t.billing.balance === 'number') {
        totalBalance += t.billing.balance;
        if (t.billing.currency) currency = t.billing.currency;
      }
      if (typeof t.machinesCount === 'number') totalMachines += t.machinesCount;
      if (typeof t.controllableCount === 'number') controllableMachines += t.controllableCount;
      if (typeof t.privateLockedCount === 'number') privateLockedMachines += t.privateLockedCount;
      if (t.usage && typeof t.usage.totalCost === 'number') totalCost += t.usage.totalCost;
      if (t.usage && t.usage.rates && !rates) rates = t.usage.rates;
      if (!t.error && t.account && typeof t.account.maxVms === 'number') totalMaxVms += t.account.maxVms;
      if (Array.isArray(t.machines)) {
        for (const m of t.machines) {
          totalAllocatedVcpu += (m.resources && m.resources.vcpu) ? m.resources.vcpu : 0;
          totalAllocatedRamBytes += (m.resources && m.resources.memoryBytes) ? m.resources.memoryBytes : 0;
        }
      }
    }

    res.json({
      success: true,
      syncedAt: Date.now(),
      summary: {
        totalAccounts: results.length,
        activeAccounts,
        totalBalance: parseFloat(totalBalance.toFixed(4)),
        currency,
        totalMachines,
        controllableMachines,
        privateLockedMachines,
        totalMaxVms,
        totalAllocatedVcpu,
        totalAllocatedRamBytes,
        totalAllocatedRamGb: parseFloat((totalAllocatedRamBytes / (1024 * 1024 * 1024)).toFixed(2)),
        totalCost: parseFloat(totalCost.toFixed(6)),
        rates: rates || { vcpuHour: 0.047, ramHour: 0.014, diskHour: 0.000096 }
      },
      accounts: results
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/accounts/:id/telemetry', async (req, res) => {
  try {
    const account = dbHelper.getAccountById(req.params.id);
    if (!account) {
      return res.status(404).json({ error: 'Akun tidak ditemukan' });
    }
    const telemetry = await boxdService.getAccountTelemetry(account);
    res.json({ success: true, telemetry });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/accounts', async (req, res) => {
  const ip = auth.extractClientIp(req);
  const { label, apiKey, notes } = req.body;

  if (!label || !label.trim()) {
    return res.status(400).json({ error: 'Label akun wajib diisi' });
  }
  if (!apiKey || !apiKey.trim()) {
    return res.status(400).json({ error: 'Boxd API Key wajib diisi' });
  }

  const trimmedKey = apiKey.trim();

  // Check duplicate API key first
  const existing = dbHelper.getAccountByApiKey(trimmedKey);
  if (existing) {
    return res.status(409).json({
      error: `API Key sudah terdaftar pada akun "${existing.label}" (${existing.id})`
    });
  }

  // Validate against Boxd BEFORE inserting into SQLite so failed keys never pollute DB
  const validation = await boxdService.validateNewApiKey(trimmedKey);
  if (!validation.success) {
    dbHelper.logAudit('ADD_ACCOUNT_FAILED', null, { label: label.trim(), error: validation.error }, ip);
    return res.status(400).json({
      error: `Validasi Boxd API Key gagal: ${validation.error}`
    });
  }

  const accId = 'acc_' + crypto.randomBytes(6).toString('hex');
  const created = dbHelper.createAccount({
    id: accId,
    label: label.trim(),
    api_key: trimmedKey,
    notes: notes || '',
    ...validation.fields
  });

  const safeAccount = dbHelper.getAccounts().find(a => a.id === created.id) || created;
  dbHelper.logAudit('ADD_ACCOUNT_SUCCESS', accId, { label: label.trim(), user_id: created.user_id, key_scope: created.key_scope }, ip);
  res.status(201).json({ success: true, account: safeAccount });
});

app.post('/api/accounts/:id/sync', async (req, res) => {
  const ip = auth.extractClientIp(req);
  const account = dbHelper.getAccountById(req.params.id);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  const result = await boxdService.syncAccount(account);
  dbHelper.logAudit('SYNC_ACCOUNT', account.id, { success: result.success }, ip);

  if (!result.success) {
    return res.status(400).json({ error: result.error, account: result.account });
  }
  res.json({ success: true, account: result.account });
});

app.patch('/api/accounts/:id', (req, res) => {
  const account = dbHelper.getAccountById(req.params.id);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  const { label, notes } = req.body;
  const updates = {};
  if (label !== undefined) updates.label = label.trim();
  if (notes !== undefined) updates.notes = notes;

  const updated = dbHelper.updateAccount(account.id, updates);
  res.json({ success: true, account: updated });
});

app.delete('/api/accounts/:id', (req, res) => {
  const ip = auth.extractClientIp(req);
  const account = dbHelper.getAccountById(req.params.id);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  boxdService.clearClientCache(account.api_key);
  dbHelper.deleteAccount(account.id);
  dbHelper.logAudit('DELETE_ACCOUNT', account.id, { label: account.label }, ip);
  res.json({ success: true, id: req.params.id });
});

// ================= MACHINES ROUTES =================

app.get('/api/machines', async (req, res) => {
  try {
    const { accountId } = req.query;

    if (accountId && accountId !== 'all') {
      const account = dbHelper.getAccountById(accountId);
      if (!account) {
        return res.status(404).json({ error: 'Akun tidak ditemukan' });
      }
      try {
        const machines = await boxdService.listMachinesForAccount(account);
        return res.json({ success: true, machines, accountStatuses: { [accountId]: { success: true, count: machines.length } } });
      } catch (err) {
        return res.json({ success: true, machines: [], accountStatuses: { [accountId]: { success: false, error: err.message, count: 0 } } });
      }
    }

    const accounts = dbHelper.getAccounts();
    if (accounts.length === 0) {
      return res.json({ success: true, machines: [], accountStatuses: {} });
    }

    const fullAccounts = accounts.map(a => dbHelper.getAccountById(a.id)).filter(Boolean);
    const result = await boxdService.listAllMachines(fullAccounts);

    res.json({ success: true, machines: result.machines, accountStatuses: result.accountStatuses });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/machines', deployRateLimiter, async (req, res) => {
  const ip = auth.extractClientIp(req);
  const { accountId, name, vcpu, memory, region, shared, autoSuspendTimeout, autoHibernateTimeout } = req.body;

  if (!accountId) {
    return res.status(400).json({ error: 'Target akun wajib dipilih' });
  }

  // Layer 1 Validation
  const valError = auth.validateMachineInput({ name, region, vcpu, memory });
  if (valError) {
    return res.status(400).json({ error: valError });
  }

  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    const newMachine = await boxdService.createMachine(account, {
      name,
      vcpu,
      memory,
      region,
      shared,
      autoSuspendTimeout,
      autoHibernateTimeout
    });

    dbHelper.logAudit('CREATE_MACHINE', account.id, { machineId: newMachine.id, name: newMachine.name, region: newMachine.region, shared: newMachine.shared }, ip);
    res.status(201).json({ success: true, machine: newMachine });
  } catch (err) {
    dbHelper.logAudit('CREATE_MACHINE_FAILED', account.id, { name, error: err.message }, ip);
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/machines/:id/action', actionRateLimiter, async (req, res) => {
  const ip = auth.extractClientIp(req);
  const machineId = req.params.id;
  const { accountId, action, region } = req.body;

  if (!accountId) {
    return res.status(400).json({ error: 'accountId wajib disertakan' });
  }
  if (!action) {
    return res.status(400).json({ error: 'action wajib disertakan' });
  }

  const allowedActions = ['start', 'stop', 'resume', 'pause', 'hibernate', 'reboot', 'wake'];
  if (!allowedActions.includes(action.toLowerCase())) {
    return res.status(400).json({ error: `Aksi tidak valid. Pilihan: ${allowedActions.join(', ')}` });
  }

  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    const result = await boxdService.machineAction(account, machineId, action, region);
    dbHelper.logAudit('MACHINE_ACTION', account.id, { machineId, action, region }, ip);
    res.json({ success: true, action, machineId, result });
  } catch (err) {
    dbHelper.logAudit('MACHINE_ACTION_FAILED', account.id, { machineId, action, error: err.message }, ip);
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/machines/:id', actionRateLimiter, async (req, res) => {
  const ip = auth.extractClientIp(req);
  const machineId = req.params.id;
  const accountId = req.query.accountId || req.body.accountId;
  const region = req.query.region || req.body.region;

  if (!accountId) {
    return res.status(400).json({ error: 'accountId wajib disertakan' });
  }

  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    await boxdService.deleteMachine(account, machineId, region);
    dbHelper.logAudit('DELETE_MACHINE', account.id, { machineId, region }, ip);
    res.json({ success: true, id: machineId });
  } catch (err) {
    dbHelper.logAudit('DELETE_MACHINE_FAILED', account.id, { machineId, error: err.message }, ip);
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/machines/:id/exec', execRateLimiter, async (req, res) => {
  const ip = auth.extractClientIp(req);
  const machineId = req.params.id;
  const { accountId, command, timeout, region } = req.body;

  if (!accountId) {
    return res.status(400).json({ error: 'accountId wajib disertakan' });
  }
  if (!command || !command.trim()) {
    return res.status(400).json({ error: 'Command tidak boleh kosong' });
  }
  if (command.length > 2000) {
    return res.status(400).json({ error: 'Command dibatasi maksimal 2000 karakter' });
  }

  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    const result = await boxdService.execCommand(account, machineId, command.trim(), timeout, region);
    dbHelper.logAudit('EXEC_COMMAND', account.id, { machineId, command: command.slice(0, 100), success: result.success }, ip);
    res.json({ success: true, ...result });
  } catch (err) {
    dbHelper.logAudit('EXEC_COMMAND_FAILED', account.id, { machineId, command: command.slice(0, 100), error: err.message }, ip);
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/machines/suggest-name', async (req, res) => {
  const { accountId } = req.query;
  let account = null;
  if (accountId && accountId !== 'all') {
    account = dbHelper.getAccountById(accountId);
  }
  if (!account) {
    const accounts = dbHelper.getAccounts();
    if (accounts.length > 0) {
      account = dbHelper.getAccountById(accounts[0].id);
    }
  }

  if (!account) {
    return res.json({ success: true, name: `boxd-vm-${Math.floor(100 + Math.random() * 900)}` });
  }

  try {
    const name = await boxdService.suggestName(account);
    res.json({ success: true, name });
  } catch (err) {
    res.json({ success: true, name: `boxd-vm-${Math.floor(100 + Math.random() * 900)}` });
  }
});

// ================= SNAPSHOTS ROUTES =================

app.get('/api/snapshots', async (req, res) => {
  const { accountId, region } = req.query;
  if (!accountId) {
    return res.status(400).json({ error: 'accountId wajib disertakan' });
  }
  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    const snapshots = await boxdService.listSnapshots(account, region || 'all');
    res.json({ success: true, snapshots });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/snapshots', async (req, res) => {
  const ip = auth.extractClientIp(req);
  const { accountId, machineId, name, region } = req.body;
  if (!accountId || !machineId || !name) {
    return res.status(400).json({ error: 'accountId, machineId, dan name wajib disertakan' });
  }
  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    const snapshot = await boxdService.createSnapshot(account, machineId, name, region);
    dbHelper.logAudit('CREATE_SNAPSHOT', account.id, { machineId, name, region }, ip);
    res.status(201).json({ success: true, snapshot });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/snapshots/:name', async (req, res) => {
  const ip = auth.extractClientIp(req);
  const { name } = req.params;
  const accountId = req.query.accountId || req.body.accountId;
  const region = req.query.region || req.body.region;
  if (!accountId) {
    return res.status(400).json({ error: 'accountId wajib disertakan' });
  }
  const account = dbHelper.getAccountById(accountId);
  if (!account) {
    return res.status(404).json({ error: 'Akun tidak ditemukan' });
  }

  try {
    await boxdService.deleteSnapshot(account, name, region);
    dbHelper.logAudit('DELETE_SNAPSHOT', account.id, { name, region }, ip);
    res.json({ success: true, name });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ================= AUDIT LOGS =================

app.get('/api/audit-logs', (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 50;
    const logs = dbHelper.getRecentAuditLogs(limit);
    res.json({ success: true, logs });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= IP WHITELIST MANAGEMENT =================

app.get('/api/security/ip-whitelist', (req, res) => {
  try {
    const clientIp = auth.extractClientIp(req);
    const enabled = dbHelper.isIpWhitelistEnabled();
    const allowedIps = dbHelper.getAllowedIps();
    res.json({ success: true, enabled, currentIp: clientIp, allowedIps });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/security/ip-whitelist/toggle', (req, res) => {
  try {
    const { enabled } = req.body;
    const currentIp = auth.extractClientIp(req);

    // If enabling, ensure caller's current IP is whitelisted first to prevent accidental self-lockout
    if (enabled) {
      dbHelper.addAllowedIp(currentIp, 'Admin Device');
    }

    dbHelper.setIpWhitelistEnabled(!!enabled);
    dbHelper.logAudit('IP_WHITELIST_TOGGLE', null, { enabled: !!enabled, triggeredBy: currentIp }, currentIp);
    res.json({ success: true, enabled: !!enabled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/security/ip-whitelist', (req, res) => {
  try {
    const { ip, label } = req.body;
    if (!ip || typeof ip !== 'string' || !ip.trim()) {
      return res.status(400).json({ error: 'Alamat IP wajib diisi' });
    }
    const cleanIp = ip.trim();
    const added = dbHelper.addAllowedIp(cleanIp, label ? label.trim() : 'Allowed Device');
    dbHelper.logAudit('IP_WHITELIST_ADD', null, { ip: cleanIp, label }, auth.extractClientIp(req));
    res.json({ success: true, item: added });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/security/ip-whitelist/:id', (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id || isNaN(id)) {
      return res.status(400).json({ error: 'ID tidak valid' });
    }
    dbHelper.deleteAllowedIp(id);
    dbHelper.logAudit('IP_WHITELIST_DELETE', null, { id }, auth.extractClientIp(req));
    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/security/ip-whitelist/allow-my-ip', (req, res) => {
  try {
    const clientIp = auth.extractClientIp(req);
    const added = dbHelper.addAllowedIp(clientIp, 'Current Device (' + new Date().toLocaleDateString('id-ID') + ')');
    dbHelper.logAudit('IP_WHITELIST_ADD_SELF', null, { ip: clientIp }, clientIp);
    res.json({ success: true, item: added, currentIp: clientIp });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Catch-all route to serve SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`=========================================`);
    console.log(`⚡ BOXD FLEET MULTI-ACCOUNT MANAGER`);
    console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
    console.log(`🔒 Access Mode: Restricted PIN`);
    console.log(`=========================================`);
  });
}

module.exports = app;
