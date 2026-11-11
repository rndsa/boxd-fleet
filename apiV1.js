const express = require('express');
const crypto = require('crypto');
const dbHelper = require('./db');
const auth = require('./auth');
const boxdService = require('./boxdService');

const router = express.Router();

// In-memory sliding-window rate limiter per API Key ID
const keyRateBuckets = new Map();

// In-memory replay nonce cache for HMAC non-GET requests (5m TTL)
const hmacReplayCache = new Map();

function checkPerKeyRateLimit(apiKey) {
  const rpm = Math.max(5, Number(apiKey.rateLimitRpm) || 60);
  const now = Date.now();
  const windowMs = 60 * 1000;
  let bucket = keyRateBuckets.get(apiKey.id);
  if (!bucket || now - bucket.windowStart >= windowMs) {
    bucket = { windowStart: now, count: 0 };
  }
  if (bucket.count >= rpm) {
    const retryAfterSec = Math.max(1, Math.ceil((bucket.windowStart + windowMs - now) / 1000));
    return { allowed: false, retryAfterSec, limit: rpm, remaining: 0 };
  }
  bucket.count += 1;
  keyRateBuckets.set(apiKey.id, bucket);
  if (keyRateBuckets.size > 2000) {
    for (const [k, v] of keyRateBuckets.entries()) {
      if (now - v.windowStart >= windowMs) keyRateBuckets.delete(k);
    }
  }
  return { allowed: true, limit: rpm, remaining: Math.max(0, rpm - bucket.count) };
}

function checkAndRecordHmacNonce(keyId, timestampStr, signatureHex, method) {
  if (String(method || 'GET').toUpperCase() === 'GET') return true;
  const now = Date.now();
  if (hmacReplayCache.size > 5000) {
    for (const [k, exp] of hmacReplayCache.entries()) {
      if (now >= exp) hmacReplayCache.delete(k);
    }
  }
  const nonceKey = `${keyId}:${timestampStr}:${signatureHex}`;
  const exp = hmacReplayCache.get(nonceKey);
  if (exp && now < exp) {
    return false;
  }
  hmacReplayCache.set(nonceKey, now + 5 * 60 * 1000);
  return true;
}

function extractBearerOrHeaderKey(req) {
  const authHeader = req.headers.authorization;
  if (typeof authHeader === 'string' && authHeader.trim().toLowerCase().startsWith('bearer ')) {
    return authHeader.trim().slice(7).trim();
  }
  const xKey = req.headers['x-api-key'];
  if (typeof xKey === 'string' && xKey.trim()) {
    return xKey.trim();
  }
  return '';
}

function isAccountAllowedForKey(apiKey, accountId) {
  if (!apiKey || !Array.isArray(apiKey.allowedAccountIds)) return false;
  if (apiKey.allowedAccountIds.includes('*')) return true;
  return apiKey.allowedAccountIds.includes(accountId);
}

function getAllowedAccountsForKey(apiKey) {
  const all = dbHelper.getAccountsWithKeys();
  if (apiKey.allowedAccountIds.includes('*')) return all;
  const allowedSet = new Set(apiKey.allowedAccountIds);
  return all.filter(acc => allowedSet.has(acc.id));
}

function selectAutoAccountForDeploy(apiKey) {
  const allowed = getAllowedAccountsForKey(apiKey);
  const active = allowed.filter(a => a.status === 'active');
  const pool = active.length > 0 ? active : allowed;
  if (pool.length === 0) return null;
  // Prefer account with highest balance
  return [...pool].sort((a, b) => (Number(b.balance_micro) || 0) - (Number(a.balance_micro) || 0))[0];
}

async function resolveAccountAndVm(apiKey, machineId, explicitAccountId, explicitRegion) {
  if (explicitAccountId && explicitAccountId !== 'auto') {
    if (!isAccountAllowedForKey(apiKey, explicitAccountId)) {
      const err = new Error('API key tidak memiliki izin untuk akun yang diminta.');
      err.status = 403;
      err.code = 'ACCOUNT_NOT_ALLOWED';
      throw err;
    }
    const account = dbHelper.getAccountById(explicitAccountId);
    if (!account) {
      const err = new Error('Akun tidak ditemukan.');
      err.status = 404;
      err.code = 'ACCOUNT_NOT_FOUND';
      throw err;
    }
    return { account, region: explicitRegion || account.home_region || 'fra' };
  }

  const allowedAccounts = getAllowedAccountsForKey(apiKey);
  if (allowedAccounts.length === 0) {
    const err = new Error('Tidak ada akun aktif yang diizinkan untuk API key ini.');
    err.status = 403;
    err.code = 'ACCOUNT_NOT_ALLOWED';
    throw err;
  }

  // Fast SQLite lookup via vm_configs or vm_ssh_access
  const cfg = dbHelper.getVmConfig(machineId);
  if (cfg && isAccountAllowedForKey(apiKey, cfg.accountId)) {
    const acc = dbHelper.getAccountById(cfg.accountId);
    if (acc) return { account: acc, region: explicitRegion || cfg.region || acc.home_region || 'fra' };
  }

  const sshRec = dbHelper.getVmSshAccess(machineId);
  if (sshRec && isAccountAllowedForKey(apiKey, sshRec.account_id)) {
    const acc = dbHelper.getAccountById(sshRec.account_id);
    if (acc) return { account: acc, region: explicitRegion || sshRec.region || acc.home_region || 'fra' };
  }

  // Fallback: probe allowed accounts cleanly
  const results = await Promise.all(
    allowedAccounts.map(async acc => {
      try {
        const list = await boxdService.listMachinesForAccount(acc);
        const match = list.find(m => m.id === machineId && m.accessible !== false);
        return match ? { account: acc, region: explicitRegion || match.region || acc.home_region || 'fra' } : null;
      } catch (e) {
        return null;
      }
    })
  );

  const found = results.find(Boolean);
  if (!found) {
    const err = new Error('MicroVM tidak ditemukan atau tidak termasuk akun yang diizinkan untuk API key ini.');
    err.status = 404;
    err.code = 'VM_NOT_FOUND';
    throw err;
  }
  return found;
}

function requireScope(scope) {
  return (req, res, next) => {
    const key = req.apiKey;
    if (!key || !Array.isArray(key.scopes) || !key.scopes.includes(scope)) {
      return res.status(403).json({
        ok: false,
        error: `Izin tidak cukup: membutuhkan scope "${scope}".`,
        code: 'INSUFFICIENT_SCOPE',
        requiredScope: scope
      });
    }
    return next();
  };
}

function sendError(res, err, fallbackStatus = 500, fallbackCode = 'API_ERROR') {
  const status = (err && (err.status || err.statusCode)) || fallbackStatus;
  const code = (err && err.code) || fallbackCode;
  return res.status(status).json({
    ok: false,
    error: (err && err.message) || 'Terjadi kesalahan pada server API',
    code
  });
}

// =========================================================================
// EXTRA SECURITY GATE MIDDLEWARE (ALL /api/v1/* ROUTES)
// =========================================================================
router.use((req, res, next) => {
  const clientIp = auth.extractClientIp(req);
  req.clientIp = clientIp;

  let logSummary = '';
  res.setApiLogSummary = (msg) => {
    logSummary = String(msg || '').slice(0, 220);
  };

  res.on('finish', () => {
    const k = req.apiKey;
    dbHelper.logApiRequest({
      keyId: k ? k.id : null,
      keyName: k ? k.name : null,
      method: req.method,
      path: req.path || '/',
      statusCode: res.statusCode,
      ip: clientIp,
      summary: logSummary
    });
    if (k && res.statusCode < 500 && res.statusCode !== 401) {
      try {
        dbHelper.recordApiKeyUsage(k.id, clientIp);
      } catch (e) {}
    }
  });

  // 1. Global API Master Switch
  if (!dbHelper.isApiEnabled()) {
    res.setApiLogSummary('API disabled');
    return res.status(503).json({
      ok: false,
      error: 'API eksternal sedang dinonaktifkan oleh admin.',
      code: 'API_DISABLED'
    });
  }

  // 2. Global API Allowed IP Firewall (independent of Web UI IP firewall)
  if (dbHelper.isApiIpWhitelistEnabled() && !dbHelper.isApiIpWhitelisted(clientIp)) {
    dbHelper.logAudit('API_IP_BLOCKED', 'api-v1', `Akses API diblokir oleh API Allowed IP Firewall`, clientIp);
    res.setApiLogSummary('Blocked by global API IP firewall');
    return res.status(403).json({
      ok: false,
      error: 'Akses API ditolak: IP Anda tidak terdaftar dalam API Allowed IPs.',
      code: 'API_IP_NOT_ALLOWED',
      clientIp
    });
  }

  // 3. Extract & verify API key (Bearer or X-API-Key ONLY — never query string)
  const rawKey = extractBearerOrHeaderKey(req);
  if (!rawKey) {
    res.setApiLogSummary('Missing API key');
    return res.status(401).json({
      ok: false,
      error: 'API Key wajib disertakan lewat header Authorization: Bearer <key> atau X-API-Key.',
      code: 'API_KEY_REQUIRED'
    });
  }

  const providedHash = auth.hashApiKey(rawKey);
  const keyRecord = dbHelper.getApiKeyAuthRecordByHash(providedHash);
  if (!keyRecord || !auth.timingSafeStringEqual(providedHash, keyRecord.keyHash)) {
    dbHelper.logAudit('API_AUTH_FAIL', 'api-v1', `Percobaan API Key tidak valid`, clientIp);
    res.setApiLogSummary('Invalid API key');
    return res.status(401).json({
      ok: false,
      error: 'API Key tidak valid atau telah dicabut.',
      code: 'INVALID_API_KEY'
    });
  }

  req.apiKey = keyRecord;

  if (!keyRecord.enabled) {
    res.setApiLogSummary('API key disabled');
    return res.status(403).json({
      ok: false,
      error: 'API Key sedang dijeda (paused) oleh admin.',
      code: 'API_KEY_DISABLED'
    });
  }

  if (keyRecord.expiresAt && Date.now() > keyRecord.expiresAt) {
    res.setApiLogSummary('API key expired');
    return res.status(401).json({
      ok: false,
      error: 'API Key sudah kedaluwarsa.',
      code: 'API_KEY_EXPIRED'
    });
  }

  // 4. Per-Key Allowed IP Check (if configured on key)
  if (Array.isArray(keyRecord.allowedIps) && keyRecord.allowedIps.length > 0) {
    const matched = keyRecord.allowedIps.some(rule => dbHelper.ipMatchesRule(clientIp, rule));
    if (!matched) {
      dbHelper.logAudit('API_KEY_IP_BLOCKED', keyRecord.id, `Key "${keyRecord.name}" diblokir untuk IP ${clientIp}`, clientIp);
      res.setApiLogSummary('Blocked by per-key Allowed IP');
      return res.status(403).json({
        ok: false,
        error: 'IP Anda tidak diizinkan oleh aturan Allowed IP pada API Key ini.',
        code: 'KEY_IP_NOT_ALLOWED',
        clientIp
      });
    }
  }

  // 5. Extra Security: Anti-Replay HMAC-SHA256 Signature (when enabled on key)
  if (keyRecord.requireHmac) {
    const secret = keyRecord.hmacSecretEnc ? auth.decryptSecret(keyRecord.hmacSecretEnc) : null;
    const hmacCheck = auth.verifyHmacSignature({
      secret,
      timestampHeader: req.headers['x-api-timestamp'],
      method: req.method,
      originalUrl: req.originalUrl,
      rawBody: req.rawBody || '',
      providedSignature: req.headers['x-api-signature']
    });
    if (!hmacCheck.valid) {
      dbHelper.logAudit('API_HMAC_FAIL', keyRecord.id, `HMAC gagal (${hmacCheck.code}) untuk key "${keyRecord.name}"`, clientIp);
      res.setApiLogSummary(`HMAC failed: ${hmacCheck.code}`);
      return res.status(401).json({
        ok: false,
        error: hmacCheck.error,
        code: hmacCheck.code
      });
    }
    const tsRaw = String(req.headers['x-api-timestamp'] || '').trim();
    const sigRaw = String(req.headers['x-api-signature'] || '').trim().toLowerCase();
    if (!checkAndRecordHmacNonce(keyRecord.id, tsRaw, sigRaw, req.method)) {
      res.setApiLogSummary('HMAC replay detected');
      return res.status(401).json({
        ok: false,
        error: 'Request signature sudah pernah digunakan (replay terdeteksi). Buat timestamp baru.',
        code: 'HMAC_REPLAY_DETECTED'
      });
    }
  }

  // 6. Per-Key Sliding Rate Limiter
  const rate = checkPerKeyRateLimit(keyRecord);
  res.setHeader('X-RateLimit-Limit', String(rate.limit));
  res.setHeader('X-RateLimit-Remaining', String(rate.remaining));
  if (!rate.allowed) {
    res.setHeader('Retry-After', String(rate.retryAfterSec));
    res.setApiLogSummary('Rate limit exceeded');
    return res.status(429).json({
      ok: false,
      error: `Rate limit tercapai (${rate.limit} req/menit). Coba lagi dalam ${rate.retryAfterSec} detik.`,
      code: 'RATE_LIMITED',
      retryAfterSec: rate.retryAfterSec
    });
  }

  return next();
});

// =========================================================================
// IDENTITY & ACCOUNTS
// =========================================================================
router.get('/me', requireScope('vm:read'), (req, res) => {
  const k = req.apiKey;
  res.json({
    ok: true,
    clientIp: req.clientIp,
    serverTime: Date.now(),
    key: {
      id: k.id,
      name: k.name,
      prefix: k.keyPrefix,
      scopes: k.scopes,
      allowedAccountIds: k.allowedAccountIds,
      allowedIps: k.allowedIps,
      requireHmac: k.requireHmac,
      rateLimitRpm: k.rateLimitRpm,
      maxDeployPerHour: k.maxDeployPerHour,
      maxVcpuPerVm: k.maxVcpuPerVm,
      expiresAt: k.expiresAt
    }
  });
});

router.get('/accounts', requireScope('vm:read'), (req, res) => {
  const allowed = getAllowedAccountsForKey(req.apiKey);
  const safeAccounts = allowed.map(a => {
    let enabledRegions = [];
    try { enabledRegions = JSON.parse(a.enabled_regions || '[]'); } catch (e) {}
    return {
      id: a.id,
      label: a.label,
      maskedKey: `${String(a.api_key || '').slice(0, 8)}...${String(a.api_key || '').slice(-4)}`,
      keyScope: a.key_scope || 'unknown',
      homeRegion: a.home_region || 'fra',
      enabledRegions,
      balance: Number(((a.balance_micro || 0) / 1e6).toFixed(4)),
      currency: a.currency || 'USD',
      maxVms: a.max_vms || 100,
      status: a.status || 'active',
      lastSyncedAt: a.last_synced_at || null
    };
  });
  res.json({ ok: true, count: safeAccounts.length, accounts: safeAccounts });
});

// =========================================================================
// VM DISCOVERY & GENERATION
// =========================================================================
router.get('/vms/suggest-name', requireScope('vm:read'), async (req, res) => {
  try {
    const account = selectAutoAccountForDeploy(req.apiKey);
    if (!account) {
      return res.status(404).json({ ok: false, error: 'Tidak ada akun tersedia.', code: 'NO_ACCOUNT' });
    }
    const name = await boxdService.suggestName(account);
    return res.json({ ok: true, name });
  } catch (err) {
    return sendError(res, err, 500, 'SUGGEST_NAME_ERROR');
  }
});

router.get('/vms', requireScope('vm:read'), async (req, res) => {
  try {
    const { accountId, status, region } = req.query;
    let accounts = getAllowedAccountsForKey(req.apiKey);
    if (accountId && accountId !== 'all') {
      if (!isAccountAllowedForKey(req.apiKey, String(accountId))) {
        return res.status(403).json({ ok: false, error: 'API key tidak diizinkan mengakses akun ini.', code: 'ACCOUNT_NOT_ALLOWED' });
      }
      accounts = accounts.filter(a => a.id === String(accountId));
    }

    const { machines, errors } = await boxdService.listAllMachines(accounts);
    let filtered = machines.filter(m => m.accessible !== false);
    if (status) {
      const targetStatus = String(status).toLowerCase();
      filtered = filtered.filter(m => String(m.status || '').toLowerCase() === targetStatus);
    }
    if (region) {
      const targetReg = String(region).toLowerCase();
      filtered = filtered.filter(m => String(m.region || '').toLowerCase() === targetReg);
    }

    res.json({
      ok: true,
      count: filtered.length,
      machines: filtered,
      errors
    });
  } catch (err) {
    return sendError(res, err, 500, 'LIST_VMS_ERROR');
  }
});

router.post('/vms', requireScope('vm:create'), async (req, res) => {
  const k = req.apiKey;
  const body = req.body && typeof req.body === 'object' ? req.body : {};

  // Idempotency-Key check
  const rawIdemKey = typeof req.headers['idempotency-key'] === 'string' ? req.headers['idempotency-key'].trim() : '';
  if (rawIdemKey && !/^[a-zA-Z0-9_.:-]{8,128}$/.test(rawIdemKey)) {
    return res.status(400).json({
      ok: false,
      error: 'Idempotency-Key harus 8-128 karakter alfanumerik, titik, underscore, atau strip.',
      code: 'INVALID_IDEMPOTENCY_KEY'
    });
  }

  const idemCacheKey = rawIdemKey ? `${k.id}:${rawIdemKey}` : null;
  const requestHash = crypto.createHash('sha256').update(req.rawBody || JSON.stringify(body)).digest('hex');

  if (idemCacheKey) {
    const cached = dbHelper.getApiIdempotency(idemCacheKey);
    if (cached) {
      if (cached.request_hash !== requestHash) {
        return res.status(409).json({
          ok: false,
          error: 'Idempotency-Key sudah digunakan dengan payload berbeda.',
          code: 'IDEMPOTENCY_CONFLICT'
        });
      }
      const decryptedResp = auth.decryptSecret(cached.response_enc);
      if (decryptedResp) {
        try {
          res.setHeader('X-Idempotency-Replayed', 'true');
          res.setApiLogSummary('Idempotent replay');
          return res.status(cached.status_code).json(JSON.parse(decryptedResp));
        } catch (e) {}
      }
    }
  }

  // Enforce hourly deploy quota
  if (k.maxDeployPerHour > 0) {
    const usedLastHour = dbHelper.countKeyDeploysSince(k.id, Date.now() - 3600 * 1000);
    if (usedLastHour >= k.maxDeployPerHour) {
      res.setApiLogSummary('Hourly deploy quota exceeded');
      return res.status(429).json({
        ok: false,
        error: `Kuota generate VM per jam tercapai (${usedLastHour}/${k.maxDeployPerHour} VM/jam).`,
        code: 'DEPLOY_QUOTA_EXCEEDED'
      });
    }
  }

  // Account resolution (supports explicit accountId or 'auto'/omitted)
  const requestedAccId = body.accountId ? String(body.accountId).trim() : 'auto';
  let account = null;
  if (requestedAccId === 'auto' || requestedAccId === '') {
    account = selectAutoAccountForDeploy(k);
    if (!account) {
      return res.status(400).json({ ok: false, error: 'Tidak ada akun Boxd aktif yang tersedia untuk key ini.', code: 'NO_ACTIVE_ACCOUNT' });
    }
  } else {
    if (!isAccountAllowedForKey(k, requestedAccId)) {
      return res.status(403).json({ ok: false, error: 'API key tidak diizinkan memakai akun tersebut.', code: 'ACCOUNT_NOT_ALLOWED' });
    }
    account = dbHelper.getAccountById(requestedAccId);
    if (!account) {
      return res.status(404).json({ ok: false, error: 'Akun tidak ditemukan.', code: 'ACCOUNT_NOT_FOUND' });
    }
  }

  const vcpu = body.vcpu !== undefined && body.vcpu !== null ? parseInt(body.vcpu, 10) : 1;
  const memory = body.memory !== undefined && body.memory !== null ? body.memory : '4G';
  const region = body.region || 'default';
  const name = body.name || undefined;

  const valErr = auth.validateMachineInput({ name, region, vcpu, memory });
  if (valErr) {
    return res.status(400).json({ ok: false, error: valErr, code: 'VALIDATION_ERROR' });
  }

  if (vcpu > (k.maxVcpuPerVm || 8)) {
    return res.status(403).json({
      ok: false,
      error: `vCPU (${vcpu}) melebihi batas maksimal untuk API key ini (${k.maxVcpuPerVm} vCPU).`,
      code: 'VCPU_LIMIT_EXCEEDED'
    });
  }

  // Preset convenience ('always_on' | 'standby' | 'balanced')
  let autoSuspendTimeout = body.autoSuspendTimeout;
  let autoHibernateTimeout = body.autoHibernateTimeout;
  let botProtectionMode = body.botProtectionMode;
  if (body.preset === 'always_on') {
    autoSuspendTimeout = 0;
    autoHibernateTimeout = 0;
    if (botProtectionMode === undefined) botProtectionMode = 'off';
  } else if (body.preset === 'standby') {
    if (autoSuspendTimeout === undefined) autoSuspendTimeout = 300;
    if (autoHibernateTimeout === undefined) autoHibernateTimeout = 1800;
  }

  // SSH password option: custom sshPassword OR autoGenerateSshPassword: true
  let sshPassword = body.sshPassword ? String(body.sshPassword) : '';
  let generatedSshPassword = null;
  if (!sshPassword && body.autoGenerateSshPassword) {
    sshPassword = crypto.randomBytes(12).toString('base64url');
    generatedSshPassword = sshPassword;
  }
  const sshUser = body.sshUser || 'root';
  if (sshPassword) {
    const sshErr = auth.validateSshPasswordInput({ password: sshPassword, sshUser });
    if (sshErr) {
      return res.status(400).json({ ok: false, error: sshErr, code: 'INVALID_SSH_INPUT' });
    }
  }

  // Auto-setup defaults: enableAutoUpdate = true unless explicitly disabled
  let autoSetup = null;
  if (body.autoSetup !== false) {
    const rawAuto = body.autoSetup && typeof body.autoSetup === 'object' ? body.autoSetup : {};
    let starterKits = [];
    if (Array.isArray(rawAuto.starterKits)) {
      const allowedKits = new Set(Object.keys(boxdService.STARTER_KITS || {}));
      starterKits = rawAuto.starterKits.map(x => String(x).trim()).filter(x => allowedKits.has(x));
    }
    autoSetup = {
      enableAutoUpdate: rawAuto.enableAutoUpdate !== undefined ? !!rawAuto.enableAutoUpdate : true,
      intervalHours: Math.max(1, Math.min(168, parseInt(rawAuto.intervalHours, 10) || 12)),
      updateRuntimes: rawAuto.updateRuntimes !== undefined ? !!rawAuto.updateRuntimes : true,
      upgradeNow: !!rawAuto.upgradeNow,
      starterKits
    };
  }

  try {
    const machine = await boxdService.createMachine(account, {
      name,
      region,
      shared: body.shared !== undefined ? !!body.shared : true,
      vcpu,
      memory,
      autoSuspendTimeout,
      autoHibernateTimeout,
      botProtectionMode,
      idleIgnoreOutbound: body.idleIgnoreOutbound,
      sshPassword: sshPassword || undefined,
      sshUser,
      autoSetup
    });

    const responseBody = {
      ok: true,
      machine,
      sshCommand: machine.sshAccess && machine.sshAccess.publicPort && machine.sshAccess.dns
        ? `ssh -p ${machine.sshAccess.publicPort} ${machine.sshAccess.sshUser === 'boxd' ? 'boxd' : 'root'}@${machine.sshAccess.dns}`
        : null
    };
    if (generatedSshPassword) {
      responseBody.generatedSshPassword = generatedSshPassword;
    }

    if (idemCacheKey) {
      const encrypted = auth.encryptSecret(JSON.stringify(responseBody));
      if (encrypted) {
        dbHelper.saveApiIdempotency({
          cacheKey: idemCacheKey,
          method: 'POST',
          path: '/vms',
          requestHash,
          statusCode: 201,
          responseEnc: encrypted
        });
      }
    }

    dbHelper.logAudit('API_CREATE_VM', machine.id, `Key "${k.name}" generate VM ${machine.name} (${vcpu} vCPU, ${memory})`, req.clientIp);
    res.setApiLogSummary(`Generated VM ${machine.name} (${machine.id})`);
    return res.status(201).json(responseBody);
  } catch (err) {
    res.setApiLogSummary(`Create VM failed: ${err.message}`);
    return sendError(res, err, 400, 'CREATE_VM_FAILED');
  }
});

router.post('/vms/from-snapshot', requireScope('vm:create'), async (req, res) => {
  const k = req.apiKey;
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const fromSnapshot = String(body.fromSnapshot || '').trim();
  if (!fromSnapshot) {
    return res.status(400).json({ ok: false, error: 'fromSnapshot wajib diisi.', code: 'VALIDATION_ERROR' });
  }

  if (k.maxDeployPerHour > 0) {
    const usedLastHour = dbHelper.countKeyDeploysSince(k.id, Date.now() - 3600 * 1000);
    if (usedLastHour >= k.maxDeployPerHour) {
      return res.status(429).json({
        ok: false,
        error: `Kuota generate VM per jam tercapai (${usedLastHour}/${k.maxDeployPerHour}).`,
        code: 'DEPLOY_QUOTA_EXCEEDED'
      });
    }
  }

  const requestedAccId = body.accountId ? String(body.accountId).trim() : 'auto';
  const account = (requestedAccId === 'auto' || !requestedAccId)
    ? selectAutoAccountForDeploy(k)
    : (isAccountAllowedForKey(k, requestedAccId) ? dbHelper.getAccountById(requestedAccId) : null);

  if (!account) {
    return res.status(403).json({ ok: false, error: 'Akun tidak ditemukan atau tidak diizinkan untuk API key ini.', code: 'ACCOUNT_NOT_ALLOWED' });
  }

  try {
    const machine = await boxdService.createMachineFromSnapshot(account, {
      fromSnapshot,
      name: body.name,
      region: body.region,
      alwaysOn: !!body.alwaysOn
    });
    dbHelper.logAudit('API_CLONE_VM', machine.id, `Key "${k.name}" clone VM ${machine.name} dari snapshot ${fromSnapshot}`, req.clientIp);
    res.setApiLogSummary(`Cloned VM ${machine.name} from ${fromSnapshot}`);
    return res.status(201).json({ ok: true, machine });
  } catch (err) {
    return sendError(res, err, 400, 'CLONE_VM_FAILED');
  }
});

// =========================================================================
// SINGLE VM INSPECT, LIFECYCLE, NETWORKING, EXEC & DELETE
// =========================================================================
router.get('/vms/:id', requireScope('vm:read'), async (req, res) => {
  try {
    const { account, region } = await resolveAccountAndVm(req.apiKey, req.params.id, req.query.accountId, req.query.region);
    const state = await boxdService.getVmManageState(account, req.params.id, region, {
      inspectOs: req.query.inspect !== 'false'
    });
    return res.json({ ok: true, ...state });
  } catch (err) {
    return sendError(res, err, 500, 'GET_VM_FAILED');
  }
});

router.post('/vms/:id/action', requireScope('vm:control'), async (req, res) => {
  const { action, accountId, region } = req.body || {};
  const allowedActions = ['start', 'stop', 'resume', 'pause', 'hibernate', 'reboot', 'wake'];
  if (!action || !allowedActions.includes(action)) {
    return res.status(400).json({
      ok: false,
      error: `Action harus salah satu dari: ${allowedActions.join(', ')}`,
      code: 'INVALID_ACTION'
    });
  }
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const machine = await boxdService.machineAction(resolved.account, req.params.id, action, resolved.region);
    dbHelper.logAudit('API_VM_ACTION', req.params.id, `Key "${req.apiKey.name}" -> ${action}`, req.clientIp);
    res.setApiLogSummary(`Action ${action} on ${req.params.id}`);
    return res.json({ ok: true, machine });
  } catch (err) {
    return sendError(res, err, 400, 'VM_ACTION_FAILED');
  }
});

router.post('/vms/:id/runtime', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, alwaysOn, autoSuspendTimeout, autoHibernateTimeout, botProtectionMode, idleIgnoreOutbound } = req.body || {};
  const errMsg = auth.validateRuntimeSettings({ autoSuspendTimeout, autoHibernateTimeout, botProtectionMode });
  if (errMsg) return res.status(400).json({ ok: false, error: errMsg, code: 'VALIDATION_ERROR' });

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const machine = await boxdService.updateVmRuntimeSettings(
      resolved.account,
      req.params.id,
      { alwaysOn, autoSuspendTimeout, autoHibernateTimeout, botProtectionMode, idleIgnoreOutbound },
      resolved.region
    );
    return res.json({ ok: true, machine });
  } catch (err) {
    return sendError(res, err, 400, 'RUNTIME_UPDATE_FAILED');
  }
});

router.post('/vms/:id/resize', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, vcpu, memory } = req.body || {};
  const valErr = auth.validateMachineInput({ vcpu, memory });
  if (valErr) return res.status(400).json({ ok: false, error: valErr, code: 'VALIDATION_ERROR' });
  if (vcpu && parseInt(vcpu, 10) > (req.apiKey.maxVcpuPerVm || 8)) {
    return res.status(403).json({
      ok: false,
      error: `vCPU (${vcpu}) melebihi batas maksimal untuk API key ini (${req.apiKey.maxVcpuPerVm} vCPU).`,
      code: 'VCPU_LIMIT_EXCEEDED'
    });
  }

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const machine = await boxdService.resizeVm(resolved.account, req.params.id, { vcpu, memory, region: resolved.region });
    dbHelper.logAudit('API_RESIZE_VM', req.params.id, `Key "${req.apiKey.name}" resize -> ${vcpu} vCPU / ${memory}`, req.clientIp);
    return res.json({ ok: true, machine });
  } catch (err) {
    return sendError(res, err, 400, 'RESIZE_FAILED');
  }
});

router.post('/vms/:id/autoupdate/config', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, enabled, intervalHours, updateRuntimes } = req.body || {};
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const result = await boxdService.configureVmAutoUpdate(resolved.account, req.params.id, {
      enabled: enabled !== undefined ? !!enabled : true,
      intervalHours: Math.max(1, Math.min(168, parseInt(intervalHours, 10) || 12)),
      updateRuntimes: updateRuntimes !== undefined ? !!updateRuntimes : true,
      region: resolved.region
    });
    return res.json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'AUTOUPDATE_CONFIG_FAILED');
  }
});

router.post('/vms/:id/autoupdate/run', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, intervalHours, updateRuntimes } = req.body || {};
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const result = await boxdService.runVmUpdateNow(resolved.account, req.params.id, {
      region: resolved.region,
      intervalHours: Math.max(1, Math.min(168, parseInt(intervalHours, 10) || 12)),
      updateRuntimes: updateRuntimes !== undefined ? !!updateRuntimes : true
    });
    return res.status(202).json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'AUTOUPDATE_RUN_FAILED');
  }
});

router.post('/vms/:id/packages', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, upgradeOs, starterKits, aptPackages, npmPackages } = req.body || {};
  const errMsg = auth.validatePackageList({ starterKits, aptPackages, npmPackages });
  if (errMsg) return res.status(400).json({ ok: false, error: errMsg, code: 'VALIDATION_ERROR' });

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const jobRes = await boxdService.startVmProvisionJob(resolved.account, req.params.id, {
      upgradeOs: !!upgradeOs,
      starterKits: Array.isArray(starterKits) ? starterKits : [],
      aptPackages: Array.isArray(aptPackages) ? aptPackages : [],
      npmPackages: Array.isArray(npmPackages) ? npmPackages : [],
      region: resolved.region
    });
    return res.status(202).json({ ok: true, ...jobRes });
  } catch (err) {
    return sendError(res, err, 400, 'PACKAGES_INSTALL_FAILED');
  }
});

router.post('/vms/:id/ports', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, port, protocol } = req.body || {};
  const errMsg = auth.validatePortNumber(port);
  if (errMsg) return res.status(400).json({ ok: false, error: errMsg, code: 'VALIDATION_ERROR' });
  const proto = protocol === 'udp' ? 'udp' : 'tcp';

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const exposed = await boxdService.exposeVmPort(resolved.account, req.params.id, {
      port: parseInt(port, 10),
      protocol: proto,
      region: resolved.region
    });
    return res.status(201).json({ ok: true, port: exposed });
  } catch (err) {
    return sendError(res, err, 400, 'EXPOSE_PORT_FAILED');
  }
});

router.delete('/vms/:id/ports/:port', requireScope('vm:control'), async (req, res) => {
  const errMsg = auth.validatePortNumber(req.params.port);
  if (errMsg) return res.status(400).json({ ok: false, error: errMsg, code: 'VALIDATION_ERROR' });
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, req.query.accountId, req.query.region);
    const result = await boxdService.unexposeVmPort(resolved.account, req.params.id, {
      port: parseInt(req.params.port, 10),
      region: resolved.region
    });
    return res.json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'UNEXPOSE_PORT_FAILED');
  }
});

router.post('/vms/:id/proxies/default-port', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, port } = req.body || {};
  if (port !== 'auto') {
    const errMsg = auth.validatePortNumber(port);
    if (errMsg) return res.status(400).json({ ok: false, error: errMsg, code: 'VALIDATION_ERROR' });
  }
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const result = await boxdService.setVmDefaultProxyPort(resolved.account, req.params.id, { port, region: resolved.region });
    return res.json({ ok: true, result });
  } catch (err) {
    return sendError(res, err, 400, 'PROXY_PORT_FAILED');
  }
});

router.post('/vms/:id/proxies', requireScope('vm:control'), async (req, res) => {
  const { accountId, region, name, port } = req.body || {};
  const nameErr = auth.validateProxySubdomain(name);
  if (nameErr) return res.status(400).json({ ok: false, error: nameErr, code: 'VALIDATION_ERROR' });
  const portErr = auth.validatePortNumber(port);
  if (portErr) return res.status(400).json({ ok: false, error: portErr, code: 'VALIDATION_ERROR' });

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const proxy = await boxdService.createVmNamedProxy(resolved.account, req.params.id, {
      name: String(name).trim(),
      port: parseInt(port, 10),
      region: resolved.region
    });
    return res.status(201).json({ ok: true, proxy });
  } catch (err) {
    return sendError(res, err, 400, 'CREATE_PROXY_FAILED');
  }
});

router.delete('/vms/:id/proxies/:name', requireScope('vm:control'), async (req, res) => {
  const nameErr = auth.validateProxySubdomain(req.params.name);
  if (nameErr) return res.status(400).json({ ok: false, error: nameErr, code: 'VALIDATION_ERROR' });
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, req.query.accountId, req.query.region);
    const result = await boxdService.deleteVmNamedProxy(resolved.account, req.params.id, {
      name: String(req.params.name).trim(),
      region: resolved.region
    });
    return res.json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'DELETE_PROXY_FAILED');
  }
});

// =========================================================================
// EXEC & SSH PASSWORD (vm:exec)
// =========================================================================
router.post('/vms/:id/exec', requireScope('vm:exec'), async (req, res) => {
  const { accountId, command, timeout, region } = req.body || {};
  if (!command || typeof command !== 'string' || !command.trim()) {
    return res.status(400).json({ ok: false, error: 'Command wajib diisi.', code: 'VALIDATION_ERROR' });
  }
  const safeTimeout = Math.min(Math.max(parseInt(timeout, 10) || 30000, 1000), 120000);
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const result = await boxdService.execCommand(resolved.account, req.params.id, command, safeTimeout, resolved.region);
    dbHelper.logAudit('API_EXEC', req.params.id, `Key "${req.apiKey.name}" exec: ${command.slice(0, 60)}`, req.clientIp);
    res.setApiLogSummary(`Exec on ${req.params.id}`);
    return res.json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'EXEC_FAILED');
  }
});

router.get('/vms/:id/ssh-password', requireScope('vm:exec'), async (req, res) => {
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, req.query.accountId, req.query.region);
    const info = await boxdService.getVmSshPasswordStatus(resolved.account, req.params.id, resolved.region);
    return res.json({ ok: true, ...info });
  } catch (err) {
    return sendError(res, err, 400, 'SSH_STATUS_FAILED');
  }
});

router.post('/vms/:id/ssh-password', requireScope('vm:exec'), async (req, res) => {
  const { accountId, password, sshUser, region } = req.body || {};
  const errMsg = auth.validateSshPasswordInput({ password, sshUser });
  if (errMsg) return res.status(400).json({ ok: false, error: errMsg, code: 'VALIDATION_ERROR' });

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, accountId, region);
    const result = await boxdService.setupVmSshPassword(resolved.account, req.params.id, {
      password,
      sshUser: sshUser || 'root',
      region: resolved.region
    });
    dbHelper.logAudit('API_SSH_PASSWORD_SET', req.params.id, `Key "${req.apiKey.name}" set SSH password (${sshUser || 'root'})`, req.clientIp);
    return res.json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'SSH_SETUP_FAILED');
  }
});

router.delete('/vms/:id/ssh-password', requireScope('vm:exec'), async (req, res) => {
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, req.query.accountId, req.query.region);
    const result = await boxdService.disableVmSshPassword(resolved.account, req.params.id, resolved.region);
    dbHelper.logAudit('API_SSH_PASSWORD_OFF', req.params.id, `Key "${req.apiKey.name}" disable SSH password`, req.clientIp);
    return res.json({ ok: true, ...result });
  } catch (err) {
    return sendError(res, err, 400, 'SSH_DISABLE_FAILED');
  }
});

// =========================================================================
// DELETE VM (vm:delete) & SNAPSHOTS & JOBS
// =========================================================================
router.delete('/vms/:id', requireScope('vm:delete'), async (req, res) => {
  try {
    const resolved = await resolveAccountAndVm(req.apiKey, req.params.id, req.query.accountId, req.query.region);
    await boxdService.deleteMachine(resolved.account, req.params.id, resolved.region);
    dbHelper.logAudit('API_DELETE_VM', req.params.id, `Key "${req.apiKey.name}" delete VM ${req.params.id}`, req.clientIp);
    res.setApiLogSummary(`Deleted VM ${req.params.id}`);
    return res.json({ ok: true, id: req.params.id });
  } catch (err) {
    return sendError(res, err, 400, 'DELETE_VM_FAILED');
  }
});

router.get('/snapshots', requireScope('vm:read'), async (req, res) => {
  try {
    const { accountId, region } = req.query;
    let accounts = getAllowedAccountsForKey(req.apiKey);
    if (accountId && accountId !== 'all') {
      if (!isAccountAllowedForKey(req.apiKey, String(accountId))) {
        return res.status(403).json({ ok: false, error: 'Akun tidak diizinkan.', code: 'ACCOUNT_NOT_ALLOWED' });
      }
      accounts = accounts.filter(a => a.id === String(accountId));
    }
    const allSnaps = [];
    for (const acc of accounts) {
      try {
        const list = await boxdService.listSnapshots(acc, region || 'all');
        list.forEach(s => allSnaps.push({ ...s, accountId: acc.id, accountLabel: acc.label }));
      } catch (e) {}
    }
    return res.json({ ok: true, count: allSnaps.length, snapshots: allSnaps });
  } catch (err) {
    return sendError(res, err, 500, 'LIST_SNAPSHOTS_ERROR');
  }
});

router.post('/snapshots', requireScope('vm:control'), async (req, res) => {
  const { machineId, accountId, name, region } = req.body || {};
  if (!machineId) return res.status(400).json({ ok: false, error: 'machineId wajib diisi.', code: 'VALIDATION_ERROR' });
  const nameErr = auth.validateSnapshotName(name);
  if (nameErr) return res.status(400).json({ ok: false, error: nameErr, code: 'VALIDATION_ERROR' });

  try {
    const resolved = await resolveAccountAndVm(req.apiKey, machineId, accountId, region);
    const snapshot = await boxdService.createSnapshot(resolved.account, machineId, String(name).trim(), resolved.region);
    return res.status(201).json({ ok: true, snapshot });
  } catch (err) {
    return sendError(res, err, 400, 'CREATE_SNAPSHOT_FAILED');
  }
});

router.delete('/snapshots/:name', requireScope('vm:delete'), async (req, res) => {
  const { accountId, region } = req.query;
  const account = accountId
    ? (isAccountAllowedForKey(req.apiKey, String(accountId)) ? dbHelper.getAccountById(String(accountId)) : null)
    : selectAutoAccountForDeploy(req.apiKey);
  if (!account) {
    return res.status(403).json({ ok: false, error: 'Akun tidak ditemukan atau tidak diizinkan.', code: 'ACCOUNT_NOT_ALLOWED' });
  }
  try {
    await boxdService.deleteSnapshot(account, req.params.name, region);
    return res.json({ ok: true, name: req.params.name });
  } catch (err) {
    return sendError(res, err, 400, 'DELETE_SNAPSHOT_FAILED');
  }
});

router.get('/jobs/:jobId', requireScope('vm:read'), (req, res) => {
  const job = boxdService.getVmJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ ok: false, error: 'Job tidak ditemukan atau sudah kedaluwarsa.', code: 'JOB_NOT_FOUND' });
  }
  if (job.accountId && !isAccountAllowedForKey(req.apiKey, job.accountId)) {
    return res.status(403).json({ ok: false, error: 'API key tidak diizinkan mengakses job ini.', code: 'ACCOUNT_NOT_ALLOWED' });
  }
  return res.json({ ok: true, job });
});

router.use((req, res) => {
  return res.status(404).json({
    ok: false,
    error: `Endpoint ${req.method} /api/v1${req.path} tidak ditemukan.`,
    code: 'ENDPOINT_NOT_FOUND'
  });
});

module.exports = router;
