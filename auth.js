require('dotenv').config();
const crypto = require('crypto');
const net = require('net');
const dbHelper = require('./db');

const ACCESS_PIN = process.env.ACCESS_PIN || 'change-me-pin-2026';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days (aligned with UI & ?key= cookie)

// In-memory rate limiting for login attempts and API endpoints
const loginAttempts = new Map(); // ip -> { count: number, lockedUntil: number }
const rateLimitBuckets = new Map(); // key -> { count: number, resetTime: number }

function checkRateLimit(ip) {
  const now = Date.now();
  const record = loginAttempts.get(ip);
  if (!record) return { allowed: true };

  if (record.lockedUntil && record.lockedUntil > now) {
    const remainingSecs = Math.ceil((record.lockedUntil - now) / 1000);
    return { allowed: false, remainingSecs };
  }

  // Reset if expired
  if (record.lockedUntil && record.lockedUntil <= now) {
    loginAttempts.delete(ip);
    return { allowed: true };
  }

  return { allowed: true };
}

function recordLoginAttempt(ip, success) {
  const now = Date.now();
  if (success) {
    loginAttempts.delete(ip);
    return;
  }

  const record = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  record.count += 1;

  if (record.count >= 5) {
    record.lockedUntil = now + (15 * 60 * 1000); // lock 15 mins
  }
  loginAttempts.set(ip, record);
}

// Granular Endpoint Rate Limiter (Anti-Spam / Anti-DDoS)
function createRateLimiter({ windowMs = 60000, max = 30, message = 'Rate limit terlampaui.' }) {
  return (req, res, next) => {
    const ip = extractClientIp(req);
    const key = `${ip}:${req.baseUrl || ''}${req.route ? req.route.path : req.path}`;
    const now = Date.now();

    let bucket = rateLimitBuckets.get(key);
    if (!bucket || bucket.resetTime <= now) {
      bucket = { count: 1, resetTime: now + windowMs };
      rateLimitBuckets.set(key, bucket);
      return next();
    }

    bucket.count += 1;
    if (bucket.count > max) {
      const retryAfter = Math.ceil((bucket.resetTime - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({
        error: `${message} Coba lagi dalam ${retryAfter} detik.`,
        code: 'RATE_LIMITED',
        retryAfter
      });
    }

    next();
  };
}

// Parse memory string (e.g. "4G", "8GiB", "512M") or number (MB) into MB
function parseMemoryMb(memory) {
  if (typeof memory === 'number') return memory;
  if (typeof memory === 'string') {
    const trimmed = memory.trim();
    if (/^\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed);
    const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*(mi?b?|gi?b?)$/i);
    if (match) {
      const val = Number(match[1]);
      const unit = match[2].toLowerCase();
      return unit.startsWith('g') ? Math.round(val * 1024) : Math.round(val);
    }
  }
  return NaN;
}

// Input Validation Layer
function validateMachineInput(data) {
  const { name, region, vcpu, memory } = data;
  if (name !== undefined && name !== null && String(name).trim() !== '') {
    const cleanName = String(name).trim();
    if (!/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/.test(cleanName)) {
      return 'Nama mesin harus 2-63 karakter alfanumerik huruf kecil & strip (cth: my-vm-1)';
    }
  }
  if (region !== undefined && region !== null && String(region).trim() !== '' && String(region).toLowerCase() !== 'default') {
    const allowedRegions = ['fra', 'nyc', 'sfo', 'lon', 'ams'];
    if (typeof region !== 'string' || !allowedRegions.includes(region.toLowerCase())) {
      return `Region harus salah satu dari: default, ${allowedRegions.join(', ')}`;
    }
  }
  if (vcpu !== undefined && vcpu !== null && vcpu !== '') {
    const num = Number(vcpu);
    if (isNaN(num) || num < 1 || num > 32) {
      return 'vCPU harus berupa angka valid antara 1 hingga 32';
    }
  }
  if (memory !== undefined && memory !== null && memory !== '') {
    const mb = parseMemoryMb(memory);
    if (isNaN(mb) || mb < 512 || mb > 65536) {
      return 'Memory harus antara 512 MB hingga 64 GB (65536 MB), cth: 4G atau 4096';
    }
  }
  return null;
}

function signSession(userId = 'admin') {
  const iat = Date.now();
  const exp = iat + SESSION_DURATION_MS;
  const payload = Buffer.from(JSON.stringify({ u: userId, iat, exp })).toString('base64url');
  const hmac = crypto.createHmac('sha256', SESSION_SECRET);
  hmac.update(payload);
  const sig = hmac.digest('base64url');
  return `${payload}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const [payloadBase64, providedSig] = parts;
  const hmac = crypto.createHmac('sha256', SESSION_SECRET);
  hmac.update(payloadBase64);
  const expectedSig = hmac.digest('base64url');

  try {
    const bufProvided = Buffer.from(providedSig);
    const bufExpected = Buffer.from(expectedSig);
    if (bufProvided.length !== bufExpected.length || !crypto.timingSafeEqual(bufProvided, bufExpected)) {
      return null;
    }
  } catch (e) {
    return null;
  }

  try {
    const payload = JSON.parse(Buffer.from(payloadBase64, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) {
      return null; // Expired
    }
    return payload;
  } catch (e) {
    return null;
  }
}

function verifyPin(inputPin) {
  if (!inputPin || typeof inputPin !== 'string') return false;
  const bufInput = Buffer.from(inputPin);
  const bufExpected = Buffer.from(ACCESS_PIN);
  if (bufInput.length !== bufExpected.length) return false;
  return crypto.timingSafeEqual(bufInput, bufExpected);
}

function getVaultKey() {
  return crypto.createHash('sha256').update(`boxd-fleet-ssh-v1:${SESSION_SECRET}`).digest();
}

function encryptSecret(plaintext) {
  if (typeof plaintext !== 'string' || !plaintext) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getVaultKey(), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64url')}.${tag.toString('base64url')}.${encrypted.toString('base64url')}`;
}

function decryptSecret(ciphertext) {
  if (!ciphertext || typeof ciphertext !== 'string') return null;
  const parts = ciphertext.split('.');
  if (parts.length !== 3) return null;
  try {
    const iv = Buffer.from(parts[0], 'base64url');
    const tag = Buffer.from(parts[1], 'base64url');
    const encrypted = Buffer.from(parts[2], 'base64url');
    if (iv.length !== 12 || tag.length !== 16 || encrypted.length === 0) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', getVaultKey(), iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  } catch (e) {
    return null;
  }
}

function validateSshPasswordInput({ password, sshUser = 'root' } = {}) {
  if (typeof password !== 'string' || password.length < 6 || password.length > 128) {
    return 'Password SSH harus antara 6 hingga 128 karakter';
  }
  if (/[\r\n\0]/.test(password)) {
    return 'Password SSH tidak boleh mengandung karakter baris baru atau null byte';
  }
  if (!['root', 'boxd', 'both'].includes(sshUser)) {
    return 'Username SSH harus salah satu dari: root, boxd, atau both';
  }
  return null;
}

function validateRuntimeSettings({ autoSuspendTimeout, autoHibernateTimeout, botProtectionMode, idleIgnoreOutbound } = {}) {
  if (autoSuspendTimeout !== undefined && autoSuspendTimeout !== null && autoSuspendTimeout !== '') {
    const val = Number(autoSuspendTimeout);
    if (!Number.isInteger(val) || val < 0 || val > 604800) {
      return 'Auto-suspend harus bilangan bulat antara 0 hingga 604800 detik';
    }
  }
  if (autoHibernateTimeout !== undefined && autoHibernateTimeout !== null && autoHibernateTimeout !== '') {
    const val = Number(autoHibernateTimeout);
    if (!Number.isInteger(val) || val < 0 || val > 2592000) {
      return 'Auto-hibernate harus bilangan bulat antara 0 hingga 2592000 detik';
    }
  }
  if (botProtectionMode !== undefined && botProtectionMode !== null && botProtectionMode !== '') {
    if (!['off', 'sleep_only', 'on'].includes(String(botProtectionMode))) {
      return 'Bot protection harus salah satu dari: off, sleep_only, on';
    }
  }
  if (idleIgnoreOutbound !== undefined && typeof idleIgnoreOutbound !== 'boolean') {
    return 'idleIgnoreOutbound harus boolean';
  }
  return null;
}

function validatePackageList(rawPackages, type = 'apt') {
  if (!['apt', 'npm'].includes(type)) {
    return { error: 'Tipe paket harus apt atau npm', packages: [] };
  }
  const items = Array.isArray(rawPackages)
    ? rawPackages
    : String(rawPackages || '').split(/[\s,]+/).filter(Boolean);
  const clean = [];
  const aptRe = /^[a-z0-9][a-z0-9+.-]{0,63}$/;
  const npmRe = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]{0,80}(@[a-zA-Z0-9._-]+)?$/;

  for (const raw of items) {
    const pkg = String(raw || '').trim();
    if (!pkg) continue;
    const ok = type === 'apt' ? aptRe.test(pkg) : npmRe.test(pkg);
    if (!ok) {
      return { error: `Nama paket ${type.toUpperCase()} tidak valid: "${pkg}"`, packages: [] };
    }
    if (!clean.includes(pkg)) clean.push(pkg);
  }
  if (clean.length > 25) {
    return { error: 'Maksimal 25 paket dalam satu kali instalasi', packages: [] };
  }
  return { error: null, packages: clean };
}

function validatePortNumber(port) {
  const num = Number(port);
  if (!Number.isInteger(num) || num < 1 || num > 65535) {
    return 'Nomor port harus antara 1 hingga 65535';
  }
  return null;
}

function validateProxySubdomain(name) {
  const clean = String(name || '').trim();
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(clean)) {
    return 'Nama subdomain harus huruf kecil/angka/strip (1-63 kar., tidak diawali/diakhiri strip)';
  }
  return null;
}

function validateSnapshotName(name) {
  const clean = String(name || '').trim();
  if (!/^[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/.test(clean)) {
    return 'Nama snapshot harus 2-63 karakter huruf kecil, angka, atau strip';
  }
  return null;
}

function isHttpsRequest(req) {
  if (!req) return false;
  if (req.secure) return true;
  const proto = req.headers && req.headers['x-forwarded-proto'];
  if (proto && String(proto).split(',')[0].trim().toLowerCase() === 'https') return true;
  return false;
}

function getSessionCookieOptions(req) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: isHttpsRequest(req),
    path: '/',
    maxAge: SESSION_DURATION_MS
  };
}

function getClearCookieOptions(req) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: isHttpsRequest(req),
    path: '/'
  };
}

function requireAuth(req, res, next) {
  // 1. Check Cookie
  let token = req.cookies && req.cookies.boxd_session;

  // 2. Check Authorization Header
  if (!token && req.headers.authorization) {
    const match = req.headers.authorization.match(/^Bearer\s+(.+)$/i);
    if (match) token = match[1];
  }

  // 3. Check X-Session-Token or Query Token
  if (!token && req.headers['x-session-token']) {
    token = req.headers['x-session-token'];
  }
  if (!token && req.query && req.query.token) {
    token = req.query.token;
  }

  // 4. Check Direct PIN header or Query Key parameter (?key=...)
  const directPin = req.headers['x-access-pin'] || (req.query && req.query.key);
  if (directPin && verifyPin(directPin)) {
    const freshToken = signSession('admin');
    res.cookie('boxd_session', freshToken, getSessionCookieOptions(req));
    req.user = 'admin';
    return next();
  }

  if (token) {
    const session = verifySession(token);
    if (session) {
      req.user = session.u || 'admin';
      return next();
    }
  }

  // Reject unauthorized access with 401
  return res.status(401).json({
    authenticated: false,
    error: 'Akses ditolak: Autentikasi sesi atau PIN diperlukan.',
    code: 'UNAUTHORIZED'
  });
}

function timingSafeStringEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function normalizeValidIp(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const norm = dbHelper.normalizeIpAddress(raw);
  return norm ? norm.ip : null;
}

function extractClientIp(req) {
  if (!req) return '127.0.0.1';
  const headers = req.headers || {};
  const proxySecret = process.env.PROXY_SECRET;
  const providedSecret = headers['x-boxd-proxy-secret'];

  if (proxySecret && typeof providedSecret === 'string' && timingSafeStringEqual(providedSecret, proxySecret)) {
    const trustedWorkerIp = normalizeValidIp(headers['x-boxd-client-ip']) ||
      normalizeValidIp(headers['x-real-ip']) ||
      (headers['x-forwarded-for'] ? normalizeValidIp(String(headers['x-forwarded-for']).split(',')[0]) : null);
    if (trustedWorkerIp) return trustedWorkerIp;
  }

  // If PROXY_SECRET is not set (local/custom setup without worker secret), allow X-Boxd-Client-IP if provided alongside CF header
  if (!proxySecret) {
    const workerIp = normalizeValidIp(headers['x-boxd-client-ip']);
    if (workerIp) return workerIp;
  }

  const cfIp = normalizeValidIp(headers['cf-connecting-ip']);
  if (cfIp) return cfIp;

  if (!proxySecret) {
    const xReal = normalizeValidIp(headers['x-real-ip']);
    if (xReal) return xReal;

    const xff = headers['x-forwarded-for'];
    if (xff) {
      const first = normalizeValidIp(String(xff).split(',')[0]);
      if (first) return first;
    }
  }

  const rawSocket = (req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || '127.0.0.1';
  return normalizeValidIp(rawSocket) || '127.0.0.1';
}

const VALID_API_SCOPES = ['vm:read', 'vm:create', 'vm:control', 'vm:exec', 'vm:delete'];

function hashApiKey(rawKey) {
  if (!rawKey || typeof rawKey !== 'string') return '';
  return crypto
    .createHash('sha256')
    .update(`boxd-fleet-api-key-v1:${rawKey.trim()}`)
    .digest('hex');
}

function generateApiKeyPair({ requireHmac = false } = {}) {
  const rawKey = `bfk_live_${crypto.randomBytes(24).toString('base64url')}`;
  const keyPrefix = `${rawKey.slice(0, 15)}...${rawKey.slice(-4)}`;
  const keyHash = hashApiKey(rawKey);

  let rawHmacSecret = null;
  let hmacSecretEnc = null;
  if (requireHmac) {
    rawHmacSecret = `bfk_sec_${crypto.randomBytes(24).toString('base64url')}`;
    hmacSecretEnc = encryptSecret(rawHmacSecret);
  }

  return {
    rawKey,
    keyPrefix,
    keyHash,
    rawHmacSecret,
    hmacSecretEnc
  };
}

function verifyHmacSignature({ secret, timestampHeader, method, originalUrl, rawBody, providedSignature }) {
  if (!secret || typeof secret !== 'string') {
    return { valid: false, code: 'HMAC_CONFIG_ERROR', error: 'Konfigurasi signing secret tidak valid.' };
  }
  const tsRaw = String(timestampHeader || '').trim();
  const sigRaw = String(providedSignature || '').trim().toLowerCase();
  if (!tsRaw || !sigRaw) {
    return { valid: false, code: 'HMAC_HEADERS_MISSING', error: 'Header X-API-Timestamp dan X-API-Signature wajib disertakan.' };
  }
  if (!/^\d{10,16}$/.test(tsRaw)) {
    return { valid: false, code: 'HMAC_INVALID_TIMESTAMP', error: 'Format X-API-Timestamp harus Unix timestamp (detik atau ms).' };
  }
  const tsNum = Number(tsRaw);
  const tsMs = tsRaw.length <= 10 ? tsNum * 1000 : tsNum;
  if (!Number.isFinite(tsMs) || Math.abs(Date.now() - tsMs) > 300000) {
    return { valid: false, code: 'HMAC_TIMESTAMP_EXPIRED', error: 'Timestamp kedaluwarsa (maksimal selisih ±5 menit dari waktu server).' };
  }
  if (!/^[a-f0-9]{64}$/.test(sigRaw)) {
    return { valid: false, code: 'HMAC_INVALID_SIGNATURE', error: 'Format X-API-Signature harus HMAC-SHA256 hex 64 karakter.' };
  }

  const bodyHash = crypto.createHash('sha256').update(rawBody || '').digest('hex');
  const canonical = `${tsRaw}.${String(method || 'GET').toUpperCase()}.${originalUrl || '/'}.${bodyHash}`;
  const expected = crypto.createHmac('sha256', secret).update(canonical).digest('hex');

  if (!timingSafeStringEqual(sigRaw, expected)) {
    return { valid: false, code: 'HMAC_INVALID_SIGNATURE', error: 'Verifikasi X-API-Signature gagal.' };
  }
  return { valid: true };
}

function validateApiKeyInput(input = {}, { isUpdate = false } = {}) {
  const clean = {};

  if (!isUpdate || input.name !== undefined) {
    const name = String(input.name || '').trim();
    if (!name || name.length < 2 || name.length > 64) {
      return { error: 'Nama API key harus 2 hingga 64 karakter.' };
    }
    clean.name = name;
  }

  if (!isUpdate || input.scopes !== undefined) {
    const rawScopes = Array.isArray(input.scopes) ? input.scopes : ['vm:read', 'vm:create', 'vm:control'];
    const filtered = [...new Set(rawScopes.map(s => String(s).trim()).filter(s => VALID_API_SCOPES.includes(s)))];
    if (filtered.length === 0) {
      return { error: 'Pilih minimal satu izin (scope) API yang valid.' };
    }
    clean.scopes = filtered;
  }

  if (!isUpdate || input.allowedAccountIds !== undefined) {
    const rawAcc = Array.isArray(input.allowedAccountIds) ? input.allowedAccountIds : ['*'];
    const cleanedAcc = [...new Set(rawAcc.map(a => String(a).trim()).filter(Boolean))];
    clean.allowedAccountIds = cleanedAcc.length === 0 || cleanedAcc.includes('*') ? ['*'] : cleanedAcc;
  }

  if (!isUpdate || input.allowedIps !== undefined) {
    let rawIps = input.allowedIps;
    if (typeof rawIps === 'string') {
      rawIps = rawIps.split(/[\n,;]+/).map(s => s.trim()).filter(Boolean);
    } else if (!Array.isArray(rawIps)) {
      rawIps = [];
    }
    const normalizedIps = [];
    for (const entry of rawIps) {
      const parsed = dbHelper.parseIpOrCidr(entry);
      if (!parsed) {
        return { error: `Allowed IP/CIDR tidak valid: "${entry}"` };
      }
      normalizedIps.push(parsed.canonical);
    }
    clean.allowedIps = [...new Set(normalizedIps)];
  }

  if (!isUpdate || input.requireHmac !== undefined) {
    clean.requireHmac = !!input.requireHmac;
  }

  if (!isUpdate || input.rateLimitRpm !== undefined) {
    const rawRpm = (input.rateLimitRpm === undefined || input.rateLimitRpm === null || input.rateLimitRpm === '') ? 60 : input.rateLimitRpm;
    const rpm = parseInt(rawRpm, 10);
    if (isNaN(rpm) || rpm < 5 || rpm > 600) {
      return { error: 'Rate limit harus antara 5 hingga 600 request per menit.' };
    }
    clean.rateLimitRpm = rpm;
  }

  if (!isUpdate || input.maxDeployPerHour !== undefined) {
    const rawDep = (input.maxDeployPerHour === undefined || input.maxDeployPerHour === null || input.maxDeployPerHour === '') ? 10 : input.maxDeployPerHour;
    const maxDep = parseInt(rawDep, 10);
    if (isNaN(maxDep) || maxDep < 0 || maxDep > 200) {
      return { error: 'Batas generate VM/jam harus antara 0 (unlimited) hingga 200.' };
    }
    clean.maxDeployPerHour = maxDep;
  }

  if (!isUpdate || input.maxVcpuPerVm !== undefined) {
    const rawVcpu = (input.maxVcpuPerVm === undefined || input.maxVcpuPerVm === null || input.maxVcpuPerVm === '') ? 8 : input.maxVcpuPerVm;
    const maxVcpu = parseInt(rawVcpu, 10);
    if (isNaN(maxVcpu) || ![1, 2, 4, 8, 16, 32].includes(maxVcpu)) {
      return { error: 'Batas maksimal vCPU harus salah satu dari 1, 2, 4, 8, 16, atau 32.' };
    }
    clean.maxVcpuPerVm = maxVcpu;
  }

  if (!isUpdate || input.expiresDays !== undefined) {
    if (input.expiresDays === undefined || input.expiresDays === null || input.expiresDays === '' || input.expiresDays === 0 || input.expiresDays === 'never') {
      clean.expiresAt = null;
    } else {
      const days = parseInt(input.expiresDays, 10);
      if (isNaN(days) || days < 1 || days > 3650) {
        return { error: 'Masa berlaku harus antara 1 hingga 3650 hari (atau selamanya).' };
      }
      clean.expiresAt = Date.now() + days * 24 * 60 * 60 * 1000;
    }
  }

  if (input.enabled !== undefined) {
    clean.enabled = !!input.enabled;
  }

  return { valid: true, data: clean };
}

module.exports = {
  ACCESS_PIN,
  VALID_API_SCOPES,
  signSession,
  verifySession,
  verifyPin,
  encryptSecret,
  decryptSecret,
  timingSafeStringEqual,
  hashApiKey,
  generateApiKeyPair,
  verifyHmacSignature,
  validateApiKeyInput,
  validateSshPasswordInput,
  validateRuntimeSettings,
  validatePackageList,
  validatePortNumber,
  validateProxySubdomain,
  validateSnapshotName,
  checkRateLimit,
  recordLoginAttempt,
  createRateLimiter,
  validateMachineInput,
  getSessionCookieOptions,
  getClearCookieOptions,
  extractClientIp,
  requireAuth
};
