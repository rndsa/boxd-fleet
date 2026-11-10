require('dotenv').config();
const crypto = require('crypto');
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
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
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

function requireAuth(req, res, next) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

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
    res.cookie('boxd_session', freshToken, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 30 * 24 * 60 * 60 * 1000
    });
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

function extractClientIp(req) {
  if (!req) return '127.0.0.1';
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp) return cfIp.trim();

  const xff = req.headers['x-forwarded-for'];
  if (xff) {
    const parts = xff.split(',');
    return parts[0].trim();
  }

  const xReal = req.headers['x-real-ip'];
  if (xReal) return xReal.trim();

  let raw = req.socket?.remoteAddress || req.connection?.remoteAddress || '127.0.0.1';
  if (raw.startsWith('::ffff:')) {
    raw = raw.replace('::ffff:', '');
  }
  return raw;
}

module.exports = {
  ACCESS_PIN,
  signSession,
  verifySession,
  verifyPin,
  checkRateLimit,
  recordLoginAttempt,
  createRateLimiter,
  validateMachineInput,
  extractClientIp,
  requireAuth
};
