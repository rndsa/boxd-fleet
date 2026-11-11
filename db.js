const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const net = require('net');

const dbDir = path.join(__dirname, 'data');
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const dbPath = process.env.BOXD_DB_PATH
  ? path.resolve(process.env.BOXD_DB_PATH)
  : path.join(dbDir, 'boxd.db');
const db = new Database(dbPath);

// Enable WAL mode for performance & concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    api_key TEXT NOT NULL,
    user_id TEXT,
    display_name TEXT,
    org_id TEXT,
    org_name TEXT,
    org_slug TEXT,
    key_scope TEXT DEFAULT 'unknown',
    home_region TEXT DEFAULT 'fra',
    enabled_regions TEXT DEFAULT '[]',
    balance_micro INTEGER DEFAULT 0,
    currency TEXT DEFAULT 'USD',
    max_vms INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    last_error TEXT,
    notes TEXT,
    last_synced_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    action TEXT NOT NULL,
    account_id TEXT,
    details TEXT,
    ip TEXT
  );

  CREATE TABLE IF NOT EXISTS allowed_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS security_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS vm_ssh_access (
    machine_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    machine_name TEXT,
    region TEXT DEFAULT 'fra',
    ssh_user TEXT DEFAULT 'root',
    public_port INTEGER,
    dns TEXT,
    password_enc TEXT,
    enabled INTEGER DEFAULT 1,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS vm_configs (
    machine_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    region TEXT DEFAULT 'fra',
    auto_update_enabled INTEGER DEFAULT 0,
    auto_update_interval_hours INTEGER DEFAULT 12,
    auto_update_runtimes INTEGER DEFAULT 1,
    always_on_mode INTEGER DEFAULT 0,
    starter_kits TEXT DEFAULT '[]',
    last_update_status TEXT,
    last_update_summary TEXT,
    last_update_at INTEGER,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    hmac_secret_enc TEXT,
    require_hmac INTEGER DEFAULT 0,
    scopes TEXT DEFAULT '["vm:read","vm:create","vm:control"]',
    allowed_account_ids TEXT DEFAULT '["*"]',
    allowed_ips TEXT DEFAULT '[]',
    rate_limit_rpm INTEGER DEFAULT 60,
    max_deploy_per_hour INTEGER DEFAULT 10,
    max_vcpu_per_vm INTEGER DEFAULT 8,
    enabled INTEGER DEFAULT 1,
    expires_at INTEGER,
    last_used_at INTEGER,
    last_used_ip TEXT,
    request_count INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_allowed_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    key_id TEXT,
    key_name TEXT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    ip TEXT,
    summary TEXT
  );

  CREATE TABLE IF NOT EXISTS api_idempotency (
    cache_key TEXT PRIMARY KEY,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    response_enc TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_allowed_ips_ip ON allowed_ips(ip);
  CREATE INDEX IF NOT EXISTS idx_vm_ssh_account ON vm_ssh_access(account_id);
  CREATE INDEX IF NOT EXISTS idx_vm_configs_account ON vm_configs(account_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_api_allowed_ips_ip ON api_allowed_ips(ip);
  CREATE INDEX IF NOT EXISTS idx_api_req_logs_ts ON api_request_logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_api_req_logs_key_ts ON api_request_logs(key_id, timestamp);
  CREATE INDEX IF NOT EXISTS idx_api_idem_created ON api_idempotency(created_at);
`);

// Safe schema migration for existing DBs
try {
  const existingCols = new Set(db.prepare('PRAGMA table_info(accounts)').all().map(c => c.name));
  const migrations = [
    ['org_slug', 'TEXT'],
    ['key_scope', "TEXT DEFAULT 'unknown'"],
    ['home_region', "TEXT DEFAULT 'fra'"],
    ['enabled_regions', "TEXT DEFAULT '[]'"],
    ['last_synced_at', 'INTEGER']
  ];
  for (const [col, def] of migrations) {
    if (!existingCols.has(col)) {
      db.exec(`ALTER TABLE accounts ADD COLUMN ${col} ${def}`);
    }
  }
} catch (e) {
  console.error('DB migration warning:', e.message);
}

// Seed default localhost & optional host IP if not exists
try {
  const insertIp = db.prepare('INSERT OR IGNORE INTO allowed_ips (ip, label, created_at) VALUES (?, ?, ?)');
  insertIp.run('127.0.0.1', 'Localhost (IPv4)', Date.now());
  insertIp.run('::1', 'Localhost (IPv6)', Date.now());
  if (process.env.VPS_HOST_IP) {
    insertIp.run(process.env.VPS_HOST_IP.trim(), 'VPS Host Node', Date.now());
  }
  const insertApiIp = db.prepare('INSERT OR IGNORE INTO api_allowed_ips (ip, label, created_at) VALUES (?, ?, ?)');
  insertApiIp.run('127.0.0.1', 'Localhost (IPv4)', Date.now());
  insertApiIp.run('::1', 'Localhost (IPv6)', Date.now());
} catch (e) {}

let cachedBlockList = null;
let cachedDataVersion = -1;
let cachedApiBlockList = null;
let cachedApiDataVersion = -1;

function normalizeIpAddress(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let clean = raw.trim();
  if (!clean) return null;
  if (clean.toLowerCase().startsWith('::ffff:')) {
    const v4 = clean.slice(7);
    if (net.isIPv4(v4)) clean = v4;
  }
  const family = net.isIP(clean);
  if (!family) return null;
  return { ip: clean, family: family === 4 ? 'ipv4' : 'ipv6' };
}

function parseIpOrCidr(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const clean = raw.trim();
  if (!clean) return null;

  if (clean.includes('/')) {
    const parts = clean.split('/');
    if (parts.length !== 2) return null;
    const norm = normalizeIpAddress(parts[0]);
    if (!norm) return null;
    if (!/^\d+$/.test(parts[1].trim())) return null;
    const prefix = Number(parts[1].trim());
    const maxPrefix = norm.family === 'ipv4' ? 32 : 128;
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) return null;
    return {
      type: 'cidr',
      ip: norm.ip,
      family: norm.family,
      prefix,
      canonical: `${norm.ip}/${prefix}`
    };
  }

  const norm = normalizeIpAddress(clean);
  if (!norm) return null;
  return {
    type: 'ip',
    ip: norm.ip,
    family: norm.family,
    canonical: norm.ip
  };
}

function invalidateIpCache() {
  cachedBlockList = null;
  cachedDataVersion = -1;
}

function invalidateApiIpCache() {
  cachedApiBlockList = null;
  cachedApiDataVersion = -1;
}

function safeJsonArray(str, fallback = []) {
  try {
    const parsed = JSON.parse(str || '[]');
    return Array.isArray(parsed) ? parsed : fallback;
  } catch (e) {
    return fallback;
  }
}

function formatApiKeyRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    keyPrefix: row.key_prefix,
    requireHmac: !!row.require_hmac,
    scopes: safeJsonArray(row.scopes, ['vm:read']),
    allowedAccountIds: safeJsonArray(row.allowed_account_ids, ['*']),
    allowedIps: safeJsonArray(row.allowed_ips, []),
    rateLimitRpm: Number(row.rate_limit_rpm) || 60,
    maxDeployPerHour: row.max_deploy_per_hour !== undefined && row.max_deploy_per_hour !== null ? Number(row.max_deploy_per_hour) : 10,
    maxVcpuPerVm: Number(row.max_vcpu_per_vm) || 8,
    enabled: !!row.enabled,
    expiresAt: row.expires_at ? Number(row.expires_at) : null,
    lastUsedAt: row.last_used_at ? Number(row.last_used_at) : null,
    lastUsedIp: row.last_used_ip || null,
    requestCount: Number(row.request_count) || 0,
    createdAt: Number(row.created_at),
    updatedAt: Number(row.updated_at)
  };
}

function getCompiledApiBlockList() {
  const verRow = db.prepare('PRAGMA data_version').get();
  const ver = verRow ? verRow.data_version : 0;
  if (cachedApiBlockList && cachedApiDataVersion === ver) return cachedApiBlockList;
  const bl = new net.BlockList();
  const rows = db.prepare('SELECT ip FROM api_allowed_ips').all();
  for (const row of rows) {
    const parsed = parseIpOrCidr(row.ip);
    if (!parsed) continue;
    try {
      if (parsed.type === 'cidr') {
        bl.addSubnet(parsed.ip, parsed.prefix, parsed.family);
      } else {
        bl.addAddress(parsed.ip, parsed.family);
      }
    } catch (e) {
      // Skip malformed row
    }
  }
  cachedApiBlockList = bl;
  cachedApiDataVersion = ver;
  return bl;
}

function getCompiledBlockList() {
  const verRow = db.prepare('PRAGMA data_version').get();
  const ver = verRow ? verRow.data_version : 0;
  if (cachedBlockList && cachedDataVersion === ver) return cachedBlockList;
  const bl = new net.BlockList();
  const rows = db.prepare('SELECT ip FROM allowed_ips').all();
  for (const row of rows) {
    const parsed = parseIpOrCidr(row.ip);
    if (!parsed) continue;
    try {
      if (parsed.type === 'cidr') {
        bl.addSubnet(parsed.ip, parsed.prefix, parsed.family);
      } else {
        bl.addAddress(parsed.ip, parsed.family);
      }
    } catch (e) {
      // Skip malformed legacy row cleanly
    }
  }
  cachedBlockList = bl;
  cachedDataVersion = ver;
  return bl;
}

function ipMatchesRule(clientIp, rule) {
  const norm = normalizeIpAddress(clientIp);
  const parsed = parseIpOrCidr(rule);
  if (!norm || !parsed) return false;
  try {
    const bl = new net.BlockList();
    if (parsed.type === 'cidr') {
      bl.addSubnet(parsed.ip, parsed.prefix, parsed.family);
    } else {
      bl.addAddress(parsed.ip, parsed.family);
    }
    return bl.check(norm.ip, norm.family);
  } catch (e) {
    return false;
  }
}

module.exports = {
  db,
  normalizeIpAddress,
  parseIpOrCidr,
  ipMatchesRule,
  getAccounts() {
    return db.prepare("SELECT id, label, user_id, display_name, org_id, org_name, org_slug, key_scope, home_region, enabled_regions, balance_micro, currency, max_vms, status, last_error, notes, last_synced_at, created_at, updated_at, (substr(api_key, 1, 8) || '...' || substr(api_key, -4)) as masked_key FROM accounts ORDER BY created_at ASC").all();
  },
  getAccountsWithKeys() {
    return db.prepare('SELECT * FROM accounts ORDER BY created_at ASC').all();
  },
  getAccountById(id) {
    return db.prepare('SELECT * FROM accounts WHERE id = ?').get(id);
  },
  getAccountByApiKey(apiKey) {
    return db.prepare('SELECT id, label, status FROM accounts WHERE api_key = ?').get(apiKey);
  },
  createAccount({ id, label, api_key, user_id, display_name, org_id, org_name, org_slug, key_scope, home_region, enabled_regions, balance_micro, currency, max_vms, status, last_error, notes, last_synced_at }) {
    const now = Date.now();
    const regionsStr = Array.isArray(enabled_regions) ? JSON.stringify(enabled_regions) : (enabled_regions || '[]');
    db.prepare(`
      INSERT INTO accounts (id, label, api_key, user_id, display_name, org_id, org_name, org_slug, key_scope, home_region, enabled_regions, balance_micro, currency, max_vms, status, last_error, notes, last_synced_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, label, api_key, user_id || null, display_name || null, org_id || null, org_name || null, org_slug || null, key_scope || 'unknown', home_region || 'fra', regionsStr, balance_micro || 0, currency || 'USD', max_vms || 0, status || 'active', last_error || null, notes || '', last_synced_at || null, now, now);
    return this.getAccountById(id);
  },
  updateAccount(id, updates) {
    const allowed = ['label', 'user_id', 'display_name', 'org_id', 'org_name', 'org_slug', 'key_scope', 'home_region', 'enabled_regions', 'balance_micro', 'currency', 'max_vms', 'status', 'last_error', 'notes', 'last_synced_at'];
    const sets = [];
    const values = [];
    for (const key of allowed) {
      if (updates[key] !== undefined) {
        sets.push(`${key} = ?`);
        if (key === 'enabled_regions' && Array.isArray(updates[key])) {
          values.push(JSON.stringify(updates[key]));
        } else {
          values.push(updates[key]);
        }
      }
    }
    if (sets.length === 0) return this.getAccountById(id);
    sets.push('updated_at = ?');
    values.push(Date.now());
    values.push(id);
    db.prepare(`UPDATE accounts SET ${sets.join(', ')} WHERE id = ?`).run(...values);
    return this.getAccountById(id);
  },
  deleteAccount(id) {
    db.prepare('DELETE FROM vm_ssh_access WHERE account_id = ?').run(id);
    db.prepare('DELETE FROM vm_configs WHERE account_id = ?').run(id);
    return db.prepare('DELETE FROM accounts WHERE id = ?').run(id);
  },
  getVmConfig(machineId) {
    const row = db.prepare('SELECT * FROM vm_configs WHERE machine_id = ?').get(machineId);
    if (!row) return null;
    let starterKits = [];
    try {
      const parsed = JSON.parse(row.starter_kits || '[]');
      if (Array.isArray(parsed)) starterKits = parsed;
    } catch (e) {}
    return {
      machineId: row.machine_id,
      accountId: row.account_id,
      region: row.region || 'fra',
      autoUpdateEnabled: !!row.auto_update_enabled,
      autoUpdateIntervalHours: row.auto_update_interval_hours || 12,
      autoUpdateRuntimes: row.auto_update_runtimes !== 0,
      alwaysOnMode: !!row.always_on_mode,
      starterKits,
      lastUpdateStatus: row.last_update_status || null,
      lastUpdateSummary: row.last_update_summary || null,
      lastUpdateAt: row.last_update_at || null,
      updatedAt: row.updated_at || null
    };
  },
  getVmConfigsByAccount(accountId) {
    const rows = db.prepare('SELECT * FROM vm_configs WHERE account_id = ?').all(accountId);
    const map = {};
    for (const row of rows) {
      let starterKits = [];
      try {
        const parsed = JSON.parse(row.starter_kits || '[]');
        if (Array.isArray(parsed)) starterKits = parsed;
      } catch (e) {}
      map[row.machine_id] = {
        autoUpdateEnabled: !!row.auto_update_enabled,
        autoUpdateIntervalHours: row.auto_update_interval_hours || 12,
        autoUpdateRuntimes: row.auto_update_runtimes !== 0,
        alwaysOnMode: !!row.always_on_mode,
        starterKits,
        lastUpdateStatus: row.last_update_status || null,
        lastUpdateSummary: row.last_update_summary || null,
        lastUpdateAt: row.last_update_at || null,
        updatedAt: row.updated_at || null
      };
    }
    return map;
  },
  upsertVmConfig({
    machine_id,
    account_id,
    region = 'fra',
    auto_update_enabled,
    auto_update_interval_hours,
    auto_update_runtimes,
    always_on_mode,
    starter_kits,
    last_update_status,
    last_update_summary,
    last_update_at
  }) {
    const existing = this.getVmConfig(machine_id);
    const now = Date.now();
    const nextAutoUpd = auto_update_enabled !== undefined
      ? (auto_update_enabled ? 1 : 0)
      : (existing && existing.autoUpdateEnabled ? 1 : 0);
    const nextInterval = auto_update_interval_hours !== undefined
      ? Math.max(1, Math.min(168, parseInt(auto_update_interval_hours, 10) || 12))
      : (existing ? existing.autoUpdateIntervalHours : 12);
    const nextRuntimes = auto_update_runtimes !== undefined
      ? (auto_update_runtimes ? 1 : 0)
      : (existing ? (existing.autoUpdateRuntimes ? 1 : 0) : 1);
    const nextAlwaysOn = always_on_mode !== undefined
      ? (always_on_mode ? 1 : 0)
      : (existing && existing.alwaysOnMode ? 1 : 0);
    const kitsArr = starter_kits !== undefined
      ? (Array.isArray(starter_kits) ? starter_kits : [])
      : (existing ? existing.starterKits : []);
    const nextStatus = last_update_status !== undefined
      ? last_update_status
      : (existing ? existing.lastUpdateStatus : null);
    const nextSummary = last_update_summary !== undefined
      ? last_update_summary
      : (existing ? existing.lastUpdateSummary : null);
    const nextAt = last_update_at !== undefined
      ? last_update_at
      : (existing ? existing.lastUpdateAt : null);

    db.prepare(`
      INSERT INTO vm_configs (
        machine_id, account_id, region,
        auto_update_enabled, auto_update_interval_hours, auto_update_runtimes,
        always_on_mode, starter_kits, last_update_status, last_update_summary, last_update_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(machine_id) DO UPDATE SET
        account_id = excluded.account_id,
        region = excluded.region,
        auto_update_enabled = excluded.auto_update_enabled,
        auto_update_interval_hours = excluded.auto_update_interval_hours,
        auto_update_runtimes = excluded.auto_update_runtimes,
        always_on_mode = excluded.always_on_mode,
        starter_kits = excluded.starter_kits,
        last_update_status = excluded.last_update_status,
        last_update_summary = excluded.last_update_summary,
        last_update_at = excluded.last_update_at,
        updated_at = excluded.updated_at
    `).run(
      machine_id,
      account_id,
      region || (existing && existing.region) || 'fra',
      nextAutoUpd,
      nextInterval,
      nextRuntimes,
      nextAlwaysOn,
      JSON.stringify(kitsArr),
      nextStatus,
      nextSummary,
      nextAt,
      now
    );
    return this.getVmConfig(machine_id);
  },
  deleteVmConfig(machineId) {
    return db.prepare('DELETE FROM vm_configs WHERE machine_id = ?').run(machineId);
  },
  getVmSshAccess(machineId) {
    return db.prepare('SELECT * FROM vm_ssh_access WHERE machine_id = ?').get(machineId);
  },
  getVmSshAccessByAccount(accountId) {
    const rows = db.prepare('SELECT * FROM vm_ssh_access WHERE account_id = ?').all(accountId);
    const map = {};
    for (const r of rows) {
      map[r.machine_id] = {
        enabled: !!r.enabled,
        sshUser: r.ssh_user || 'root',
        publicPort: r.public_port || null,
        dns: r.dns || null,
        hasPassword: !!r.password_enc,
        updatedAt: r.updated_at || null
      };
    }
    return map;
  },
  upsertVmSshAccess({ machine_id, account_id, machine_name, region, ssh_user, public_port, dns, password_enc, enabled = 1 }) {
    const now = Date.now();
    db.prepare(`
      INSERT INTO vm_ssh_access (machine_id, account_id, machine_name, region, ssh_user, public_port, dns, password_enc, enabled, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(machine_id) DO UPDATE SET
        account_id = excluded.account_id,
        machine_name = excluded.machine_name,
        region = excluded.region,
        ssh_user = excluded.ssh_user,
        public_port = excluded.public_port,
        dns = excluded.dns,
        password_enc = COALESCE(excluded.password_enc, vm_ssh_access.password_enc),
        enabled = excluded.enabled,
        updated_at = excluded.updated_at
    `).run(machine_id, account_id, machine_name || null, region || 'fra', ssh_user || 'root', public_port || null, dns || null, password_enc || null, enabled ? 1 : 0, now);
    return this.getVmSshAccess(machine_id);
  },
  deleteVmSshAccess(machineId) {
    return db.prepare('DELETE FROM vm_ssh_access WHERE machine_id = ?').run(machineId);
  },
  logAudit(action, account_id, details, ip) {
    try {
      db.prepare(`
        INSERT INTO audit_logs (timestamp, action, account_id, details, ip)
        VALUES (?, ?, ?, ?, ?)
      `).run(Date.now(), action, account_id || null, typeof details === 'object' ? JSON.stringify(details) : details, ip || null);
    } catch (e) {
      console.error('Audit log error:', e.message);
    }
  },
  getRecentAuditLogs(limit = 50) {
    return db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?').all(limit);
  },
  // IP Whitelist Methods
  getAllowedIps() {
    return db.prepare('SELECT * FROM allowed_ips ORDER BY created_at ASC').all();
  },
  addAllowedIp(ip, label = '') {
    const parsed = parseIpOrCidr(ip);
    if (!parsed) return null;
    const cleanIp = parsed.canonical;
    const now = Date.now();
    db.prepare('INSERT OR REPLACE INTO allowed_ips (ip, label, created_at) VALUES (?, ?, ?)').run(cleanIp, label || 'Client Device', now);
    invalidateIpCache();
    return db.prepare('SELECT * FROM allowed_ips WHERE ip = ?').get(cleanIp);
  },
  ensureIpAllowed(ip, label = 'Admin Device') {
    if (this.isIpWhitelisted(ip)) {
      return db.prepare('SELECT * FROM allowed_ips ORDER BY created_at ASC').all().find(item => ipMatchesRule(ip, item.ip)) || null;
    }
    return this.addAllowedIp(ip, label);
  },
  deleteAllowedIp(id) {
    const res = db.prepare('DELETE FROM allowed_ips WHERE id = ?').run(id);
    invalidateIpCache();
    return res;
  },
  isIpWhitelisted(clientIp) {
    const norm = normalizeIpAddress(clientIp);
    if (!norm) return false;
    try {
      const bl = getCompiledBlockList();
      return bl.check(norm.ip, norm.family);
    } catch (e) {
      return false;
    }
  },
  isIpWhitelistEnabled() {
    const row = db.prepare('SELECT value FROM security_config WHERE key = ?').get('ip_whitelist_enabled');
    return row ? row.value === '1' : false;
  },
  setIpWhitelistEnabled(enabled) {
    const val = enabled ? '1' : '0';
    db.prepare('INSERT OR REPLACE INTO security_config (key, value) VALUES (?, ?)').run('ip_whitelist_enabled', val);
    return enabled;
  },

  // --- API Master & Dedicated API Allowed IP Firewall ---
  isApiEnabled() {
    const row = db.prepare('SELECT value FROM security_config WHERE key = ?').get('api_enabled');
    return row ? row.value !== '0' : true;
  },
  setApiEnabled(enabled) {
    const val = enabled ? '1' : '0';
    db.prepare('INSERT OR REPLACE INTO security_config (key, value) VALUES (?, ?)').run('api_enabled', val);
    return enabled;
  },
  isApiIpWhitelistEnabled() {
    const row = db.prepare('SELECT value FROM security_config WHERE key = ?').get('api_ip_whitelist_enabled');
    return row ? row.value === '1' : false;
  },
  setApiIpWhitelistEnabled(enabled) {
    const val = enabled ? '1' : '0';
    db.prepare('INSERT OR REPLACE INTO security_config (key, value) VALUES (?, ?)').run('api_ip_whitelist_enabled', val);
    return enabled;
  },
  getApiAllowedIps() {
    return db.prepare('SELECT * FROM api_allowed_ips ORDER BY created_at ASC').all();
  },
  addApiAllowedIp(ip, label = '') {
    const parsed = parseIpOrCidr(ip);
    if (!parsed) return null;
    const cleanIp = parsed.canonical;
    const now = Date.now();
    db.prepare('INSERT OR REPLACE INTO api_allowed_ips (ip, label, created_at) VALUES (?, ?, ?)').run(cleanIp, label || 'API Client', now);
    invalidateApiIpCache();
    return db.prepare('SELECT * FROM api_allowed_ips WHERE ip = ?').get(cleanIp);
  },
  ensureApiIpAllowed(ip, label = 'API Client') {
    if (this.isApiIpWhitelisted(ip)) {
      return db.prepare('SELECT * FROM api_allowed_ips ORDER BY created_at ASC').all().find(item => ipMatchesRule(ip, item.ip)) || null;
    }
    return this.addApiAllowedIp(ip, label);
  },
  deleteApiAllowedIp(id) {
    const res = db.prepare('DELETE FROM api_allowed_ips WHERE id = ?').run(id);
    invalidateApiIpCache();
    return res;
  },
  isApiIpWhitelisted(clientIp) {
    const norm = normalizeIpAddress(clientIp);
    if (!norm) return false;
    try {
      const bl = getCompiledApiBlockList();
      return bl.check(norm.ip, norm.family);
    } catch (e) {
      return false;
    }
  },

  // --- API Keys CRUD ---
  getApiKeys() {
    const rows = db.prepare(`
      SELECT id, name, key_prefix, require_hmac, scopes, allowed_account_ids, allowed_ips,
             rate_limit_rpm, max_deploy_per_hour, max_vcpu_per_vm, enabled, expires_at,
             last_used_at, last_used_ip, request_count, created_at, updated_at
      FROM api_keys
      ORDER BY created_at DESC
    `).all();
    return rows.map(formatApiKeyRow);
  },
  getApiKeyById(id) {
    const row = db.prepare(`
      SELECT id, name, key_prefix, require_hmac, scopes, allowed_account_ids, allowed_ips,
             rate_limit_rpm, max_deploy_per_hour, max_vcpu_per_vm, enabled, expires_at,
             last_used_at, last_used_ip, request_count, created_at, updated_at
      FROM api_keys
      WHERE id = ?
    `).get(id);
    return formatApiKeyRow(row);
  },
  getApiKeyAuthRecordByHash(keyHash) {
    const row = db.prepare('SELECT * FROM api_keys WHERE key_hash = ?').get(keyHash);
    if (!row) return null;
    return {
      ...formatApiKeyRow(row),
      keyHash: row.key_hash,
      hmacSecretEnc: row.hmac_secret_enc || null
    };
  },
  createApiKey({
    id,
    name,
    keyPrefix,
    keyHash,
    hmacSecretEnc = null,
    requireHmac = false,
    scopes = ['vm:read', 'vm:create', 'vm:control'],
    allowedAccountIds = ['*'],
    allowedIps = [],
    rateLimitRpm = 60,
    maxDeployPerHour = 10,
    maxVcpuPerVm = 8,
    expiresAt = null
  }) {
    const now = Date.now();
    db.prepare(`
      INSERT INTO api_keys (
        id, name, key_prefix, key_hash, hmac_secret_enc, require_hmac,
        scopes, allowed_account_ids, allowed_ips, rate_limit_rpm,
        max_deploy_per_hour, max_vcpu_per_vm, enabled, expires_at,
        request_count, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 0, ?, ?)
    `).run(
      id,
      name,
      keyPrefix,
      keyHash,
      hmacSecretEnc,
      requireHmac ? 1 : 0,
      JSON.stringify(scopes),
      JSON.stringify(allowedAccountIds),
      JSON.stringify(allowedIps),
      rateLimitRpm,
      maxDeployPerHour,
      maxVcpuPerVm,
      expiresAt,
      now,
      now
    );
    return this.getApiKeyById(id);
  },
  updateApiKey(id, fields = {}) {
    const existing = db.prepare('SELECT * FROM api_keys WHERE id = ?').get(id);
    if (!existing) return null;
    const now = Date.now();
    const sets = [];
    const params = [];

    if (fields.name !== undefined) { sets.push('name = ?'); params.push(fields.name); }
    if (fields.keyPrefix !== undefined) { sets.push('key_prefix = ?'); params.push(fields.keyPrefix); }
    if (fields.keyHash !== undefined) { sets.push('key_hash = ?'); params.push(fields.keyHash); }
    if (fields.hmacSecretEnc !== undefined) { sets.push('hmac_secret_enc = ?'); params.push(fields.hmacSecretEnc); }
    if (fields.requireHmac !== undefined) { sets.push('require_hmac = ?'); params.push(fields.requireHmac ? 1 : 0); }
    if (fields.scopes !== undefined) { sets.push('scopes = ?'); params.push(JSON.stringify(fields.scopes)); }
    if (fields.allowedAccountIds !== undefined) { sets.push('allowed_account_ids = ?'); params.push(JSON.stringify(fields.allowedAccountIds)); }
    if (fields.allowedIps !== undefined) { sets.push('allowed_ips = ?'); params.push(JSON.stringify(fields.allowedIps)); }
    if (fields.rateLimitRpm !== undefined) { sets.push('rate_limit_rpm = ?'); params.push(fields.rateLimitRpm); }
    if (fields.maxDeployPerHour !== undefined) { sets.push('max_deploy_per_hour = ?'); params.push(fields.maxDeployPerHour); }
    if (fields.maxVcpuPerVm !== undefined) { sets.push('max_vcpu_per_vm = ?'); params.push(fields.maxVcpuPerVm); }
    if (fields.enabled !== undefined) { sets.push('enabled = ?'); params.push(fields.enabled ? 1 : 0); }
    if (fields.expiresAt !== undefined) { sets.push('expires_at = ?'); params.push(fields.expiresAt); }

    if (sets.length === 0) return formatApiKeyRow(existing);
    sets.push('updated_at = ?');
    params.push(now, id);

    db.prepare(`UPDATE api_keys SET ${sets.join(', ')} WHERE id = ?`).run(...params);
    return this.getApiKeyById(id);
  },
  recordApiKeyUsage(id, ip) {
    if (!id) return;
    db.prepare('UPDATE api_keys SET last_used_at = ?, last_used_ip = ?, request_count = request_count + 1 WHERE id = ?').run(Date.now(), ip || null, id);
  },
  deleteApiKey(id) {
    return db.prepare('DELETE FROM api_keys WHERE id = ?').run(id);
  },

  // --- API Request Logs & Deploy Quota ---
  logApiRequest({ keyId = null, keyName = null, method, path, statusCode, ip = null, summary = '' }) {
    try {
      db.exec('SAVEPOINT sp_api_log');
      db.prepare('INSERT INTO api_request_logs (timestamp, key_id, key_name, method, path, status_code, ip, summary) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(Date.now(), keyId, keyName, String(method || 'GET').slice(0, 12), String(path || '/').slice(0, 180), Number(statusCode) || 200, ip, String(summary || '').slice(0, 220));
      db.prepare('DELETE FROM api_request_logs WHERE id NOT IN (SELECT id FROM api_request_logs ORDER BY id DESC LIMIT 200)').run();
      db.exec('RELEASE SAVEPOINT sp_api_log');
    } catch (e) {
      try { db.exec('ROLLBACK TO SAVEPOINT sp_api_log; RELEASE SAVEPOINT sp_api_log'); } catch (_) {}
      return null;
    }
  },
  getRecentApiRequestLogs(limit = 50) {
    const safeLimit = Math.max(1, Math.min(200, parseInt(limit, 10) || 50));
    return db.prepare('SELECT * FROM api_request_logs ORDER BY id DESC LIMIT ?').all(safeLimit);
  },
  countKeyDeploysSince(keyId, sinceMs) {
    if (!keyId) return 0;
    const row = db.prepare(`
      SELECT COUNT(*) as cnt
      FROM api_request_logs
      WHERE key_id = ?
        AND method = 'POST'
        AND (path = '/vms' OR path = '/vms/from-snapshot')
        AND status_code IN (201, 202)
        AND timestamp >= ?
    `).get(keyId, sinceMs);
    return row ? Number(row.cnt) : 0;
  },

  // --- API Idempotency Cache (24h TTL) ---
  getApiIdempotency(cacheKey) {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    const row = db.prepare('SELECT * FROM api_idempotency WHERE cache_key = ? AND created_at >= ?').get(cacheKey, cutoff);
    return row || null;
  },
  saveApiIdempotency({ cacheKey, method, path, requestHash, statusCode, responseEnc }) {
    const now = Date.now();
    const cutoff = now - 24 * 60 * 60 * 1000;
    try {
      db.exec('SAVEPOINT sp_api_idem');
      db.prepare(`
        INSERT OR REPLACE INTO api_idempotency (cache_key, method, path, request_hash, status_code, response_enc, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(cacheKey, method, path, requestHash, statusCode, responseEnc, now);
      db.prepare('DELETE FROM api_idempotency WHERE created_at < ?').run(cutoff);
      db.exec('RELEASE SAVEPOINT sp_api_idem');
    } catch (e) {
      try { db.exec('ROLLBACK TO SAVEPOINT sp_api_idem; RELEASE SAVEPOINT sp_api_idem'); } catch (_) {}
    }
  }
};
