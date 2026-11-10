const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

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

  CREATE INDEX IF NOT EXISTS idx_accounts_status ON accounts(status);
  CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
  CREATE INDEX IF NOT EXISTS idx_allowed_ips_ip ON allowed_ips(ip);
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
} catch (e) {}

module.exports = {
  db,
  getAccounts() {
    return db.prepare("SELECT id, label, user_id, display_name, org_id, org_name, org_slug, key_scope, home_region, enabled_regions, balance_micro, currency, max_vms, status, last_error, notes, last_synced_at, created_at, updated_at, (substr(api_key, 1, 8) || '...' || substr(api_key, -4)) as masked_key FROM accounts ORDER BY created_at ASC").all();
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
    return db.prepare('DELETE FROM accounts WHERE id = ?').run(id);
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
    if (!ip || typeof ip !== 'string') return null;
    const cleanIp = ip.trim();
    const now = Date.now();
    db.prepare('INSERT OR REPLACE INTO allowed_ips (ip, label, created_at) VALUES (?, ?, ?)').run(cleanIp, label || 'Client Device', now);
    return db.prepare('SELECT * FROM allowed_ips WHERE ip = ?').get(cleanIp);
  },
  deleteAllowedIp(id) {
    return db.prepare('DELETE FROM allowed_ips WHERE id = ?').run(id);
  },
  isIpWhitelisted(clientIp) {
    if (!clientIp) return false;
    const clean = clientIp.trim();
    // 1. Direct match
    const direct = db.prepare('SELECT id FROM allowed_ips WHERE ip = ?').get(clean);
    if (direct) return true;
    // 2. Localhost aliases
    if (clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') return true;
    return false;
  },
  isIpWhitelistEnabled() {
    const row = db.prepare('SELECT value FROM security_config WHERE key = ?').get('ip_whitelist_enabled');
    return row ? row.value === '1' : false;
  },
  setIpWhitelistEnabled(enabled) {
    const val = enabled ? '1' : '0';
    db.prepare('INSERT OR REPLACE INTO security_config (key, value) VALUES (?, ?)').run('ip_whitelist_enabled', val);
    return enabled;
  }
};
