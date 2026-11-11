require('dotenv').config();
const fs = require('fs');
const os = require('os');
const path = require('path');
const assert = require('assert');
const http = require('http');

const TEMP_DB = path.join(os.tmpdir(), `boxd_smoke_${process.pid}_${Date.now()}.db`);
process.env.BOXD_DB_PATH = TEMP_DB;

const auth = require('../auth');
const dbHelper = require('../db');
const boxdService = require('../boxdService');
const app = require('../server');

const TEST_PIN = process.env.ACCESS_PIN || 'change-me-pin-2026';

function cleanupTempDb() {
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      if (fs.existsSync(TEMP_DB + suffix)) fs.unlinkSync(TEMP_DB + suffix);
    } catch (e) {}
  }
}

async function runTests() {
  console.log('🧪 Starting Boxd Fleet Smoke Tests (Isolated Temp DB)...\n');

  // 1. Test Auth logic & Validation
  console.log('1. Testing Auth & Validation Module...');
  assert.strictEqual(auth.verifyPin(TEST_PIN), true, 'PIN check should pass');
  assert.strictEqual(auth.verifyPin('wrongpin'), false, 'Wrong PIN should fail');

  const token = auth.signSession('admin');
  assert(token && token.includes('.'), 'Token must be formatted with payload.signature');

  const session = auth.verifySession(token);
  assert(session && session.u === 'admin', 'Session must be decoded and valid');

  const invalidSession = auth.verifySession(token + 'tampered');
  assert.strictEqual(invalidSession, null, 'Tampered token must be rejected');

  assert.strictEqual(auth.validateMachineInput({ name: '', region: 'default', vcpu: 1, memory: '4G' }), null, '4G + default region + empty name must pass');
  assert.strictEqual(auth.validateMachineInput({ name: 'worker-01', region: 'fra', vcpu: 2, memory: 8192 }), null, 'Numeric MB memory must pass');
  assert.notStrictEqual(auth.validateMachineInput({ name: 'INVALID_NAME!', region: 'fra', vcpu: 1, memory: '4G' }), null, 'Uppercase/underscore name must fail');
  assert.notStrictEqual(auth.validateMachineInput({ name: 'ok-vm', region: 'fra', vcpu: 1, memory: '128M' }), null, 'RAM below 512M must fail');
  console.log('  ✓ Auth & Validation tests passed.\n');

  // 2. Test Usage Status & Region Resolver
  console.log('2. Testing BoxdService Region & Usage Reconciliation...');
  const nycRes = boxdService.resolveRegionFromUsageStatus('in nyc', 'fra');
  assert.deepStrictEqual(nycRes, { region: 'nyc', normalizedStatus: 'remote', isDeleted: false });
  const hibRes = boxdService.resolveRegionFromUsageStatus('hibernated', 'fra');
  assert.deepStrictEqual(hibRes, { region: 'fra', normalizedStatus: 'hibernated', isDeleted: false });
  const delRes = boxdService.resolveRegionFromUsageStatus('deleted', 'fra');
  assert.deepStrictEqual(delRes, { region: null, normalizedStatus: 'deleted', isDeleted: true });
  console.log('  ✓ Usage region/status resolution tests passed.\n');

  // 3. Test DB Module
  console.log('3. Testing Database Module...');
  const testAccId = 'acc_test_' + Date.now();
  const created = dbHelper.createAccount({
    id: testAccId,
    label: 'Test Account',
    api_key: 'bxd_test_1234567890abcdef',
    user_id: 'usr_test',
    display_name: 'Tester',
    org_name: 'TestOrg',
    org_slug: 'test-org',
    key_scope: 'org',
    home_region: 'fra',
    enabled_regions: ['fra', 'nyc'],
    balance_micro: 30000000,
    currency: 'USD',
    max_vms: 100,
    status: 'active'
  });
  assert.strictEqual(created.id, testAccId, 'Created account ID must match');
  assert.strictEqual(created.key_scope, 'org');

  const list = dbHelper.getAccounts();
  const found = list.find(a => a.id === testAccId);
  assert(found, 'Account must be in list');
  assert(found.masked_key.includes('...'), 'Key must be masked');
  assert(!found.masked_key.includes('1234567890'), 'Full raw key must not be exposed in getAccounts');
  assert.strictEqual(found.org_slug, 'test-org');

  dbHelper.updateAccount(testAccId, { label: 'Updated Label' });
  const updated = dbHelper.getAccountById(testAccId);
  assert.strictEqual(updated.label, 'Updated Label', 'Label must be updated');

  dbHelper.deleteAccount(testAccId);
  const afterDel = dbHelper.getAccountById(testAccId);
  assert.strictEqual(afterDel, undefined, 'Account must be deleted');
  console.log('  ✓ Database Module tests passed.\n');

  // 3. Test HTTP Server
  console.log('3. Testing HTTP API endpoints...');
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  console.log(`  - Test server listening on 127.0.0.1:${port}`);

  function request(path, options = {}) {
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: '127.0.0.1',
        port,
        path,
        method: options.method || 'GET',
        headers: options.headers || {}
      };
      const req = http.request(opts, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(body); } catch (e) {}
          resolve({ status: res.statusCode, headers: res.headers, body, json });
        });
      });
      req.on('error', reject);
      if (options.body) {
        req.write(typeof options.body === 'object' ? JSON.stringify(options.body) : options.body);
      }
      req.end();
    });
  }

  // 3a. Check unauthenticated status
  const unauthRes = await request('/api/auth/status');
  assert.strictEqual(unauthRes.status, 200);
  assert.strictEqual(unauthRes.json.authenticated, false, 'Initial state should be unauthenticated');
  console.log('  ✓ GET /api/auth/status returned authenticated: false');

  // 4b. Try to access protected route without auth
  const protectedRes = await request('/api/accounts');
  assert.strictEqual(protectedRes.status, 401, 'Protected route must return 401 without auth');
  assert(protectedRes.headers['cache-control'].includes('no-store'), 'API responses must include no-store Cache-Control');
  console.log('  ✓ GET /api/accounts returned 401 Unauthorized with no-store header');

  // 4c. Login with wrong PIN
  const wrongLogin = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: { pin: 'wrong' }
  });
  assert.strictEqual(wrongLogin.status, 401, 'Wrong PIN must return 401');
  console.log('  ✓ POST /api/auth/login rejected wrong PIN');

  // 4d. Login with valid PIN
  const loginRes = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: { pin: TEST_PIN }
  });
  assert.strictEqual(loginRes.status, 200, 'Valid PIN must return 200');
  assert(loginRes.json.success, 'Login response must indicate success');
  assert(loginRes.json.token, 'Login response must return a session token');

  const cookieHeader = loginRes.headers['set-cookie'];
  assert(cookieHeader, 'Login must set-cookie');
  const sessionCookie = cookieHeader[0].split(';')[0];
  console.log('  ✓ POST /api/auth/login issued cookie & token successfully');

  // 4e. Access protected route with session cookie
  const authAccountsRes = await request('/api/accounts', {
    headers: { 'Cookie': sessionCookie }
  });
  assert.strictEqual(authAccountsRes.status, 200, 'Protected route must return 200 with session cookie');
  assert(Array.isArray(authAccountsRes.json.accounts), 'Must return accounts array');
  console.log('  ✓ GET /api/accounts accessible with session cookie');

  // 4f. Add invalid boxd key - must fail validation AND NOT leave junk row in DB
  const countBefore = dbHelper.getAccounts().length;
  const addInvalidKeyRes = await request('/api/accounts', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { label: 'Invalid Account', apiKey: 'bxd_i...123' }
  });
  assert.strictEqual(addInvalidKeyRes.status, 400, 'Invalid Boxd key must be rejected by Boxd API check');
  assert(addInvalidKeyRes.json.error.includes('Validasi Boxd API Key gagal'), 'Must surface clear error message');
  assert.strictEqual(dbHelper.getAccounts().length, countBefore, 'Rejected API key must NOT leave junk row in DB');
  console.log('  ✓ POST /api/accounts safely rejected fake Boxd API key without polluting DB');

  // 4g. Check HTML SPA serving
  const htmlRes = await request('/');
  assert.strictEqual(htmlRes.status, 200);
  assert(htmlRes.body.toUpperCase().includes('BOXD'), 'HTML must include BOXD');
  assert(htmlRes.headers['cache-control'].includes('no-store'), 'HTML must send no-store Cache-Control');
  console.log('  ✓ GET / correctly serves SPA frontend with no-store header');

  // 5. Test IP Whitelist, CIDR, Anti-Spoofing, and Cookie Persistence Policy
  console.log('\n4. Testing IP Whitelist Strict Enforcement & Cookie Auth Interaction...');
  const prevProxySecret = process.env.PROXY_SECRET;
  process.env.PROXY_SECRET = 'smoke-test-proxy-secret-12345';

  // Verify extractClientIp anti-spoofing
  assert.strictEqual(
    auth.extractClientIp({
      headers: {
        'x-boxd-client-ip': '127.0.0.1',
        'x-forwarded-for': '127.0.0.1, 198.51.100.77',
        'cf-connecting-ip': '198.51.100.77'
      },
      socket: { remoteAddress: '127.0.0.1' }
    }),
    '198.51.100.77',
    'Spoofed X-Boxd-Client-IP/XFF without valid proxy secret must be ignored in favor of CF-Connecting-IP'
  );
  assert.strictEqual(
    auth.extractClientIp({
      headers: {
        'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
        'x-boxd-client-ip': '203.0.113.42',
        'cf-connecting-ip': '2a06:98c0:3600::103'
      },
      socket: { remoteAddress: '127.0.0.1' }
    }),
    '203.0.113.42',
    'Valid proxy secret must extract X-Boxd-Client-IP over overwritten CF-Connecting-IP'
  );

  // Verify CIDR + IPv6 + IPv4-mapped IPv6 matching
  const addedSubnet = dbHelper.addAllowedIp('203.0.113.0/24', 'Office CIDR');
  assert(addedSubnet && addedSubnet.ip === '203.0.113.0/24');
  assert.strictEqual(dbHelper.isIpWhitelisted('203.0.113.42'), true, 'CIDR match should allow 203.0.113.42');
  assert.strictEqual(dbHelper.isIpWhitelisted('::ffff:203.0.113.42'), true, 'IPv4-mapped IPv6 should normalize and match CIDR');
  assert.strictEqual(dbHelper.isIpWhitelisted('198.51.100.77'), false, 'Non-whitelisted IP must fail match');
  assert.strictEqual(dbHelper.parseIpOrCidr('not-an-ip'), null, 'Invalid IP must be rejected by parser');

  // Cookie works when Filter IP is OFF
  dbHelper.setIpWhitelistEnabled(false);
  const offCookieCheck = await request('/api/auth/status', {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '198.51.100.77'
    }
  });
  assert.strictEqual(offCookieCheck.status, 200);
  assert.strictEqual(offCookieCheck.json.authenticated, true, 'Valid cookie must authenticate without PIN when IP filter is OFF');

  // Turn Filter IP ON: non-allowed IP MUST be rejected 403 on ALL routes even WITH valid cookie or ?key=
  dbHelper.setIpWhitelistEnabled(true);
  const blockedRoot = await request('/', {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '198.51.100.77'
    }
  });
  assert.strictEqual(blockedRoot.status, 403, 'Non-whitelisted IP must get 403 on / even with valid cookie');

  const blockedAsset = await request('/app.js', {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '198.51.100.77'
    }
  });
  assert.strictEqual(blockedAsset.status, 403, 'Non-whitelisted IP must get 403 on static JS assets too');

  const blockedApiWithCookieAndKey = await request(`/api/accounts?key=${encodeURIComponent(TEST_PIN)}`, {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '198.51.100.77'
    }
  });
  assert.strictEqual(blockedApiWithCookieAndKey.status, 403, 'Non-whitelisted IP must get 403 on /api even with cookie and PIN key');
  assert.strictEqual(blockedApiWithCookieAndKey.json.code, 'IP_NOT_ALLOWED');

  // Whitelisted IP WITH valid cookie enters seamlessly without PIN
  const allowedWithCookie = await request('/api/auth/status', {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '203.0.113.42'
    }
  });
  assert.strictEqual(allowedWithCookie.status, 200);
  assert.strictEqual(allowedWithCookie.json.authenticated, true, 'Whitelisted IP with valid cookie must auto-authenticate');

  const allowedAccounts = await request('/api/accounts', {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '203.0.113.42'
    }
  });
  assert.strictEqual(allowedAccounts.status, 200, 'Whitelisted IP with valid cookie must access protected API');

  // Toggle Filter IP back OFF via API -> blocked IP works again with its valid cookie
  const toggleOffRes = await request('/api/security/ip-whitelist/toggle', {
    method: 'POST',
    headers: {
      'Cookie': sessionCookie,
      'Content-Type': 'application/json',
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '203.0.113.42'
    },
    body: { enabled: false }
  });
  assert.strictEqual(toggleOffRes.status, 200);
  assert.strictEqual(toggleOffRes.json.enabled, false);

  const afterOffRes = await request('/api/accounts', {
    headers: {
      'Cookie': sessionCookie,
      'x-boxd-proxy-secret': 'smoke-test-proxy-secret-12345',
      'x-boxd-client-ip': '198.51.100.77'
    }
  });
  assert.strictEqual(afterOffRes.status, 200, 'Previously blocked IP with valid cookie works again once Filter IP is toggled OFF');

  if (prevProxySecret === undefined) delete process.env.PROXY_SECRET;
  else process.env.PROXY_SECRET = prevProxySecret;
  console.log('  ✓ Strict IP Whitelist, CIDR, anti-spoofing, and cookie persistence verified.\n');

  // 6. Test VM SSH Password Encryption, Validation, DB Persistence & API Routes
  console.log('5. Testing VM SSH Password Feature...');
  const samplePass = 'SshSmoke!Test#2026';
  const enc = auth.encryptSecret(samplePass);
  assert(enc && enc.split('.').length === 3 && !enc.includes(samplePass), 'Encrypted secret must use 3-part GCM format and not leak plaintext');
  assert.strictEqual(auth.decryptSecret(enc), samplePass, 'Decrypted secret must match original');
  const tampered = enc.slice(0, -3) + (enc.slice(-3, -2) === 'A' ? 'B' : 'A') + enc.slice(-2);
  assert.strictEqual(auth.decryptSecret(tampered), null, 'Tampered ciphertext must fail GCM authentication');

  assert.strictEqual(auth.validateSshPasswordInput({ password: samplePass, sshUser: 'root' }), null);
  assert.strictEqual(auth.validateSshPasswordInput({ password: samplePass, sshUser: 'boxd' }), null);
  assert.strictEqual(auth.validateSshPasswordInput({ password: samplePass, sshUser: 'both' }), null);
  assert.notStrictEqual(auth.validateSshPasswordInput({ password: '123', sshUser: 'root' }), null, 'Short password must be rejected');
  assert.notStrictEqual(auth.validateSshPasswordInput({ password: 'bad\npass', sshUser: 'root' }), null, 'Newline in password must be rejected');
  assert.notStrictEqual(auth.validateSshPasswordInput({ password: samplePass, sshUser: 'hacker' }), null, 'Invalid sshUser must be rejected');

  // DB table isolation & safe account-map projection
  const dummyAcc = dbHelper.createAccount({ id: 'acc_ssh_unit_1', label: 'SSH Test Acc', api_key: 'bxd_dummy_test_key_for_ssh_unit_check', status: 'active' });
  dbHelper.upsertVmSshAccess({
    machine_id: 'vm-ssh-unit-1',
    account_id: dummyAcc.id,
    machine_name: 'unit-box',
    region: 'fra',
    ssh_user: 'root',
    public_port: 49123,
    dns: 'unit-box.boxd.sh',
    password_enc: enc,
    enabled: 1
  });
  const sshMap = dbHelper.getVmSshAccessByAccount(dummyAcc.id);
  assert.strictEqual(sshMap['vm-ssh-unit-1'].publicPort, 49123);
  assert.strictEqual(sshMap['vm-ssh-unit-1'].hasPassword, true);
  assert.strictEqual(sshMap['vm-ssh-unit-1'].password, undefined, 'Account summary map must NEVER include plaintext password');
  assert.strictEqual(sshMap['vm-ssh-unit-1'].password_enc, undefined, 'Account summary map must NEVER include raw ciphertext');

  // HTTP validation & mocked service integration
  const badPassRes = await request('/api/machines/vm-ssh-unit-1/ssh-password', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: dummyAcc.id, password: 'short', sshUser: 'root' }
  });
  assert.strictEqual(badPassRes.status, 400, 'POST ssh-password must reject short password');

  const badUserRes = await request('/api/machines/vm-ssh-unit-1/ssh-password', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: dummyAcc.id, password: samplePass, sshUser: 'admin' }
  });
  assert.strictEqual(badUserRes.status, 400, 'POST ssh-password must reject invalid sshUser');

  // Mock boxdService methods cleanly for HTTP contract + audit-log secrecy check
  const origSetup = boxdService.setupVmSshPassword;
  const origStatus = boxdService.getVmSshPasswordStatus;
  const origDisable = boxdService.disableVmSshPassword;
  try {
    boxdService.setupVmSshPassword = async (acc, mId, opts) => {
      dbHelper.upsertVmSshAccess({
        machine_id: mId,
        account_id: acc.id,
        machine_name: 'unit-box',
        region: opts.region || 'fra',
        ssh_user: opts.sshUser,
        public_port: 49222,
        dns: 'unit-box.boxd.sh',
        password_enc: auth.encryptSecret(opts.password),
        enabled: 1
      });
      return {
        success: true,
        machineId: mId,
        machineName: 'unit-box',
        region: 'fra',
        sshUser: opts.sshUser,
        publicPort: 49222,
        dns: 'unit-box.boxd.sh',
        command: 'ssh -p 49222 root@unit-box.boxd.sh',
        password: opts.password
      };
    };
    boxdService.getVmSshPasswordStatus = async (acc, mId) => {
      const row = dbHelper.getVmSshAccess(mId);
      return {
        machineId: mId,
        machineName: 'unit-box',
        region: 'fra',
        status: 'running',
        enabled: !!row,
        portExposed: !!row,
        sshServiceActive: !!row,
        sshUser: row ? row.ssh_user : 'root',
        publicPort: row ? row.public_port : null,
        dns: row ? row.dns : 'unit-box.boxd.sh',
        command: row ? `ssh -p ${row.public_port} root@${row.dns}` : null,
        hasPassword: !!(row && row.password_enc),
        password: row && row.password_enc ? auth.decryptSecret(row.password_enc) : null
      };
    };
    boxdService.disableVmSshPassword = async (acc, mId) => {
      dbHelper.deleteVmSshAccess(mId);
      return { success: true, machineId: mId, region: 'fra' };
    };

    const setSshRes = await request('/api/machines/vm-ssh-unit-1/ssh-password', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: dummyAcc.id, region: 'fra', password: samplePass, sshUser: 'both' }
    });
    assert.strictEqual(setSshRes.status, 200);
    assert.strictEqual(setSshRes.json.publicPort, 49222);

    const getSshRes = await request(`/api/machines/vm-ssh-unit-1/ssh-password?accountId=${encodeURIComponent(dummyAcc.id)}&region=fra`, {
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(getSshRes.status, 200);
    assert.strictEqual(getSshRes.json.enabled, true);
    assert.strictEqual(getSshRes.json.sshUser, 'both');
    assert.strictEqual(getSshRes.json.password, samplePass);

    // Ensure audit log NEVER stores plaintext password
    const logs = dbHelper.getRecentAuditLogs(20);
    const sshAudit = logs.find(l => l.action === 'SET_VM_SSH_PASSWORD');
    assert(sshAudit, 'SET_VM_SSH_PASSWORD must be audited');
    assert(!sshAudit.details.includes(samplePass), 'Audit log MUST NOT leak plaintext SSH password');

    const delSshRes = await request(`/api/machines/vm-ssh-unit-1/ssh-password?accountId=${encodeURIComponent(dummyAcc.id)}&region=fra`, {
      method: 'DELETE',
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(delSshRes.status, 200);
    assert.strictEqual(dbHelper.getVmSshAccess('vm-ssh-unit-1'), undefined);
  } finally {
    boxdService.setupVmSshPassword = origSetup;
    boxdService.getVmSshPasswordStatus = origStatus;
    boxdService.disableVmSshPassword = origDisable;
  }

  dbHelper.deleteAccount(dummyAcc.id);
  console.log('  ✓ VM SSH Password encryption, validation, DB, API, and audit safety verified.\n');

  // 7. Test VM Auto-Update, Always-On, Starter Kits, Ports/Proxies & Snapshot Routes
  console.log('6. Testing Auto-Update, Always-On, Packages, Runtime, Network & Snapshot Features...');

  // Validators
  assert.strictEqual(auth.validateRuntimeSettings({ autoSuspendTimeout: 0, autoHibernateTimeout: 0, botProtectionMode: 'off', idleIgnoreOutbound: false }), null);
  assert.notStrictEqual(auth.validateRuntimeSettings({ autoSuspendTimeout: -5 }), null, 'Negative suspend timeout must be rejected');
  assert.notStrictEqual(auth.validateRuntimeSettings({ botProtectionMode: 'bypass' }), null, 'Invalid botProtectionMode must be rejected');

  const aptOk = auth.validatePackageList('htop, curl jq', 'apt');
  assert.strictEqual(aptOk.error, null);
  assert.deepStrictEqual(aptOk.packages, ['htop', 'curl', 'jq']);
  assert.notStrictEqual(auth.validatePackageList('curl; rm -rf /', 'apt').error, null, 'Shell injection in APT packages must be rejected');
  const npmOk = auth.validatePackageList(['pm2', '@nestjs/cli'], 'npm');
  assert.strictEqual(npmOk.error, null);
  assert.deepStrictEqual(npmOk.packages, ['pm2', '@nestjs/cli']);
  assert.notStrictEqual(auth.validatePackageList('pm2 && whoami', 'npm').error, null, 'Shell injection in NPM packages must be rejected');

  assert.strictEqual(auth.validatePortNumber(3000), null);
  assert.notStrictEqual(auth.validatePortNumber(70000), null);
  assert.strictEqual(auth.validateProxySubdomain('api-v1'), null);
  assert.notStrictEqual(auth.validateProxySubdomain('-bad-'), null);
  assert.strictEqual(auth.validateSnapshotName('ready-stack-v1'), null);
  assert.notStrictEqual(auth.validateSnapshotName('bad_name!'), null);

  // DB vm_configs table & deleteAccount cleanup
  const manageAcc = dbHelper.createAccount({ id: 'acc_manage_unit_1', label: 'Manage Test Acc', api_key: 'bxd_dummy_manage_unit_test_key_1234', status: 'active' });
  const upsertedCfg = dbHelper.upsertVmConfig({
    machine_id: 'vm-manage-1',
    account_id: manageAcc.id,
    region: 'fra',
    auto_update_enabled: true,
    auto_update_interval_hours: 12,
    auto_update_runtimes: true,
    always_on_mode: true,
    starter_kits: ['essentials', 'node_pm2'],
    last_update_status: 'success',
    last_update_summary: '+3 paket di-upgrade (sisa 0)',
    last_update_at: Date.now()
  });
  assert.strictEqual(upsertedCfg.autoUpdateEnabled, true);
  assert.strictEqual(upsertedCfg.alwaysOnMode, true);
  assert.deepStrictEqual(upsertedCfg.starterKits, ['essentials', 'node_pm2']);
  const cfgMap = dbHelper.getVmConfigsByAccount(manageAcc.id);
  assert(cfgMap['vm-manage-1'] && cfgMap['vm-manage-1'].autoUpdateIntervalHours === 12);

  // HTTP validation tests
  const badIntervalRes = await request('/api/machines/vm-manage-1/autoupdate/config', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: manageAcc.id, enabled: true, intervalHours: 999 }
  });
  assert.strictEqual(badIntervalRes.status, 400, 'Interval > 168h must be rejected');

  const badBatchRes = await request('/api/machines/autoupdate-all', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: manageAcc.id, intervalHours: 0 }
  });
  assert.strictEqual(badBatchRes.status, 400, 'Batch interval < 1h must be rejected');

  const badPkgRes = await request('/api/machines/vm-manage-1/packages', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: manageAcc.id, aptPackages: ['htop; id'] }
  });
  assert.strictEqual(badPkgRes.status, 400, 'Unsafe package string must be rejected');

  const badSubdomainRes = await request('/api/machines/vm-manage-1/proxies', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: manageAcc.id, name: '-invalid-', port: 3000 }
  });
  assert.strictEqual(badSubdomainRes.status, 400, 'Invalid proxy subdomain must be rejected');

  const badPortRes = await request('/api/machines/vm-manage-1/ports', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: manageAcc.id, port: 99999, protocol: 'tcp' }
  });
  assert.strictEqual(badPortRes.status, 400, 'Invalid port must be rejected');

  const badSnapRes = await request('/api/snapshots', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { accountId: manageAcc.id, machineId: 'vm-manage-1', name: 'invalid snap!' }
  });
  assert.strictEqual(badSnapRes.status, 400, 'Invalid snapshot name must be rejected');

  // Happy path mocked service integration
  const origFns = {
    getVmManageState: boxdService.getVmManageState,
    configureVmAutoUpdate: boxdService.configureVmAutoUpdate,
    runVmUpdateNow: boxdService.runVmUpdateNow,
    prepareFleetAutoUpdate: boxdService.prepareFleetAutoUpdate,
    startVmProvisionJob: boxdService.startVmProvisionJob,
    getVmJob: boxdService.getVmJob,
    updateVmRuntimeSettings: boxdService.updateVmRuntimeSettings,
    resizeVm: boxdService.resizeVm,
    exposeVmPort: boxdService.exposeVmPort,
    unexposeVmPort: boxdService.unexposeVmPort,
    setVmDefaultProxyPort: boxdService.setVmDefaultProxyPort,
    createVmNamedProxy: boxdService.createVmNamedProxy,
    deleteVmNamedProxy: boxdService.deleteVmNamedProxy,
    createMachineFromSnapshot: boxdService.createMachineFromSnapshot
  };

  try {
    const fakeJob = {
      id: 'job_smoke_123',
      machineId: 'vm-manage-1',
      accountId: manageAcc.id,
      region: 'fra',
      type: 'autoupdate',
      title: 'Update Paket OS & Runtime',
      status: 'success',
      phase: 'done',
      startedAt: Date.now() - 2000,
      finishedAt: Date.now(),
      output: 'Auto-Update DONE (upgraded: 2, sisa: 0)',
      error: null
    };

    boxdService.getVmManageState = async () => ({
      machine: { id: 'vm-manage-1', name: 'manage-vm', region: 'fra', status: 'running', resources: { vcpu: 1, memory: '4G' }, vmConfig: dbHelper.getVmConfig('vm-manage-1'), alwaysOn: true },
      vmConfig: dbHelper.getVmConfig('vm-manage-1'),
      inspection: { reachable: true, os: 'Ubuntu 24.04 LTS', upgradableCount: 0, timerEnabled: true, timerActive: true, tools: ['git', 'curl', 'node', 'pm2'] },
      ports: [{ machinePort: 3000, publicPort: 45123, dns: 'manage-vm.fra.boxd.sh', protocol: 'tcp' }],
      proxies: [{ name: null, domain: 'manage-vm.fra.boxd.sh', port: 3000, portMode: 'locked', isDefault: true }],
      snapshots: [{ id: 'snap_1', name: 'ready-v1', status: 'ready', sizeBytes: 1073741824, region: 'fra' }],
      starterKits: Object.values(boxdService.STARTER_KITS),
      jobs: [fakeJob]
    });
    boxdService.configureVmAutoUpdate = async (acc, mId, opts) => ({
      success: true,
      machineId: mId,
      region: 'fra',
      vmConfig: dbHelper.upsertVmConfig({
        machine_id: mId,
        account_id: acc.id,
        region: 'fra',
        auto_update_enabled: !!opts.enabled,
        auto_update_interval_hours: opts.intervalHours,
        auto_update_runtimes: !!opts.updateRuntimes
      })
    });
    boxdService.runVmUpdateNow = async () => ({ success: true, jobId: fakeJob.id, job: fakeJob, region: 'fra' });
    boxdService.prepareFleetAutoUpdate = async () => ({ success: true, total: 1, configured: 1, upgradedJobs: 0, skippedStopped: 0, failed: 0, results: [{ machineId: 'vm-manage-1', status: 'configured' }] });
    boxdService.startVmProvisionJob = async () => ({ success: true, jobId: fakeJob.id, job: fakeJob, region: 'fra' });
    boxdService.getVmJob = (id) => (id === fakeJob.id ? fakeJob : null);
    boxdService.updateVmRuntimeSettings = async (acc, mId, s) => ({
      id: mId,
      name: 'manage-vm',
      alwaysOn: !!s.alwaysOn,
      autoSuspendTimeout: s.alwaysOn ? 0 : (s.autoSuspendTimeout || 0),
      autoHibernateTimeout: s.alwaysOn ? 0 : (s.autoHibernateTimeout || 0),
      botProtectionMode: s.alwaysOn ? 'off' : (s.botProtectionMode || 'on')
    });
    boxdService.resizeVm = async (acc, mId, s) => ({ id: mId, resources: { vcpu: s.vcpu, memory: s.memory } });
    boxdService.exposeVmPort = async (acc, mId, opts) => ({ machineId: mId, machinePort: Number(opts.port), publicPort: 46001, dns: 'manage-vm.fra.boxd.sh', protocol: opts.protocol });
    boxdService.unexposeVmPort = async (acc, mId, opts) => ({ success: true, port: Number(opts.port) });
    boxdService.setVmDefaultProxyPort = async (acc, mId, opts) => ({ ok: true, port: opts.port });
    boxdService.createVmNamedProxy = async (acc, mId, opts) => ({ name: opts.name, port: Number(opts.port) });
    boxdService.deleteVmNamedProxy = async (acc, mId, opts) => ({ success: true, name: opts.name });
    boxdService.createMachineFromSnapshot = async (acc, opts) => ({ id: 'vm-from-snap-1', name: opts.name || 'restored-vm', region: opts.region || 'fra' });

    const manageRes = await request(`/api/machines/vm-manage-1/manage?accountId=${encodeURIComponent(manageAcc.id)}&region=fra`, {
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(manageRes.status, 200);
    assert.strictEqual(manageRes.json.inspection.reachable, true);
    assert.strictEqual(manageRes.json.ports[0].machinePort, 3000);

    const cfgRes = await request('/api/machines/vm-manage-1/autoupdate/config', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, enabled: true, intervalHours: 6, updateRuntimes: true }
    });
    assert.strictEqual(cfgRes.status, 200);
    assert.strictEqual(cfgRes.json.vmConfig.autoUpdateIntervalHours, 6);

    const batchRes = await request('/api/machines/autoupdate-all', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, runUpgrade: false }
    });
    assert.strictEqual(batchRes.status, 200);
    assert.strictEqual(batchRes.json.configured, 1);

    const runRes = await request('/api/machines/vm-manage-1/autoupdate/run', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id }
    });
    assert.strictEqual(runRes.status, 202);
    assert.strictEqual(runRes.json.jobId, fakeJob.id);

    const jobRes = await request(`/api/jobs/${fakeJob.id}`, {
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(jobRes.status, 200);
    assert.strictEqual(jobRes.json.job.status, 'success');

    const pkgRes = await request('/api/machines/vm-manage-1/packages', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, starterKits: ['essentials'], aptPackages: 'htop,jq', npmPackages: 'pm2' }
    });
    assert.strictEqual(pkgRes.status, 202);

    const rtRes = await request('/api/machines/vm-manage-1/runtime-settings', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, alwaysOn: true }
    });
    assert.strictEqual(rtRes.status, 200);
    assert.strictEqual(rtRes.json.machine.alwaysOn, true);

    const resizeRes = await request('/api/machines/vm-manage-1/resize', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, vcpu: 2, memory: '8G' }
    });
    assert.strictEqual(resizeRes.status, 200);
    assert.strictEqual(resizeRes.json.machine.resources.vcpu, 2);

    const expPortRes = await request('/api/machines/vm-manage-1/ports', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, port: 3000, protocol: 'tcp' }
    });
    assert.strictEqual(expPortRes.status, 201);
    assert.strictEqual(expPortRes.json.exposed.publicPort, 46001);

    const unexpPortRes = await request(`/api/machines/vm-manage-1/ports/3000?accountId=${encodeURIComponent(manageAcc.id)}`, {
      method: 'DELETE',
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(unexpPortRes.status, 200);

    const defProxyRes = await request('/api/machines/vm-manage-1/proxies/default-port', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, port: 'auto' }
    });
    assert.strictEqual(defProxyRes.status, 200);

    const namedProxyRes = await request('/api/machines/vm-manage-1/proxies', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, name: 'api', port: 8080 }
    });
    assert.strictEqual(namedProxyRes.status, 201);

    const delProxyRes = await request(`/api/machines/vm-manage-1/proxies/api?accountId=${encodeURIComponent(manageAcc.id)}`, {
      method: 'DELETE',
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(delProxyRes.status, 200);

    const snapDeployRes = await request('/api/machines/from-snapshot', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { accountId: manageAcc.id, fromSnapshot: 'ready-v1', name: 'clone-01', alwaysOn: true }
    });
    assert.strictEqual(snapDeployRes.status, 201);
    assert.strictEqual(snapDeployRes.json.machine.name, 'clone-01');
  } finally {
    Object.assign(boxdService, origFns);
  }

  dbHelper.deleteAccount(manageAcc.id);
  assert.strictEqual(dbHelper.getVmConfig('vm-manage-1'), null, 'Deleting account must cascade-delete vm_configs');
  console.log('  ✓ Auto-Update, Always-On, Starter Kits, Ports/Proxies & Snapshot routes verified.\n');

  // 7. External Developer API (/api/v1/*) + Extra Security + Dedicated API Allowed IPs
  console.log('7. Testing External API (/api/v1/*), Allowed IP Firewall, HMAC & VM Generation...');
  const apiAcc = dbHelper.createAccount({
    id: 'acc_api_test_' + Date.now(),
    label: 'API Deploy Account',
    api_key: 'bxd_test_api_secret_9876543210',
    user_id: 'usr_api',
    display_name: 'ApiOwner',
    org_name: 'ApiOrg',
    org_slug: 'api-org',
    key_scope: 'org',
    home_region: 'fra',
    enabled_regions: ['fra', 'nyc'],
    balance_micro: 45000000,
    currency: 'USD',
    max_vms: 100,
    status: 'active'
  });

  const apiOrigFns = {
    createMachine: boxdService.createMachine,
    machineAction: boxdService.machineAction,
    execCommand: boxdService.execCommand,
    deleteMachine: boxdService.deleteMachine,
    listAllMachines: boxdService.listAllMachines
  };

  let createdCounter = 0;
  boxdService.createMachine = async (acc, params) => {
    createdCounter++;
    return {
      id: `vm-api-${createdCounter}`,
      name: params.name || `api-vm-${createdCounter}`,
      status: 'running',
      region: params.region && params.region !== 'default' ? params.region : 'fra',
      shared: true,
      accessible: true,
      accountId: acc.id,
      accountLabel: acc.label,
      resources: { vcpu: params.vcpu || 1, memoryHuman: '4 GB', memoryBytes: 4294967296 },
      sshAccess: params.sshPassword ? { enabled: true, sshUser: 'root', publicPort: 45555, dns: 'api-vm.fra.boxd.sh', hasPassword: true } : null
    };
  };
  boxdService.machineAction = async (acc, id, action) => ({ id, status: action === 'stop' ? 'stopped' : 'running', accountId: acc.id });
  boxdService.execCommand = async (acc, id, cmd) => ({ stdout: `ok:${cmd}`, stderr: '', exitCode: 0, success: true });
  boxdService.deleteMachine = async (acc, id) => ({ success: true, id });
  boxdService.listAllMachines = async (accs) => ({
    machines: [{ id: 'vm-api-1', name: 'api-vm-1', status: 'running', region: 'fra', accessible: true, accountId: apiAcc.id }],
    errors: []
  });

  process.env.PROXY_SECRET = 'smoke-api-proxy-secret-xyz';
  try {
    // 7a. Create Standard API Key via Admin Route
    const createKeyRes = await request('/api/api-keys', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: {
        name: 'Bot Deploy Smoke',
        scopes: ['vm:read', 'vm:create', 'vm:control', 'vm:exec'],
        allowedAccountIds: [apiAcc.id],
        allowedIps: ['203.0.113.0/24'],
        requireHmac: false,
        rateLimitRpm: 60,
        maxDeployPerHour: 2,
        maxVcpuPerVm: 4
      }
    });
    assert.strictEqual(createKeyRes.status, 201, 'Admin must be able to create API key');
    assert(createKeyRes.json.rawKey && createKeyRes.json.rawKey.startsWith('bfk_live_'), 'Raw API key must start with bfk_live_');
    const stdKey = createKeyRes.json.rawKey;
    const stdKeyId = createKeyRes.json.apiKey.id;

    // Ensure raw hash & hmac secret are NOT leaked in listing
    const listKeysRes = await request('/api/api-keys', { headers: { 'Cookie': sessionCookie } });
    assert.strictEqual(listKeysRes.status, 200);
    const listedKey = listKeysRes.json.keys.find(k => k.id === stdKeyId);
    assert(listedKey && !listedKey.keyHash && !listedKey.hmacSecretEnc, 'Hashed key/secret must never be returned in list');

    // 7b. Privilege separation: API key cannot access web admin routes
    const adminAttempt = await request('/api/accounts', {
      headers: { 'Authorization': `Bearer ${stdKey}` }
    });
    assert.strictEqual(adminAttempt.status, 401, 'API key must NOT authorize web admin endpoints');

    // 7c. Missing key rejected 401
    const noKeyRes = await request('/api/v1/me');
    assert.strictEqual(noKeyRes.status, 401);
    assert.strictEqual(noKeyRes.json.code, 'API_KEY_REQUIRED');

    // 7d. Per-key IP allowlist enforcement
    const badKeyIpRes = await request('/api/v1/me', {
      headers: {
        'Authorization': `Bearer ${stdKey}`,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '198.51.100.22'
      }
    });
    assert.strictEqual(badKeyIpRes.status, 403);
    assert.strictEqual(badKeyIpRes.json.code, 'KEY_IP_NOT_ALLOWED');

    const okKeyIpRes = await request('/api/v1/me', {
      headers: {
        'Authorization': `Bearer ${stdKey}`,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      }
    });
    assert.strictEqual(okKeyIpRes.status, 200);
    assert.strictEqual(okKeyIpRes.json.clientIp, '203.0.113.45');

    // 7e. Global API Allowed IP Firewall (independent from Web IP Firewall!)
    await request('/api/security/api-ips', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { ip: '203.0.113.45', label: 'Allowed API Server' }
    });
    await request('/api/security/api-ips/toggle', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { enabled: true }
    });

    const blockedGlobalApiIp = await request('/api/v1/me', {
      headers: {
        'Authorization': `Bearer ${stdKey}`,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.99'
      }
    });
    assert.strictEqual(blockedGlobalApiIp.status, 403);
    assert.strictEqual(blockedGlobalApiIp.json.code, 'API_IP_NOT_ALLOWED');

    // 7f. Generate VM via API + Idempotency-Key + vCPU cap + Hourly deploy quota + Auto SSH password
    const deployHeaders = {
      'Authorization': `Bearer ${stdKey}`,
      'Content-Type': 'application/json',
      'Idempotency-Key': 'idem-deploy-smoke-01',
      'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
      'X-Boxd-Client-IP': '203.0.113.45'
    };
    const vcpuTooHighRes = await request('/api/v1/vms', {
      method: 'POST',
      headers: deployHeaders,
      body: JSON.stringify({ name: 'too-big', vcpu: 8, memory: '32G' })
    });
    assert.strictEqual(vcpuTooHighRes.status, 403);
    assert.strictEqual(vcpuTooHighRes.json.code, 'VCPU_LIMIT_EXCEEDED');

    const genVmBody = JSON.stringify({
      name: 'bot-node-01',
      vcpu: 2,
      memory: '8G',
      preset: 'always_on',
      autoGenerateSshPassword: true
    });
    const genVmRes = await request('/api/v1/vms', {
      method: 'POST',
      headers: deployHeaders,
      body: genVmBody
    });
    assert.strictEqual(genVmRes.status, 201, 'POST /api/v1/vms must create VM');
    assert.strictEqual(genVmRes.json.machine.name, 'bot-node-01');
    assert(genVmRes.json.generatedSshPassword && genVmRes.json.generatedSshPassword.length >= 10, 'Must return auto-generated SSH password');
    assert(genVmRes.json.sshCommand && genVmRes.json.sshCommand.includes('ssh -p 45555'), 'Must return direct SSH command');

    // Idempotent replay must NOT call createMachine again
    const prevCreatedCount = createdCounter;
    const replayVmRes = await request('/api/v1/vms', {
      method: 'POST',
      headers: deployHeaders,
      body: genVmBody
    });
    assert.strictEqual(replayVmRes.status, 201);
    assert.strictEqual(replayVmRes.headers['x-idempotency-replayed'], 'true');
    assert.strictEqual(createdCounter, prevCreatedCount, 'Idempotent replay must not deploy duplicate VM');

    // Idempotency conflict with different body
    const conflictRes = await request('/api/v1/vms', {
      method: 'POST',
      headers: deployHeaders,
      body: JSON.stringify({ name: 'different-vm', vcpu: 1, memory: '4G' })
    });
    assert.strictEqual(conflictRes.status, 409);
    assert.strictEqual(conflictRes.json.code, 'IDEMPOTENCY_CONFLICT');

    // Scope enforcement: standard key lacks vm:delete
    const delForbiddenRes = await request('/api/v1/vms/vm-api-1', {
      method: 'DELETE',
      headers: {
        'X-API-Key': stdKey,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      }
    });
    assert.strictEqual(delForbiddenRes.status, 403);
    assert.strictEqual(delForbiddenRes.json.code, 'INSUFFICIENT_SCOPE');

    // Exec command via API
    const execApiRes = await request('/api/v1/vms/vm-api-1/exec', {
      method: 'POST',
      headers: {
        'X-API-Key': stdKey,
        'Content-Type': 'application/json',
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      },
      body: JSON.stringify({ accountId: apiAcc.id, command: 'uname -a' })
    });
    assert.strictEqual(execApiRes.status, 200);
    assert.strictEqual(execApiRes.json.stdout, 'ok:uname -a');

    // 7g. HMAC-SHA256 Anti-Replay Extra Security Key
    const hmacCreateRes = await request('/api/api-keys', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: {
        name: 'Strict HMAC Key',
        scopes: ['vm:read', 'vm:create', 'vm:delete'],
        requireHmac: true
      }
    });
    assert.strictEqual(hmacCreateRes.status, 201);
    const hmacKey = hmacCreateRes.json.rawKey;
    const hmacSecret = hmacCreateRes.json.rawHmacSecret;
    assert(hmacSecret && hmacSecret.startsWith('bfk_sec_'), 'HMAC secret must start with bfk_sec_');

    // Missing HMAC headers -> 401
    const noSigRes = await request('/api/v1/me', {
      headers: {
        'Authorization': `Bearer ${hmacKey}`,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      }
    });
    assert.strictEqual(noSigRes.status, 401);
    assert.strictEqual(noSigRes.json.code, 'HMAC_HEADERS_MISSING');

    // Valid signed POST /api/v1/vms + replay detection
    const cryptoMod = require('crypto');
    const signReq = (method, urlPath, rawBody, ts) => {
      const bodyHash = cryptoMod.createHash('sha256').update(rawBody).digest('hex');
      const canonical = `${ts}.${method.toUpperCase()}.${urlPath}.${bodyHash}`;
      return cryptoMod.createHmac('sha256', hmacSecret).update(canonical).digest('hex');
    };
    const tsNow = String(Date.now());
    const hmacBody = JSON.stringify({ name: 'hmac-vm', vcpu: 1, memory: '4G' });
    const sig = signReq('POST', '/api/v1/vms', hmacBody, tsNow);

    const hmacOkRes = await request('/api/v1/vms', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${hmacKey}`,
        'Content-Type': 'application/json',
        'X-API-Timestamp': tsNow,
        'X-API-Signature': sig,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      },
      body: hmacBody
    });
    assert.strictEqual(hmacOkRes.status, 201, 'Valid HMAC signed request must succeed');

    // Replay same non-GET timestamp+signature -> 401 HMAC_REPLAY_DETECTED
    const hmacReplayRes = await request('/api/v1/vms', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${hmacKey}`,
        'Content-Type': 'application/json',
        'X-API-Timestamp': tsNow,
        'X-API-Signature': sig,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      },
      body: hmacBody
    });
    assert.strictEqual(hmacReplayRes.status, 401);
    assert.strictEqual(hmacReplayRes.json.code, 'HMAC_REPLAY_DETECTED');

    // 7h. Key Rotation invalidates old key immediately + Master API Switch
    const rotateRes = await request(`/api/api-keys/${stdKeyId}/rotate`, {
      method: 'POST',
      headers: { 'Cookie': sessionCookie }
    });
    assert.strictEqual(rotateRes.status, 200);
    assert(rotateRes.json.rawKey !== stdKey, 'Rotated key must differ from previous key');

    const oldKeyRejected = await request('/api/v1/me', {
      headers: {
        'Authorization': `Bearer ${stdKey}`,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      }
    });
    assert.strictEqual(oldKeyRejected.status, 401, 'Old key must be rejected immediately after rotation');

    // Master API OFF -> 503
    await request('/api/security/api-config/toggle', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { enabled: false }
    });
    const apiOffRes = await request('/api/v1/me', {
      headers: {
        'Authorization': `Bearer ${rotateRes.json.rawKey}`,
        'X-Boxd-Proxy-Secret': process.env.PROXY_SECRET,
        'X-Boxd-Client-IP': '203.0.113.45'
      }
    });
    assert.strictEqual(apiOffRes.status, 503);
    assert.strictEqual(apiOffRes.json.code, 'API_DISABLED');

    // Reset API master ON & API IP firewall OFF for clean finish
    await request('/api/security/api-config/toggle', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { enabled: true }
    });
    await request('/api/security/api-ips/toggle', {
      method: 'POST',
      headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
      body: { enabled: false }
    });
  } finally {
    process.env.PROXY_SECRET = prevProxySecret;
    Object.assign(boxdService, apiOrigFns);
    dbHelper.deleteAccount(apiAcc.id);
  }
  console.log('  ✓ External API, Allowed IP Firewall, HMAC Anti-Replay, Idempotency & VM Generation verified.\n');

  server.close();
  cleanupTempDb();
  console.log('🎉 ALL TESTS PASSED SUCCESSFULLY! 100% verified.');
}

runTests().catch(err => {
  cleanupTempDb();
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
