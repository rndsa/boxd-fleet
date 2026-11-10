require('dotenv').config();
const assert = require('assert');
const http = require('http');
const auth = require('../auth');
const dbHelper = require('../db');
const app = require('../server');

const TEST_PIN = process.env.ACCESS_PIN || 'change-me-pin-2026';

async function runTests() {
  console.log('🧪 Starting Boxd Fleet Smoke Tests...\n');

  // 1. Test Auth logic
  console.log('1. Testing Auth Module...');
  assert.strictEqual(auth.verifyPin(TEST_PIN), true, 'PIN check should pass');
  assert.strictEqual(auth.verifyPin('wrongpin'), false, 'Wrong PIN should fail');

  const token = auth.signSession('admin');
  assert(token && token.includes('.'), 'Token must be formatted with payload.signature');

  const session = auth.verifySession(token);
  assert(session && session.u === 'admin', 'Session must be decoded and valid');

  const invalidSession = auth.verifySession(token + 'tampered');
  assert.strictEqual(invalidSession, null, 'Tampered token must be rejected');
  console.log('  ✓ Auth Module tests passed.\n');

  // 2. Test DB Module
  console.log('2. Testing Database Module...');
  const testAccId = 'acc_test_' + Date.now();
  const created = dbHelper.createAccount({
    id: testAccId,
    label: 'Test Account',
    api_key: 'bxd_test_1234567890abcdef',
    user_id: 'usr_test',
    display_name: 'Tester',
    org_name: 'TestOrg',
    balance_micro: 30000000,
    currency: 'EUR',
    max_vms: 5,
    status: 'active'
  });
  assert.strictEqual(created.id, testAccId, 'Created account ID must match');
  assert.strictEqual(created.label, 'Test Account');

  const list = dbHelper.getAccounts();
  const found = list.find(a => a.id === testAccId);
  assert(found, 'Account must be in list');
  assert(found.masked_key.includes('...'), 'Key must be masked');
  assert(!found.masked_key.includes('1234567890'), 'Full raw key must not be exposed in getAccounts');

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

  // 3b. Try to access protected route without auth
  const protectedRes = await request('/api/accounts');
  assert.strictEqual(protectedRes.status, 401, 'Protected route must return 401 without auth');
  console.log('  ✓ GET /api/accounts returned 401 Unauthorized');

  // 3c. Login with wrong PIN
  const wrongLogin = await request('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: { pin: 'wrong' }
  });
  assert.strictEqual(wrongLogin.status, 401, 'Wrong PIN must return 401');
  console.log('  ✓ POST /api/auth/login rejected wrong PIN');

  // 3d. Login with valid PIN
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

  // 3e. Access protected route with session cookie
  const authAccountsRes = await request('/api/accounts', {
    headers: { 'Cookie': sessionCookie }
  });
  assert.strictEqual(authAccountsRes.status, 200, 'Protected route must return 200 with session cookie');
  assert(Array.isArray(authAccountsRes.json.accounts), 'Must return accounts array');
  console.log('  ✓ GET /api/accounts accessible with session cookie');

  // 3f. Add invalid boxd key - should fail validation gracefully
  const addInvalidKeyRes = await request('/api/accounts', {
    method: 'POST',
    headers: { 'Cookie': sessionCookie, 'Content-Type': 'application/json' },
    body: { label: 'Invalid Account', apiKey: 'bxd_invalid_fake_key_123' }
  });
  assert.strictEqual(addInvalidKeyRes.status, 400, 'Invalid Boxd key must be rejected by Boxd API check');
  assert(addInvalidKeyRes.json.error.includes('Validasi Boxd API Key gagal'), 'Must surface clear error message');
  console.log('  ✓ POST /api/accounts safely verified and rejected fake Boxd API key');

  // 3g. Check HTML SPA serving
  const htmlRes = await request('/');
  assert.strictEqual(htmlRes.status, 200);
  assert(htmlRes.body.includes('Boxd Fleet'), 'HTML must include Boxd Fleet');
  console.log('  ✓ GET / correctly serves SPA frontend');

  server.close();
  console.log('\n🎉 ALL TESTS PASSED SUCCESSFULLY! 100% verified.');
}

runTests().catch(err => {
  console.error('\n❌ Test failed:', err);
  process.exit(1);
});
