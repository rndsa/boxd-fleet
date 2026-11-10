const { Boxd } = require('@boxd-sh/sdk');
const dbHelper = require('./db');

const clientCache = new Map();

function getClient(apiKey) {
  if (!apiKey) throw new Error('API key is required');
  if (clientCache.has(apiKey)) {
    return clientCache.get(apiKey);
  }
  const client = new Boxd({ apiKey, timeout: 25000, maxRetries: 2 });
  clientCache.set(apiKey, client);
  return client;
}

function clearClientCache(apiKey) {
  if (apiKey) clientCache.delete(apiKey);
  else clientCache.clear();
}

/**
 * Validate and sync account info from Boxd API
 */
async function syncAccount(account) {
  const client = getClient(account.api_key);
  try {
    const [accData, orgsData, billingData] = await Promise.allSettled([
      client.account.get(),
      client.orgs.list(),
      client.orgs.billingActivityPage()
    ]);

    if (accData.status === 'rejected') {
      const err = accData.reason;
      const errorMsg = err.message || 'Failed to authenticate with Boxd';
      const isAuthError = err.grpcCode === 16 || errorMsg.includes('API key') || errorMsg.includes('unauthenticated');
      const updated = dbHelper.updateAccount(account.id, {
        status: isAuthError ? 'invalid' : 'error',
        last_error: errorMsg
      });
      return { success: false, error: errorMsg, account: updated };
    }

    const acc = accData.value;
    let orgName = account.org_name || '';
    let orgId = account.org_id || '';

    if (orgsData.status === 'fulfilled' && Array.isArray(orgsData.value) && orgsData.value.length > 0) {
      orgName = orgsData.value[0].name || orgName;
      orgId = orgsData.value[0].id || orgId;
    }

    let balanceMicro = account.balance_micro || 0;
    let currency = account.currency || 'usd';

    if (billingData.status === 'fulfilled' && billingData.value) {
      balanceMicro = billingData.value.balanceMicro !== undefined ? billingData.value.balanceMicro : balanceMicro;
      currency = billingData.value.currency || currency;
    }

    const updated = dbHelper.updateAccount(account.id, {
      user_id: acc.userId || null,
      display_name: acc.displayName || acc.userId || null,
      org_id: orgId || null,
      org_name: orgName || null,
      balance_micro: balanceMicro,
      currency: currency,
      max_vms: (acc.billing && acc.billing.maxVms) || 0,
      status: 'active',
      last_error: null
    });

    return { success: true, account: updated };
  } catch (err) {
    const errorMsg = err.message || 'Unexpected error syncing account';
    const updated = dbHelper.updateAccount(account.id, {
      status: 'error',
      last_error: errorMsg
    });
    return { success: false, error: errorMsg, account: updated };
  }
}

/**
 * Format a machine object for frontend consumption
 */
function formatMachine(machine, account) {
  const region = machine.region || (machine.access && machine.access.domain && machine.access.domain.includes('nyc') ? 'nyc' : 'fra');
  return {
    id: machine.id,
    name: machine.name,
    status: machine.status,
    region: region,
    resources: {
      vcpu: machine.resources ? machine.resources.vcpu : 1,
      memoryBytes: machine.resources ? machine.resources.memoryBytes : 0,
      memoryHuman: machine.resources ? `${Math.round(machine.resources.memoryBytes / (1024 * 1024 * 1024))} GB` : '4 GB',
      diskBytes: machine.resources ? machine.resources.diskBytes : 0
    },
    access: {
      url: machine.access ? machine.access.url : `https://${machine.name}.boxd.sh`,
      sshPort: machine.access ? machine.access.sshPort : null,
      domain: machine.access ? machine.access.domain : 'boxd.sh',
      desktopUrl: machine.access ? machine.access.desktopUrl : ''
    },
    createdAt: machine.createdAt ? (machine.createdAt.toISOString ? machine.createdAt.toISOString() : machine.createdAt) : null,
    autoSuspendTimeout: machine.autoSuspendTimeout || 0,
    autoHibernateTimeout: machine.autoHibernateTimeout || 0,
    accountId: account.id,
    accountLabel: account.label,
    accountOrg: account.org_name || 'Personal'
  };
}

/**
 * List machines for a single account across all regions
 */
async function listMachinesForAccount(account) {
  const client = getClient(account.api_key);
  try {
    const machines = await client.machines.list({ allContexts: true, region: 'all' });
    return (machines || []).map(m => formatMachine(m, account));
  } catch (err) {
    console.error(`Error listing machines for ${account.label}:`, err.message);
    throw err;
  }
}

/**
 * List machines across all accounts in parallel
 */
async function listAllMachines(accounts) {
  const tasks = accounts.map(async (account) => {
    try {
      const machines = await listMachinesForAccount(account);
      return { accountId: account.id, success: true, machines };
    } catch (err) {
      return { accountId: account.id, success: false, error: err.message, machines: [] };
    }
  });

  const results = await Promise.all(tasks);
  const allMachines = [];
  const accountStatuses = {};

  for (const res of results) {
    accountStatuses[res.accountId] = {
      success: res.success,
      error: res.error || null,
      count: res.machines.length
    };
    if (res.success && Array.isArray(res.machines)) {
      allMachines.push(...res.machines);
    }
  }

  return { machines: allMachines, accountStatuses };
}

/**
 * Get comprehensive telemetry (account, orgs, balance, usage rates, activity) for an account
 */
async function getAccountTelemetry(account) {
  const client = getClient(account.api_key);

  const [accRes, orgsRes, billingRes] = await Promise.allSettled([
    client.account.get(),
    client.orgs.list(),
    client.orgs.billingActivityPage()
  ]);

  const acc = accRes.status === 'fulfilled' ? accRes.value : null;
  const orgs = orgsRes.status === 'fulfilled' ? orgsRes.value : [];
  const billing = billingRes.status === 'fulfilled' ? billingRes.value : null;

  let usage = null;
  const orgName = (orgs && orgs.length > 0 && orgs[0].name) || account.org_name;
  if (orgName) {
    try {
      usage = await client.orgs.usage(orgName);
    } catch (e) {
      // orgs.usage may fail if insufficient permissions or empty
    }
  }

  let machines = [];
  try {
    const rawMachines = await client.machines.list({ allContexts: true, region: 'all' });
    machines = (rawMachines || []).map(m => formatMachine(m, account));
  } catch (e) {
    console.error('Telemetry machine list error:', e.message);
  }

  // Update DB balance if available
  if (billing && billing.balanceMicro !== undefined) {
    dbHelper.updateAccount(account.id, {
      balance_micro: billing.balanceMicro,
      currency: billing.currency || account.currency
    });
  }

  const balanceVal = billing && billing.balanceMicro !== undefined
    ? billing.balanceMicro / 1e6
    : (account.balance_micro || 0) / 1e6;

  return {
    account: {
      id: account.id,
      label: account.label,
      userId: (acc && acc.userId) || account.user_id,
      displayName: (acc && acc.displayName) || account.display_name || 'Primary Account',
      maxVms: (acc && acc.billing && acc.billing.maxVms) || account.max_vms || 100,
      subscriptionStatus: (acc && acc.billing && acc.billing.subscriptionStatus) || 'active',
      status: account.status,
      notes: account.notes,
      maskedKey: account.masked_key || (account.api_key ? account.api_key.slice(0, 8) + '...' + account.api_key.slice(-4) : '')
    },
    org: orgs && orgs.length > 0 ? orgs[0] : { name: account.org_name || "Personal" },
    billing: billing ? {
      balanceMicro: billing.balanceMicro,
      balance: balanceVal,
      currency: (billing.currency || 'usd').toUpperCase(),
      entries: (billing.entries || []).map(entry => ({
        id: entry.id,
        kind: entry.kind,
        amountMicro: entry.amountMicro,
        amount: entry.amountMicro / 1e6,
        createdAt: entry.createdAt
      }))
    } : {
      balanceMicro: account.balance_micro || 0,
      balance: balanceVal,
      currency: (account.currency || 'usd').toUpperCase(),
      entries: []
    },
    usage: usage ? {
      totalCostMicro: usage.totalCostMicro || 0,
      totalCost: (usage.totalCostMicro || 0) / 1e6,
      rates: {
        vcpuHour: (usage.rates && usage.rates.vcpuHourMicro ? usage.rates.vcpuHourMicro / 1e6 : 0.047),
        ramHour: (usage.rates && usage.rates.ramGibHourMicro ? usage.rates.ramGibHourMicro / 1e6 : 0.014),
        diskHour: (usage.rates && usage.rates.diskGibHourMicro ? usage.rates.diskGibHourMicro / 1e6 : 0.000096)
      },
      machines: (usage.machines || []).map(m => ({
        machineId: m.machineId,
        name: m.name,
        status: m.status,
        vcpu: m.resources ? m.resources.vcpu : 1,
        memoryBytes: m.resources ? m.resources.memoryBytes : 0,
        runningSeconds: m.seconds ? m.seconds.running : 0,
        vcpuHours: m.vcpuHours || 0,
        ramGibHours: m.ramGibHours || 0,
        diskGibHours: m.diskGibHours || 0,
        cost: (m.costMicro || 0) / 1e6
      }))
    } : null,
    machinesCount: machines.length,
    machines: machines
  };
}

/**
 * Perform a lifecycle action on a machine
 */
async function machineAction(account, machineId, action, region) {
  const client = getClient(account.api_key);
  const validActions = ['start', 'stop', 'reboot', 'pause', 'resume', 'hibernate', 'wake'];
  if (!validActions.includes(action)) {
    throw new Error(`Invalid machine action: ${action}. Allowed: ${validActions.join(', ')}`);
  }

  if (typeof client.machines[action] !== 'function') {
    throw new Error(`SDK does not support action: ${action}`);
  }

  const opts = region && region !== 'default' ? { region } : undefined;
  const result = await client.machines[action](machineId, opts);
  return result || { success: true };
}

/**
 * Create a new machine
 */
async function createMachine(account, params) {
  const client = getClient(account.api_key);
  const createPayload = {};

  if (params.name && params.name.trim()) {
    createPayload.name = params.name.trim();
  }

  if (params.region && params.region !== 'default') {
    createPayload.region = params.region;
  }

  const config = {};
  if (params.vcpu) config.vcpu = parseInt(params.vcpu, 10);
  if (params.memory) config.memory = String(params.memory);
  if (params.autoSuspendTimeout !== undefined) config.autoSuspendTimeout = parseInt(params.autoSuspendTimeout, 10);
  if (params.autoHibernateTimeout !== undefined) config.autoHibernateTimeout = parseInt(params.autoHibernateTimeout, 10);

  if (Object.keys(config).length > 0) {
    createPayload.config = config;
  }

  const machine = await client.machines.create(createPayload);
  return formatMachine(machine, account);
}

/**
 * Delete a machine
 */
async function deleteMachine(account, machineId, region) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  await client.machines.delete(machineId, opts);
  return { success: true, id: machineId };
}

/**
 * Execute a command inside a machine
 */
async function execCommand(account, machineId, command, timeoutMs = 30000, region) {
  const client = getClient(account.api_key);
  const execOpts = {
    command,
    timeout: timeoutMs
  };
  if (region && region !== 'default') {
    execOpts.region = region;
  }

  const result = await client.machines.exec(machineId, execOpts);
  return {
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    exitCode: result.exitCode !== undefined ? result.exitCode : (result.success ? 0 : 1),
    success: !!result.success
  };
}

/**
 * Suggest a machine name
 */
async function suggestName(account) {
  const client = getClient(account.api_key);
  try {
    return await client.machines.suggestName();
  } catch (err) {
    const adjectives = ['swift', 'silent', 'cyber', 'hyper', 'shadow', 'neon', 'iron', 'quantum', 'flat', 'red'];
    const nouns = ['node', 'box', 'vault', 'edge', 'core', 'forge', 'nexus', 'prism', 'wolf', 'reef'];
    const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
    const noun = nouns[Math.floor(Math.random() * nouns.length)];
    const rand = Math.floor(100 + Math.random() * 900);
    return `${adj}-${noun}-${rand}`;
  }
}

/**
 * List snapshots for an account
 */
async function listSnapshots(account) {
  const client = getClient(account.api_key);
  const snaps = await client.snapshots.list();
  return snaps || [];
}

/**
 * Create a snapshot from a machine
 */
async function createSnapshot(account, machineId, name) {
  const client = getClient(account.api_key);
  return await client.snapshots.create(machineId, name);
}

/**
 * Delete a snapshot
 */
async function deleteSnapshot(account, name) {
  const client = getClient(account.api_key);
  await client.snapshots.delete(name);
  return { success: true, name };
}

module.exports = {
  getClient,
  clearClientCache,
  syncAccount,
  formatMachine,
  listMachinesForAccount,
  listAllMachines,
  getAccountTelemetry,
  machineAction,
  createMachine,
  deleteMachine,
  execCommand,
  suggestName,
  listSnapshots,
  createSnapshot,
  deleteSnapshot
};
