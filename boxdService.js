const { Boxd } = require('@boxd-sh/sdk');
const crypto = require('crypto');
const dbHelper = require('./db');
const auth = require('./auth');

const clientCache = new Map();
const vmJobs = new Map();

const STARTER_KITS = {
  essentials: {
    id: 'essentials',
    label: 'Essentials',
    desc: 'build-essential, python3-venv, pip, tmux, screen, sqlite3, lsof, ncdu, tree, dnsutils, socat',
    apt: [
      'ca-certificates', 'gnupg', 'build-essential', 'python3-venv',
      'python3-pip', 'tmux', 'screen', 'sqlite3', 'lsof', 'ncdu',
      'tree', 'dnsutils', 'net-tools', 'socat'
    ],
    npm: []
  },
  node_pm2: {
    id: 'node_pm2',
    label: 'Node PM2 + pnpm',
    desc: 'Install pm2, pnpm, tsx global + symlink /usr/local/bin untuk root & boxd',
    apt: [],
    npm: ['pm2', 'pnpm', 'tsx']
  },
  python_dev: {
    id: 'python_dev',
    label: 'Python Dev',
    desc: 'python3-dev, python3-venv, python3-pip, pipx + PATH uv',
    apt: ['python3-dev', 'python3-venv', 'python3-pip', 'pipx'],
    npm: []
  },
  docker_ready: {
    id: 'docker_ready',
    label: 'Docker Siap Pakai',
    desc: 'Aktifkan docker.service & izin user boxd menjalankan docker tanpa sudo',
    apt: [],
    npm: [],
    enableDocker: true
  }
};

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
 * Detect whether an API key is org-scoped (shared VMs only) or member-scoped (full access)
 */
async function detectKeyScope(client) {
  try {
    await client.teams.list();
    return 'member';
  } catch (err) {
    const msg = String(err && err.message ? err.message : '').toLowerCase();
    if (msg.includes('org-scoped') || msg.includes('shared fleet') || msg.includes('member credential')) {
      return 'org';
    }
    return 'unknown';
  }
}

/**
 * Resolve true region and status from Boxd orgs.usage() status field.
 * Remember: orgs.usage() queries the home region (fra); VMs in other regions report status like "in nyc".
 */
function resolveRegionFromUsageStatus(rawStatus, homeRegion = 'fra') {
  const s = String(rawStatus || '').trim().toLowerCase();
  if (s === 'deleted') {
    return { region: null, normalizedStatus: 'deleted', isDeleted: true };
  }
  const remoteMatch = s.match(/^in\s+([a-z0-9-]+)$/i);
  if (remoteMatch) {
    return {
      region: remoteMatch[1].toLowerCase(),
      normalizedStatus: 'remote',
      isDeleted: false
    };
  }
  return {
    region: (homeRegion || 'fra').toLowerCase(),
    normalizedStatus: s || 'unknown',
    isDeleted: false
  };
}

/**
 * Inspect account metadata, org, billing, regions, machine limit, and key scope from Boxd API
 */
async function inspectAccountWithKey(apiKey) {
  const client = getClient(apiKey);
  const [accRes, orgsRes, billingRes, limitRes, regionsRes, keyScope] = await Promise.allSettled([
    client.account.get(),
    client.orgs.list(),
    client.orgs.billingActivityPage(),
    client.orgs.getMachineLimit(),
    client.orgs.regions(),
    detectKeyScope(client)
  ]);

  if (accRes.status === 'rejected') {
    const err = accRes.reason || new Error('Failed to authenticate with Boxd');
    const errorMsg = err.message || 'Failed to authenticate with Boxd';
    const isAuthError = err.grpcCode === 16 || errorMsg.includes('API key') || errorMsg.includes('unauthenticated');
    return { success: false, isAuthError, error: errorMsg };
  }

  const acc = accRes.value;
  const orgs = orgsRes.status === 'fulfilled' && Array.isArray(orgsRes.value) ? orgsRes.value : [];
  const primaryOrg = orgs[0] || null;
  const billing = billingRes.status === 'fulfilled' ? billingRes.value : null;
  const machineLimit = limitRes.status === 'fulfilled' ? limitRes.value : null;
  const regions = regionsRes.status === 'fulfilled' && Array.isArray(regionsRes.value) ? regionsRes.value : [];
  const scope = keyScope.status === 'fulfilled' ? keyScope.value : 'unknown';

  const homeRegionObj = regions.find(r => r.home) || regions[0];
  const homeRegion = homeRegionObj ? homeRegionObj.id : 'fra';
  const enabledRegions = regions.filter(r => r.orgState === 'enabled').map(r => r.id);

  const maxVms = (machineLimit && typeof machineLimit.maxVms === 'number' && machineLimit.maxVms > 0)
    ? machineLimit.maxVms
    : ((acc.billing && acc.billing.maxVms) || 100);

  return {
    success: true,
    client,
    acc,
    orgs,
    primaryOrg,
    billing,
    machineLimit,
    regions,
    homeRegion,
    enabledRegions,
    keyScope: scope,
    maxVms
  };
}

/**
 * Validate a brand-new API key BEFORE saving to SQLite (prevents polluting DB with invalid rows)
 */
async function validateNewApiKey(apiKey) {
  const info = await inspectAccountWithKey(apiKey);
  if (!info.success) {
    clearClientCache(apiKey);
    return info;
  }
  return {
    success: true,
    fields: {
      user_id: info.acc.userId || null,
      display_name: info.acc.displayName || info.acc.userId || null,
      org_id: info.primaryOrg ? info.primaryOrg.id : null,
      org_name: info.primaryOrg ? info.primaryOrg.name : null,
      org_slug: info.primaryOrg ? info.primaryOrg.slug : null,
      key_scope: info.keyScope,
      home_region: info.homeRegion,
      enabled_regions: info.enabledRegions,
      balance_micro: info.billing && info.billing.balanceMicro !== undefined ? info.billing.balanceMicro : 0,
      currency: (info.billing && info.billing.currency) || 'usd',
      max_vms: info.maxVms,
      status: 'active',
      last_error: null,
      last_synced_at: Date.now()
    }
  };
}

/**
 * Validate and sync an existing account row from Boxd API -> SQLite
 */
async function syncAccount(account) {
  try {
    const info = await inspectAccountWithKey(account.api_key);
    if (!info.success) {
      if (info.isAuthError) clearClientCache(account.api_key);
      const updated = dbHelper.updateAccount(account.id, {
        status: info.isAuthError ? 'invalid' : 'error',
        last_error: info.error,
        last_synced_at: Date.now()
      });
      return { success: false, error: info.error, account: updated };
    }

    const updated = dbHelper.updateAccount(account.id, {
      user_id: info.acc.userId || account.user_id || null,
      display_name: info.acc.displayName || info.acc.userId || account.display_name || null,
      org_id: (info.primaryOrg && info.primaryOrg.id) || account.org_id || null,
      org_name: (info.primaryOrg && info.primaryOrg.name) || account.org_name || null,
      org_slug: (info.primaryOrg && info.primaryOrg.slug) || account.org_slug || null,
      key_scope: info.keyScope !== 'unknown' ? info.keyScope : (account.key_scope || 'unknown'),
      home_region: info.homeRegion || account.home_region || 'fra',
      enabled_regions: info.enabledRegions.length > 0 ? info.enabledRegions : account.enabled_regions,
      balance_micro: info.billing && info.billing.balanceMicro !== undefined ? info.billing.balanceMicro : (account.balance_micro || 0),
      currency: (info.billing && info.billing.currency) || account.currency || 'usd',
      max_vms: info.maxVms || account.max_vms || 100,
      status: 'active',
      last_error: null,
      last_synced_at: Date.now()
    });

    return { success: true, account: updated };
  } catch (err) {
    const errorMsg = err.message || 'Unexpected error syncing account';
    const updated = dbHelper.updateAccount(account.id, {
      status: 'error',
      last_error: errorMsg,
      last_synced_at: Date.now()
    });
    return { success: false, error: errorMsg, account: updated };
  }
}

/**
 * Format a live machine object from SDK for frontend consumption
 */
function formatMachine(machine, account, extras = {}) {
  const domain = (machine.access && machine.access.domain) || 'boxd.sh';
  let region = machine.region;
  if (!region) {
    if (domain.includes('nyc')) region = 'nyc';
    else if (domain.includes('fra')) region = 'fra';
    else region = account.home_region || 'fra';
  }
  const memoryBytes = machine.resources ? machine.resources.memoryBytes : 0;
  const memoryGb = memoryBytes ? Math.round(memoryBytes / (1024 * 1024 * 1024)) : 0;
  const autoSuspendTimeout = machine.idle ? (machine.idle.suspendAfter || 0) : (machine.autoSuspendTimeout || 0);
  const autoHibernateTimeout = machine.idle ? (machine.idle.hibernateAfter || 0) : (machine.autoHibernateTimeout || 0);

  return {
    id: machine.id,
    name: machine.name,
    status: machine.status,
    rawUsageStatus: extras.rawUsageStatus || machine.status,
    region: region.toLowerCase(),
    shared: !!machine.shared,
    accessible: extras.accessible !== undefined ? extras.accessible : true,
    accessReason: extras.accessReason || null,
    resources: {
      vcpu: machine.resources ? machine.resources.vcpu : 1,
      memoryBytes,
      memoryGb,
      memoryHuman: memoryGb ? `${memoryGb} GB` : '4 GB',
      diskBytes: machine.resources ? machine.resources.diskBytes : 0
    },
    access: {
      url: machine.access ? machine.access.url : `https://${machine.name}.${domain}`,
      sshPort: machine.access ? machine.access.sshPort : null,
      domain,
      desktopUrl: machine.access ? machine.access.desktopUrl : ''
    },
    createdAt: machine.createdAt ? (machine.createdAt.toISOString ? machine.createdAt.toISOString() : machine.createdAt) : null,
    autoSuspendTimeout,
    autoHibernateTimeout,
    botProtectionMode: machine.botProtectionMode || 'on',
    idleIgnoreOutbound: !!machine.idleIgnoreOutbound,
    alwaysOn: autoSuspendTimeout === 0 && autoHibernateTimeout === 0,
    runningSeconds: extras.runningSeconds || 0,
    costMicro: extras.costMicro || 0,
    cost: extras.cost || 0,
    ownerName: machine.createdByName || extras.ownerName || null,
    accountId: account.id,
    accountLabel: account.label,
    accountOrg: account.org_name || 'Personal',
    accountOrgSlug: account.org_slug || null,
    accountKeyScope: extras.keyScope || account.key_scope || 'unknown',
    sshAccess: extras.sshAccess || null,
    vmConfig: extras.vmConfig || null
  };
}

/**
 * Fetch and reconcile FULL live snapshot for a single account:
 * - Syncs DB account metadata (balance, org_slug, max_vms, key_scope, regions)
 * - Lists all directly controllable machines via machines.list({ allContexts: true, region: 'all' })
 * - Reads orgs.usage() and reconciles non-deleted private VMs hidden from org-scoped API keys
 * - Produces unified machine list + telemetry + billing ledger with real regions & statuses
 */
async function fetchAccountFleetSnapshot(account) {
  const info = await inspectAccountWithKey(account.api_key);

  if (!info.success) {
    if (info.isAuthError) clearClientCache(account.api_key);
    const nextStatus = info.isAuthError ? 'invalid' : 'error';
    const updated = dbHelper.updateAccount(account.id, {
      status: nextStatus,
      last_error: info.error,
      last_synced_at: Date.now()
    });
    const balMicro = updated.balance_micro || 0;
    return {
      success: false,
      error: info.error,
      account: {
        id: updated.id,
        label: updated.label,
        userId: updated.user_id,
        displayName: updated.display_name || updated.user_id || updated.label,
        maxVms: updated.max_vms || 100,
        subscriptionStatus: updated.status,
        status: updated.status,
        lastError: info.error,
        keyScope: updated.key_scope || 'unknown',
        homeRegion: updated.home_region || 'fra',
        enabledRegions: safeJsonArray(updated.enabled_regions),
        notes: updated.notes,
        maskedKey: maskKey(updated.api_key)
      },
      org: { id: updated.org_id, name: updated.org_name || 'Personal', slug: updated.org_slug || '' },
      billing: {
        balanceMicro: balMicro,
        balance: balMicro / 1e6,
        currency: (updated.currency || 'usd').toUpperCase(),
        entries: []
      },
      usage: null,
      machinesCount: 0,
      controllableCount: 0,
      privateLockedCount: 0,
      machines: []
    };
  }

  const { client, acc, primaryOrg, billing, homeRegion, enabledRegions, keyScope, maxVms } = info;
  const orgSlugOrId = (primaryOrg && (primaryOrg.slug || primaryOrg.id)) || account.org_slug || account.org_id || '';

  // Persist fresh state back to DB so /api/accounts & /api/accounts/telemetry stay 100% in sync
  const updatedAccount = dbHelper.updateAccount(account.id, {
    user_id: acc.userId || null,
    display_name: acc.displayName || acc.userId || null,
    org_id: (primaryOrg && primaryOrg.id) || account.org_id || null,
    org_name: (primaryOrg && primaryOrg.name) || account.org_name || null,
    org_slug: (primaryOrg && primaryOrg.slug) || account.org_slug || null,
    key_scope: keyScope,
    home_region: homeRegion,
    enabled_regions: enabledRegions,
    balance_micro: billing && billing.balanceMicro !== undefined ? billing.balanceMicro : (account.balance_micro || 0),
    currency: (billing && billing.currency) || account.currency || 'usd',
    max_vms: maxVms,
    status: 'active',
    last_error: null,
    last_synced_at: Date.now()
  });

  // Fetch controllable machines + usage report in parallel
  const [liveMachinesRes, usageRes] = await Promise.allSettled([
    client.machines.list({ allContexts: true, region: 'all' }),
    (async () => {
      try {
        return await client.orgs.usage(orgSlugOrId ? { org: orgSlugOrId } : {});
      } catch (e) {
        return await client.orgs.usage();
      }
    })()
  ]);

  const rawLiveMachines = liveMachinesRes.status === 'fulfilled' && Array.isArray(liveMachinesRes.value)
    ? liveMachinesRes.value
    : [];
  const rawUsage = usageRes.status === 'fulfilled' ? usageRes.value : null;

  const usageById = new Map();
  if (rawUsage && Array.isArray(rawUsage.machines)) {
    for (const um of rawUsage.machines) {
      usageById.set(um.machineId, um);
    }
  }

  const liveById = new Map();
  const reconciledMachines = [];
  const sshAccessMap = dbHelper.getVmSshAccessByAccount(updatedAccount.id);
  const vmConfigMap = dbHelper.getVmConfigsByAccount(updatedAccount.id);

  for (const lm of rawLiveMachines) {
    const um = usageById.get(lm.id);
    const formatted = formatMachine(lm, updatedAccount, {
      accessible: true,
      keyScope,
      rawUsageStatus: um ? um.status : lm.status,
      runningSeconds: um && um.seconds ? (um.seconds.running || 0) : 0,
      costMicro: um ? (um.costMicro || 0) : 0,
      cost: um ? (um.costMicro || 0) / 1e6 : 0,
      sshAccess: sshAccessMap[lm.id] || null,
      vmConfig: vmConfigMap[lm.id] || null
    });
    liveById.set(lm.id, formatted);
    reconciledMachines.push(formatted);
  }

  // Reconcile orgs.usage() telemetry (only controllable live machines appear in reconciledMachines; private VMs stay hidden)
  const normalizedUsageMachines = [];
  let privateLockedCount = 0;
  if (rawUsage && Array.isArray(rawUsage.machines)) {
    for (const um of rawUsage.machines) {
      const liveMatch = liveById.get(um.machineId);
      const resolved = resolveRegionFromUsageStatus(um.status, homeRegion);
      const effectiveRegion = (liveMatch && liveMatch.region) || resolved.region || homeRegion || 'fra';
      const memBytes = um.resources ? (um.resources.memoryBytes || 0) : 0;
      const runSec = um.seconds ? (um.seconds.running || 0) : 0;
      const costMicro = um.costMicro || 0;
      const cost = costMicro / 1e6;

      let displayStatus = um.status || 'active';
      if (liveMatch) {
        displayStatus = liveMatch.status;
      } else if (resolved.isDeleted) {
        displayStatus = 'deleted';
      } else if (resolved.normalizedStatus === 'remote') {
        displayStatus = 'remote';
      } else {
        displayStatus = resolved.normalizedStatus;
      }

      if (!liveMatch && !resolved.isDeleted) {
        privateLockedCount++;
      }

      normalizedUsageMachines.push({
        machineId: um.machineId,
        name: um.name,
        status: displayStatus,
        rawStatus: um.status,
        region: effectiveRegion,
        shared: liveMatch ? liveMatch.shared : !!um.shared,
        accessible: !!liveMatch,
        isDeleted: resolved.isDeleted,
        vcpu: um.resources ? (um.resources.vcpu || 1) : 1,
        memoryBytes: memBytes,
        diskBytes: um.resources ? (um.resources.diskBytes || 0) : 0,
        runningSeconds: runSec,
        vcpuHours: um.vcpuHours || 0,
        ramGibHours: um.ramGibHours || 0,
        diskGibHours: um.diskGibHours || 0,
        costMicro,
        cost
      });
    }
  }

  // Sort: running first, then standby/hibernated, then name
  const statusRank = { running: 0, suspended: 1, paused: 1, hibernated: 2, remote: 3, stopped: 4 };
  reconciledMachines.sort((a, b) => {
    const ra = statusRank[a.status] ?? 5;
    const rb = statusRank[b.status] ?? 5;
    if (ra !== rb) return ra - rb;
    return String(a.name).localeCompare(String(b.name));
  });

  const balanceMicro = billing && billing.balanceMicro !== undefined
    ? billing.balanceMicro
    : (updatedAccount.balance_micro || 0);
  const controllableCount = reconciledMachines.length;

  return {
    success: true,
    error: null,
    account: {
      id: updatedAccount.id,
      label: updatedAccount.label,
      userId: updatedAccount.user_id,
      displayName: updatedAccount.display_name || 'Primary Account',
      maxVms,
      subscriptionStatus: (acc.billing && acc.billing.subscriptionStatus) || 'active',
      status: updatedAccount.status,
      lastError: null,
      keyScope,
      homeRegion,
      enabledRegions,
      notes: updatedAccount.notes,
      maskedKey: maskKey(updatedAccount.api_key)
    },
    org: primaryOrg || { id: updatedAccount.org_id, name: updatedAccount.org_name || 'Personal', slug: updatedAccount.org_slug || '' },
    billing: billing ? {
      balanceMicro,
      balance: balanceMicro / 1e6,
      currency: (billing.currency || 'usd').toUpperCase(),
      entries: (billing.entries || []).slice(0, 25).map(entry => ({
        id: entry.id,
        kind: entry.kind,
        amountMicro: entry.amountMicro,
        amount: entry.amountMicro / 1e6,
        createdAt: entry.createdAt
      }))
    } : {
      balanceMicro,
      balance: balanceMicro / 1e6,
      currency: (updatedAccount.currency || 'usd').toUpperCase(),
      entries: []
    },
    usage: rawUsage ? {
      totalCostMicro: rawUsage.totalCostMicro || 0,
      totalCost: (rawUsage.totalCostMicro || 0) / 1e6,
      rates: {
        vcpuHour: rawUsage.rates && rawUsage.rates.vcpuHourMicro ? rawUsage.rates.vcpuHourMicro / 1e6 : 0.047,
        ramHour: rawUsage.rates && rawUsage.rates.ramGibHourMicro ? rawUsage.rates.ramGibHourMicro / 1e6 : 0.014,
        diskHour: rawUsage.rates && rawUsage.rates.diskGibHourMicro ? rawUsage.rates.diskGibHourMicro / 1e6 : 0.000096
      },
      machines: normalizedUsageMachines
    } : null,
    machinesCount: reconciledMachines.length,
    controllableCount,
    privateLockedCount,
    machines: reconciledMachines
  };
}

function maskKey(key) {
  if (!key || key.length < 12) return key ? `${key.slice(0, 4)}...` : '';
  return `${key.slice(0, 8)}...${key.slice(-4)}`;
}

function safeJsonArray(val) {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try {
      const parsed = JSON.parse(val);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }
  return [];
}

/**
 * List reconciled machines for a single account
 */
async function listMachinesForAccount(account) {
  const snapshot = await fetchAccountFleetSnapshot(account);
  if (!snapshot.success) {
    throw new Error(snapshot.error || `Gagal mengambil mesin akun ${account.label}`);
  }
  return snapshot.machines;
}

/**
 * List reconciled machines across all accounts in parallel
 */
async function listAllMachines(accounts) {
  const tasks = accounts.map(async (account) => {
    try {
      const snapshot = await fetchAccountFleetSnapshot(account);
      return {
        accountId: account.id,
        success: snapshot.success,
        error: snapshot.error || null,
        machines: snapshot.machines || []
      };
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
    if (Array.isArray(res.machines)) {
      allMachines.push(...res.machines);
    }
  }

  return { machines: allMachines, accountStatuses };
}

/**
 * Get comprehensive telemetry for an account (unified with fleet snapshot)
 */
async function getAccountTelemetry(account) {
  return await fetchAccountFleetSnapshot(account);
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
 * Normalize memory parameter for SDK parseSize ("4G" or numeric MB -> "4096M")
 */
function normalizeMemoryForSdk(memory) {
  if (memory === undefined || memory === null || memory === '') return undefined;
  const s = String(memory).trim();
  if (/^\d+(\.\d+)?$/.test(s)) {
    return `${Math.round(Number(s))}M`;
  }
  return s;
}

/**
 * Create a new machine
 */
async function createMachine(account, params) {
  const client = getClient(account.api_key);
  let keyScope = account.key_scope;
  let orgSlug = account.org_slug || account.org_id;

  if (!keyScope || keyScope === 'unknown' || !orgSlug) {
    const syncRes = await syncAccount(account);
    if (syncRes.success && syncRes.account) {
      keyScope = syncRes.account.key_scope;
      orgSlug = syncRes.account.org_slug || syncRes.account.org_id;
    }
  }

  const createPayload = {};

  if (params.name && params.name.trim()) {
    createPayload.name = params.name.trim();
  }

  if (params.region && params.region !== 'default') {
    createPayload.region = params.region;
  }

  if (orgSlug) {
    createPayload.org = orgSlug;
  }

  if (keyScope === 'org') {
    if (params.shared === false) {
      throw new Error('API Key bertipe ORG hanya bisa mengelola Shared VM. Aktifkan "Share with Org" atau gunakan Member API Key.');
    }
    createPayload.shared = true;
  } else if (params.shared !== undefined) {
    createPayload.shared = !!params.shared;
  }

  const config = {};
  if (params.vcpu) config.vcpu = parseInt(params.vcpu, 10);
  const memStr = normalizeMemoryForSdk(params.memory);
  if (memStr) config.memory = memStr;
  if (params.autoSuspendTimeout !== undefined && params.autoSuspendTimeout !== null && params.autoSuspendTimeout !== '') {
    config.autoSuspendTimeout = parseInt(params.autoSuspendTimeout, 10);
  }
  if (params.idleIgnoreOutbound !== undefined) {
    config.idleIgnoreOutbound = !!params.idleIgnoreOutbound;
  }

  if (Object.keys(config).length > 0) {
    createPayload.config = config;
  }

  let machine = await client.machines.create(createPayload);
  const targetRegion = machine.region || params.region || account.home_region || 'fra';
  const opts = targetRegion && targetRegion !== 'default' ? { region: targetRegion } : undefined;

  // Apply post-create idle / botProtection settings not handled directly by SDK toVmConfig()
  const setupWarnings = [];
  if (params.autoHibernateTimeout !== undefined && params.autoHibernateTimeout !== null && params.autoHibernateTimeout !== '') {
    try {
      await client.machines.setAutoHibernateTimeout(machine.id, parseInt(params.autoHibernateTimeout, 10), opts);
    } catch (err) {
      setupWarnings.push(`Auto-hibernate: ${err.message}`);
    }
  }
  if (params.botProtectionMode && ['off', 'sleep_only', 'on'].includes(params.botProtectionMode)) {
    try {
      await client.machines.setBotProtection(machine.id, params.botProtectionMode, opts);
    } catch (err) {
      setupWarnings.push(`Bot protection: ${err.message}`);
    }
  }

  let sshAccess = null;
  let sshSetupError = null;
  const autoSetup = params.autoSetup && typeof params.autoSetup === 'object' ? params.autoSetup : null;
  const needsReady = Boolean(
    (params.sshPassword && String(params.sshPassword).length > 0) ||
    (autoSetup && (
      autoSetup.enableAutoUpdate ||
      autoSetup.upgradeNow ||
      (Array.isArray(autoSetup.starterKits) && autoSetup.starterKits.length > 0)
    ))
  );

  if (needsReady) {
    try {
      await client.machines.waitUntilReady(machine.id, { ...(opts || {}), timeout: 45000 });
    } catch (err) {
      setupWarnings.push(`Wait ready: ${err.message}`);
    }
  }

  if (params.sshPassword && String(params.sshPassword).length > 0) {
    try {
      const sshRes = await setupVmSshPassword(account, machine.id, {
        password: String(params.sshPassword),
        sshUser: params.sshUser || 'root',
        region: targetRegion
      });
      sshAccess = {
        enabled: true,
        sshUser: sshRes.sshUser,
        publicPort: sshRes.publicPort,
        dns: sshRes.dns,
        hasPassword: true,
        updatedAt: Date.now()
      };
    } catch (err) {
      sshSetupError = err.message || 'Gagal mengatur password SSH otomatis';
    }
  }

  const alwaysOnFlag = Number(params.autoSuspendTimeout) === 0 && Number(params.autoHibernateTimeout) === 0;
  let vmConfig = dbHelper.upsertVmConfig({
    machine_id: machine.id,
    account_id: account.id,
    region: targetRegion,
    auto_update_enabled: !!(autoSetup && autoSetup.enableAutoUpdate),
    auto_update_interval_hours: (autoSetup && autoSetup.intervalHours) ? parseInt(autoSetup.intervalHours, 10) : 12,
    auto_update_runtimes: autoSetup && autoSetup.updateRuntimes !== undefined ? !!autoSetup.updateRuntimes : true,
    always_on_mode: alwaysOnFlag,
    starter_kits: (autoSetup && Array.isArray(autoSetup.starterKits)) ? autoSetup.starterKits : []
  });

  let provisionJobId = null;
  if (autoSetup && (
    autoSetup.enableAutoUpdate ||
    autoSetup.upgradeNow ||
    (Array.isArray(autoSetup.starterKits) && autoSetup.starterKits.length > 0)
  )) {
    try {
      if (autoSetup.enableAutoUpdate) {
        await configureVmAutoUpdate(account, machine.id, {
          enabled: true,
          intervalHours: autoSetup.intervalHours || 12,
          updateRuntimes: autoSetup.updateRuntimes !== undefined ? !!autoSetup.updateRuntimes : true,
          region: targetRegion,
          skipWake: true
        });
      }
      const needsBgWork = Boolean(
        autoSetup.upgradeNow ||
        (Array.isArray(autoSetup.starterKits) && autoSetup.starterKits.length > 0)
      );
      if (needsBgWork) {
        const jobRes = await startVmProvisionJob(account, machine.id, {
          upgradeOs: !!autoSetup.upgradeNow,
          starterKits: Array.isArray(autoSetup.starterKits) ? autoSetup.starterKits : [],
          region: targetRegion,
          skipWake: true
        });
        provisionJobId = jobRes.jobId;
      } else if (!autoSetup.enableAutoUpdate) {
        // Lightweight APT index + PATH setup when only basic autoSetup requested
        await ensureVmFleetBaseTools(account, machine.id, targetRegion, { refreshApt: true });
      }
      vmConfig = dbHelper.getVmConfig(machine.id);
    } catch (err) {
      setupWarnings.push(`Auto-setup: ${err.message}`);
    }
  }

  try {
    machine = await client.machines.get(machine.id, opts);
  } catch (e) {}

  const formatted = formatMachine(machine, account, { accessible: true, keyScope, sshAccess, vmConfig });
  if (sshSetupError) formatted.sshSetupError = sshSetupError;
  if (provisionJobId) formatted.provisionJobId = provisionJobId;
  if (setupWarnings.length > 0) formatted.setupWarnings = setupWarnings;
  return formatted;
}

/**
 * Create a new machine from an existing snapshot
 */
async function createMachineFromSnapshot(account, params) {
  const client = getClient(account.api_key);
  let keyScope = account.key_scope;
  let orgSlug = account.org_slug || account.org_id;
  if (!keyScope || keyScope === 'unknown' || !orgSlug) {
    const syncRes = await syncAccount(account);
    if (syncRes.success && syncRes.account) {
      keyScope = syncRes.account.key_scope;
      orgSlug = syncRes.account.org_slug || syncRes.account.org_id;
    }
  }

  const payload = {
    fromSnapshot: String(params.fromSnapshot || '').trim()
  };
  if (params.name && params.name.trim()) payload.name = params.name.trim();
  if (params.region && params.region !== 'default') payload.region = params.region;
  if (orgSlug) payload.org = orgSlug;
  // Note: Boxd SDK explicitly rejects `shared: true` on create({ fromSnapshot }) — snapshots inherit org sharing from capture.

  let machine = await client.machines.create(payload);
  const targetRegion = machine.region || params.region || account.home_region || 'fra';
  const opts = targetRegion && targetRegion !== 'default' ? { region: targetRegion } : undefined;
  if (params.alwaysOn) {
    try {
      await client.machines.setAutoSuspendTimeout(machine.id, 0, opts);
      await client.machines.setAutoHibernateTimeout(machine.id, 0, opts);
      await client.machines.setBotProtection(machine.id, 'off', opts);
    } catch (e) {}
  }
  try {
    machine = await client.machines.get(machine.id, opts);
  } catch (e) {}
  const vmConfig = params.alwaysOn
    ? dbHelper.upsertVmConfig({
        machine_id: machine.id,
        account_id: account.id,
        region: targetRegion,
        always_on_mode: true
      })
    : dbHelper.getVmConfig(machine.id);
  return formatMachine(machine, account, { accessible: true, keyScope, vmConfig });
}

/**
 * Delete a machine
 */
async function deleteMachine(account, machineId, region) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  await client.machines.delete(machineId, opts);
  dbHelper.deleteVmSshAccess(machineId);
  dbHelper.deleteVmConfig(machineId);
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
 * Build isolated sshd config & systemd unit that never conflicts with Boxd's masked ssh.socket
 */
function buildFleetSshdConfig(sshUser = 'root') {
  const allowUsers = sshUser === 'both' ? 'root boxd' : sshUser;
  const permitRoot = sshUser === 'boxd' ? 'no' : 'yes';
  return [
    'Port 22',
    'HostKey /etc/ssh/ssh_host_rsa_key',
    'HostKey /etc/ssh/ssh_host_ecdsa_key',
    'HostKey /etc/ssh/ssh_host_ed25519_key',
    'PasswordAuthentication yes',
    'KbdInteractiveAuthentication no',
    'PermitEmptyPasswords no',
    `PermitRootLogin ${permitRoot}`,
    `AllowUsers ${allowUsers}`,
    'PubkeyAuthentication yes',
    'UsePAM yes',
    'X11Forwarding yes',
    'PrintMotd no',
    'AcceptEnv LANG LC_*',
    'Subsystem sftp /usr/lib/openssh/sftp-server',
    'ClientAliveInterval 60',
    'ClientAliveCountMax 10',
    'PidFile /run/boxd-fleet-sshd.pid'
  ].join('\n') + '\n';
}

function buildFleetSshdServiceUnit() {
  return [
    '[Unit]',
    'Description=Boxd Fleet Password SSH Server',
    'After=network.target',
    '',
    '[Service]',
    'ExecStartPre=/usr/bin/ssh-keygen -A',
    'ExecStartPre=/usr/sbin/sshd -t -f /etc/ssh/sshd_config_fleet',
    'ExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_config_fleet',
    'ExecReload=/usr/sbin/sshd -t -f /etc/ssh/sshd_config_fleet',
    'ExecReload=/bin/kill -HUP $MAINPID',
    'KillMode=process',
    'Restart=on-failure',
    'RestartPreventExitStatus=255',
    'RuntimeDirectory=sshd',
    'RuntimeDirectoryMode=0755',
    '',
    '[Install]',
    'WantedBy=multi-user.target'
  ].join('\n') + '\n';
}

function buildSshCommand(publicPort, sshUser, dns) {
  if (!publicPort || !dns) return null;
  const primaryUser = sshUser === 'boxd' ? 'boxd' : 'root';
  return `ssh -p ${publicPort} ${primaryUser}@${dns}`;
}

/**
 * Inspect live SSH password status & exposed TCP port 22 for a VM
 */
async function getVmSshPasswordStatus(account, machineId, region) {
  const client = getClient(account.api_key);
  const effectiveRegion = region && region !== 'default' ? region : undefined;
  const opts = effectiveRegion ? { region: effectiveRegion } : undefined;

  const machine = await client.machines.get(machineId, opts);
  const resolvedRegion = (machine.region || effectiveRegion || account.home_region || 'fra').toLowerCase();
  const portOpts = { region: resolvedRegion };

  const [portsList, stored] = await Promise.all([
    client.machines.ports.list(machineId, portOpts).catch(() => []),
    Promise.resolve(dbHelper.getVmSshAccess(machineId))
  ]);

  const port22 = Array.isArray(portsList)
    ? portsList.find(p => Number(p.machinePort) === 22)
    : null;

  let sshServiceActive = null;
  if (machine.status === 'running') {
    try {
      const probe = await execCommand(
        account,
        machineId,
        'systemctl is-active boxd-fleet-sshd 2>/dev/null || echo inactive',
        8000,
        resolvedRegion
      );
      sshServiceActive = (probe.stdout || '').trim() === 'active';
    } catch (e) {
      sshServiceActive = null;
    }
  }

  const publicPort = port22 ? Number(port22.publicPort) : (stored && stored.public_port ? Number(stored.public_port) : null);
  const domain = (machine.access && machine.access.domain) || `${resolvedRegion}.boxd.sh`;
  const dns = (port22 && port22.dns) || (stored && stored.dns) || `${machine.name}.${domain}`;
  const sshUser = (stored && stored.ssh_user) || 'root';

  // Keep local DB port metadata synced if port22 state diverged externally
  const enabled = !!(port22 && ((stored && stored.enabled) || sshServiceActive));
  if (stored && port22 && (Number(stored.public_port) !== Number(port22.publicPort) || stored.dns !== port22.dns)) {
    dbHelper.upsertVmSshAccess({
      machine_id: machineId,
      account_id: account.id,
      machine_name: machine.name,
      region: resolvedRegion,
      ssh_user: sshUser,
      public_port: Number(port22.publicPort),
      dns: port22.dns,
      password_enc: null,
      enabled: stored.enabled ? 1 : 0
    });
  } else if (stored && stored.enabled && !port22 && Array.isArray(portsList)) {
    // Port 22 was removed externally
    dbHelper.upsertVmSshAccess({
      machine_id: machineId,
      account_id: account.id,
      machine_name: machine.name,
      region: resolvedRegion,
      ssh_user: sshUser,
      public_port: null,
      dns,
      password_enc: null,
      enabled: 0
    });
  }

  const decryptedPassword = stored && stored.password_enc ? auth.decryptSecret(stored.password_enc) : null;

  return {
    machineId,
    machineName: machine.name,
    region: resolvedRegion,
    status: machine.status,
    enabled: !!(port22 && (stored ? stored.enabled : sshServiceActive)),
    portExposed: !!port22,
    sshServiceActive,
    sshUser,
    publicPort: port22 ? Number(port22.publicPort) : null,
    dns,
    command: port22 ? buildSshCommand(Number(port22.publicPort), sshUser, dns) : null,
    hasPassword: !!(stored && stored.password_enc),
    password: decryptedPassword,
    updatedAt: stored ? stored.updated_at : null
  };
}

/**
 * Set/reset VM SSH password, configure dedicated sshd service, and expose port 22
 */
async function setupVmSshPassword(account, machineId, { password, sshUser = 'root', region } = {}) {
  const errMsg = auth.validateSshPasswordInput({ password, sshUser });
  if (errMsg) {
    throw new Error(errMsg);
  }

  const client = getClient(account.api_key);
  const effectiveRegion = region && region !== 'default' ? region : undefined;
  const opts = effectiveRegion ? { region: effectiveRegion } : undefined;

  const machine = await client.machines.get(machineId, opts);
  const resolvedRegion = (machine.region || effectiveRegion || account.home_region || 'fra').toLowerCase();
  const portOpts = { region: resolvedRegion };

  if (machine.status === 'stopped') {
    throw new Error('VM sedang STOPPED. Nyalakan (Start) VM terlebih dahulu sebelum mengatur password SSH.');
  }

  // Ensure port 22 is exposed (reuse existing forward if already exposed)
  const existingPorts = await client.machines.ports.list(machineId, portOpts).catch(() => []);
  let port22 = Array.isArray(existingPorts) ? existingPorts.find(p => Number(p.machinePort) === 22) : null;
  if (!port22) {
    try {
      port22 = await client.machines.ports.expose(machineId, 22, { protocol: 'tcp', ...portOpts });
    } catch (err) {
      const msg = err && err.message ? err.message : String(err);
      if (msg.toLowerCase().includes('limit') || msg.toLowerCase().includes('max')) {
        throw new Error('Batas port forward VM penuh (maksimal 3 port per VM). Hapus salah satu port terlebih dahulu.');
      }
      throw new Error(`Gagal membuka port forward SSH (22): ${msg}`);
    }
  }

  const b64Cfg = Buffer.from(buildFleetSshdConfig(sshUser), 'utf8').toString('base64');
  const b64Unit = Buffer.from(buildFleetSshdServiceUnit(), 'utf8').toString('base64');

  const chpasswdLines = [];
  if (sshUser === 'root' || sshUser === 'both') chpasswdLines.push(`root:${password}`);
  if (sshUser === 'boxd' || sshUser === 'both') chpasswdLines.push(`boxd:${password}`);
  const b64Pass = Buffer.from(chpasswdLines.join('\n') + '\n', 'utf8').toString('base64');

  const setupCmd = [
    'sudo mkdir -p /run/sshd /etc/ssh /etc/systemd/system',
    `printf "%s" ${b64Cfg} | base64 -d | sudo tee /etc/ssh/sshd_config_fleet >/dev/null`,
    `printf "%s" ${b64Unit} | base64 -d | sudo tee /etc/systemd/system/boxd-fleet-sshd.service >/dev/null`,
    `printf "%s" ${b64Pass} | base64 -d | sudo chpasswd`,
    'sudo systemctl daemon-reload',
    'sudo systemctl enable boxd-fleet-sshd >/dev/null 2>&1',
    'sudo systemctl restart boxd-fleet-sshd',
    'if [ "$(ls -1 /var/lib/apt/lists/*_Packages* 2>/dev/null | wc -l)" -eq 0 ]; then (sudo DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=45 update -qq >/dev/null 2>&1 || true) & fi',
    'systemctl is-active boxd-fleet-sshd'
  ].join(' && ');

  const execRes = await execCommand(account, machineId, setupCmd, 25000, resolvedRegion);
  const serviceState = (execRes.stdout || '').trim().split('\n').pop();
  if (!execRes.success || serviceState !== 'active') {
    const detail = (execRes.stderr || execRes.stdout || '').trim();
    throw new Error(`Gagal mengaktifkan service SSH di dalam VM${detail ? `: ${detail.slice(0, 180)}` : ''}`);
  }

  const publicPort = Number(port22.publicPort);
  const domain = (machine.access && machine.access.domain) || `${resolvedRegion}.boxd.sh`;
  const dns = port22.dns || `${machine.name}.${domain}`;
  const encrypted = auth.encryptSecret(password);

  dbHelper.upsertVmSshAccess({
    machine_id: machineId,
    account_id: account.id,
    machine_name: machine.name,
    region: resolvedRegion,
    ssh_user: sshUser,
    public_port: publicPort,
    dns,
    password_enc: encrypted,
    enabled: 1
  });

  return {
    success: true,
    machineId,
    machineName: machine.name,
    region: resolvedRegion,
    sshUser,
    publicPort,
    dns,
    command: buildSshCommand(publicPort, sshUser, dns),
    password
  };
}

/**
 * Disable password SSH inside VM (best effort if stopped) and unexpose port 22
 */
async function disableVmSshPassword(account, machineId, region) {
  const client = getClient(account.api_key);
  const effectiveRegion = region && region !== 'default' ? region : undefined;
  const opts = effectiveRegion ? { region: effectiveRegion } : undefined;

  let machine = null;
  try {
    machine = await client.machines.get(machineId, opts);
  } catch (e) {
    machine = null;
  }

  const resolvedRegion = ((machine && machine.region) || effectiveRegion || account.home_region || 'fra').toLowerCase();
  const portOpts = { region: resolvedRegion };

  if (machine && machine.status !== 'stopped') {
    const revertCmd = [
      'sudo systemctl disable --now boxd-fleet-sshd >/dev/null 2>&1 || true',
      'sudo rm -f /etc/systemd/system/boxd-fleet-sshd.service /etc/ssh/sshd_config_fleet',
      'sudo systemctl daemon-reload >/dev/null 2>&1 || true',
      'sudo usermod -p "*" root >/dev/null 2>&1 || true',
      'sudo usermod -p "!" boxd >/dev/null 2>&1 || true'
    ].join('; ');
    await execCommand(account, machineId, revertCmd, 20000, resolvedRegion).catch(() => null);
  }

  await client.machines.ports.unexpose(machineId, 22, portOpts).catch(() => null);
  dbHelper.deleteVmSshAccess(machineId);

  return {
    success: true,
    machineId,
    region: resolvedRegion
  };
}

/**
 * Build shell profile + /usr/local/bin symlink helper for nvm/bun/uv
 */
function buildFleetPathProfileScript() {
  return [
    '# Managed by boxd-fleet',
    'for _bf_dir in /home/boxd/.nvm/versions/node/*/bin; do',
    '  if [ -d "$_bf_dir" ]; then',
    '    case ":$PATH:" in *":$_bf_dir:"*) ;; *) PATH="$_bf_dir:$PATH" ;; esac',
    '  fi',
    'done',
    'if [ -d /home/boxd/.bun/bin ]; then',
    '  case ":$PATH:" in *":/home/boxd/.bun/bin:"*) ;; *) PATH="/home/boxd/.bun/bin:$PATH" ;; esac',
    'fi',
    'if [ -d /home/boxd/.local/bin ]; then',
    '  case ":$PATH:" in *":/home/boxd/.local/bin:"*) ;; *) PATH="/home/boxd/.local/bin:$PATH" ;; esac',
    'fi',
    'export PATH',
    ''
  ].join('\n');
}

function buildFleetSyncPathScript() {
  return [
    '#!/usr/bin/env bash',
    'set -e',
    'NODE_BIN="$(ls -d /home/boxd/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -n1 || true)"',
    'link_bin() {',
    '  local src="$1"',
    '  local name="$2"',
    '  if [ -x "$src" ] && [ ! -e "/usr/bin/$name" ]; then',
    '    ln -sf "$src" "/usr/local/bin/$name"',
    '  fi',
    '}',
    'if [ -n "$NODE_BIN" ] && [ -d "$NODE_BIN" ]; then',
    '  for b in node npm npx corepack pm2 pnpm tsx yarn; do',
    '    link_bin "$NODE_BIN/$b" "$b"',
    '  done',
    'fi',
    'for b in bun bunx; do',
    '  link_bin "/home/boxd/.bun/bin/$b" "$b"',
    'done',
    'for b in uv uvx; do',
    '  link_bin "/home/boxd/.local/bin/$b" "$b"',
    'done',
    ''
  ].join('\n');
}

function buildAptReadyScript() {
  return [
    '#!/usr/bin/env bash',
    'set -uo pipefail',
    'export DEBIAN_FRONTEND=noninteractive',
    'mkdir -p /var/lib/boxd-fleet /run',
    'LOCK_FILE="/run/boxd-fleet-apt-ready.lock"',
    'exec 9>"$LOCK_FILE"',
    'if ! flock -w 45 9; then',
    '  exit 0',
    'fi',
    'PKG_COUNT="$(ls -1 /var/lib/apt/lists/*_Packages* 2>/dev/null | wc -l || echo 0)"',
    'FRESH_REL="$(find /var/lib/apt/lists -maxdepth 1 -name "*_InRelease" -mmin -360 -print -quit 2>/dev/null || true)"',
    'if [ "${FORCE_APT_REFRESH:-0}" = "1" ] || [ "$PKG_COUNT" -eq 0 ] || [ -z "$FRESH_REL" ]; then',
    '  ok=0',
    '  for attempt in 1 2 3; do',
    '    if apt-get -o DPkg::Lock::Timeout=90 update -qq >/dev/null 2>&1 || apt-get -o DPkg::Lock::Timeout=90 update -y; then',
    '      if [ "$(ls -1 /var/lib/apt/lists/*_Packages* 2>/dev/null | wc -l || echo 0)" -gt 0 ]; then',
    '        ok=1',
    '        break',
    '      fi',
    '    fi',
    '    sleep 2',
    '  done',
    '  if [ "$ok" -ne 1 ]; then',
    '    echo "APT index refresh gagal" >&2',
    '    exit 1',
    '  fi',
    'fi',
    'exit 0',
    ''
  ].join('\n');
}

function buildAptReadyService() {
  return [
    '[Unit]',
    'Description=Boxd Fleet APT Index Self-Healer',
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=oneshot',
    'ExecStart=/usr/local/sbin/boxd-fleet-apt-ready',
    'Nice=10',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    ''
  ].join('\n');
}

function buildAutoUpdateScript() {
  return [
    '#!/usr/bin/env bash',
    'set -uo pipefail',
    'export DEBIAN_FRONTEND=noninteractive',
    'mkdir -p /var/lib/boxd-fleet /etc/boxd-fleet /var/log',
    'LOG_FILE="/var/log/boxd-fleet-autoupdate.log"',
    'STATUS_FILE="/var/lib/boxd-fleet/autoupdate.status.json"',
    'ENV_FILE="/etc/boxd-fleet/autoupdate.env"',
    'LOCK_FILE="/run/boxd-fleet-autoupdate.lock"',
    'AUTO_UPDATE_RUNTIMES="1"',
    '[ -f "$ENV_FILE" ] && source "$ENV_FILE" || true',
    'exec 9>"$LOCK_FILE"',
    'if ! flock -n 9; then',
    '  exit 0',
    'fi',
    'START_TS="$(date +%s000)"',
    'write_status() {',
    '  python3 - "$STATUS_FILE" "$1" "$2" "$START_TS" "$3" "$4" "$5" "$6" <<\'PYEOF\'',
    'import json, sys, time',
    'path, st, phase, start_ts, before_s, after_s, rc_s, err = sys.argv[1:9]',
    'now_ts = int(time.time() * 1000)',
    'st_ts = int(start_ts) if start_ts.isdigit() else now_ts',
    'before = int(before_s) if before_s.isdigit() else 0',
    'after = int(after_s) if after_s.isdigit() else 0',
    'rc = int(rc_s) if rc_s.lstrip("-").isdigit() else 0',
    'data = {',
    '  "status": st,',
    '  "phase": phase,',
    '  "startedAt": st_ts,',
    '  "finishedAt": None if st == "running" else now_ts,',
    '  "durationSec": max(0, round((now_ts - st_ts) / 1000)),',
    '  "upgradableBefore": before,',
    '  "upgradableAfter": after,',
    '  "upgradedCount": max(0, before - after) if st != "running" else 0,',
    '  "exitCode": rc,',
    '  "error": err or None',
    '}',
    'tmp = path + ".tmp"',
    'with open(tmp, "w") as f:',
    '  json.dump(data, f)',
    'import os; os.replace(tmp, path)',
    'PYEOF',
    '}',
    'exec > >(tee -a "$LOG_FILE") 2>&1',
    'echo "===== [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Boxd Fleet Auto-Update START ====="',
    'write_status "running" "apt_update" "0" "0" "0" ""',
    'if ! apt-get -o DPkg::Lock::Timeout=90 update -y; then',
    '  write_status "error" "apt_update" "0" "0" "1" "apt-get update gagal"',
    '  exit 1',
    'fi',
    'BEFORE="$(apt list --upgradable 2>/dev/null | grep -c "\\[upgradable" || true)"',
    'echo "Paket upgradable terdeteksi: $BEFORE"',
    'write_status "running" "apt_upgrade" "$BEFORE" "$BEFORE" "0" ""',
    'if ! apt-get -o DPkg::Lock::Timeout=90 upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"; then',
    '  AFTER="$(apt list --upgradable 2>/dev/null | grep -c "\\[upgradable" || true)"',
    '  write_status "error" "apt_upgrade" "$BEFORE" "$AFTER" "1" "apt-get upgrade gagal"',
    '  exit 1',
    'fi',
    'write_status "running" "apt_clean" "$BEFORE" "0" "0" ""',
    'apt-get -o DPkg::Lock::Timeout=90 autoremove -y >/dev/null 2>&1 || true',
    'apt-get -o DPkg::Lock::Timeout=90 autoclean -y >/dev/null 2>&1 || true',
    'if [ "${AUTO_UPDATE_RUNTIMES:-1}" = "1" ]; then',
    '  write_status "running" "runtimes" "$BEFORE" "0" "0" ""',
    '  NODE_BIN="$(ls -d /home/boxd/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -n1 || true)"',
    '  if [ -n "$NODE_BIN" ] && [ -x "$NODE_BIN/npm" ]; then',
    '    echo "Updating global npm packages via boxd nvm..."',
    '    runuser -u boxd -- env HOME=/home/boxd PATH="$NODE_BIN:/usr/local/bin:/usr/bin:/bin" npm update -g || true',
    '  elif command -v npm >/dev/null 2>&1; then',
    '    npm update -g || true',
    '  fi',
    '  if [ -x /home/boxd/.bun/bin/bun ]; then',
    '    echo "Checking bun upgrade..."',
    '    runuser -u boxd -- env HOME=/home/boxd /home/boxd/.bun/bin/bun upgrade || true',
    '  fi',
    '  if [ -x /home/boxd/.local/bin/uv ]; then',
    '    echo "Checking uv update..."',
    '    runuser -u boxd -- env HOME=/home/boxd /home/boxd/.local/bin/uv self update || true',
    '  fi',
    'fi',
    '/usr/local/sbin/boxd-fleet-sync-path >/dev/null 2>&1 || true',
    'AFTER="$(apt list --upgradable 2>/dev/null | grep -c "\\[upgradable" || true)"',
    'write_status "success" "done" "$BEFORE" "$AFTER" "0" ""',
    'echo "===== [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Auto-Update DONE (upgraded: $((BEFORE > AFTER ? BEFORE - AFTER : 0)), sisa: $AFTER) ====="',
    'if [ -f "$LOG_FILE" ]; then tail -n 500 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"; fi',
    'exit 0',
    ''
  ].join('\n');
}

function buildAutoUpdateService() {
  return [
    '[Unit]',
    'Description=Boxd Fleet Auto-Update Service',
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=oneshot',
    'ExecStart=/usr/local/sbin/boxd-fleet-autoupdate',
    'Nice=10',
    'IOSchedulingClass=best-effort',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    ''
  ].join('\n');
}

function buildAutoUpdateTimer(intervalHours = 12) {
  const hrs = Math.max(1, Math.min(168, parseInt(intervalHours, 10) || 12));
  return [
    '[Unit]',
    'Description=Boxd Fleet Scheduled Auto-Update Timer',
    '',
    '[Timer]',
    'OnBootSec=45s',
    `OnUnitActiveSec=${hrs}h`,
    'RandomizedDelaySec=45',
    'Persistent=true',
    '',
    '[Install]',
    'WantedBy=timers.target',
    ''
  ].join('\n');
}

function buildPkgRunnerScript() {
  return [
    '#!/usr/bin/env bash',
    'set -uo pipefail',
    'export DEBIAN_FRONTEND=noninteractive',
    'mkdir -p /var/lib/boxd-fleet /etc/boxd-fleet /var/log',
    'LOG_FILE="/var/log/boxd-fleet-pkg.log"',
    'STATUS_FILE="/var/lib/boxd-fleet/pkg.status.json"',
    'TASK_FILE="/etc/boxd-fleet/pkg-task.env"',
    'LOCK_FILE="/run/boxd-fleet-pkg.lock"',
    'DO_APT_UPGRADE="0"',
    'APT_PKGS=""',
    'NPM_PKGS=""',
    'ENABLE_DOCKER="0"',
    '[ -f "$TASK_FILE" ] && source "$TASK_FILE" || true',
    'exec 9>"$LOCK_FILE"',
    'if ! flock -n 9; then',
    '  exit 0',
    'fi',
    'START_TS="$(date +%s000)"',
    'write_status() {',
    '  python3 - "$STATUS_FILE" "$1" "$2" "$START_TS" "$3" "$4" <<\'PYEOF\'',
    'import json, sys, time, os',
    'path, st, phase, start_ts, rc_s, err = sys.argv[1:7]',
    'now_ts = int(time.time() * 1000)',
    'st_ts = int(start_ts) if start_ts.isdigit() else now_ts',
    'rc = int(rc_s) if rc_s.lstrip("-").isdigit() else 0',
    'data = {',
    '  "status": st,',
    '  "phase": phase,',
    '  "startedAt": st_ts,',
    '  "finishedAt": None if st == "running" else now_ts,',
    '  "durationSec": max(0, round((now_ts - st_ts) / 1000)),',
    '  "exitCode": rc,',
    '  "error": err or None',
    '}',
    'tmp = path + ".tmp"',
    'with open(tmp, "w") as f:',
    '  json.dump(data, f)',
    'os.replace(tmp, path)',
    'PYEOF',
    '}',
    ': > "$LOG_FILE"',
    'exec > >(tee -a "$LOG_FILE") 2>&1',
    'echo "===== [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Boxd Fleet Provisioning START ====="',
    'write_status "running" "prepare" "0" ""',
    'if [ "$DO_APT_UPGRADE" = "1" ] || [ -n "$APT_PKGS" ]; then',
    '  write_status "running" "apt_update" "0" ""',
    '  if ! apt-get -o DPkg::Lock::Timeout=90 update -y; then',
    '    write_status "error" "apt_update" "1" "apt-get update gagal"',
    '    exit 1',
    '  fi',
    'fi',
    'if [ "$DO_APT_UPGRADE" = "1" ]; then',
    '  write_status "running" "apt_upgrade" "0" ""',
    '  if ! apt-get -o DPkg::Lock::Timeout=90 upgrade -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"; then',
    '    write_status "error" "apt_upgrade" "1" "apt-get upgrade gagal"',
    '    exit 1',
    '  fi',
    'fi',
    'if [ -n "$APT_PKGS" ]; then',
    '  write_status "running" "apt_install" "0" ""',
    '  echo "Installing APT packages: $APT_PKGS"',
    '  # shellcheck disable=SC2086',
    '  if ! apt-get -o DPkg::Lock::Timeout=90 install -y --no-install-recommends $APT_PKGS; then',
    '    write_status "error" "apt_install" "1" "Gagal install paket APT"',
    '    exit 1',
    '  fi',
    'fi',
    'if [ -n "$NPM_PKGS" ]; then',
    '  write_status "running" "npm_install" "0" ""',
    '  echo "Installing NPM global packages: $NPM_PKGS"',
    '  NODE_BIN="$(ls -d /home/boxd/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -n1 || true)"',
    '  if [ -n "$NODE_BIN" ] && [ -x "$NODE_BIN/npm" ]; then',
    '    # shellcheck disable=SC2086',
    '    if ! runuser -u boxd -- env HOME=/home/boxd PATH="$NODE_BIN:/usr/local/bin:/usr/bin:/bin" npm install -g $NPM_PKGS; then',
    '      write_status "error" "npm_install" "1" "Gagal install paket NPM global"',
    '      exit 1',
    '    fi',
    '  elif command -v npm >/dev/null 2>&1; then',
    '    # shellcheck disable=SC2086',
    '    if ! npm install -g $NPM_PKGS; then',
    '      write_status "error" "npm_install" "1" "Gagal install paket NPM global"',
    '      exit 1',
    '    fi',
    '  else',
    '    write_status "error" "npm_install" "1" "npm tidak ditemukan di VM"',
    '    exit 1',
    '  fi',
    'fi',
    'if [ "$ENABLE_DOCKER" = "1" ]; then',
    '  write_status "running" "docker" "0" ""',
    '  systemctl enable --now docker >/dev/null 2>&1 || true',
    '  usermod -aG docker boxd >/dev/null 2>&1 || true',
    '  docker --version || true',
    'fi',
    '/usr/local/sbin/boxd-fleet-sync-path >/dev/null 2>&1 || true',
    'apt-get -o DPkg::Lock::Timeout=90 autoremove -y >/dev/null 2>&1 || true',
    'apt-get -o DPkg::Lock::Timeout=90 autoclean -y >/dev/null 2>&1 || true',
    'write_status "success" "done" "0" ""',
    'echo "===== [$(date -u +%Y-%m-%dT%H:%M:%SZ)] Boxd Fleet Provisioning DONE ====="',
    'exit 0',
    ''
  ].join('\n');
}

function buildPkgRunnerService() {
  return [
    '[Unit]',
    'Description=Boxd Fleet Package Provisioning Runner',
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=oneshot',
    'ExecStart=/usr/local/sbin/boxd-fleet-pkg-runner',
    'Nice=10',
    '',
    '[Install]',
    'WantedBy=multi-user.target',
    ''
  ].join('\n');
}

function createVmJob({ machineId, accountId, region, type, title }) {
  const id = 'job_' + crypto.randomBytes(6).toString('hex');
  const job = {
    id,
    machineId,
    accountId,
    region,
    type,
    title: title || type,
    status: 'running',
    phase: 'starting',
    startedAt: Date.now(),
    finishedAt: null,
    output: '',
    error: null,
    meta: null
  };
  vmJobs.set(id, job);
  // Prune old completed jobs (> 45 min or > 80 entries)
  if (vmJobs.size > 80) {
    const cutoff = Date.now() - 45 * 60 * 1000;
    for (const [k, v] of vmJobs.entries()) {
      if (v.status !== 'running' && (v.finishedAt || v.startedAt) < cutoff) {
        vmJobs.delete(k);
      }
    }
  }
  return job;
}

function getVmJob(jobId) {
  return vmJobs.get(jobId) || null;
}

function listVmJobsForMachine(machineId) {
  const list = [];
  for (const job of vmJobs.values()) {
    if (job.machineId === machineId) list.push(job);
  }
  list.sort((a, b) => b.startedAt - a.startedAt);
  return list.slice(0, 8);
}

/**
 * Wake/resume VM cleanly if suspended or hibernated
 */
async function ensureVmAwake(account, machineId, region) {
  const client = getClient(account.api_key);
  let effectiveRegion = region && region !== 'default' ? region : undefined;
  let machine = await client.machines.get(machineId, effectiveRegion ? { region: effectiveRegion } : undefined);
  const resolvedRegion = ((machine && machine.region) || effectiveRegion || account.home_region || 'fra').toLowerCase();
  const opts = { region: resolvedRegion };

  if (machine.status === 'stopped') {
    throw new Error('VM sedang STOPPED. Nyalakan (Start) VM terlebih dahulu.');
  }

  let wasWoken = false;
  if (machine.status === 'suspended' || machine.status === 'paused') {
    await client.machines.resume(machineId, opts);
    await client.machines.waitUntilReady(machineId, { ...opts, timeout: 35000 });
    wasWoken = true;
  } else if (machine.status === 'hibernated') {
    await client.machines.wake(machineId, opts);
    await client.machines.waitUntilReady(machineId, { ...opts, timeout: 50000 });
    wasWoken = true;
  } else if (machine.status === 'pending' || machine.status === 'starting') {
    await client.machines.waitUntilReady(machineId, { ...opts, timeout: 50000 });
  }

  machine = await client.machines.get(machineId, opts);
  return { machine, resolvedRegion, wasWoken };
}

/**
 * Ensure base fleet scripts + PATH profile + systemd units are installed on VM
 */
async function ensureVmFleetBaseTools(account, machineId, region, options = {}) {
  const refreshApt = !!options.refreshApt;
  const intervalHours = Math.max(1, Math.min(168, parseInt(options.intervalHours, 10) || 12));
  const updateRuntimes = options.updateRuntimes !== false;

  const files = [
    { path: '/etc/profile.d/boxd-fleet-path.sh', mode: '644', content: buildFleetPathProfileScript() },
    { path: '/usr/local/sbin/boxd-fleet-sync-path', mode: '755', content: buildFleetSyncPathScript() },
    { path: '/usr/local/sbin/boxd-fleet-apt-ready', mode: '755', content: buildAptReadyScript() },
    { path: '/etc/systemd/system/boxd-fleet-apt-ready.service', mode: '644', content: buildAptReadyService() },
    { path: '/usr/local/sbin/boxd-fleet-autoupdate', mode: '755', content: buildAutoUpdateScript() },
    { path: '/etc/systemd/system/boxd-fleet-autoupdate.service', mode: '644', content: buildAutoUpdateService() },
    { path: '/etc/systemd/system/boxd-fleet-autoupdate.timer', mode: '644', content: buildAutoUpdateTimer(intervalHours) },
    { path: '/usr/local/sbin/boxd-fleet-pkg-runner', mode: '755', content: buildPkgRunnerScript() },
    { path: '/etc/systemd/system/boxd-fleet-pkg.service', mode: '644', content: buildPkgRunnerService() },
    {
      path: '/etc/boxd-fleet/autoupdate.env',
      mode: '644',
      content: `AUTO_UPDATE_RUNTIMES=${updateRuntimes ? '1' : '0'}\nINTERVAL_HOURS=${intervalHours}\n`
    }
  ];

  const writeCmds = [
    'sudo mkdir -p /usr/local/sbin /etc/boxd-fleet /var/lib/boxd-fleet /etc/profile.d'
  ];
  for (const f of files) {
    const b64 = Buffer.from(f.content, 'utf8').toString('base64');
    writeCmds.push(`echo '${b64}' | base64 -d | sudo tee '${f.path}' >/dev/null && sudo chmod ${f.mode} '${f.path}'`);
  }
  writeCmds.push('sudo /usr/local/sbin/boxd-fleet-sync-path >/dev/null 2>&1 || true');
  writeCmds.push('sudo systemctl daemon-reload');
  writeCmds.push('sudo systemctl enable boxd-fleet-apt-ready.service >/dev/null 2>&1 || true');
  if (refreshApt) {
    writeCmds.push('sudo /usr/local/sbin/boxd-fleet-apt-ready');
  }

  const res = await execCommand(account, machineId, writeCmds.join(' && '), refreshApt ? 65000 : 45000, region);
  if (res.exitCode !== 0) {
    throw new Error(res.stderr || res.stdout || 'Gagal memasang utilitas auto-update ke VM');
  }
  return res;
}

/**
 * Watch systemd service inside VM and update in-memory job + DB
 */
function watchVmSystemdJob(job, account, machineId, region, kind = 'autoupdate') {
  const statusFile = kind === 'autoupdate'
    ? '/var/lib/boxd-fleet/autoupdate.status.json'
    : '/var/lib/boxd-fleet/pkg.status.json';
  const logFile = kind === 'autoupdate'
    ? '/var/log/boxd-fleet-autoupdate.log'
    : '/var/log/boxd-fleet-pkg.log';
  const serviceName = kind === 'autoupdate'
    ? 'boxd-fleet-autoupdate.service'
    : 'boxd-fleet-pkg.service';

  const maxDurationMs = 10 * 60 * 1000;
  let polling = false;
  let consecutiveErrs = 0;

  const timer = setInterval(async () => {
    if (polling) return;
    polling = true;
    try {
      if (Date.now() - job.startedAt > maxDurationMs) {
        job.status = 'error';
        job.phase = 'timeout';
        job.error = 'Job melebihi batas waktu pantau 10 menit.';
        job.finishedAt = Date.now();
        clearInterval(timer);
        return;
      }

      const cmd = [
        `SVC_ACTIVE=$(systemctl is-active ${serviceName} 2>/dev/null || echo inactive)`,
        `echo "__BF_SVC__:$SVC_ACTIVE"`,
        `if [ -f "${statusFile}" ]; then echo "__BF_JSON__:$(cat "${statusFile}" | tr -d '\\n')"; else echo "__BF_JSON__:null"; fi`,
        `echo "__BF_LOG__"`,
        `if [ -f "${logFile}" ]; then tail -n 35 "${logFile}"; fi`
      ].join('; ');

      const res = await execCommand(account, machineId, cmd, 15000, region);
      consecutiveErrs = 0;
      const out = String(res.stdout || '');
      const svcMatch = out.match(/__BF_SVC__:([^\r\n]+)/);
      const jsonMatch = out.match(/__BF_JSON__:([^\r\n]+)/);
      const logIdx = out.indexOf('__BF_LOG__');
      const svcActive = svcMatch ? svcMatch[1].trim() : 'unknown';
      const logTail = logIdx >= 0 ? out.slice(logIdx + '__BF_LOG__'.length).trim() : '';

      if (logTail) job.output = logTail;

      let parsed = null;
      if (jsonMatch && jsonMatch[1] && jsonMatch[1].trim() !== 'null') {
        try {
          parsed = JSON.parse(jsonMatch[1].trim());
        } catch (e) {}
      }

      if (parsed) {
        job.phase = parsed.phase || job.phase;
        job.meta = parsed;
        if (parsed.status === 'success' || parsed.status === 'error') {
          // Ensure systemd job has actually exited before marking done
          if (svcActive !== 'activating' || Date.now() - job.startedAt > 5000) {
            job.status = parsed.status;
            job.error = parsed.error || null;
            job.finishedAt = parsed.finishedAt || Date.now();
            if (kind === 'autoupdate') {
              const summary = parsed.status === 'success'
                ? `+${parsed.upgradedCount || 0} paket di-upgrade (sisa ${parsed.upgradableAfter || 0})`
                : (parsed.error || 'Update gagal');
              dbHelper.upsertVmConfig({
                machine_id: machineId,
                account_id: account.id,
                region,
                last_update_status: parsed.status,
                last_update_summary: summary,
                last_update_at: job.finishedAt
              });
            }
            clearInterval(timer);
            return;
          }
        }
      }

      if ((svcActive === 'inactive' || svcActive === 'failed') && Date.now() - job.startedAt > 5000) {
        job.status = svcActive === 'failed' ? 'error' : 'success';
        job.phase = svcActive === 'failed' ? 'failed' : 'done';
        if (svcActive === 'failed' && !job.error) {
          job.error = 'Service systemd berhenti dengan status failed.';
        }
        job.finishedAt = Date.now();
        if (kind === 'autoupdate') {
          dbHelper.upsertVmConfig({
            machine_id: machineId,
            account_id: account.id,
            region,
            last_update_status: job.status,
            last_update_summary: job.status === 'success' ? 'Auto-update selesai' : (job.error || 'Update gagal'),
            last_update_at: job.finishedAt
          });
        }
        clearInterval(timer);
      }
    } catch (err) {
      consecutiveErrs++;
      if (consecutiveErrs >= 5) {
        job.status = 'error';
        job.phase = 'unreachable';
        job.error = err.message || 'Gagal membaca progress VM';
        job.finishedAt = Date.now();
        clearInterval(timer);
      }
    } finally {
      polling = false;
    }
  }, 2500);
}

/**
 * Configure scheduled Auto-Update inside VM
 */
async function configureVmAutoUpdate(account, machineId, { enabled, intervalHours = 12, updateRuntimes = true, region, skipWake = false } = {}) {
  const safeHours = Math.max(1, Math.min(168, parseInt(intervalHours, 10) || 12));
  let resolvedRegion = region && region !== 'default' ? region : (account.home_region || 'fra');

  if (!skipWake) {
    const awake = await ensureVmAwake(account, machineId, region);
    resolvedRegion = awake.resolvedRegion;
  }

  await ensureVmFleetBaseTools(account, machineId, resolvedRegion, {
    intervalHours: safeHours,
    updateRuntimes: !!updateRuntimes,
    refreshApt: !!enabled
  });

  if (enabled) {
    const res = await execCommand(
      account,
      machineId,
      'sudo systemctl enable --now boxd-fleet-autoupdate.timer && systemctl is-enabled boxd-fleet-autoupdate.timer && systemctl is-active boxd-fleet-autoupdate.timer',
      20000,
      resolvedRegion
    );
    if (res.exitCode !== 0) {
      throw new Error(res.stderr || res.stdout || 'Gagal mengaktifkan timer auto-update');
    }
  } else {
    await execCommand(
      account,
      machineId,
      'sudo systemctl disable --now boxd-fleet-autoupdate.timer >/dev/null 2>&1 || true',
      15000,
      resolvedRegion
    );
  }

  const vmConfig = dbHelper.upsertVmConfig({
    machine_id: machineId,
    account_id: account.id,
    region: resolvedRegion,
    auto_update_enabled: !!enabled,
    auto_update_interval_hours: safeHours,
    auto_update_runtimes: !!updateRuntimes
  });

  return {
    success: true,
    machineId,
    region: resolvedRegion,
    vmConfig
  };
}

/**
 * Trigger immediate Auto-Update job inside VM (non-blocking)
 */
async function runVmUpdateNow(account, machineId, { region, updateRuntimes, intervalHours, skipWake = false } = {}) {
  let resolvedRegion = region && region !== 'default' ? region : (account.home_region || 'fra');
  if (!skipWake) {
    const awake = await ensureVmAwake(account, machineId, region);
    resolvedRegion = awake.resolvedRegion;
  }

  const existingCfg = dbHelper.getVmConfig(machineId);
  const effectiveHours = intervalHours || (existingCfg && existingCfg.autoUpdateIntervalHours) || 12;
  const effectiveRuntimes = updateRuntimes !== undefined
    ? !!updateRuntimes
    : (existingCfg ? existingCfg.autoUpdateRuntimes : true);

  await ensureVmFleetBaseTools(account, machineId, resolvedRegion, {
    intervalHours: effectiveHours,
    updateRuntimes: effectiveRuntimes,
    refreshApt: false
  });

  const job = createVmJob({
    machineId,
    accountId: account.id,
    region: resolvedRegion,
    type: 'autoupdate',
    title: 'Update Paket OS & Runtime'
  });

  const triggerCmd = [
    'sudo mkdir -p /var/lib/boxd-fleet',
    'sudo rm -f /var/lib/boxd-fleet/autoupdate.status.json',
    'sudo systemctl reset-failed boxd-fleet-autoupdate.service >/dev/null 2>&1 || true',
    'sudo systemctl start --no-block boxd-fleet-autoupdate.service'
  ].join(' && ');

  const res = await execCommand(account, machineId, triggerCmd, 20000, resolvedRegion);
  if (res.exitCode !== 0) {
    job.status = 'error';
    job.phase = 'trigger_failed';
    job.error = res.stderr || res.stdout || 'Gagal memulai service auto-update';
    job.finishedAt = Date.now();
    throw new Error(job.error);
  }

  dbHelper.upsertVmConfig({
    machine_id: machineId,
    account_id: account.id,
    region: resolvedRegion,
    last_update_status: 'running',
    last_update_summary: 'Sedang memperbarui sistem...'
  });

  watchVmSystemdJob(job, account, machineId, resolvedRegion, 'autoupdate');

  return {
    success: true,
    jobId: job.id,
    job,
    region: resolvedRegion
  };
}

/**
 * Start a background provisioning job (OS upgrade + starter kits + custom apt/npm packages)
 */
async function startVmProvisionJob(account, machineId, {
  upgradeOs = false,
  starterKits = [],
  aptPackages = [],
  npmPackages = [],
  region,
  skipWake = false
} = {}) {
  let resolvedRegion = region && region !== 'default' ? region : (account.home_region || 'fra');
  if (!skipWake) {
    const awake = await ensureVmAwake(account, machineId, region);
    resolvedRegion = awake.resolvedRegion;
  }

  const allApt = [];
  const allNpm = [];
  let enableDocker = false;
  const chosenKits = [];

  for (const kitId of (Array.isArray(starterKits) ? starterKits : [])) {
    const kit = STARTER_KITS[kitId];
    if (!kit) continue;
    chosenKits.push(kitId);
    for (const p of (kit.apt || [])) {
      if (!allApt.includes(p)) allApt.push(p);
    }
    for (const p of (kit.npm || [])) {
      if (!allNpm.includes(p)) allNpm.push(p);
    }
    if (kit.enableDocker) enableDocker = true;
  }

  const customAptRes = auth.validatePackageList(aptPackages, 'apt');
  if (customAptRes.error) throw new Error(customAptRes.error);
  for (const p of customAptRes.packages) {
    if (!allApt.includes(p)) allApt.push(p);
  }

  const customNpmRes = auth.validatePackageList(npmPackages, 'npm');
  if (customNpmRes.error) throw new Error(customNpmRes.error);
  for (const p of customNpmRes.packages) {
    if (!allNpm.includes(p)) allNpm.push(p);
  }

  if (!upgradeOs && allApt.length === 0 && allNpm.length === 0 && !enableDocker) {
    throw new Error('Pilih minimal satu starter stack atau paket untuk di-install');
  }

  const existingCfg = dbHelper.getVmConfig(machineId);
  await ensureVmFleetBaseTools(account, machineId, resolvedRegion, {
    intervalHours: (existingCfg && existingCfg.autoUpdateIntervalHours) || 12,
    updateRuntimes: existingCfg ? existingCfg.autoUpdateRuntimes : true,
    refreshApt: false
  });

  const envContent = [
    `DO_APT_UPGRADE="${upgradeOs ? '1' : '0'}"`,
    `APT_PKGS="${allApt.join(' ')}"`,
    `NPM_PKGS="${allNpm.join(' ')}"`,
    `ENABLE_DOCKER="${enableDocker ? '1' : '0'}"`,
    ''
  ].join('\n');

  const envB64 = Buffer.from(envContent, 'utf8').toString('base64');
  const titleParts = [];
  if (upgradeOs) titleParts.push('Upgrade OS');
  if (chosenKits.length > 0) titleParts.push(chosenKits.map(k => STARTER_KITS[k].label).join(', '));
  if (customAptRes.packages.length > 0) titleParts.push(`APT(${customAptRes.packages.length})`);
  if (customNpmRes.packages.length > 0) titleParts.push(`NPM(${customNpmRes.packages.length})`);

  const job = createVmJob({
    machineId,
    accountId: account.id,
    region: resolvedRegion,
    type: 'provision',
    title: `Install: ${titleParts.join(' + ')}`
  });

  const cmd = [
    'sudo mkdir -p /etc/boxd-fleet /var/lib/boxd-fleet',
    `echo '${envB64}' | base64 -d | sudo tee /etc/boxd-fleet/pkg-task.env >/dev/null`,
    'sudo rm -f /var/lib/boxd-fleet/pkg.status.json',
    'sudo systemctl reset-failed boxd-fleet-pkg.service >/dev/null 2>&1 || true',
    'sudo systemctl start --no-block boxd-fleet-pkg.service'
  ].join(' && ');

  const res = await execCommand(account, machineId, cmd, 20000, resolvedRegion);
  if (res.exitCode !== 0) {
    job.status = 'error';
    job.phase = 'trigger_failed';
    job.error = res.stderr || res.stdout || 'Gagal memulai provisioning VM';
    job.finishedAt = Date.now();
    throw new Error(job.error);
  }

  if (chosenKits.length > 0) {
    const mergedKits = Array.from(new Set([...(existingCfg ? existingCfg.starterKits : []), ...chosenKits]));
    dbHelper.upsertVmConfig({
      machine_id: machineId,
      account_id: account.id,
      region: resolvedRegion,
      starter_kits: mergedKits
    });
  }

  watchVmSystemdJob(job, account, machineId, resolvedRegion, 'provision');

  return {
    success: true,
    jobId: job.id,
    job,
    region: resolvedRegion
  };
}

/**
 * Inspect complete VM readiness, auto-update, runtime settings, ports, proxies, and snapshots
 */
async function getVmManageState(account, machineId, region) {
  const client = getClient(account.api_key);
  const initialOpts = region && region !== 'default' ? { region } : undefined;
  const rawMachine = await client.machines.get(machineId, initialOpts);
  const resolvedRegion = ((rawMachine && rawMachine.region) || region || account.home_region || 'fra').toLowerCase();
  const opts = { region: resolvedRegion };

  const [portsRes, proxiesRes, snapsRes] = await Promise.allSettled([
    client.machines.ports.list(machineId, opts),
    client.machines.proxies.list(machineId, opts),
    listSnapshots(account, resolvedRegion)
  ]);

  const ports = portsRes.status === 'fulfilled' && Array.isArray(portsRes.value) ? portsRes.value : [];
  const proxies = proxiesRes.status === 'fulfilled' && Array.isArray(proxiesRes.value) ? proxiesRes.value : [];
  const snapshots = snapsRes.status === 'fulfilled' && Array.isArray(snapsRes.value) ? snapsRes.value : [];

  const sshAccess = dbHelper.getVmSshAccess(machineId);
  let vmConfig = dbHelper.getVmConfig(machineId);

  let inspection = null;
  if (rawMachine.status === 'running') {
    const inspectCmd = [
      'OS_NAME=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || uname -s)',
      'KERNEL=$(uname -r)',
      'UPTIME_P=$(uptime -p 2>/dev/null || echo "-")',
      'DISK_INFO=$(df -h / | awk "NR==2{print \\$3\\"/\\"\\$2\\" (\\"\\$5\\")\\"}")',
      'TMR_EN=$(systemctl is-enabled boxd-fleet-autoupdate.timer 2>/dev/null || echo disabled)',
      'TMR_ACT=$(systemctl is-active boxd-fleet-autoupdate.timer 2>/dev/null || echo inactive)',
      'SVC_UPD=$(systemctl is-active boxd-fleet-autoupdate.service 2>/dev/null || echo inactive)',
      'SVC_PKG=$(systemctl is-active boxd-fleet-pkg.service 2>/dev/null || echo inactive)',
      'APT_LISTS=$(ls -1 /var/lib/apt/lists/*_Packages* 2>/dev/null | wc -l)',
      'UPG_CNT=$(apt list --upgradable 2>/dev/null | grep -c "\\[upgradable" || true)',
      'NODE_BIN=$(ls -d /home/boxd/.nvm/versions/node/*/bin 2>/dev/null | sort -V | tail -n1 || true)',
      'P_SEARCH="$PATH:$NODE_BIN:/home/boxd/.bun/bin:/home/boxd/.local/bin:/usr/local/bin"',
      'TOOLS=""',
      'for t in git curl wget tmux gcc python3 pip3 node npm pm2 pnpm bun uv docker sqlite3 nginx; do PATH="$P_SEARCH" command -v "$t" >/dev/null 2>&1 && TOOLS="$TOOLS,$t"; done',
      'echo "OS=$OS_NAME"',
      'echo "KERNEL=$KERNEL"',
      'echo "UPTIME=$UPTIME_P"',
      'echo "DISK=$DISK_INFO"',
      'echo "TMR_EN=$TMR_EN"',
      'echo "TMR_ACT=$TMR_ACT"',
      'echo "SVC_UPD=$SVC_UPD"',
      'echo "SVC_PKG=$SVC_PKG"',
      'echo "APT_LISTS=$APT_LISTS"',
      'echo "UPG_CNT=$UPG_CNT"',
      'echo "TOOLS=${TOOLS#,}"',
      'if [ -f /etc/boxd-fleet/autoupdate.env ]; then echo "ENV_RUNTIMES=$(grep -E "^AUTO_UPDATE_RUNTIMES=" /etc/boxd-fleet/autoupdate.env | cut -d= -f2)"; echo "ENV_HOURS=$(grep -E "^INTERVAL_HOURS=" /etc/boxd-fleet/autoupdate.env | cut -d= -f2)"; fi',
      'if [ -f /var/lib/boxd-fleet/autoupdate.status.json ]; then echo "UPD_JSON=$(cat /var/lib/boxd-fleet/autoupdate.status.json | tr -d "\\n")"; fi',
      'if [ -f /var/lib/boxd-fleet/pkg.status.json ]; then echo "PKG_JSON=$(cat /var/lib/boxd-fleet/pkg.status.json | tr -d "\\n")"; fi'
    ].join('; ');

    try {
      const res = await execCommand(account, machineId, inspectCmd, 12000, resolvedRegion);
      if (res.exitCode === 0 && res.stdout) {
        const kv = {};
        for (const line of res.stdout.split(/\r?\n/)) {
          const idx = line.indexOf('=');
          if (idx > 0) {
            kv[line.slice(0, idx)] = line.slice(idx + 1).trim();
          }
        }
        let updStatusJson = null;
        let pkgStatusJson = null;
        try { if (kv.UPD_JSON) updStatusJson = JSON.parse(kv.UPD_JSON); } catch (e) {}
        try { if (kv.PKG_JSON) pkgStatusJson = JSON.parse(kv.PKG_JSON); } catch (e) {}

        const timerEnabled = kv.TMR_EN === 'enabled';
        const timerActive = kv.TMR_ACT === 'active';
        const envHours = parseInt(kv.ENV_HOURS || '', 10) || (vmConfig && vmConfig.autoUpdateIntervalHours) || 12;
        const envRuntimes = kv.ENV_RUNTIMES ? kv.ENV_RUNTIMES === '1' : (vmConfig ? vmConfig.autoUpdateRuntimes : true);

        inspection = {
          reachable: true,
          os: kv.OS || 'Linux',
          kernel: kv.KERNEL || '',
          uptime: kv.UPTIME || '',
          disk: kv.DISK || '',
          timerEnabled,
          timerActive,
          updateServiceActive: kv.SVC_UPD === 'active' || kv.SVC_UPD === 'activating',
          pkgServiceActive: kv.SVC_PKG === 'active' || kv.SVC_PKG === 'activating',
          aptCacheReady: parseInt(kv.APT_LISTS || '0', 10) > 0,
          upgradableCount: parseInt(kv.UPG_CNT || '0', 10) || 0,
          tools: kv.TOOLS ? kv.TOOLS.split(',').filter(Boolean) : [],
          updateStatus: updStatusJson,
          pkgStatus: pkgStatusJson
        };

        // Reconcile DB config with real live state inside VM
        const syncPatch = {
          machine_id: machineId,
          account_id: account.id,
          region: resolvedRegion,
          auto_update_enabled: timerEnabled || timerActive,
          auto_update_interval_hours: envHours,
          auto_update_runtimes: envRuntimes,
          always_on_mode: (rawMachine.idle ? rawMachine.idle.suspendAfter === 0 && rawMachine.idle.hibernateAfter === 0 : false)
        };
        if (updStatusJson && updStatusJson.status && updStatusJson.status !== 'running') {
          syncPatch.last_update_status = updStatusJson.status;
          syncPatch.last_update_at = updStatusJson.finishedAt || Date.now();
          syncPatch.last_update_summary = updStatusJson.status === 'success'
            ? `+${updStatusJson.upgradedCount || 0} paket di-upgrade (sisa ${updStatusJson.upgradableAfter || 0})`
            : (updStatusJson.error || 'Update gagal');
        }
        vmConfig = dbHelper.upsertVmConfig(syncPatch);
      }
    } catch (err) {
      inspection = { reachable: false, error: err.message };
    }
  }

  const machine = formatMachine(rawMachine, account, {
    accessible: true,
    keyScope: account.key_scope || 'unknown',
    sshAccess: sshAccess ? {
      enabled: !!sshAccess.enabled,
      sshUser: sshAccess.ssh_user || 'root',
      publicPort: sshAccess.public_port || null,
      dns: sshAccess.dns || null,
      hasPassword: !!sshAccess.password_enc,
      updatedAt: sshAccess.updated_at || null
    } : null,
    vmConfig
  });

  return {
    machine,
    vmConfig,
    inspection,
    ports,
    proxies,
    snapshots,
    starterKits: Object.values(STARTER_KITS),
    jobs: listVmJobsForMachine(machineId)
  };
}

/**
 * Update VM runtime settings (Always-On, Auto-Suspend, Auto-Hibernate, Bot Protection, Idle Outbound)
 */
async function updateVmRuntimeSettings(account, machineId, settings = {}, region) {
  const client = getClient(account.api_key);
  const initialOpts = region && region !== 'default' ? { region } : undefined;
  let machine = await client.machines.get(machineId, initialOpts);
  const resolvedRegion = ((machine && machine.region) || region || account.home_region || 'fra').toLowerCase();
  const opts = { region: resolvedRegion };

  const targetSuspend = settings.alwaysOn ? 0 : settings.autoSuspendTimeout;
  const targetHibernate = settings.alwaysOn ? 0 : settings.autoHibernateTimeout;
  const targetBot = settings.alwaysOn && settings.botProtectionMode === undefined
    ? 'off'
    : settings.botProtectionMode;
  const targetIgnoreOutbound = settings.alwaysOn && settings.idleIgnoreOutbound === undefined
    ? false
    : settings.idleIgnoreOutbound;

  if (targetSuspend !== undefined && targetSuspend !== null && targetSuspend !== '') {
    await client.machines.setAutoSuspendTimeout(machineId, parseInt(targetSuspend, 10), opts);
  }
  if (targetHibernate !== undefined && targetHibernate !== null && targetHibernate !== '') {
    await client.machines.setAutoHibernateTimeout(machineId, parseInt(targetHibernate, 10), opts);
  }
  if (targetBot !== undefined && targetBot !== null && targetBot !== '') {
    await client.machines.setBotProtection(machineId, String(targetBot), opts);
  }
  if (targetIgnoreOutbound !== undefined) {
    await client.machines.setIdleIgnoreOutbound(machineId, !!targetIgnoreOutbound, opts);
  }

  machine = await client.machines.get(machineId, opts);
  const autoSusp = machine.idle ? (machine.idle.suspendAfter || 0) : 0;
  const autoHib = machine.idle ? (machine.idle.hibernateAfter || 0) : 0;
  const vmConfig = dbHelper.upsertVmConfig({
    machine_id: machineId,
    account_id: account.id,
    region: resolvedRegion,
    always_on_mode: autoSusp === 0 && autoHib === 0
  });

  return formatMachine(machine, account, {
    accessible: true,
    keyScope: account.key_scope || 'unknown',
    vmConfig
  });
}

/**
 * Resize machine vCPU / RAM tier (1x4, 2x8, 4x16, 8x32)
 */
async function resizeVm(account, machineId, { vcpu, memory, region } = {}) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  const payload = {};
  if (vcpu) payload.vcpu = parseInt(vcpu, 10);
  if (memory) payload.memory = normalizeMemoryForSdk(memory);
  const machine = await client.machines.resize(machineId, payload, opts);
  return formatMachine(machine, account, {
    accessible: true,
    keyScope: account.key_scope || 'unknown',
    vmConfig: dbHelper.getVmConfig(machineId)
  });
}

/**
 * Expose / unexpose port forward
 */
async function exposeVmPort(account, machineId, { port, protocol = 'tcp', region } = {}) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  return await client.machines.ports.expose(machineId, parseInt(port, 10), { ...(opts || {}), protocol });
}

async function unexposeVmPort(account, machineId, { port, region } = {}) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  await client.machines.ports.unexpose(machineId, parseInt(port, 10), opts);
  return { success: true, port: parseInt(port, 10) };
}

/**
 * Set default web proxy port or create/delete named subdomain proxy
 */
async function setVmDefaultProxyPort(account, machineId, { port, region } = {}) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  const targetPort = port === 'auto' ? 'auto' : parseInt(port, 10);
  return await client.machines.proxies.setPort(machineId, targetPort, opts);
}

async function createVmNamedProxy(account, machineId, { name, port, region } = {}) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  return await client.machines.proxies.create(machineId, String(name).trim(), parseInt(port, 10), opts);
}

async function deleteVmNamedProxy(account, machineId, { name, region } = {}) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  await client.machines.proxies.delete(machineId, String(name).trim(), opts);
  return { success: true, name };
}

/**
 * List snapshots for an account across all regions
 */
async function listSnapshots(account, region = 'all') {
  const client = getClient(account.api_key);
  const snaps = await client.snapshots.list({ region });
  return snaps || [];
}

/**
 * Create a snapshot from a machine
 */
async function createSnapshot(account, machineId, name, region) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  return await client.snapshots.create(machineId, name, opts);
}

/**
 * Batch-configure Auto-Update & fresh APT cache across controllable VMs
 */
async function prepareFleetAutoUpdate(accounts, {
  runUpgrade = false,
  wakeStandby = true,
  intervalHours = 12,
  updateRuntimes = true
} = {}) {
  const accList = Array.isArray(accounts) ? accounts : [];
  const accMap = new Map(accList.map(a => [a.id, a]));
  const { machines } = await listAllMachines(accList);

  const controllable = machines.filter(m => m.accessible !== false);
  const results = [];
  let configured = 0;
  let upgradedJobs = 0;
  let skippedStopped = 0;
  let failed = 0;

  const targets = [];
  for (const vm of controllable) {
    if (vm.status === 'stopped') {
      skippedStopped++;
      results.push({ machineId: vm.id, name: vm.name, status: 'skipped_stopped' });
      continue;
    }
    if (!wakeStandby && vm.status !== 'running') {
      skippedStopped++;
      results.push({ machineId: vm.id, name: vm.name, status: 'skipped_asleep' });
      continue;
    }
    targets.push(vm);
  }

  // Process max 3 VMs in parallel to avoid overwhelming Boxd API or local limits
  const concurrency = 3;
  let idx = 0;
  async function worker() {
    while (idx < targets.length) {
      const curIdx = idx++;
      const vm = targets[curIdx];
      const account = accMap.get(vm.accountId);
      if (!account) {
        failed++;
        results.push({ machineId: vm.id, name: vm.name, status: 'error', error: 'Akun tidak ditemukan' });
        continue;
      }
      try {
        const awake = await ensureVmAwake(account, vm.id, vm.region);
        await configureVmAutoUpdate(account, vm.id, {
          enabled: true,
          intervalHours,
          updateRuntimes,
          region: awake.resolvedRegion,
          skipWake: true
        });
        configured++;
        let jobId = null;
        if (runUpgrade) {
          const runRes = await runVmUpdateNow(account, vm.id, {
            region: awake.resolvedRegion,
            intervalHours,
            updateRuntimes,
            skipWake: true
          });
          jobId = runRes.jobId;
          upgradedJobs++;
        }
        results.push({
          machineId: vm.id,
          name: vm.name,
          region: awake.resolvedRegion,
          status: 'configured',
          jobId
        });
      } catch (err) {
        failed++;
        results.push({
          machineId: vm.id,
          name: vm.name,
          status: 'error',
          error: err.message
        });
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, targets.length || 1) }, () => worker()));

  return {
    success: true,
    total: controllable.length,
    configured,
    upgradedJobs,
    skippedStopped,
    failed,
    results
  };
}

/**
 * Delete a snapshot
 */
async function deleteSnapshot(account, name, region) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  await client.snapshots.delete(name, opts);
  return { success: true, name };
}

module.exports = {
  STARTER_KITS,
  getClient,
  clearClientCache,
  detectKeyScope,
  resolveRegionFromUsageStatus,
  validateNewApiKey,
  syncAccount,
  formatMachine,
  fetchAccountFleetSnapshot,
  listMachinesForAccount,
  listAllMachines,
  getAccountTelemetry,
  machineAction,
  createMachine,
  createMachineFromSnapshot,
  deleteMachine,
  execCommand,
  getVmSshPasswordStatus,
  setupVmSshPassword,
  disableVmSshPassword,
  getVmManageState,
  configureVmAutoUpdate,
  runVmUpdateNow,
  prepareFleetAutoUpdate,
  startVmProvisionJob,
  getVmJob,
  listVmJobsForMachine,
  updateVmRuntimeSettings,
  resizeVm,
  exposeVmPort,
  unexposeVmPort,
  setVmDefaultProxyPort,
  createVmNamedProxy,
  deleteVmNamedProxy,
  suggestName,
  listSnapshots,
  createSnapshot,
  deleteSnapshot
};
