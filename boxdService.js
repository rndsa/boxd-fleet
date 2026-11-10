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
    autoSuspendTimeout: machine.idle ? (machine.idle.suspendAfter || 0) : (machine.autoSuspendTimeout || 0),
    autoHibernateTimeout: machine.idle ? (machine.idle.hibernateAfter || 0) : (machine.autoHibernateTimeout || 0),
    runningSeconds: extras.runningSeconds || 0,
    costMicro: extras.costMicro || 0,
    cost: extras.cost || 0,
    ownerName: machine.createdByName || extras.ownerName || null,
    accountId: account.id,
    accountLabel: account.label,
    accountOrg: account.org_name || 'Personal',
    accountOrgSlug: account.org_slug || null,
    accountKeyScope: extras.keyScope || account.key_scope || 'unknown'
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

  for (const lm of rawLiveMachines) {
    const um = usageById.get(lm.id);
    const formatted = formatMachine(lm, updatedAccount, {
      accessible: true,
      keyScope,
      rawUsageStatus: um ? um.status : lm.status,
      runningSeconds: um && um.seconds ? (um.seconds.running || 0) : 0,
      costMicro: um ? (um.costMicro || 0) : 0,
      cost: um ? (um.costMicro || 0) / 1e6 : 0
    });
    liveById.set(lm.id, formatted);
    reconciledMachines.push(formatted);
  }

  // Reconcile non-deleted private VMs reported by orgs.usage() that are hidden from org-scoped API keys
  const normalizedUsageMachines = [];
  if (rawUsage && Array.isArray(rawUsage.machines)) {
    for (const um of rawUsage.machines) {
      const liveMatch = liveById.get(um.machineId);
      const resolved = resolveRegionFromUsageStatus(um.status, homeRegion);
      const effectiveRegion = (liveMatch && liveMatch.region) || resolved.region || homeRegion || 'fra';
      const memBytes = um.resources ? (um.resources.memoryBytes || 0) : 0;
      const memGb = memBytes ? Math.round(memBytes / (1024 * 1024 * 1024)) : 0;
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
        const domain = effectiveRegion ? `${effectiveRegion}.boxd.sh` : 'boxd.sh';
        reconciledMachines.push({
          id: um.machineId,
          name: um.name,
          status: resolved.normalizedStatus === 'remote' ? 'remote' : resolved.normalizedStatus,
          rawUsageStatus: um.status,
          region: effectiveRegion,
          shared: !!um.shared,
          accessible: false,
          accessReason: keyScope === 'org' && !um.shared ? 'org_scoped_private' : 'unreachable',
          resources: {
            vcpu: um.resources ? (um.resources.vcpu || 1) : 1,
            memoryBytes: memBytes,
            memoryGb: memGb,
            memoryHuman: memGb ? `${memGb} GB` : '4 GB',
            diskBytes: um.resources ? (um.resources.diskBytes || 0) : 0
          },
          access: {
            url: `https://${um.name}.${domain}`,
            sshPort: null,
            domain,
            desktopUrl: ''
          },
          createdAt: null,
          autoSuspendTimeout: 0,
          autoHibernateTimeout: 0,
          runningSeconds: runSec,
          costMicro,
          cost,
          ownerName: um.ownerName || null,
          accountId: updatedAccount.id,
          accountLabel: updatedAccount.label,
          accountOrg: updatedAccount.org_name || 'Personal',
          accountOrgSlug: updatedAccount.org_slug || null,
          accountKeyScope: keyScope
        });
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

  // Sort: controllable first, then running, then remote/hibernated, then name
  const statusRank = { running: 0, suspended: 1, paused: 1, hibernated: 2, remote: 3, stopped: 4 };
  reconciledMachines.sort((a, b) => {
    if (a.accessible !== b.accessible) return a.accessible ? -1 : 1;
    const ra = statusRank[a.status] ?? 5;
    const rb = statusRank[b.status] ?? 5;
    if (ra !== rb) return ra - rb;
    return String(a.name).localeCompare(String(b.name));
  });

  const balanceMicro = billing && billing.balanceMicro !== undefined
    ? billing.balanceMicro
    : (updatedAccount.balance_micro || 0);
  const controllableCount = reconciledMachines.filter(m => m.accessible).length;
  const privateLockedCount = reconciledMachines.filter(m => !m.accessible).length;

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
  if (params.autoSuspendTimeout !== undefined) config.autoSuspendTimeout = parseInt(params.autoSuspendTimeout, 10);
  if (params.autoHibernateTimeout !== undefined) config.autoHibernateTimeout = parseInt(params.autoHibernateTimeout, 10);

  if (Object.keys(config).length > 0) {
    createPayload.config = config;
  }

  const machine = await client.machines.create(createPayload);
  return formatMachine(machine, account, { accessible: true, keyScope });
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
 * Delete a snapshot
 */
async function deleteSnapshot(account, name, region) {
  const client = getClient(account.api_key);
  const opts = region && region !== 'default' ? { region } : undefined;
  await client.snapshots.delete(name, opts);
  return { success: true, name };
}

module.exports = {
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
  deleteMachine,
  execCommand,
  suggestName,
  listSnapshots,
  createSnapshot,
  deleteSnapshot
};
