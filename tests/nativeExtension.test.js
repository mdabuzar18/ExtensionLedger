import { test } from 'node:test';
import assert from 'node:assert/strict';
import { 
  saveBaseline, 
  getBaseline, 
  clearAllAuditData, 
  recordLifecycleEvent, 
  getLifecycleEvents,
  STORAGE_KEYS
} from '../src/core/storage.js';
import { getInventory, normalizeExtension } from '../src/core/inventory.js';
import { diffSnapshots } from '../src/core/differ.js';
import { evaluateAllChanges, SEVERITY_LEVELS } from '../src/core/riskEngine.js';
import { performAuditScan } from '../service-worker.js';

test('Native Extension: Real baseline capture stores schemaVersion 1.0 and full inventory map', async () => {
  await clearAllAuditData();

  const realInventory = [
    normalizeExtension({
      id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      name: 'Privacy Shield Pro',
      version: '1.2.0',
      enabled: true,
      installType: 'normal',
      permissions: ['storage'],
      hostPermissions: []
    }),
    normalizeExtension({
      id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      name: 'Password Vault',
      version: '3.0.1',
      enabled: true,
      installType: 'normal',
      permissions: ['storage', 'unlimitedStorage'],
      hostPermissions: ['https://vault.example.com/*']
    })
  ];

  const baseline = await saveBaseline(realInventory, 'Q4 Verified Baseline');

  assert.ok(baseline.id.startsWith('snap_'));
  assert.equal(baseline.schemaVersion, '1.0');
  assert.equal(baseline.label, 'Q4 Verified Baseline');
  assert.equal(baseline.extensionCount, 2);
  assert.ok(baseline.timestamp);
  // Verify timestamp is fresh (not fake 2 weeks ago)
  const diffMs = Math.abs(Date.now() - new Date(baseline.timestamp).getTime());
  assert.ok(diffMs < 5000, 'Baseline timestamp must be current');

  const retrieved = await getBaseline();
  assert.equal(retrieved.id, baseline.id);
  assert.equal(retrieved.extensions['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'].version, '1.2.0');
  assert.equal(retrieved.extensions['bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'].websiteScope, '1 Specific Site');
});

test('Native Extension: Change detection between baseline and subsequent scan', async () => {
  await clearAllAuditData();

  const baselineInventory = [
    normalizeExtension({
      id: 'cccccccccccccccccccccccccccccccc',
      name: 'Markdown Notes',
      version: '1.0.0',
      enabled: true,
      installType: 'normal',
      permissions: ['storage'],
      hostPermissions: []
    })
  ];

  const baseline = await saveBaseline(baselineInventory, 'Clean Baseline');

  // Next scan: extension updated to 1.1.0 and added cookies permission
  const currentInventory = [
    normalizeExtension({
      id: 'cccccccccccccccccccccccccccccccc',
      name: 'Markdown Notes',
      version: '1.1.0',
      enabled: true,
      installType: 'normal',
      permissions: ['storage', 'cookies'],
      hostPermissions: ['*://*/*']
    })
  ];

  const rawChanges = diffSnapshots(baseline, currentInventory);
  const evaluated = evaluateAllChanges(rawChanges);

  assert.ok(evaluated.length > 0);
  const cookieFinding = evaluated.find(f => f.assessment.title.includes('cookies') || f.assessment.whatChanged?.includes('cookies'));
  assert.ok(cookieFinding, 'Must identify added cookies permission');
  assert.equal(cookieFinding.assessment.requiresReview, true);

  const hostFinding = evaluated.find(f => f.assessment.severity === SEVERITY_LEVELS.CRITICAL || f.assessment.severity === SEVERITY_LEVELS.HIGH);
  assert.ok(hostFinding, 'Must flag broad host access expansion');
});

test('Native Extension: Self-exclusion of ExtensionLedger from threats', async () => {
  const previousChrome = globalThis.chrome;
  const selfId = 'extensionledgerid00000000000000';

  // Mock chrome runtime with ExtensionLedger's own extension ID
  globalThis.chrome = {
    runtime: { id: selfId },
    management: {
      getAll: (cb) => {
        cb([
          {
            id: selfId,
            name: 'ExtensionLedger - Extension Security Auditor',
            version: '1.0.0',
            type: 'extension',
            installType: 'development',
            permissions: ['management', 'storage']
          },
          {
            id: 'dddddddddddddddddddddddddddddddd',
            name: 'Ad Blocker Lite',
            version: '2.0.0',
            type: 'extension',
            installType: 'normal',
            permissions: ['webRequest']
          }
        ]);
      }
    },
    storage: {
      local: {
        get: (keys, cb) => cb({}),
        set: (items, cb) => cb()
      }
    }
  };

  try {
    // 1. By default, getInventory excludes ExtensionLedger itself
    const defaultList = await getInventory();
    assert.equal(defaultList.length, 1);
    assert.equal(defaultList[0].id, 'dddddddddddddddddddddddddddddddd');
    assert.ok(!defaultList.some(e => e.id === selfId), 'Auditing extension must be excluded by default');

    // 2. If caller requests with excludeSelf: false, ExtensionLedger is labeled as auditing extension
    const fullList = await getInventory({ excludeSelf: false });
    assert.equal(fullList.length, 2);
    const selfRecord = fullList.find(e => e.id === selfId);
    assert.ok(selfRecord.isSelf, 'isSelf must be true');
    assert.equal(selfRecord.publisher, 'ExtensionLedger (Auditing Extension)');
  } finally {
    globalThis.chrome = previousChrome;
  }
});

test('Native Extension: Empty inventory is handled truthfully without synthetic fallback', async () => {
  const previousChrome = globalThis.chrome;

  globalThis.chrome = {
    management: {
      getAll: (cb) => cb([])
    },
    storage: {
      local: {
        get: (keys, cb) => cb({}),
        set: (items, cb) => cb()
      }
    }
  };

  try {
    const inv = await getInventory();
    assert.deepEqual(inv, []);
    assert.equal(inv.length, 0, 'Empty browser profile must return empty array, never mock records');
  } finally {
    globalThis.chrome = previousChrome;
  }
});

test('Native Extension: Real lifecycle events are recorded in persistent storage', async () => {
  await clearAllAuditData();

  await recordLifecycleEvent({
    type: 'INSTALLED',
    extensionId: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    extensionName: 'Secure Shell Client',
    version: '1.0.0'
  });

  await recordLifecycleEvent({
    type: 'ENABLED',
    extensionId: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    extensionName: 'Secure Shell Client'
  });

  const events = await getLifecycleEvents();
  assert.equal(events.length, 2);
  assert.equal(events[0].type, 'ENABLED', 'Most recent event must be first');
  assert.equal(events[1].type, 'INSTALLED');
  assert.equal(events[0].extensionId, 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
  assert.ok(events[0].timestamp);
});

test('Native Extension: Background service worker scan does not auto-capture baseline when none exists', async () => {
  await clearAllAuditData();

  const result = await performAuditScan();
  assert.equal(result.baselineCreated, false);
  assert.equal(result.unreviewedCount, 0);

  const baseline = await getBaseline();
  assert.equal(baseline, null, 'Background worker must not silently create baseline without user action');
});
