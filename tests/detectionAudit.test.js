/**
 * ExtensionLedger - Comprehensive Detection Engine Audit Test Suite
 * 
 * Verifies correctness, absence of false positives, and accuracy across:
 * Test A: Harmless extension installation.
 * Test B: Extension requesting broad website access.
 * Test C: Update introducing suspicious outbound data transmission without permission change.
 * Test D: Harmless code update.
 * Test E: New permission genuinely introduced in an update.
 * Test F: Synthetic metadata containing an invalid Chrome extension ID.
 * Test G: Manifest V3 package declaring webRequestBlocking.
 * Test H: Missing baseline data.
 * Test I: Browser API error or unsupported browser context.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';

import { 
  normalizeExtension, 
  validateExtensionId, 
  categorizePermissions,
  INSTALL_TYPES 
} from '../src/core/inventory.js';
import { 
  diffSnapshots, 
  diffExtension, 
  CHANGE_TYPES 
} from '../src/core/differ.js';
import { 
  evaluateChangeRisk, 
  evaluateExtensionRisk, 
  SEVERITY_LEVELS 
} from '../src/core/riskEngine.js';
import { 
  analyzeSinglePackage, 
  comparePackages, 
  scanCodeForPatterns,
  PATTERN_CATEGORIES 
} from '../src/core/packageAnalyzer.js';
import { 
  detectRuntimeContext, 
  getAllExtensions, 
  RUNTIME_CONTEXTS 
} from '../src/core/browserApi.js';

const FIXTURES_DIR = path.resolve('test-fixtures');

// ---------------------------------------------------------------------------
// TEST A: Harmless Extension Installation
// ---------------------------------------------------------------------------
test('Test A: Harmless extension installation (low severity, no false positive high alarm)', () => {
  // Scenario: User installs a standard notes/calc utility declaring only 'storage'
  const baseline = [];
  const current = [
    normalizeExtension({
      id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', // valid 32-char store format
      name: 'Clean Calculator',
      version: '1.0.0',
      installType: 'normal',
      permissions: ['storage']
    })
  ];

  // Action
  const changes = diffSnapshots(baseline, current);
  assert.equal(changes.length, 1);
  const change = changes[0];
  assert.equal(change.type, CHANGE_TYPES.EXTENSION_ADDED);

  const assessment = evaluateChangeRisk(change);

  // Expected vs Actual
  // Expected: Severity LOW, requiresReview = false, title = 'Standard Extension Installed'
  assert.equal(assessment.severity, SEVERITY_LEVELS.LOW, `Expected LOW severity, got ${assessment.severity}`);
  assert.equal(assessment.requiresReview, false, 'Expected requiresReview to be false for harmless install');
  assert.equal(assessment.title, 'Standard Extension Installed');

  // False positive assertions:
  // Must NOT be classified as HIGH or CRITICAL
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.HIGH, 'FALSE POSITIVE: Harmless store install was labeled HIGH');
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.CRITICAL, 'FALSE POSITIVE: Harmless store install was labeled CRITICAL');
  // Must NOT mention malware or suspicious claims
  const text = JSON.stringify(assessment).toLowerCase();
  assert.ok(!text.includes('malicious'), 'FALSE POSITIVE: Unwarranted malicious term in assessment');
});

// ---------------------------------------------------------------------------
// TEST B: Extension Requesting Broad Website Access
// ---------------------------------------------------------------------------
test('Test B: Extension requesting broad website access (MEDIUM risk indicator, not proof of malice)', () => {
  // Scenario: Extension requests <all_urls> or *://*/* from official store
  const extension = normalizeExtension({
    id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    name: 'Web Page Styler Pro',
    version: '2.0.0',
    installType: 'normal',
    permissions: ['storage'],
    hostPermissions: ['*://*/*']
  });

  const change = {
    type: CHANGE_TYPES.EXTENSION_ADDED,
    extensionId: extension.id,
    extensionName: extension.name,
    extensionVersion: extension.version,
    details: {
      version: extension.version,
      permissions: extension.allPermissions,
      websiteScope: extension.websiteScope,
      installType: extension.installType
    }
  };

  const assessment = evaluateChangeRisk(change);

  // Expected vs Actual
  // Expected: Severity MEDIUM, requiresReview = true
  assert.equal(assessment.severity, SEVERITY_LEVELS.MEDIUM, `Expected MEDIUM severity, got ${assessment.severity}`);
  assert.equal(assessment.requiresReview, true, 'Expected requiresReview to be true for broad host access');

  // Explainability & False Positive Verification:
  // The reasoning MUST clarify that broad access is an architectural risk indicator, NOT proof of malice.
  assert.ok(
    assessment.whyItMatters.includes('risk indicator') || assessment.whyItMatters.includes('attack surface'),
    'Expected whyItMatters to state broad access is a risk indicator and increases attack surface'
  );
  assert.ok(
    assessment.whyItMatters.includes('not proof of malicious behavior') || !assessment.whyItMatters.includes('malicious'),
    'FALSE POSITIVE: Broad access was falsely claimed to be proof of malice'
  );
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.HIGH, 'FALSE POSITIVE: Store extension with broad access prematurely marked HIGH');
});

// ---------------------------------------------------------------------------
// TEST C: Update Introducing Suspicious Outbound Data Path Without Changing Permissions
// ---------------------------------------------------------------------------
test('Test C: Update introducing suspicious outbound data-transmission path without changing permissions', async () => {
  // Scenario: stealth-code-v1 vs stealth-code-v2 (permissions stay ['storage', 'tabs'], but v2 adds eval + remote endpoint)
  const [bytes1, bytes2] = await Promise.all([
    fs.readFile(path.join(FIXTURES_DIR, 'stealth-code-v1.zip')),
    fs.readFile(path.join(FIXTURES_DIR, 'stealth-code-v2.zip'))
  ]);

  const report = await comparePackages(bytes1, bytes2, 'stealth-v1.zip', 'stealth-v2.zip');

  // Expected vs Actual
  // 1. Permissions must be confirmed UNCHANGED (0 added permissions)
  assert.deepEqual(report.addedPermissions, [], 'Expected permissions to be completely unchanged between v1 and v2');

  // 2. Outbound endpoint & code leads must be detected in package delta
  assert.ok(report.newDiscoveredEndpoints.length > 0, 'Expected new outbound endpoint to be detected');
  assert.ok(
    report.newDiscoveredEndpoints.some(ep => ep.includes('telemetry-analytics-collector-gateway.com')),
    'Expected telemetry endpoint destination to be identified'
  );

  const evalLead = report.newInvestigationLeads.find(l => l.category === PATTERN_CATEGORIES.DYNAMIC_EXECUTION);
  assert.ok(evalLead, 'Expected Dynamic Code Execution lead for eval construct');
  assert.equal(report.overallSeverity, 'HIGH', 'Expected overall severity HIGH due to newly introduced dynamic execution');

  // False positive assertion:
  // Must NOT accuse extension of permission expansion when permissions are unchanged
  assert.equal(report.addedPermissions.length, 0, 'FALSE POSITIVE: Reported phantom permission expansion on unchanged manifest');
});

// ---------------------------------------------------------------------------
// TEST D: Harmless Code Update
// ---------------------------------------------------------------------------
test('Test D: Harmless code update (zero high-risk leads, benign version bump)', async () => {
  // Scenario: benign-v1 vs benign-v2 (bug fix update, zero sensitive patterns)
  const [bytes1, bytes2] = await Promise.all([
    fs.readFile(path.join(FIXTURES_DIR, 'benign-v1.zip')),
    fs.readFile(path.join(FIXTURES_DIR, 'benign-v2.zip'))
  ]);

  const report = await comparePackages(bytes1, bytes2, 'benign-v1.zip', 'benign-v2.zip');

  // Expected vs Actual
  assert.deepEqual(report.addedPermissions, []);
  assert.equal(report.newInvestigationLeads.length, 0, 'Expected 0 new investigation leads in benign bugfix update');
  assert.equal(report.newDiscoveredEndpoints.length, 0, 'Expected 0 new endpoints in benign update');

  // False positive assertion:
  // Must NOT flag high or critical severity on routine bug fix
  assert.notEqual(report.overallSeverity, 'HIGH', 'FALSE POSITIVE: Benign code update was flagged as HIGH severity');
  assert.notEqual(report.overallSeverity, 'CRITICAL', 'FALSE POSITIVE: Benign code update was flagged as CRITICAL severity');
});

// ---------------------------------------------------------------------------
// TEST E: New Permission Genuinely Introduced in an Update
// ---------------------------------------------------------------------------
test('Test E: New permission genuinely introduced in an update (exact delta, no phantom additions)', () => {
  // Scenario: Baseline has ['storage']. v1.1.0 genuinely introduces ['cookies'].
  const before = {
    id: 'cccccccccccccccccccccccccccccccc',
    name: 'Session Saver',
    version: '1.0.0',
    enabled: true,
    installType: 'normal',
    apiPermissions: ['storage'],
    hostPermissions: [],
    websiteScope: 'None'
  };

  const after = {
    id: 'cccccccccccccccccccccccccccccccc',
    name: 'Session Saver',
    version: '1.1.0',
    enabled: true,
    installType: 'normal',
    apiPermissions: ['storage', 'cookies'],
    hostPermissions: [],
    websiteScope: 'None'
  };

  const changes = diffExtension(before, after);
  const permChange = changes.find(c => c.type === CHANGE_TYPES.PERMISSIONS_EXPANDED);

  assert.ok(permChange, 'Expected PERMISSIONS_EXPANDED event');
  // Exact delta assertion:
  assert.deepEqual(permChange.details.added, ['cookies'], 'Expected only "cookies" to be in added list');
  // False positive assertion:
  assert.ok(!permChange.details.added.includes('storage'), 'FALSE POSITIVE: Pre-existing "storage" permission marked as newly added');
});

// ---------------------------------------------------------------------------
// TEST F: Synthetic Metadata Containing an Invalid Chrome Extension ID
// ---------------------------------------------------------------------------
test('Test F: Synthetic metadata containing an invalid Chrome extension ID', () => {
  // Official store format: 32 chars [a-p]
  const validStoreId = 'abcdefghijklmnopabcdefghijklmnop';
  const val1 = validateExtensionId(validStoreId);
  assert.equal(val1.isValidFormat, true);
  assert.equal(val1.isStoreFormat, true);
  assert.equal(val1.type, 'store_verified_format');

  // Synthetic / test fixture format (e.g. 'ext_weather_widget_02')
  const syntheticId = 'ext_weather_widget_02';
  const val2 = validateExtensionId(syntheticId);
  assert.equal(val2.isValidFormat, true);
  assert.equal(val2.isStoreFormat, false, 'FALSE POSITIVE: Synthetic fixture ID was verified as official store format');
  assert.equal(val2.type, 'custom_or_synthetic');

  // Illegal / malformed ID (illegal characters or bad length)
  const malformedId = 'not-a-valid-id-$$$';
  const val3 = validateExtensionId(malformedId);
  assert.equal(val3.isValidFormat, false);
  assert.equal(val3.isStoreFormat, false);
  assert.equal(val3.type, 'malformed');

  // Empty ID
  const val4 = validateExtensionId('');
  assert.equal(val4.isValidFormat, false);
});

// ---------------------------------------------------------------------------
// TEST G: Manifest V3 Package That Declares webRequestBlocking
// ---------------------------------------------------------------------------
test('Test G: Manifest V3 package declaring webRequestBlocking triggers MV3 restricted rule', async () => {
  // Scenario: MV3 package declaring 'webRequestBlocking' (restricted in Chrome Web Store MV3)
  const zipBytes = await fs.readFile(path.join(FIXTURES_DIR, 'mv3-webrequestblocking.zip'));
  const report = await analyzeSinglePackage(zipBytes, 'mv3-webrequestblocking.zip');

  assert.equal(report.manifestVersion, 3);
  assert.ok(report.permissions.includes('webRequestBlocking'));

  // Lead check:
  const mv3Lead = report.investigationLeads.find(l => l.category === 'Manifest V3 Compatibility');
  assert.ok(mv3Lead, 'Expected Manifest V3 Compatibility lead for webRequestBlocking');
  assert.equal(mv3Lead.severity, 'HIGH');
  assert.ok(
    mv3Lead.description.includes('enterprise-policy') || mv3Lead.description.includes('declarativeNetRequest'),
    'Expected lead to mention enterprise policy restriction and declarativeNetRequest migration'
  );

  // False positive check:
  // Must NOT treat MV3 webRequestBlocking as a valid unflagged store permission
  const normalExt = normalizeExtension({
    id: 'dddddddddddddddddddddddddddddddd',
    name: 'Blocking AdBlock',
    version: '1.0.0',
    installType: INSTALL_TYPES.NORMAL,
    permissions: ['webRequestBlocking']
  });
  assert.ok(normalExt.incompatibilities.some(i => i.rule === 'MV3_RESTRICTED_PERMISSION'));
});

// ---------------------------------------------------------------------------
// TEST H: Missing Baseline Data
// ---------------------------------------------------------------------------
test('Test H: Missing baseline data does not cause false-positive addition avalanche', () => {
  const currentInventory = [
    normalizeExtension({ id: 'ext1', name: 'App 1', version: '1.0.0' }),
    normalizeExtension({ id: 'ext2', name: 'App 2', version: '2.0.0' })
  ];

  // When baseline is null or undefined (e.g. fresh installation or uninitialized storage)
  const changesNull = diffSnapshots(null, currentInventory);
  assert.deepEqual(changesNull, [], 'Expected empty diff when baseline is null');

  const changesUndefined = diffSnapshots(undefined, currentInventory);
  assert.deepEqual(changesUndefined, [], 'Expected empty diff when baseline is undefined');

  // False positive assertion:
  // Must NOT report every installed extension as a newly added drift event when baseline is missing
  assert.equal(changesNull.length, 0, 'FALSE POSITIVE: Existing extensions reported as additions on missing baseline');
});

// ---------------------------------------------------------------------------
// TEST I: Browser API Error or Unsupported Browser Context
// ---------------------------------------------------------------------------
test('Test I: Browser API error or unsupported browser context falls back safely', async () => {
  // Scenario: Running in Node.js or Safari without chrome.management
  const context = detectRuntimeContext();

  assert.equal(context, RUNTIME_CONTEXTS.WEB_STANDALONE);
  assert.equal(typeof chrome === 'undefined' || !chrome.management, true);

  // Calling getAllExtensions() in unsupported context must NOT throw unhandled exceptions
  const extensions = await getAllExtensions();
  assert.ok(Array.isArray(extensions), 'Expected array return from getAllExtensions in standalone mode');
  assert.equal(extensions.length, 0, 'Expected 0 live extensions in mock/standalone mode without synthetic flag');

  // False positive assertion:
  // Must NOT fabricate fake installed extensions and claim they are real browser scans
  for (const ext of extensions) {
    assert.ok(ext.isSynthetic !== false, 'FALSE POSITIVE: Live scan claimed in unsupported browser context');
  }
});
