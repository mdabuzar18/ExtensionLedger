/**
 * ExtensionLedger - Host-Permission Classification & Dual-Assessment Regression Tests
 * 
 * Verifies the 8 core security logic scenarios mandated by the specification:
 * 1. An extension with restricted website access.
 * 2. An extension declaring <all_urls> without other suspicious evidence.
 * 3. An extension with broad host access and sensitive API permissions.
 * 4. An extension with an actual permission expansion.
 * 5. A harmless version update.
 * 6. A package with a newly introduced data-transmission path.
 * 7. Missing baseline data.
 * 8. Unsupported or unavailable metadata.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.resolve(__dirname, '..', 'test-fixtures');
import { normalizeExtension, categorizePermissions } from '../src/core/inventory.js';
import { 
  evaluateExposure, 
  evaluateSuspicion, 
  evaluateExtensionAssessment, 
  evaluateExtensionRisk, 
  evaluateChangeRisk,
  EXPOSURE_LEVELS, 
  SUSPICION_LEVELS, 
  SEVERITY_LEVELS 
} from '../src/core/riskEngine.js';
import { diffSnapshots, diffExtension, CHANGE_TYPES } from '../src/core/differ.js';
import { comparePackages } from '../src/core/packageAnalyzer.js';
import { SYNTHETIC_SCENARIOS, base64ToUint8Array } from '../src/core/syntheticData.js';

test('Scenario 1: Extension with restricted website access', () => {
  const ext = normalizeExtension({
    id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    name: 'GitHub PR Notifier',
    version: '1.2.0',
    installType: 'normal',
    permissions: ['storage', 'notifications'],
    hostPermissions: ['https://api.github.com/*']
  });

  assert.equal(ext.hasBroadHost, false);
  assert.equal(ext.websiteScope, '1 Specific Site');
  assert.deepEqual(ext.apiPermissions, ['notifications', 'storage']);
  assert.deepEqual(ext.hostPermissions, ['https://api.github.com/*']);

  const assessment = evaluateExtensionAssessment(ext);

  // Exposure must be Limited (scoped only to specific domain, standard utility APIs)
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.LIMITED);
  assert.equal(assessment.exposure.hasBroadHost, false);
  assert.ok(assessment.exposure.summary.includes('Limited blast radius'));

  // Suspicion must be "No indicators observed" (never claim "safe", but no anomalies)
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.ok(assessment.suspicion.summary.includes('No anomalies'));
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.HIGH);
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.CRITICAL);
});

test('Scenario 2: Extension declaring <all_urls> without other suspicious evidence', () => {
  // Common pattern: Web Page Theme Styler or Reader mode declaring <all_urls> with only storage
  const ext = normalizeExtension({
    id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    name: 'Dark Reader Minimal',
    version: '3.0.0',
    installType: 'normal',
    permissions: ['storage', 'alarms'],
    hostPermissions: ['<all_urls>']
  });

  assert.equal(ext.hasBroadHost, true);
  assert.equal(ext.websiteScope, 'All Websites');
  assert.deepEqual(ext.apiPermissions, ['alarms', 'storage']);
  assert.deepEqual(ext.hostPermissions, ['<all_urls>']);

  const assessment = evaluateExtensionAssessment(ext);

  // Broad host alone -> Exposure is Broad (NOT Extensive, NOT Limited)
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.BROAD);
  assert.equal(assessment.exposure.hasBroadHost, true);
  assert.ok(assessment.exposure.blastRadius.includes('Universal website scope declared'));

  // <all_urls> alone must NOT classify as suspicious or critical/malicious
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.equal(assessment.severity, SEVERITY_LEVELS.MEDIUM, '<all_urls> alone is a MEDIUM risk indicator');
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.CRITICAL, '<all_urls> alone must not trigger CRITICAL');
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.HIGH, '<all_urls> alone without sensitive APIs must not trigger HIGH');
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.BROAD);
  assert.ok(assessment.exposure.score >= 30, 'Exposure score reflects technical capability');
});

test('Scenario 3: Extension with broad host access and sensitive API permissions (Photoshop profile)', () => {
  // Case Study: Adobe Photoshop / Desktop Companion extension
  const ext = normalizeExtension({
    id: 'cccccccccccccccccccccccccccccccc',
    name: 'Adobe Photoshop Extension Companion',
    version: '2.5.1',
    installType: 'normal',
    permissions: ['nativeMessaging', 'storage', 'contextMenus', 'tabs', 'unlimitedStorage'],
    hostPermissions: ['<all_urls>']
  });

  assert.equal(ext.hasBroadHost, true);
  assert.equal(ext.websiteScope, 'All Websites');
  assert.ok(ext.apiPermissions.includes('nativeMessaging'));
  assert.ok(ext.hostPermissions.includes('<all_urls>'));

  const assessment = evaluateExtensionAssessment(ext);

  // High capability + broad host -> Exposure is Extensive
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.EXTENSIVE);
  assert.ok(assessment.exposure.criticalApis.includes('nativeMessaging'));
  assert.ok(assessment.exposure.summary.includes('Extensive blast radius'));
  assert.ok(assessment.exposure.blastRadius.includes('Universal website access combined with privileged execution'));

  // In absence of baseline drift or malicious behavior, suspicion remains "No indicators observed"
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.equal(assessment.suspicion.unreviewedChangesCount, 0);
  assert.ok(assessment.suspicion.evidence.some(e => e.includes('Matches verified baseline snapshot')));
});

test('Scenario 4: Extension with an actual permission expansion relative to baseline', () => {
  const before = normalizeExtension({
    id: 'dddddddddddddddddddddddddddddddd',
    name: 'Weather Forecast',
    version: '1.0.0',
    permissions: ['storage'],
    hostPermissions: ['https://api.weather.com/*']
  });

  const after = normalizeExtension({
    id: 'dddddddddddddddddddddddddddddddd',
    name: 'Weather Forecast',
    version: '2.0.0',
    permissions: ['storage', 'cookies'],
    hostPermissions: ['https://api.weather.com/*', '<all_urls>']
  });

  const changes = diffExtension(before, after);
  assert.ok(changes.length >= 2, 'Must detect both API expansion and host expansion');

  const hostChange = changes.find(c => c.type === CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED);
  assert.ok(hostChange);
  assert.deepEqual(hostChange.details.added, ['<all_urls>']);
  assert.deepEqual(hostChange.details.before, ['https://api.weather.com/*']);
  assert.deepEqual(hostChange.details.after, ['<all_urls>', 'https://api.weather.com/*']);

  const apiChange = changes.find(c => c.type === CHANGE_TYPES.PERMISSIONS_EXPANDED);
  assert.ok(apiChange);
  assert.deepEqual(apiChange.details.added, ['cookies']);
  assert.deepEqual(apiChange.details.before, ['storage']);
  assert.deepEqual(apiChange.details.after, ['cookies', 'storage']);

  // Evaluate change risks
  const hostRisk = evaluateChangeRisk(hostChange);
  assert.equal(hostRisk.severity, SEVERITY_LEVELS.HIGH, 'Broad host expansion triggers HIGH investigation warning, not CRITICAL');
  assert.equal(hostRisk.requiresReview, true);
  assert.equal(hostRisk.exposureImpact, EXPOSURE_LEVELS.BROAD);
  assert.equal(hostRisk.suspicionImpact, SUSPICION_LEVELS.REVIEW_REQUIRED);
  assert.ok(hostRisk.evidence.some(e => e.includes('Baseline host permissions: https://api.weather.com/*')));
  assert.ok(hostRisk.evidence.some(e => e.includes('Newly added hosts: <all_urls>')));
  assert.ok(hostRisk.evidence.some(e => e.includes('Current host permissions: <all_urls>, https://api.weather.com/*')));

  // Extension Suspicion Level with unreviewed changes must be "Review required"
  const assessment = evaluateExtensionAssessment(after, [hostChange, apiChange]);
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.EXTENSIVE);
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.REVIEW_REQUIRED);
  assert.equal(assessment.suspicion.unreviewedChangesCount, 2);
  assert.equal(assessment.severity, SEVERITY_LEVELS.HIGH, 'Unreviewed broad host expansion elevates overall severity to HIGH');
  assert.notEqual(assessment.severity, SEVERITY_LEVELS.CRITICAL, 'Permission expansion alone without critical APIs must not trigger CRITICAL');
  assert.ok(assessment.suspicion.summary.includes('unreviewed baseline drift event(s) detected'));
});

test('Scenario 5: Harmless version update does not increase severity', () => {
  const before = normalizeExtension({
    id: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    name: 'Code Formatter',
    version: '1.4.0',
    permissions: ['storage', 'activeTab'],
    hostPermissions: []
  });

  const after = normalizeExtension({
    id: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    name: 'Code Formatter',
    version: '1.4.1',
    permissions: ['storage', 'activeTab'],
    hostPermissions: []
  });

  const changes = diffExtension(before, after);
  assert.equal(changes.length, 1);
  assert.equal(changes[0].type, CHANGE_TYPES.VERSION_CHANGED);
  assert.equal(changes[0].direction, 'upgrade');

  const risk = evaluateChangeRisk(changes[0]);
  assert.equal(risk.severity, SEVERITY_LEVELS.LOW);
  assert.equal(risk.requiresReview, false);
  assert.ok(risk.whyItMatters.includes('Routine software update'));

  const assessment = evaluateExtensionAssessment(after, changes);
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.LIMITED);
});

test('Scenario 6: Package with newly introduced data-transmission path increases suspicion', async () => {
  const [bytes1, bytes2] = await Promise.all([
    fs.readFile(path.join(FIXTURES_DIR, 'stealth-code-v1.zip')),
    fs.readFile(path.join(FIXTURES_DIR, 'stealth-code-v2.zip'))
  ]);

  const diffReport = await comparePackages(bytes1, bytes2, 'tool-v1.zip', 'tool-v2.zip');
  assert.ok(diffReport.newDiscoveredEndpoints.length > 0, 'Must detect new outbound endpoint');
  assert.ok(diffReport.newInvestigationLeads.length > 0, 'Must generate investigation leads');

  const ext = normalizeExtension({
    id: 'ffffffffffffffffffffffffffffffff',
    name: 'Exfiltrating Utility',
    version: '2.0.0',
    permissions: ['storage'],
    hostPermissions: []
  });

  // Evaluate with package analysis evidence attached
  const assessment = evaluateExtensionAssessment(ext, [], {}, { packageReport: diffReport });
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.SUSPICIOUS);
  assert.ok(assessment.suspicion.evidence.some(e => e.includes('Package Audit:')));
  assert.ok(assessment.suspicion.summary.includes('Concrete suspicious indicators detected'));
});

test('Scenario 7: Missing baseline data handled gracefully without false alarms', () => {
  // User opens ExtensionLedger for the first time without having saved a baseline
  const inventory = [
    normalizeExtension({
      id: '11111111111111111111111111111111',
      name: 'Ad Blocker Ultra',
      version: '4.5.0',
      permissions: ['webRequest', 'storage'],
      hostPermissions: ['<all_urls>']
    })
  ];

  // diffSnapshots with null baseline returns empty array (no false addition panic)
  const changes = diffSnapshots(null, inventory);
  assert.deepEqual(changes, []);

  // Extension evaluates cleanly
  const assessment = evaluateExtensionAssessment(inventory[0], changes);
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.EXTENSIVE);
  // Without baseline, missing data is NOT treated as evidence of malicious behavior
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.ok(assessment.suspicion.evidence.some(e => e.includes('Matches verified baseline snapshot') || e.includes('no unexpected updates')));
});

test('Scenario 8: Unsupported or unavailable metadata handled safely', () => {
  // Malformed raw input with missing arrays, nulls, undefined fields
  const malformedRaw = {
    id: '22222222222222222222222222222222',
    name: '',
    version: null,
    permissions: null,
    hostPermissions: undefined,
    icons: null
  };

  const ext = normalizeExtension(malformedRaw);
  assert.equal(ext.name, 'Unnamed Extension');
  assert.equal(ext.version, '0.0.0');
  assert.deepEqual(ext.apiPermissions, []);
  assert.deepEqual(ext.hostPermissions, []);
  assert.equal(ext.hasBroadHost, false);
  assert.equal(ext.websiteScope, 'None');

  const assessment = evaluateExtensionAssessment(ext);
  assert.equal(assessment.exposure.level, EXPOSURE_LEVELS.LIMITED);
  assert.equal(assessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.equal(assessment.severity, SEVERITY_LEVELS.LOW);
});
