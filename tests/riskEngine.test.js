import { test } from 'node:test';
import assert from 'node:assert/strict';
import { 
  evaluateChangeRisk, 
  evaluateExtensionRisk, 
  evaluateExtensionAssessment,
  SEVERITY_LEVELS,
  EXPOSURE_LEVELS,
  SUSPICION_LEVELS,
  CRITICAL_EVIDENCE_RULES
} from '../src/core/riskEngine.js';
import { CHANGE_TYPES } from '../src/core/differ.js';

test('risk engine never outputs arbitrary malicious labels', () => {
  const permChange = {
    type: CHANGE_TYPES.PERMISSIONS_EXPANDED,
    extensionId: 'unknown_ext',
    extensionName: 'Any Extension',
    details: { added: ['cookies', 'webRequest'] },
    changeKey: 'test_key_01'
  };

  const assessment = evaluateChangeRisk(permChange);

  // Must contain evidence, reasoning, recommendations
  assert.ok(assessment.severity);
  assert.ok(Array.isArray(assessment.evidence));
  assert.ok(typeof assessment.reasoning === 'string');
  assert.ok(Array.isArray(assessment.recommendations));
  assert.ok(assessment.recommendations.length > 0);

  // Must NOT accuse as "malicious malware" directly
  const textBlob = `${assessment.title} ${assessment.reasoning} ${assessment.recommendations.join(' ')}`.toLowerCase();
  assert.equal(textBlob.includes('is malicious malware'), false);
});

test('broad host permission expansion triggers HIGH investigation warning without labeling malice', () => {
  const change = {
    type: CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED,
    extensionId: 'weather_01',
    extensionName: 'Weather Widget',
    details: {
      added: ['<all_urls>'],
      before: ['https://api.weather.com/*'],
      after: ['<all_urls>', 'https://api.weather.com/*'],
      scopeFrom: '1 Specific Site',
      scopeTo: 'All Websites'
    },
    changeKey: 'weather_host_exp'
  };

  const assessment = evaluateChangeRisk(change);

  // Broad host expansion alone is an elevated HIGH investigation warning, NOT CRITICAL
  assert.equal(assessment.severity, SEVERITY_LEVELS.HIGH);
  assert.equal(assessment.requiresReview, true);
  assert.equal(assessment.exposureImpact, EXPOSURE_LEVELS.BROAD);
  assert.equal(assessment.suspicionImpact, SUSPICION_LEVELS.REVIEW_REQUIRED);

  // Verified permission expansion identifies exact previous, added, and current permissions
  assert.ok(assessment.evidence.some(e => e.includes('Newly added hosts: <all_urls>')));
  assert.ok(assessment.evidence.some(e => e.includes('Baseline host permissions: https://api.weather.com/*')));
  assert.ok(assessment.evidence.some(e => e.includes('Current host permissions: <all_urls>, https://api.weather.com/*')));

  // Explains blast radius without accusing malice
  assert.ok(assessment.reasoning.includes('universal web page access'));
  assert.ok(assessment.reasoning.includes('does not establish malicious behavior'));
});

test('critical severity requires explicit evidentiary rules (Rule C1-C4) and is not triggered by broad host permissions alone', () => {
  // 1. Broad host permission alone: triggers MEDIUM severity, never CRITICAL
  const broadHostExt = {
    id: 'broad_01',
    name: 'Reader Mode',
    version: '1.0.0',
    installType: 'normal',
    apiPermissions: ['storage'],
    hostPermissions: ['<all_urls>']
  };
  const broadAssessment = evaluateExtensionAssessment(broadHostExt);
  assert.equal(broadAssessment.exposure.level, EXPOSURE_LEVELS.BROAD);
  assert.equal(broadAssessment.suspicion.level, SUSPICION_LEVELS.NO_INDICATORS);
  assert.equal(broadAssessment.severity, SEVERITY_LEVELS.MEDIUM, 'Broad host alone must be MEDIUM, not CRITICAL');

  // 2. Broad host expansion alone: triggers HIGH investigation warning, never CRITICAL
  const hostChange = {
    type: CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED,
    extensionId: 'broad_01',
    extensionName: 'Reader Mode',
    details: {
      added: ['<all_urls>'],
      before: ['https://example.com/*'],
      after: ['<all_urls>', 'https://example.com/*'],
      scopeFrom: '1 Specific Site',
      scopeTo: 'All Websites'
    },
    changeKey: 'broad_exp_01'
  };
  const changeRisk = evaluateChangeRisk(hostChange);
  assert.equal(changeRisk.severity, SEVERITY_LEVELS.HIGH, 'Broad host expansion must be HIGH investigation warning');
  assert.equal(changeRisk.requiresReview, true);
  assert.equal(changeRisk.exposureImpact, EXPOSURE_LEVELS.BROAD);
  assert.equal(changeRisk.suspicionImpact, SUSPICION_LEVELS.REVIEW_REQUIRED);

  // 3. Rule C2: Runtime Instrumentation (debugger + tabs) explicitly triggers CRITICAL
  const debuggerExt = {
    id: 'debug_01',
    name: 'Runtime Instrumenter',
    version: '1.0.0',
    installType: 'normal',
    apiPermissions: ['debugger', 'tabs'],
    hostPermissions: []
  };
  const debugAssessment = evaluateExtensionAssessment(debuggerExt);
  assert.equal(debugAssessment.severity, SEVERITY_LEVELS.CRITICAL, 'Rule C2: debugger + tabs must trigger CRITICAL');
  assert.equal(debugAssessment.criticalRuleTriggered, CRITICAL_EVIDENCE_RULES.C2_RUNTIME_INSTRUMENTATION);

  // 4. Rule C4: Permission expansion introducing critical system APIs (debugger) triggers CRITICAL
  const criticalApiChange = {
    type: CHANGE_TYPES.PERMISSIONS_EXPANDED,
    extensionId: 'ext_sys_01',
    extensionName: 'System Tool',
    details: {
      added: ['debugger'],
      before: ['storage'],
      after: ['debugger', 'storage']
    },
    changeKey: 'crit_perm_01'
  };
  const critRisk = evaluateChangeRisk(criticalApiChange);
  assert.equal(critRisk.severity, SEVERITY_LEVELS.CRITICAL, 'Rule C4: Adding debugger API must trigger CRITICAL');
  assert.equal(critRisk.criticalRule, CRITICAL_EVIDENCE_RULES.C4_CRITICAL_SYSTEM_EXPANSION);
});

test('minor version updates and benign metadata updates evaluate to LOW / INFO', () => {
  const versionChange = {
    type: CHANGE_TYPES.VERSION_CHANGED,
    extensionId: 'ext_notes',
    extensionName: 'Notes App',
    direction: 'upgrade',
    details: { from: '1.0.0', to: '1.0.1' },
    changeKey: 'notes_ver'
  };

  const assessment = evaluateChangeRisk(versionChange);
  assert.equal(assessment.severity, SEVERITY_LEVELS.LOW);
  assert.equal(assessment.requiresReview, false);

  const metaChange = {
    type: CHANGE_TYPES.METADATA_UPDATED,
    extensionId: 'ext_notes',
    extensionName: 'Notes App',
    details: { changedFields: ['description'] },
    summary: 'Updated metadata: description',
    changeKey: 'notes_meta'
  };

  const metaAssessment = evaluateChangeRisk(metaChange);
  assert.equal(metaAssessment.severity, SEVERITY_LEVELS.INFO);
  assert.equal(metaAssessment.requiresReview, false);
});

test('evaluateExtensionRisk calculates holistic exposure score and flags', () => {
  const safeExt = {
    id: 'safe_01',
    name: 'Simple Clock',
    version: '1.0.0',
    installType: 'normal',
    apiPermissions: ['alarms'],
    hostPermissions: []
  };

  const safeRisk = evaluateExtensionRisk(safeExt);
  assert.equal(safeRisk.severity, SEVERITY_LEVELS.LOW);

  const riskyExt = {
    id: 'risky_01',
    name: 'Suspicious Proxy',
    version: '1.0.0',
    installType: 'development',
    apiPermissions: ['proxy', 'webRequestBlocking', 'cookies'],
    hostPermissions: ['<all_urls>']
  };

  const highRisk = evaluateExtensionRisk(riskyExt);
  assert.equal(highRisk.severity, SEVERITY_LEVELS.CRITICAL);
  assert.ok(highRisk.flags.some(f => f.type === 'BROAD_HOST_ACCESS'));
  assert.ok(highRisk.flags.some(f => f.type === 'SENSITIVE_APIS'));
});
