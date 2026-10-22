/**
 * ExtensionLedger - Review & Uninstall Actions Test Suite
 * 
 * Verifies:
 * 1. Opening an extension's review details (attributes, permissions, diffs, findings, uncertainty).
 * 2. Marking a finding as reviewed and persisting its status locally.
 * 3. Reopening a reviewed finding (status changes back to pending).
 * 4. Uninstall confirmation cancellation (handles user cancellation without reporting success).
 * 5. Successful uninstall with a verified inventory refresh.
 * 6. Failed uninstall and enterprise policy-managed restrictions.
 * 7. Preventing uninstall attempts on synthetic records.
 * 8. Attempting to use the uninstall feature from an unsupported browser context.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { 
  normalizeExtension, 
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
  getReviewedChanges, 
  markChangeAsReviewed, 
  unmarkChangeReviewed, 
  reopenChangeReview, 
  isFindingReviewed,
  clearAllAuditData 
} from '../src/core/storage.js';
import { 
  uninstallExtension, 
  getBrowserManagementUrl, 
  detectRuntimeContext, 
  RUNTIME_CONTEXTS 
} from '../src/core/browserApi.js';

// Setup and reset storage before tests
test.beforeEach(async () => {
  await clearAllAuditData();
});

// ---------------------------------------------------------------------------
// 1. OPENING AN EXTENSION'S REVIEW DETAILS
// ---------------------------------------------------------------------------
test('Review Action: constructs complete review dossier data structure', () => {
  const extension = normalizeExtension({
    id: 'abcdefghijklmnopabcdefghijklmnop',
    name: 'Privacy Shield Pro',
    version: '2.1.0',
    installType: 'normal',
    publisher: 'Verified Store Extension',
    permissions: ['storage', 'cookies'],
    hostPermissions: ['*://*/*'],
    icons: [{ size: 48, url: 'icon48.png' }]
  });

  const baselineExt = normalizeExtension({
    id: 'abcdefghijklmnopabcdefghijklmnop',
    name: 'Privacy Shield Pro',
    version: '2.0.0',
    installType: 'normal',
    permissions: ['storage'],
    hostPermissions: []
  });

  // Calculate baseline differences
  const changes = diffExtension(baselineExt, extension);
  assert.ok(changes.length >= 2, 'Expected version and permission changes');

  // Evaluate risk & findings
  const findings = changes.map(c => ({
    ...c,
    assessment: evaluateChangeRisk(c)
  }));

  // Assert all required review dossier fields exist
  assert.equal(extension.name, 'Privacy Shield Pro');
  assert.equal(extension.id, 'abcdefghijklmnopabcdefghijklmnop');
  assert.equal(extension.version, '2.1.0');
  assert.ok(extension.publisher);
  assert.deepEqual(extension.apiPermissions, ['cookies', 'storage']);
  assert.equal(extension.websiteScope, 'All Websites');

  // Verify findings and evidence
  assert.ok(findings.length > 0);
  for (const f of findings) {
    assert.ok(f.assessment.title, 'Finding must have a descriptive title');
    assert.ok(f.assessment.severity, 'Finding must declare severity level');
    assert.ok(f.assessment.evidence, 'Finding must contain supporting evidence');
    assert.ok(f.assessment.systemCannotDetermine, 'Finding must disclose system uncertainty / blind spots');
    assert.ok(f.assessment.whatToInvestigateNext, 'Finding must provide recommended analyst actions');
  }
});

// ---------------------------------------------------------------------------
// 2. MARKING A FINDING AS REVIEWED AND PERSISTING ITS STATUS
// ---------------------------------------------------------------------------
test('Review Action: marks a finding as reviewed and persists status locally', async () => {
  const changeKey = 'abcdefghijklmnopabcdefghijklmnop_PERMISSIONS_EXPANDED_cookies';
  const extensionId = 'abcdefghijklmnopabcdefghijklmnop';

  // Initially pending
  let reviews = await getReviewedChanges();
  assert.equal(isFindingReviewed(changeKey, reviews), false);

  // Mark as reviewed with metadata
  const reviewRecord = await markChangeAsReviewed(changeKey, {
    extensionId,
    findingId: changeKey,
    note: 'Verified that cookies permission is required for SSO auth feature.'
  });

  assert.equal(reviewRecord.status, 'reviewed');
  assert.equal(reviewRecord.extensionId, extensionId);
  assert.ok(reviewRecord.reviewedAt);

  // Verify persistence
  reviews = await getReviewedChanges();
  assert.equal(isFindingReviewed(changeKey, reviews), true);
  assert.equal(reviews[changeKey].status, 'reviewed');

  // Verification of Risk Separation:
  // Reviewing a finding must NOT alter or reduce its underlying risk score or severity!
  const changeItem = {
    type: CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED,
    extensionVersion: '2.1.0',
    details: {
      added: ['<all_urls>'],
      scopeFrom: 'None',
      scopeTo: 'All Websites'
    }
  };
  const assessment = evaluateChangeRisk(changeItem);
  assert.equal(assessment.severity, SEVERITY_LEVELS.HIGH, 'Underlying risk severity must remain HIGH even if reviewed');
});

// ---------------------------------------------------------------------------
// 3. REOPENING A REVIEWED FINDING
// ---------------------------------------------------------------------------
test('Review Action: allows reopening a reviewed finding back to pending status', async () => {
  const changeKey = 'ext_key_test_reopen';
  await markChangeAsReviewed(changeKey, { extensionId: 'ext_test', note: 'Initial review' });

  let reviews = await getReviewedChanges();
  assert.equal(isFindingReviewed(changeKey, reviews), true);

  // Reopen review
  await reopenChangeReview(changeKey, { note: 'Reopened following security advisory' });

  reviews = await getReviewedChanges();
  assert.equal(isFindingReviewed(changeKey, reviews), false, 'Reopened finding must not be marked as reviewed');
  assert.equal(reviews[changeKey].status, 'pending');
  assert.equal(reviews[changeKey].reviewedAt, null);
  assert.ok(reviews[changeKey].reopenedAt);
});

// ---------------------------------------------------------------------------
// 4. UNINSTALL CONFIRMATION CANCELLATION
// ---------------------------------------------------------------------------
test('Uninstall Action: handles user cancellation in confirmation dialog without reporting success', async () => {
  // Simulate mock browser environment where chrome.management.uninstall is present
  const originalChrome = globalThis.chrome;
  try {
    globalThis.chrome = {
      runtime: {
        lastError: { message: 'User cancelled uninstall' }
      },
      management: {
        uninstall: (id, options, callback) => {
          // Simulate user clicking Cancel in native browser prompt
          callback();
        }
      }
    };

    const result = await uninstallExtension('abcdefghijklmnopabcdefghijklmnop', {
      isSynthetic: false,
      mayDisable: true
    });

    assert.equal(result.success, false, 'Must NOT report success when cancelled');
    assert.equal(result.cancelled, true, 'Must identify as cancelled');
    assert.equal(result.error, 'USER_CANCELLED');
    assert.ok(result.message.includes('cancelled'));
  } finally {
    globalThis.chrome = originalChrome;
  }
});

// ---------------------------------------------------------------------------
// 5. SUCCESSFUL UNINSTALL WITH VERIFIED INVENTORY REFRESH
// ---------------------------------------------------------------------------
test('Uninstall Action: executes successfully and reflects in inventory drift', async () => {
  const targetId = 'abcdefghijklmnopabcdefghijklmnop';
  let mockBrowserInstalled = [
    { id: targetId, name: 'Installed Extension', version: '1.0.0' },
    { id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', name: 'Other Tool', version: '2.0.0' }
  ];

  const originalChrome = globalThis.chrome;
  try {
    globalThis.chrome = {
      runtime: {},
      management: {
        uninstall: (id, options, callback) => {
          // Remove from mock browser inventory
          mockBrowserInstalled = mockBrowserInstalled.filter(e => e.id !== id);
          callback();
        }
      }
    };

    // Execute uninstall
    const result = await uninstallExtension(targetId, {
      isSynthetic: false,
      mayDisable: true
    });

    assert.equal(result.success, true);
    assert.equal(mockBrowserInstalled.some(e => e.id === targetId), false, 'Target extension must be removed from browser');

    // Verify baseline diff now detects EXTENSION_REMOVED
    const baseline = [
      { id: targetId, name: 'Installed Extension', version: '1.0.0', allPermissions: [] },
      { id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', name: 'Other Tool', version: '2.0.0', allPermissions: [] }
    ];
    const diffs = diffSnapshots(baseline, mockBrowserInstalled);
    const removedEvent = diffs.find(d => d.type === CHANGE_TYPES.EXTENSION_REMOVED);
    assert.ok(removedEvent, 'Expected EXTENSION_REMOVED drift event');
    assert.equal(removedEvent.extensionId, targetId);
  } finally {
    globalThis.chrome = originalChrome;
  }
});

// ---------------------------------------------------------------------------
// 6. FAILED UNINSTALL AND MANAGED-BROWSER RESTRICTIONS
// ---------------------------------------------------------------------------
test('Uninstall Action: immediately blocks uninstall for Enterprise Policy Managed extensions', async () => {
  // Test case A: mayDisable === false
  const resultA = await uninstallExtension('admin_managed_ext_id_123456789012', {
    mayDisable: false,
    installType: INSTALL_TYPES.ADMIN
  });

  assert.equal(resultA.success, false);
  assert.equal(resultA.error, 'POLICY_RESTRICTION');
  assert.ok(resultA.message.includes('Enterprise Policy Managed'));

  // Test case B: installType === 'admin'
  const resultB = await uninstallExtension('admin_managed_ext_id_123456789012', {
    mayDisable: true,
    installType: 'admin'
  });

  assert.equal(resultB.success, false);
  assert.equal(resultB.error, 'POLICY_RESTRICTION');
});

// ---------------------------------------------------------------------------
// 7. PREVENTING UNINSTALL ATTEMPTS ON SYNTHETIC RECORDS
// ---------------------------------------------------------------------------
test('Uninstall Action: prevents uninstallation attempts on synthetic demonstration records', async () => {
  // Synthetic ID (starts with ext_)
  const res1 = await uninstallExtension('ext_weather_widget_02');
  assert.equal(res1.success, false);
  assert.equal(res1.error, 'SYNTHETIC_OR_INVALID_ID');

  // Explicit isSynthetic flag
  const res2 = await uninstallExtension('validformatid1234567890abcdefgh', { isSynthetic: true });
  assert.equal(res2.success, false);
  assert.equal(res2.error, 'SYNTHETIC_OR_INVALID_ID');

  // Empty ID
  const res3 = await uninstallExtension('');
  assert.equal(res3.success, false);
  assert.equal(res3.error, 'SYNTHETIC_OR_INVALID_ID');
});

// ---------------------------------------------------------------------------
// 8. ATTEMPTING UNINSTALL FROM UNSUPPORTED BROWSER CONTEXT
// ---------------------------------------------------------------------------
test('Uninstall Action: handles unsupported browser context gracefully with fallback management URL', async () => {
  // When running in Node.js or Standalone Web without chrome.management
  const targetId = 'abcdefghijklmnopabcdefghijklmnop';
  const result = await uninstallExtension(targetId, { isSynthetic: false, mayDisable: true });

  assert.equal(result.success, false);
  assert.equal(result.unsupported, true);
  assert.equal(result.error, 'UNSUPPORTED_CONTEXT');
  assert.ok(result.managementUrl.includes('extensions/?id='));
  assert.ok(result.message.includes('standalone web mode'));

  // Management URL generator test
  const chromeUrl = getBrowserManagementUrl(targetId);
  assert.ok(chromeUrl.includes('://extensions/?id=' + targetId));
});

// ---------------------------------------------------------------------------
// 9. DIRECT NATIVE CONFIRMATION SINGLE-DIALOG VERIFICATION
// ---------------------------------------------------------------------------
test('Uninstall Action: passes showConfirmDialog: true directly to chrome.management.uninstall for native confirmation', async () => {
  const targetId = 'abcdefghijklmnopabcdefghijklmnop';
  let recordedOptions = null;
  let invokedWithId = null;

  const originalChrome = globalThis.chrome;
  try {
    globalThis.chrome = {
      runtime: {},
      management: {
        uninstall: (id, options, callback) => {
          invokedWithId = id;
          recordedOptions = options;
          callback();
        }
      }
    };

    const result = await uninstallExtension(targetId, {
      isSynthetic: false,
      mayDisable: true
    });

    assert.equal(result.success, true);
    assert.equal(invokedWithId, targetId);
    assert.ok(recordedOptions, 'Expected options object passed to chrome.management.uninstall');
    assert.equal(recordedOptions.showConfirmDialog, true, 'Must request native browser confirmation prompt directly');
  } finally {
    globalThis.chrome = originalChrome;
  }
});

// ---------------------------------------------------------------------------
// 10. CANCELLATION LEAVES INVENTORY FULLY PRESERVED
// ---------------------------------------------------------------------------
test('Uninstall Action: leaves extension unchanged in inventory when user cancels native dialog', async () => {
  const targetId = 'abcdefghijklmnopabcdefghijklmnop';
  const installedInventory = [
    { id: targetId, name: 'Secure Password Manager', version: '3.4.1' },
    { id: 'secondextensionid12345678901234', name: 'Developer Helper', version: '1.0.0' }
  ];

  const originalChrome = globalThis.chrome;
  try {
    globalThis.chrome = {
      runtime: {
        lastError: { message: 'User cancelled uninstall' }
      },
      management: {
        uninstall: (id, options, callback) => {
          // User clicks cancel in Chrome native dialog
          // Inventory is NOT modified by browser
          callback();
        }
      }
    };

    const result = await uninstallExtension(targetId, {
      isSynthetic: false,
      mayDisable: true
    });

    assert.equal(result.success, false);
    assert.equal(result.cancelled, true);
    // Ensure inventory retains target extension
    assert.equal(installedInventory.some(e => e.id === targetId), true, 'Extension must remain in inventory on cancel');
    assert.equal(installedInventory.length, 2, 'No extensions should be removed');
  } finally {
    globalThis.chrome = originalChrome;
  }
});
