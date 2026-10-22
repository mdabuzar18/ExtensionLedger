import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffSnapshots, diffExtension, CHANGE_TYPES, compareVersions } from '../src/core/differ.js';
import { SYNTHETIC_SCENARIOS } from '../src/core/syntheticData.js';

test('compareVersions accurately ranks semantic versions', () => {
  assert.equal(compareVersions('1.0.1', '1.0.0'), 1);
  assert.equal(compareVersions('1.0.0', '1.0.1'), -1);
  assert.equal(compareVersions('2.0.0', '2.0.0'), 0);
  assert.equal(compareVersions('1.10.0', '1.2.0'), 1);
});

test('diffExtension identifies permission expansions and reductions', () => {
  const before = {
    id: 'test_ext',
    name: 'Test Ext',
    version: '1.0.0',
    enabled: true,
    installType: 'normal',
    apiPermissions: ['storage'],
    hostPermissions: ['https://api.test.com/*'],
    websiteScope: '1 Specific Site'
  };

  const after = {
    id: 'test_ext',
    name: 'Test Ext',
    version: '1.1.0',
    enabled: true,
    installType: 'normal',
    apiPermissions: ['storage', 'cookies', 'webRequest'],
    hostPermissions: ['<all_urls>'],
    websiteScope: 'All Websites'
  };

  const changes = diffExtension(before, after);

  // version, api perms added, host perms added (<all_urls>), host perms removed (https://api.test.com/*)
  assert.equal(changes.length, 4);
  const permChange = changes.find(c => c.type === CHANGE_TYPES.PERMISSIONS_EXPANDED);
  assert.ok(permChange);
  assert.deepEqual(permChange.details.added, ['cookies', 'webRequest']);

  const hostExpChange = changes.find(c => c.type === CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED);
  assert.ok(hostExpChange);
  assert.deepEqual(hostExpChange.details.added, ['<all_urls>']);

  const hostRedChange = changes.find(c => c.type === CHANGE_TYPES.HOST_PERMISSIONS_REDUCED);
  assert.ok(hostRedChange);
  assert.deepEqual(hostRedChange.details.removed, ['https://api.test.com/*']);
});

test('diffSnapshots identifies additions, removals, and metadata modifications across full inventory', () => {
  const baseline = SYNTHETIC_SCENARIOS.BASELINE;
  const drifted = SYNTHETIC_SCENARIOS.DRIFTED;

  const changes = diffSnapshots(baseline, drifted);

  // AutoSaver Shopping Coupons was added
  const added = changes.find(c => c.type === CHANGE_TYPES.EXTENSION_ADDED);
  assert.ok(added);
  assert.equal(added.extensionId, 'ext_coupon_finder_06');

  // Weather Widget experienced permissions expansion
  const weatherExp = changes.find(c => c.extensionId === 'ext_weather_widget_02' && c.type === CHANGE_TYPES.PERMISSIONS_EXPANDED);
  assert.ok(weatherExp);
  assert.deepEqual(weatherExp.details.added, ['cookies', 'webRequest']);

  // Tab Colorizer had benign metadata changes
  const metaChange = changes.find(c => c.extensionId === 'ext_tab_colorizer_04' && c.type === CHANGE_TYPES.METADATA_UPDATED);
  assert.ok(metaChange);
  assert.equal(metaChange.isFunctionalChange, false);
});
