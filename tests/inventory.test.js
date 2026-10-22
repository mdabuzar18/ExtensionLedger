import { test } from 'node:test';
import assert from 'node:assert/strict';
import { categorizePermissions, normalizeExtension } from '../src/core/inventory.js';

test('categorizePermissions correctly separates API permissions and host patterns', () => {
  const rawPerms = [
    'storage',
    'alarms',
    'https://api.github.com/*',
    '<all_urls>',
    'cookies',
    'http://*.example.com/*'
  ];

  const result = categorizePermissions(rawPerms);

  assert.deepEqual(result.apiPermissions.sort(), ['alarms', 'cookies', 'storage']);
  assert.equal(result.hostPermissions.includes('<all_urls>'), true);
  assert.equal(result.hostPermissions.includes('https://api.github.com/*'), true);
  assert.equal(result.websiteScope, 'All Websites');
});

test('categorizePermissions handles specific site access scope', () => {
  const rawPerms = ['storage', 'https://example.com/api/*'];
  const result = categorizePermissions(rawPerms);

  assert.equal(result.websiteScope, '1 Specific Site');
  assert.deepEqual(result.apiPermissions, ['storage']);
});

test('categorizePermissions handles zero website access', () => {
  const rawPerms = ['storage', 'alarms', 'unlimitedStorage'];
  const result = categorizePermissions(rawPerms);

  assert.equal(result.websiteScope, 'None');
  assert.equal(result.hostPermissions.length, 0);
});

test('normalizeExtension sanitizes missing fields with safe defaults', () => {
  const normalized = normalizeExtension({
    id: 'test_ext_123',
    name: 'Safe Extension',
    version: '1.2.3'
  });

  assert.equal(normalized.id, 'test_ext_123');
  assert.equal(normalized.name, 'Safe Extension');
  assert.equal(normalized.version, '1.2.3');
  assert.equal(normalized.enabled, false);
  assert.equal(normalized.installType, 'normal');
  assert.deepEqual(normalized.apiPermissions, []);
  assert.deepEqual(normalized.hostPermissions, []);
});

test('detectRuntimeContext accurately identifies standalone web/Node environment', async () => {
  const { detectRuntimeContext, RUNTIME_CONTEXTS } = await import('../src/core/browserApi.js');
  const context = detectRuntimeContext();
  assert.equal(context, RUNTIME_CONTEXTS.WEB_STANDALONE);
});
