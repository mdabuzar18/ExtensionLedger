import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');

/**
 * Validates an SVG path `d` attribute string according to the W3C SVG specification.
 * Checks for:
 * 1. Valid command characters (m, z, l, h, v, c, s, q, t, a).
 * 2. Exact expected argument counts per command.
 * 3. Absence of malformed number sequences or orphaned coordinates.
 */
function validateSvgPath(d) {
  const commandRegex = /([mzlhvcsqta])([^mzlhvcsqta]*)/gi;
  let match;
  let hasCommands = false;
  
  while ((match = commandRegex.exec(d)) !== null) {
    hasCommands = true;
    const cmd = match[1];
    const argsStr = match[2].trim();
    if (!argsStr && !'zZ'.includes(cmd)) {
      return { valid: false, error: `Missing arguments for command ${cmd}` };
    }
    const numRegex = /[-+]?(?:\d*\.\d+|\d+)(?:[eE][-+]?\d+)?/g;
    const nums = [];
    let numMatch;
    while ((numMatch = numRegex.exec(argsStr)) !== null) {
      nums.push(parseFloat(numMatch[0]));
    }
    
    const lowerCmd = cmd.toLowerCase();
    const expectedArgs = {
      m: 2, l: 2, h: 1, v: 1, c: 6, s: 4, q: 4, t: 2, a: 7, z: 0
    }[lowerCmd];
    
    if (expectedArgs === undefined) {
      return { valid: false, error: `Unknown SVG command ${cmd}` };
    }
    
    if (expectedArgs === 0) {
      if (nums.length > 0) {
        return { valid: false, error: `Command ${cmd} expects 0 arguments but received ${nums.length}` };
      }
    } else {
      if (nums.length === 0 || nums.length % expectedArgs !== 0) {
        return { 
          valid: false, 
          error: `Command ${cmd} expects multiples of ${expectedArgs} arguments but received ${nums.length}: "${match[0]}"` 
        };
      }
    }
  }
  return { valid: hasCommands, error: hasCommands ? null : 'No commands found' };
}

test('SVG Regression: Change Intelligence navigation icon has valid path syntax without malformed sequences', () => {
  const dashboardHtml = fs.readFileSync(path.join(ROOT, 'dashboard', 'dashboard.html'), 'utf8');
  const match = dashboardHtml.match(/data-tab=[\"']tab-intelligence[\"'][\s\S]*?<path\s+d=[\"']([^\"']+)[\"']/);
  assert.ok(match, 'Expected tab-intelligence nav-link SVG path to exist in dashboard.html');
  
  const d = match[1];
  assert.equal(d.includes('8-8 8 8zm'), false, 'Malformed sequence "8-8 8 8zm" must not be present');
  assert.ok(d.includes('8-3.58 8-8 8zm'), 'Expected valid arc coordinates "8-3.58 8-8 8zm"');
  
  const res = validateSvgPath(d);
  assert.equal(res.valid, true, `tab-intelligence SVG path failed validation: ${res.error}`);
});

test('SVG Regression: All inline SVG paths in dashboard.html and popup.html are syntactically valid', () => {
  const filesToScan = [
    path.join(ROOT, 'dashboard', 'dashboard.html'),
    path.join(ROOT, 'popup', 'popup.html')
  ];

  for (const filePath of filesToScan) {
    const content = fs.readFileSync(filePath, 'utf8');
    const pathMatches = [...content.matchAll(/<path[^>]*\b(?<![a-zA-Z0-9_-])d=[\"']([^\"']+)[\"']/gi)];
    assert.ok(pathMatches.length > 0, `Expected SVG paths to be found in ${path.basename(filePath)}`);

    for (const m of pathMatches) {
      const d = m[1];
      const res = validateSvgPath(d);
      assert.equal(res.valid, true, `Invalid SVG path in ${path.basename(filePath)}: "${d}" -> ${res.error}`);
    }
  }
});

test('SVG Regression: Dynamically injected SVG templates in dashboard.js and popup.js are syntactically valid', () => {
  const scriptFiles = [
    path.join(ROOT, 'dashboard', 'dashboard.js'),
    path.join(ROOT, 'popup', 'popup.js')
  ];

  for (const filePath of scriptFiles) {
    const content = fs.readFileSync(filePath, 'utf8');
    const pathMatches = [...content.matchAll(/<path[^>]*\b(?<![a-zA-Z0-9_-])d=[\"']([^\"']+)[\"']/gi)];

    for (const m of pathMatches) {
      const d = m[1];
      const res = validateSvgPath(d);
      assert.equal(res.valid, true, `Invalid dynamic SVG path in ${path.basename(filePath)}: "${d}" -> ${res.error}`);
    }
  }
});
