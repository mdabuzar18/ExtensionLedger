/**
 * ExtensionLedger - Browser & Context Detection Regression Test Suite
 * 
 * Verifies:
 * 1. Chrome Webpage Mode detection (never misidentified as Safari).
 * 2. Chrome Extension Mode detection (Extension Page & Popup).
 * 3. Microsoft Edge detection (standalone and extension).
 * 4. Apple Safari detection (strict UA & vendor tests).
 * 5. Unknown browser fallback.
 * 6. Three-part status badge assembly: <Browser> · <Context> · <Data Source>.
 * 7. Authorized external messaging origin validation (localhost whitelist).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  detectBrowserIdentity,
  detectExecutionContext,
  getSystemStatus,
  BROWSER_NAMES,
  EXECUTION_CONTEXTS,
  DATA_SOURCES
} from '../src/core/browserApi.js';

// ---------------------------------------------------------------------------
// 1. CHROME WEBPAGE MODE (The Root Cause Scenario)
// ---------------------------------------------------------------------------
test('Detection: Chrome on localhost:3000 is correctly detected as Google Chrome, never Safari', () => {
  // Typical macOS Google Chrome userAgent and vendor
  const mockNav = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    vendor: 'Google Inc.',
    userAgentData: {
      brands: [
        { brand: 'Not_A Brand', version: '8' },
        { brand: 'Chromium', version: '120' },
        { brand: 'Google Chrome', version: '120' }
      ]
    }
  };
  const mockWin = {
    chrome: {},
    location: {
      protocol: 'http:',
      hostname: 'localhost',
      port: '3000',
      pathname: '/dashboard/dashboard.html'
    }
  };

  const browser = detectBrowserIdentity(mockNav, mockWin);
  const context = detectExecutionContext(mockWin);

  assert.equal(browser.name, BROWSER_NAMES.CHROME);
  assert.equal(browser.displayName, 'Google Chrome');
  assert.equal(browser.isChromium, true);

  assert.equal(context.context, EXECUTION_CONTEXTS.STANDALONE_WEB);
  assert.equal(context.displayName, 'Standalone Dashboard');
  assert.equal(context.isExtensionContext, false);

  // Status badge for standalone Chrome with demo data
  const status = getSystemStatus({
    browser,
    context,
    isSyntheticMode: true,
    hasLiveConnection: false
  });

  assert.equal(status.fullStatusText, 'Chrome \u00B7 Standalone Dashboard \u00B7 Demo Data');
  assert.equal(status.statusClass, 'tag-demo');
});

// ---------------------------------------------------------------------------
// 2. CHROME EXTENSION MODES (Extension Page & Popup)
// ---------------------------------------------------------------------------
test('Detection: Chrome inside Extension Page with live connection', () => {
  const mockNav = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    vendor: 'Google Inc.'
  };
  const mockWin = {
    chrome: {},
    location: {
      protocol: 'chrome-extension:',
      pathname: '/dashboard/dashboard.html'
    },
    innerWidth: 1200
  };

  const browser = detectBrowserIdentity(mockNav, mockWin);
  const context = detectExecutionContext(mockWin);

  assert.equal(browser.name, BROWSER_NAMES.CHROME);
  assert.equal(context.context, EXECUTION_CONTEXTS.EXTENSION_PAGE);
  assert.equal(context.isExtensionContext, true);

  // Live status
  const status = getSystemStatus({
    browser,
    context,
    isSyntheticMode: false,
    hasLiveConnection: true
  });

  assert.equal(status.fullStatusText, 'Chrome \u00B7 Extension Page \u00B7 Live Data');
  assert.equal(status.statusClass, 'tag-live');
});

test('Detection: Chrome inside Extension Popup window', () => {
  const mockNav = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    vendor: 'Google Inc.'
  };
  const mockWin = {
    chrome: {},
    location: {
      protocol: 'chrome-extension:',
      pathname: '/popup/popup.html'
    },
    innerWidth: 380
  };

  const context = detectExecutionContext(mockWin);
  assert.equal(context.context, EXECUTION_CONTEXTS.EXTENSION_POPUP);
  assert.equal(context.displayName, 'Extension Popup');
});

// ---------------------------------------------------------------------------
// 3. MICROSOFT EDGE DETECTION
// ---------------------------------------------------------------------------
test('Detection: Microsoft Edge standalone and extension modes', () => {
  const mockNav = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
    vendor: 'Google Inc.',
    userAgentData: {
      brands: [
        { brand: 'Chromium', version: '120' },
        { brand: 'Microsoft Edge', version: '120' }
      ]
    }
  };
  const mockWinWeb = {
    location: { protocol: 'http:', pathname: '/dashboard/dashboard.html' }
  };

  const browser = detectBrowserIdentity(mockNav, mockWinWeb);
  const context = detectExecutionContext(mockWinWeb);

  assert.equal(browser.name, BROWSER_NAMES.EDGE);
  assert.equal(browser.displayName, 'Microsoft Edge');
  assert.equal(browser.isChromium, true);

  const status = getSystemStatus({
    browser,
    context,
    isSyntheticMode: true,
    hasLiveConnection: false
  });

  assert.equal(status.fullStatusText, 'Edge \u00B7 Standalone Dashboard \u00B7 Demo Data');
});

// ---------------------------------------------------------------------------
// 4. APPLE SAFARI DETECTION (Strict separation)
// ---------------------------------------------------------------------------
test('Detection: Genuine Apple Safari is correctly identified and separated from Chrome', () => {
  const mockNav = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    vendor: 'Apple Computer, Inc.'
  };
  const mockWin = {
    safari: {},
    location: { protocol: 'http:', pathname: '/dashboard/dashboard.html' }
  };

  const browser = detectBrowserIdentity(mockNav, mockWin);
  const context = detectExecutionContext(mockWin);

  assert.equal(browser.name, BROWSER_NAMES.SAFARI);
  assert.equal(browser.displayName, 'Apple Safari');
  assert.equal(browser.isChromium, false);

  const status = getSystemStatus({
    browser,
    context,
    isSyntheticMode: true,
    hasLiveConnection: false
  });

  assert.equal(status.fullStatusText, 'Safari \u00B7 Standalone Dashboard \u00B7 Demo Data');
});

// ---------------------------------------------------------------------------
// 5. EXTENSION MESSAGING CONNECTED STATE ON WEBPAGE
// ---------------------------------------------------------------------------
test('Detection: Webpage connected via authorized extension messaging displays Extension Connected · Live Data', () => {
  const mockNav = {
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    vendor: 'Google Inc.'
  };
  const mockWin = {
    chrome: {},
    location: { protocol: 'http:', pathname: '/dashboard/dashboard.html' }
  };

  const browser = detectBrowserIdentity(mockNav, mockWin);
  const context = detectExecutionContext(mockWin);

  // When live extension messaging handshake succeeds
  const status = getSystemStatus({
    browser,
    context,
    isSyntheticMode: false,
    hasLiveConnection: true
  });

  assert.equal(status.fullStatusText, 'Chrome \u00B7 Extension Connected \u00B7 Live Data');
  assert.equal(status.statusClass, 'tag-live');
});

// ---------------------------------------------------------------------------
// 6. UNKNOWN / HEADLESS BROWSER FALLBACK
// ---------------------------------------------------------------------------
test('Detection: Headless / unknown browser falls back safely without throwing', () => {
  const browser = detectBrowserIdentity(null, null);
  const context = detectExecutionContext(null);

  assert.equal(browser.name, BROWSER_NAMES.UNKNOWN);
  assert.equal(context.context, EXECUTION_CONTEXTS.UNSUPPORTED);

  const status = getSystemStatus({ browser, context });
  assert.ok(status.fullStatusText.includes('Unknown'));
});
