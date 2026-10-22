/**
 * ExtensionLedger - Synthetic Test Datasets
 * Provides reproducible benchmark scenarios for inventory, baseline drift,
 * permission creep, and false-positive verification.
 */

import { normalizeExtension } from './inventory.js';

export const SYNTHETIC_SCENARIOS = {
  // Scenario 1: Clean Initial Baseline (5 extensions)
  BASELINE: [
    {
      id: 'ext_notes_util_01',
      name: 'Quick Notes Utility',
      version: '1.0.0',
      description: 'Simple local note taking utility',
      enabled: true,
      installType: 'normal',
      permissions: ['storage']
    },
    {
      id: 'ext_weather_widget_02',
      name: 'Weather Widget Pro',
      version: '2.1.0',
      description: 'Shows local weather forecasts',
      enabled: true,
      installType: 'normal',
      permissions: ['alarms'],
      hostPermissions: ['https://api.weather.com/*']
    },
    {
      id: 'ext_pdf_tools_03',
      name: 'PDF Reader Tools',
      version: '1.4.0',
      description: 'Enhance PDF viewing and reading',
      enabled: true,
      installType: 'normal',
      permissions: ['storage', 'tabs']
    },
    {
      id: 'ext_tab_colorizer_04',
      name: 'Tab Colorizer',
      version: '3.0.0',
      description: 'Colorize tabs for productivity',
      enabled: true,
      installType: 'normal',
      permissions: ['tabs', 'storage']
    },
    {
      id: 'ext_password_manager_05',
      name: 'SecureVault Password Autofill',
      version: '5.2.1',
      description: 'Official password autofill integration',
      enabled: true,
      installType: 'normal',
      permissions: ['storage', 'clipboardRead', 'activeTab'],
      hostPermissions: ['https://*/*']
    }
  ].map(e => ({ ...normalizeExtension({ ...e, isSynthetic: true }), isSynthetic: true })),

  // Scenario 2: Drifted State (simulates subsequent scan 3 weeks later)
  DRIFTED: [
    // 1. Quick Notes: Benign update
    {
      id: 'ext_notes_util_01',
      name: 'Quick Notes Utility',
      version: '1.0.1',
      description: 'Simple local note taking utility - bugfixes',
      enabled: true,
      installType: 'normal',
      permissions: ['storage']
    },
    // 2. Weather Widget: CRITICAL Permission Creep (<all_urls>, cookies, webRequest)
    {
      id: 'ext_weather_widget_02',
      name: 'Weather Widget Pro',
      version: '2.2.0',
      description: 'Shows local weather forecasts with analytics',
      enabled: true,
      installType: 'normal',
      permissions: ['alarms', 'cookies', 'webRequest'],
      hostPermissions: ['<all_urls>']
    },
    // 3. PDF Reader: Version bump, but stealth code introduced
    {
      id: 'ext_pdf_tools_03',
      name: 'PDF Reader Tools',
      version: '1.4.1',
      description: 'Enhance PDF viewing and reading',
      enabled: true,
      installType: 'normal',
      permissions: ['storage', 'tabs']
    },
    // 4. Tab Colorizer: Benign metadata polish
    {
      id: 'ext_tab_colorizer_04',
      name: 'Tab Colorizer - Organization Tool',
      version: '3.0.1',
      description: 'Colorize tabs for productivity - now with localized translation support',
      enabled: true,
      installType: 'normal',
      permissions: ['tabs', 'storage']
    },
    // 5. SecureVault: Unchanged
    {
      id: 'ext_password_manager_05',
      name: 'SecureVault Password Autofill',
      version: '5.2.1',
      description: 'Official password autofill integration',
      enabled: true,
      installType: 'normal',
      permissions: ['storage', 'clipboardRead', 'activeTab'],
      hostPermissions: ['https://*/*']
    },
    // 6. Unknown new sideloaded extension
    {
      id: 'ext_coupon_finder_06',
      name: 'AutoSaver Shopping Coupons',
      version: '0.9.4',
      description: 'Automatically scans products and injects discount codes',
      enabled: true,
      installType: 'sideload',
      permissions: ['webRequest', 'webRequestBlocking', 'storage'],
      hostPermissions: ['*://*/*']
    }
  ].map(e => ({ ...normalizeExtension({ ...e, isSynthetic: true }), isSynthetic: true })),

  // Pre-compiled base64 ZIP archives for offline / file:// demo of the package analyzer
  FIXTURE_PACKAGES: {
    SUSPICIOUS_V1_BASE64: "UEsDBBQAAAAIAOuxVl11DziQswAAACIBAAANAAAAbWFuaWZlc3QuanNvbm2Ouw6DMAxF935FlLGqQh9bv6JSB4aqQm4wJYVgZKcwIP694SGxdLyP4+thp5T20LgCJWQdsjhq9FVdDlPQgMcodIoQSmSVuvyNQd2Y9JxvfX02J3Nc3BzFsmvDmtxL6kXVZKFW/XqoIEYLEmQhWmTvZDolkXhEK5pQA3vRUTznUknxw7/NMoRWrkkCrTPrgrHkk/0Gv8BWb6Zvk0dsWDBB7pzFrCeukKdXt5b5zMvjbvwBUEsDBBQAAAAIAOuxVl2P0xk6WQAAAGgAAAANAAAAYmFja2dyb3VuZC5qcy3KMQ6AIAwAwN1XNE6wUHHUhziTpgQGgUDRGOPfHXS9HCJs7CRwhWM21kyDa1ci8D2RxJzAs1D4i9JwQ2Xp9Xc1BpHSFkRXojm/ZSjveFj0uTK5JqNe4XkBUEsBAhQDFAAAAAgA67FWXXUPOJCzAAAAIgEAAA0AAAAAAAAAAAAAAIABAAAAAG1hbmlmZXN0Lmpzb25QSwECFAMUAAAACADrsVZdj9MZOlkAAABoAAAADQAAAAAAAAAAAAAAgAHeAAAAYmFja2dyb3VuZC5qc1BLBQYAAAAAAgACAHYAAABiAQAAAAA=",
    SUSPICIOUS_V2_BASE64: "UEsDBBQAAAAIAOuxVl2tR83fxwAAAEMBAAANAAAAbWFuaWZlc3QuanNvbm2PQW7CQAxF95zCmnUVVbBDFWeo2gULhCIzMWSayRjsCaMKcfc6BJFNl///5yf5tgBwPaZwJM31lUQDJ7eG1ds4JOzJgtsS5pYEtqE5UYZPYffYZ94tq2X1PrUNqZdwzs/lu+WiENljhPIUHVnIo2aFEnILmDD+5uB1EpxJ+qCjWU2ws8pKjCj9BFjyzF2gVyx0+KLLYD84K/YPS8v20b+qD4yxHiTqZqYP6LuT8JAa424TpyTX4KkuLB3J+MtMVT86Ht8X9z9QSwMEFAAAAAgA67FWXUHWCOVoAAAAcgAAAA0AAABiYWNrZ3JvdW5kLmpzLclBCsIwEAXQvacYukqgTKVbUSgeouuSfJtgnCnptAri3V3o9r2uoxGTJVTae+75SM9sifBaJomIlMVQAxbLKoeQqj7AQfWesfIMG0px709L7m+ezhcKKqsWcNHZNddf0E03iY33py9QSwECFAMUAAAACADrsVZdrUfN38cAAABDAQAADQAAAAAAAAAAAAAAgAEAAAAAbWFuaWZlc3QuanNvblBLAQIUAxQAAAAIAOuxVl1B1gjlaAAAAHIAAAANAAAAAAAAAAAAAACAAfIAAABiYWNrZ3JvdW5kLmpzUEsFBgAAAAACAAIAdgAAAIUBAAAAAA=="
  }
};

/**
 * Decodes base64 string to Uint8Array
 * @param {string} base64 
 * @returns {Uint8Array}
 */
export function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
