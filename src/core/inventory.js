/**
 * ExtensionLedger - Extension Inventory Normalizer
 * Extracts, sanitizes, and normalizes extension metadata from chrome.management
 */

import { getAllExtensions } from './browserApi.js';

export const INSTALL_TYPES = {
  NORMAL: 'normal',
  DEVELOPMENT: 'development',
  SIDELOAD: 'sideload',
  ADMIN: 'admin',
  OTHER: 'other'
};

/**
 * Validates the format of an extension identifier.
 * Official Chrome Web Store and Microsoft Edge Add-ons IDs consist of exactly 32 lowercase [a-p] characters.
 * @param {string} id 
 * @returns {{ isValidFormat: boolean, isStoreFormat: boolean, type: string, reason: string }}
 */
export function validateExtensionId(id) {
  if (typeof id !== 'string' || !id.trim()) {
    return {
      isValidFormat: false,
      isStoreFormat: false,
      type: 'invalid',
      reason: 'Extension identifier is empty or not a string'
    };
  }

  const cleanId = id.trim();
  // Chrome Web Store and Microsoft Edge Add-ons use 32 lowercase chars from [a-p]
  const isStore = /^[a-p]{32}$/.test(cleanId);
  if (isStore) {
    return {
      isValidFormat: true,
      isStoreFormat: true,
      type: 'store_verified_format',
      reason: 'Valid 32-character Chrome / Edge Web Store identifier format [a-p]{32}'
    };
  }

  // Developer / unpacked / synthetic identifier check: 3 to 64 alphanumeric characters, underscores, dashes
  const isCustomOrSynthetic = /^[a-zA-Z0-9_-]{3,64}$/.test(cleanId);
  if (isCustomOrSynthetic) {
    return {
      isValidFormat: true,
      isStoreFormat: false,
      type: 'custom_or_synthetic',
      reason: 'Non-store identifier format (local development, sideloaded, or synthetic benchmark fixture)'
    };
  }

  return {
    isValidFormat: false,
    isStoreFormat: false,
    type: 'malformed',
    reason: 'Malformed extension identifier containing invalid characters or illegal length'
  };
}

export const BROAD_HOST_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
  'file://*/*'
];

/**
 * Checks if a host permission pattern grants access to all or widespread websites.
 * @param {string} pattern
 * @returns {boolean}
 */
export function isBroadHostPattern(pattern) {
  if (!pattern || typeof pattern !== 'string') return false;
  const p = pattern.trim();
  return BROAD_HOST_PATTERNS.includes(p) ||
    p === '*://*' ||
    p === '<all_urls>' ||
    p.startsWith('*://*.') ||
    p.startsWith('https://*.') ||
    p.startsWith('http://*.');
}

/**
 * Categorizes permissions into host access (website permissions) and API permissions.
 * Maintains strict separation between chrome.management.ExtensionInfo.permissions (API capabilities)
 * and chrome.management.ExtensionInfo.hostPermissions (website access scopes).
 * 
 * @param {Array<string>} rawPermissions Raw permissions array (API permissions)
 * @param {Array<string>} [rawHostPermissions] Raw host permissions array (Website host patterns)
 * @returns {{ apiPermissions: string[], hostPermissions: string[], websiteScope: string, hasBroadHost: boolean }}
 */
export function categorizePermissions(rawPermissions = [], rawHostPermissions = []) {
  const apiPermissions = new Set();
  const hostPermissions = new Set(rawHostPermissions || []);

  const isHostString = (str) => {
    if (!str || typeof str !== 'string') return false;
    const s = str.trim();
    return s === '<all_urls>' ||
      s.startsWith('http://') ||
      s.startsWith('https://') ||
      s.startsWith('*://') ||
      s.startsWith('file://') ||
      s.startsWith('ftp://') ||
      s.startsWith('urn:');
  };

  // Process rawPermissions: preserve API permissions, redirect any legacy host patterns to hostPermissions
  for (const perm of rawPermissions) {
    if (!perm || typeof perm !== 'string') continue;
    const clean = perm.trim();
    if (isHostString(clean)) {
      hostPermissions.add(clean);
    } else {
      apiPermissions.add(clean);
    }
  }

  // Determine whether broad host access is declared in manifest
  const hostsArray = Array.from(hostPermissions);
  const hasBroadHost = hostsArray.some(isBroadHostPattern);

  // Determine website scope description
  let websiteScope = 'None';
  if (hasBroadHost) {
    websiteScope = 'All Websites';
  } else if (hostsArray.length > 0) {
    websiteScope = `${hostsArray.length} Specific Site${hostsArray.length > 1 ? 's' : ''}`;
  }

  return {
    apiPermissions: Array.from(apiPermissions).sort(),
    hostPermissions: Array.from(hostPermissions).sort(),
    websiteScope,
    hasBroadHost
  };
}

/**
 * Normalizes an ExtensionInfo object into a standardized, audited record.
 * @param {Object} raw 
 * @returns {Object} Normalized extension record
 */
export function normalizeExtension(raw) {
  if (!raw || typeof raw !== 'object') {
    throw new Error('Invalid extension record');
  }

  const { apiPermissions, hostPermissions, websiteScope, hasBroadHost } = categorizePermissions(
    raw.permissions || [],
    raw.hostPermissions || []
  );

  // Find best icon URL
  let iconUrl = null;
  if (Array.isArray(raw.icons) && raw.icons.length > 0) {
    // Pick largest icon
    const sorted = [...raw.icons].sort((a, b) => (b.size || 0) - (a.size || 0));
    iconUrl = sorted[0].url;
  }

  // Derive publisher & distribution origin
  const selfId = (typeof chrome !== 'undefined' && chrome.runtime?.id) ? chrome.runtime.id : null;
  const isSelf = Boolean(selfId && raw.id === selfId);

  let publisher = 'Verified Store Extension';
  if (isSelf) {
    publisher = 'ExtensionLedger (Auditing Extension)';
  } else if (raw.installType === INSTALL_TYPES.DEVELOPMENT) {
    publisher = 'Local Developer Build (Unpacked)';
  } else if (raw.installType === INSTALL_TYPES.SIDELOAD) {
    publisher = 'Sideloaded (External Installer)';
  } else if (raw.installType === INSTALL_TYPES.ADMIN) {
    publisher = 'Enterprise Policy Managed';
  } else if (raw.updateUrl && (raw.updateUrl.includes('google.com') || raw.updateUrl.includes('chrome.google.com'))) {
    publisher = 'Chrome Web Store';
  } else if (raw.updateUrl && raw.updateUrl.includes('edge.microsoft.com')) {
    publisher = 'Microsoft Edge Add-ons';
  } else if (raw.homepageUrl) {
    try {
      publisher = new URL(raw.homepageUrl).hostname.replace(/^www\./, '');
    } catch {
      publisher = 'Self-Hosted / Third-Party';
    }
  }

  const idVal = validateExtensionId(raw.id);
  const isSynthetic = Boolean(raw.isSynthetic || idVal.type === 'custom_or_synthetic' && String(raw.id).startsWith('ext_'));

  // Check Manifest V3 compatibility warnings
  const incompatibilities = [];
  if (apiPermissions.includes('webRequestBlocking') && raw.installType !== INSTALL_TYPES.ADMIN) {
    incompatibilities.push({
      rule: 'MV3_RESTRICTED_PERMISSION',
      permission: 'webRequestBlocking',
      reason: 'webRequestBlocking is blocked for standard store extensions in Manifest V3 (requires enterprise policy install or migration to declarativeNetRequest).'
    });
  }

  return {
    id: raw.id || 'unknown-id',
    idValidation: idVal,
    isSynthetic,
    isSelf,
    name: raw.name || 'Unnamed Extension',
    shortName: raw.shortName || raw.name || '',
    description: raw.description || '',
    version: raw.version || '0.0.0',
    enabled: Boolean(raw.enabled),
    mayDisable: raw.mayDisable !== undefined ? Boolean(raw.mayDisable) : true,
    installType: raw.installType || INSTALL_TYPES.NORMAL,
    publisher,
    type: raw.type || 'extension',
    homepageUrl: raw.homepageUrl || '',
    updateUrl: raw.updateUrl || '',
    isApp: Boolean(raw.isApp),
    iconUrl,
    apiPermissions,
    hostPermissions,
    declaredApiPermissions: apiPermissions,
    declaredHostPermissions: hostPermissions,
    hasBroadHost,
    websiteScope,
    siteAccessNote: hasBroadHost
      ? 'Declared in manifest. Chrome allows users to restrict runtime site access (e.g. "On click" or "On specific sites"), but effective runtime access is not exposed via chrome.management.'
      : (hostPermissions.length > 0 ? 'Declared in manifest for specific host patterns.' : 'No declared website host permissions.'),
    incompatibilities,
    // Raw declared permissions combined for backward diffing
    allPermissions: Array.from(new Set([...apiPermissions, ...hostPermissions])).sort(),
    scannedAt: new Date().toISOString()
  };
}

/**
 * Fetches and normalizes the current inventory of extensions.
 * Filters out internal components, apps, themes, or the auditing extension itself.
 * @param {Object} [options={}]
 * @param {boolean} [options.includeThemes=false]
 * @param {boolean} [options.includeApps=false]
 * @param {boolean} [options.excludeSelf=true]
 * @returns {Promise<Array<Object>>}
 */
export async function getInventory(options = {}) {
  const includeThemes = Boolean(options.includeThemes);
  const includeApps = Boolean(options.includeApps);
  const excludeSelf = options.excludeSelf !== false;

  const rawList = await getAllExtensions();
  const normalized = [];
  const selfId = (typeof chrome !== 'undefined' && chrome.runtime?.id) ? chrome.runtime.id : null;

  for (const item of rawList) {
    if (!includeThemes && item.type === 'theme') {
      continue;
    }
    if (!includeApps && (item.type === 'hosted_app' || item.type === 'packaged_app' || item.type === 'legacy_packaged_app' || item.isApp)) {
      continue;
    }
    if (excludeSelf && selfId && item.id === selfId) {
      continue;
    }
    normalized.push(normalizeExtension(item));
  }

  // Sort alphabetically by name
  normalized.sort((a, b) => a.name.localeCompare(b.name));
  return normalized;
}
