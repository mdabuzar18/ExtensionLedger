/**
 * ExtensionLedger - Browser API Abstraction Layer
 * Provides cross-browser compatibility (Chrome, Edge, Firefox/WebExtensions)
 * with robust graceful degradation and explicit context detection.
 */

/**
 * ExtensionLedger - Browser API Abstraction Layer
 * Provides cross-browser compatibility (Chrome, Edge, Firefox/WebExtensions)
 * with robust graceful degradation and explicit context detection.
 */

export const BROWSER_NAMES = {
  CHROME: 'Chrome',
  EDGE: 'Edge',
  SAFARI: 'Safari',
  UNKNOWN: 'Unknown'
};

export const EXECUTION_CONTEXTS = {
  EXTENSION_PAGE: 'EXTENSION_PAGE',
  EXTENSION_POPUP: 'EXTENSION_POPUP',
  STANDALONE_WEB: 'STANDALONE_WEB',
  UNSUPPORTED: 'UNSUPPORTED'
};

export const DATA_SOURCES = {
  LIVE: 'Live Data',
  DEMO: 'Demo Data',
  DISCONNECTED: 'Disconnected'
};

export const RUNTIME_CONTEXTS = {
  EXTENSION_MANAGEMENT: 'EXTENSION_MANAGEMENT', // Inside Chrome/Edge extension page with chrome.management & chrome.storage
  EXTENSION_POPUP: 'EXTENSION_POPUP',           // Inside extension popup window
  WEB_STANDALONE: 'WEB_STANDALONE'              // Regular web page (Chrome, Edge, Safari, or localhost outside unpacked extension)
};

/**
 * Accurately detects browser identity using feature detection and client hints.
 * Never misidentifies Google Chrome as Safari simply because extension APIs are absent on web pages.
 * 
 * @param {Object} [nav] Navigator object (defaults to global navigator)
 * @param {Object} [win] Window object (defaults to global window)
 * @returns {{ name: string, displayName: string, isChromium: boolean }}
 */
export function detectBrowserIdentity(
  nav = (typeof navigator !== 'undefined' ? navigator : null),
  win = (typeof window !== 'undefined' ? window : null)
) {
  if (!nav) {
    return { name: BROWSER_NAMES.UNKNOWN, displayName: 'Node / Headless', isChromium: false };
  }

  const ua = nav.userAgent || '';
  const vendor = nav.vendor || '';

  // 1. Check navigator.userAgentData brands (Modern Chrome & Edge)
  if (nav.userAgentData?.brands && Array.isArray(nav.userAgentData.brands)) {
    const brands = nav.userAgentData.brands;
    const isEdgeBrand = brands.some(b => /Microsoft Edge|Edge/i.test(b.brand));
    if (isEdgeBrand) {
      return { name: BROWSER_NAMES.EDGE, displayName: 'Microsoft Edge', isChromium: true };
    }
    const isChromeBrand = brands.some(b => /Google Chrome|Chromium/i.test(b.brand));
    if (isChromeBrand) {
      return { name: BROWSER_NAMES.CHROME, displayName: 'Google Chrome', isChromium: true };
    }
  }

  // 2. Microsoft Edge via User-Agent token
  if (/Edg\//i.test(ua)) {
    return { name: BROWSER_NAMES.EDGE, displayName: 'Microsoft Edge', isChromium: true };
  }

  // 3. Google Chrome (contains Chrome/ token, vendor Google, without Edge/Opera)
  const hasChromeToken = /Chrome\//i.test(ua);
  const isExcluded = /Edg\/|OPR\/|Brave\//i.test(ua);
  if (hasChromeToken && !isExcluded) {
    const isGoogleVendor = vendor === 'Google Inc.' || (win && Boolean(win.chrome));
    if (isGoogleVendor) {
      return { name: BROWSER_NAMES.CHROME, displayName: 'Google Chrome', isChromium: true };
    }
  }

  // 4. Apple Safari (must contain Safari/ and NOT Chrome/ or Chromium/)
  const isSafariVendor = /Apple Computer/i.test(vendor);
  const isSafariToken = /Safari\//i.test(ua) && !/Chrome\//i.test(ua) && !/Chromium\//i.test(ua);
  const hasSafariGlobal = win && typeof win.safari !== 'undefined';
  if ((isSafariToken && isSafariVendor) || hasSafariGlobal) {
    return { name: BROWSER_NAMES.SAFARI, displayName: 'Apple Safari', isChromium: false };
  }

  return { name: BROWSER_NAMES.UNKNOWN, displayName: 'Unknown Browser', isChromium: false };
}

/**
 * Detects the execution context of the running application.
 * Distinguishes between Extension Pages (options page / full tab), Extension Popup, and Standalone Web.
 * 
 * @param {Object} [win] Window object (defaults to global window)
 * @returns {{ context: string, displayName: string, isExtensionContext: boolean }}
 */
export function detectExecutionContext(win = (typeof window !== 'undefined' ? window : null)) {
  if (!win) {
    return {
      context: EXECUTION_CONTEXTS.UNSUPPORTED,
      displayName: 'Node.js / Headless Environment',
      isExtensionContext: false
    };
  }

  const protocol = win.location?.protocol || '';
  const pathname = win.location?.pathname || '';
  const isExtProtocol = protocol === 'chrome-extension:' || protocol === 'moz-extension:' || protocol === 'edge-extension:';

  if (isExtProtocol) {
    if (pathname.includes('popup.html') || win.innerWidth <= 420) {
      return {
        context: EXECUTION_CONTEXTS.EXTENSION_POPUP,
        displayName: 'Extension Popup',
        isExtensionContext: true
      };
    }
    return {
      context: EXECUTION_CONTEXTS.EXTENSION_PAGE,
      displayName: 'Extension Page',
      isExtensionContext: true
    };
  }

  if (protocol === 'http:' || protocol === 'https:' || protocol === 'file:') {
    return {
      context: EXECUTION_CONTEXTS.STANDALONE_WEB,
      displayName: 'Standalone Dashboard',
      isExtensionContext: false
    };
  }

  return {
    context: EXECUTION_CONTEXTS.UNSUPPORTED,
    displayName: 'Unsupported Context',
    isExtensionContext: false
  };
}

/**
 * Backwards-compatible runtime context detector.
 * @returns {string} One of RUNTIME_CONTEXTS
 */
export function detectRuntimeContext() {
  if (typeof chrome !== 'undefined' && chrome.management?.getAll && chrome.storage?.local) {
    if (typeof window !== 'undefined' && (window.innerWidth <= 420 || window.location.pathname.includes('popup.html'))) {
      return RUNTIME_CONTEXTS.EXTENSION_POPUP;
    }
    return RUNTIME_CONTEXTS.EXTENSION_MANAGEMENT;
  }
  return RUNTIME_CONTEXTS.WEB_STANDALONE;
}

/**
 * Assembles a truthful, three-part system status:
 * <Browser Identity> · <Execution Context> · <Data Source>
 * 
 * Examples:
 * - "Chrome · Standalone Dashboard · Demo Data"
 * - "Chrome · Extension Connected · Live Data"
 * - "Edge · Extension Page · Live Data"
 * 
 * @param {Object} options
 * @param {boolean} [options.isSyntheticMode=false]
 * @param {boolean} [options.hasLiveConnection=false]
 * @param {Object} [options.browser]
 * @param {Object} [options.context]
 * @returns {{ browser: string, context: string, dataSource: string, fullStatusText: string, statusClass: string }}
 */
export function getSystemStatus(options = {}) {
  const browser = options.browser || detectBrowserIdentity();
  const context = options.context || detectExecutionContext();
  
  const isExtensionConnected = Boolean(options.hasLiveConnection || context.isExtensionContext);
  let dataSource = DATA_SOURCES.DISCONNECTED;

  if (options.isSyntheticMode) {
    dataSource = DATA_SOURCES.DEMO;
  } else if (isExtensionConnected) {
    dataSource = DATA_SOURCES.LIVE;
  } else {
    dataSource = DATA_SOURCES.DISCONNECTED;
  }

  // Construct readable context description
  let contextLabel = context.displayName;
  if (isExtensionConnected && context.context === EXECUTION_CONTEXTS.STANDALONE_WEB) {
    contextLabel = 'Extension Connected';
  }

  const fullStatusText = `${browser.name} \u00B7 ${contextLabel} \u00B7 ${dataSource}`;
  
  let statusClass = 'tag-demo';
  if (dataSource === DATA_SOURCES.LIVE) {
    statusClass = 'tag-live';
  } else if (dataSource === DATA_SOURCES.DISCONNECTED) {
    statusClass = 'tag-disconnected';
  }

  return {
    browser: browser.name,
    context: contextLabel,
    dataSource,
    fullStatusText,
    statusClass
  };
}

/**
 * Probes for an active messaging connection with the installed ExtensionLedger extension.
 * @param {string} [extensionId]
 * @returns {Promise<{ connected: boolean, mode: string, version?: string }>}
 */
export async function checkExtensionConnection(extensionId = null) {
  // 1. Direct management API available (inside extension page/popup)
  if (typeof chrome !== 'undefined' && Boolean(chrome.management?.getAll)) {
    return {
      connected: true,
      mode: 'DIRECT',
      version: '1.0.0'
    };
  }

  // 2. Web context with chrome.runtime external messaging
  if (typeof chrome !== 'undefined' && typeof chrome.runtime?.sendMessage === 'function') {
    const targetId = extensionId || getStoredExtensionId();
    if (targetId) {
      try {
        const response = await new Promise((resolve) => {
          const timer = setTimeout(() => resolve(null), 800);
          chrome.runtime.sendMessage(targetId, { type: 'EXTENSIONLEDGER_PING' }, (res) => {
            clearTimeout(timer);
            if (chrome.runtime?.lastError) {
              resolve(null);
            } else {
              resolve(res);
            }
          });
        });

        if (response && response.connected) {
          return {
            connected: true,
            mode: 'MESSAGING',
            version: response.version || '1.0.0'
          };
        }
      } catch {
        // Fallback to disconnected
      }
    }
  }

  return {
    connected: false,
    mode: 'NONE'
  };
}

function getStoredExtensionId() {
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      return window.localStorage.getItem('extensionledger_extension_id') || null;
    } catch {
      return null;
    }
  }
  return null;
}

export const isExtensionEnvironment = () => {
  return typeof chrome !== 'undefined' && !!chrome.management && !!chrome.storage;
};

/**
 * Get all installed extensions from the browser management API.
 * @returns {Promise<Array<chrome.management.ExtensionInfo>>}
 */
export async function getAllExtensions() {
  if (isExtensionEnvironment() && chrome.management?.getAll) {
    return new Promise((resolve) => {
      chrome.management.getAll((extensions) => {
        resolve(extensions || []);
      });
    });
  }

  // Fallback for standalone/local dashboard testing
  const fallback = getLocalMockStorage('extensionledger_mock_inventory');
  return fallback || [];
}

/**
 * Read data from local storage (chrome.storage.local with localStorage fallback)
 * @param {string|Array<string>} keys 
 * @returns {Promise<Object>}
 */
export async function storageGet(keys) {
  if (isExtensionEnvironment() && chrome.storage?.local) {
    return new Promise((resolve) => {
      chrome.storage.local.get(keys, (res) => resolve(res || {}));
    });
  }

  // Fallback to window.localStorage
  const result = {};
  const keyList = Array.isArray(keys) ? keys : [keys];
  for (const k of keyList) {
    const raw = getLocalMockStorage(k);
    if (raw !== undefined) {
      result[k] = raw;
    }
  }
  return result;
}

/**
 * Save data to local storage (chrome.storage.local with localStorage fallback)
 * @param {Object} items 
 * @returns {Promise<void>}
 */
export async function storageSet(items) {
  if (isExtensionEnvironment() && chrome.storage?.local) {
    return new Promise((resolve) => {
      chrome.storage.local.set(items, () => resolve());
    });
  }

  // Fallback to window.localStorage or Node in-memory store
  for (const [key, val] of Object.entries(items)) {
    setLocalMockStorage(key, val);
  }
}

/**
 * Update the extension action badge
 * @param {string} text 
 * @param {string} [color='#DC2626']
 */
export async function updateBadge(text, color = '#DC2626') {
  if (isExtensionEnvironment() && chrome.action?.setBadgeText) {
    try {
      await chrome.action.setBadgeText({ text: text ? String(text) : '' });
      if (text && chrome.action.setBadgeBackgroundColor) {
        await chrome.action.setBadgeBackgroundColor({ color });
      }
    } catch {
      // Ignore badge errors if action is not active
    }
  }
}

/**
 * Generates the native browser extension management page URL.
 * Handles Chrome and Edge differences.
 * @param {string} [extensionId='']
 * @returns {string}
 */
export function getBrowserManagementUrl(extensionId = '') {
  const isEdge = typeof navigator !== 'undefined' && /Edg\//i.test(navigator.userAgent);
  const scheme = isEdge ? 'edge' : 'chrome';
  return extensionId 
    ? `${scheme}://extensions/?id=${extensionId}`
    : `${scheme}://extensions/`;
}

/**
 * Safely uninstalls an extension via chrome.management.uninstall().
 * Handles user cancellation, policy restrictions, synthetic shields, and unsupported web contexts.
 * 
 * @param {string} extensionId
 * @param {Object} [options]
 * @param {boolean} [options.showConfirmDialog=true]
 * @param {boolean} [options.isSynthetic=false]
 * @param {boolean} [options.mayDisable=true]
 * @param {string} [options.installType]
 * @returns {Promise<{ success: boolean, cancelled?: boolean, unsupported?: boolean, error?: string, message: string, managementUrl?: string }>}
 */
export async function uninstallExtension(extensionId, options = {}) {
  // 1. Never attempt uninstallation on synthetic fixtures or invalid identifiers
  if (options.isSynthetic || String(extensionId).startsWith('ext_') || !extensionId) {
    return {
      success: false,
      error: 'SYNTHETIC_OR_INVALID_ID',
      message: 'Uninstallation cannot be executed on synthetic fixtures or sample benchmark records.'
    };
  }

  // 2. Guard against Enterprise Policy Managed extensions
  if (options.mayDisable === false || options.installType === 'admin') {
    return {
      success: false,
      error: 'POLICY_RESTRICTION',
      message: 'Enterprise Policy Managed extensions cannot be uninstalled by users. Removal is restricted by system administrator policy.'
    };
  }

  // 3. Check browser context and chrome.management availability
  const hasManagementUninstall = typeof chrome !== 'undefined' && Boolean(chrome.management?.uninstall);

  if (!hasManagementUninstall) {
    const mgmtUrl = getBrowserManagementUrl(extensionId);
    return {
      success: false,
      unsupported: true,
      error: 'UNSUPPORTED_CONTEXT',
      managementUrl: mgmtUrl,
      message: 'Direct uninstallation requires running inside the Chrome or Edge extension context (e.g. Options page or Toolbar popup). In standalone web mode, please use your browser management page to remove this extension.'
    };
  }

  // 4. Execute via chrome.management.uninstall
  return new Promise((resolve) => {
    try {
      chrome.management.uninstall(
        extensionId,
        { showConfirmDialog: options.showConfirmDialog !== false },
        () => {
          if (typeof chrome !== 'undefined' && chrome.runtime?.lastError) {
            const errStr = chrome.runtime.lastError.message || 'Uninstall failed';
            const isCancelled = /cancel/i.test(errStr);
            resolve({
              success: false,
              cancelled: isCancelled,
              error: isCancelled ? 'USER_CANCELLED' : 'API_ERROR',
              message: isCancelled
                ? 'Uninstallation was cancelled in the browser confirmation prompt. No changes were made.'
                : `Browser uninstall error: ${errStr}`
            });
          } else {
            resolve({
              success: true,
              message: 'Extension uninstalled successfully.'
            });
          }
        }
      );
    } catch (err) {
      resolve({
        success: false,
        error: 'EXECUTION_EXCEPTION',
        message: err.message || 'Unexpected exception during uninstallation.'
      });
    }
  });
}

const nodeMemoryStore = new Map();

function getLocalMockStorage(key) {
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      const val = window.localStorage.getItem(key);
      return val ? JSON.parse(val) : undefined;
    } catch {
      return undefined;
    }
  }
  return nodeMemoryStore.get(key);
}

function setLocalMockStorage(key, val) {
  if (typeof window !== 'undefined' && window.localStorage) {
    try {
      window.localStorage.setItem(key, JSON.stringify(val));
    } catch {
      // Ignore localStorage quotas
    }
  } else {
    nodeMemoryStore.set(key, val);
  }
}
