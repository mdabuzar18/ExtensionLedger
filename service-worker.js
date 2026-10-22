/**
 * ExtensionLedger - Background Service Worker (Manifest V3)
 * Listens for management lifecycle events, tracks drift against baselines,
 * and maintains security badge indicators.
 */

import { getInventory } from './src/core/inventory.js';
import { getBaseline, saveBaseline, getReviewedChanges, recordLifecycleEvent, getAllowlist } from './src/core/storage.js';
import { diffSnapshots } from './src/core/differ.js';
import { evaluateAllChanges } from './src/core/riskEngine.js';
import { updateBadge } from './src/core/browserApi.js';

/**
 * Triggers a native desktop notification for elevated security events
 * @param {string} title
 * @param {string} message
 */
export function notifySecurityAlert(title, message) {
  if (typeof chrome !== 'undefined' && chrome.notifications?.create) {
    try {
      chrome.notifications.create(`alert_${Date.now()}`, {
        type: 'basic',
        iconUrl: 'icons/icon-48.png',
        title: `ExtensionLedger: ${title}`,
        message,
        priority: 2
      });
    } catch {
      // Ignore notification permissions issues in non-standard environments
    }
  }
}

/**
 * Runs a background audit scan against the current baseline.
 * Calculates unreviewed changes, alerts via desktop notification, and updates badge.
 */
export async function performAuditScan(triggerNotification = false) {
  try {
    const currentInventory = await getInventory();
    const baseline = await getBaseline();

    if (!baseline) {
      // Baseline has not been established by user yet - do not auto-populate
      await updateBadge('', '#64748B');
      return { baselineCreated: false, unreviewedCount: 0, message: 'No baseline recorded yet' };
    }

    const allowlist = await getAllowlist();

    // Compare current with baseline
    const rawChanges = diffSnapshots(baseline, currentInventory);
    const enrichedChanges = evaluateAllChanges(rawChanges, allowlist);

    // Filter unreviewed actionable changes
    const reviewedMap = await getReviewedChanges();
    const pendingReview = enrichedChanges.filter(c => 
      c.assessment.requiresReview && !reviewedMap[c.changeKey]
    );

    const count = pendingReview.length;
    if (count > 0) {
      const nonAllowlisted = pendingReview.filter(c => !c.assessment.isAllowlisted);
      const hasCriticalOrHigh = nonAllowlisted.some(c => 
        c.assessment.severity === 'CRITICAL' || c.assessment.severity === 'HIGH'
      );
      await updateBadge(String(count), hasCriticalOrHigh ? '#EF4444' : '#F59E0B');

      // Trigger desktop notification if requested or critical drift detected
      if (triggerNotification && hasCriticalOrHigh) {
        const topFinding = nonAllowlisted[0];
        notifySecurityAlert(
          'Elevated Extension Risk Detected',
          `${topFinding.extensionName}: ${topFinding.assessment.title}. Click to review in dashboard.`
        );
      }
    } else {
      await updateBadge('', '#10B981');
    }

    return {
      baselineId: baseline.id,
      totalChanges: enrichedChanges.length,
      unreviewedCount: count,
      pendingReview
    };
  } catch (err) {
    console.error('[ExtensionLedger SW] Audit scan failed:', err);
    return { error: err.message };
  }
}

// Setup periodic background audit via chrome.alarms (runs every 12 hours)
if (typeof chrome !== 'undefined' && chrome.alarms) {
  chrome.alarms.create('EXTENSIONLEDGER_PERIODIC_AUDIT', {
    periodInMinutes: 720
  });

  chrome.alarms.onAlarm?.addListener((alarm) => {
    if (alarm.name === 'EXTENSIONLEDGER_PERIODIC_AUDIT') {
      performAuditScan(true);
    }
  });
}

// Notification click router
if (typeof chrome !== 'undefined' && chrome.notifications?.onClicked) {
  chrome.notifications.onClicked.addListener(() => {
    if (chrome.runtime?.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else if (chrome.tabs?.create) {
      chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/dashboard.html#tab=tab-investigation') });
    }
  });
}

// Lifecycle listeners
if (typeof chrome !== 'undefined' && chrome.management) {
  // Record lifecycle event and trigger audit whenever extensions change
  chrome.management.onInstalled?.addListener((info) => {
    recordLifecycleEvent({
      type: 'INSTALLED',
      extensionId: info.id,
      extensionName: info.name,
      version: info.version,
      installType: info.installType
    });
    performAuditScan(true);
  });

  chrome.management.onUninstalled?.addListener((id) => {
    recordLifecycleEvent({
      type: 'UNINSTALLED',
      extensionId: id
    });
    performAuditScan();
  });

  chrome.management.onEnabled?.addListener((info) => {
    recordLifecycleEvent({
      type: 'ENABLED',
      extensionId: info.id,
      extensionName: info.name
    });
    performAuditScan();
  });

  chrome.management.onDisabled?.addListener((info) => {
    recordLifecycleEvent({
      type: 'DISABLED',
      extensionId: info.id,
      extensionName: info.name
    });
    performAuditScan();
  });
}

// Whitelisted development origins for external messaging
const AUTHORIZED_EXTERNAL_ORIGINS = new Set([
  'http://localhost:3000',
  'http://127.0.0.1:3000'
]);

function isAuthorizedSender(sender) {
  if (!sender) return false;
  try {
    const origin = sender.origin || (sender.url ? new URL(sender.url).origin : null);
    return Boolean(origin && AUTHORIZED_EXTERNAL_ORIGINS.has(origin));
  } catch {
    return false;
  }
}

// Run scan on browser startup / extension install
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.onInstalled?.addListener(() => {
    performAuditScan();
  });

  chrome.runtime.onStartup?.addListener(() => {
    performAuditScan();
  });

  // Handle internal messages from dashboard or popup (within extension context)
  chrome.runtime.onMessage?.addListener((message, sender, sendResponse) => {
    if (message.action === 'PERFORM_SCAN') {
      performAuditScan().then(res => sendResponse(res));
      return true; // Keep message channel open for async response
    }
    if (message.action === 'UPDATE_BADGE') {
      performAuditScan().then(res => sendResponse(res));
      return true;
    }
  });

  // Handle external messages from dashboard running at localhost:3000
  chrome.runtime.onMessageExternal?.addListener((message, sender, sendResponse) => {
    // 1. Strict Origin Validation
    if (!isAuthorizedSender(sender)) {
      sendResponse({ success: false, error: 'UNAUTHORIZED_EXTERNAL_ORIGIN' });
      return;
    }

    // 2. Payload Validation
    if (!message || typeof message !== 'object') {
      sendResponse({ success: false, error: 'INVALID_PAYLOAD' });
      return;
    }

    const type = message.type || message.action;

    // Ping / Handshake
    if (type === 'EXTENSIONLEDGER_PING' || type === 'PING') {
      sendResponse({
        success: true,
        connected: true,
        name: 'ExtensionLedger',
        version: '1.0.0',
        authorizedOrigin: sender.origin || sender.url
      });
      return;
    }

    // Trigger Audit Scan
    if (type === 'PERFORM_SCAN') {
      performAuditScan().then(res => sendResponse(res));
      return true;
    }

    // Fetch Sanitized Inventory
    if (type === 'GET_INVENTORY') {
      getInventory().then(inv => sendResponse({ success: true, inventory: inv }));
      return true;
    }

    sendResponse({ success: false, error: 'UNSUPPORTED_ACTION' });
  });
}
