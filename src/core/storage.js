/**
 * ExtensionLedger - Local Persistence Layer
 * Manages baseline snapshots, history, and reviewed changes via chrome.storage.local.
 * ZERO external network transfer, completely local.
 */

import { storageGet, storageSet } from './browserApi.js';
import { computeSha256 } from './cryptoUtils.js';

export const STORAGE_KEYS = {
  BASELINE: 'extensionledger_baseline',
  SNAPSHOT_HISTORY: 'extensionledger_snapshots',
  REVIEWED_CHANGES: 'extensionledger_reviews',
  SETTINGS: 'extensionledger_settings',
  LAST_SCAN: 'extensionledger_last_scan',
  LIFECYCLE_EVENTS: 'extensionledger_events',
  ALLOWLIST: 'extensionledger_allowlist'
};

/**
 * @typedef {Object} Snapshot
 * @property {string} id
 * @property {string} schemaVersion
 * @property {string} sha256
 * @property {string} timestamp
 * @property {string} label
 * @property {number} extensionCount
 * @property {Record<string, Object>} extensions
 */

/**
 * Retrieve the active baseline snapshot.
 * @returns {Promise<Snapshot|null>}
 */
export async function getBaseline() {
  const data = await storageGet(STORAGE_KEYS.BASELINE);
  return data[STORAGE_KEYS.BASELINE] || null;
}

/**
 * Save an inventory list as the new baseline snapshot.
 * Calculates an immutable cryptographic SHA-256 integrity hash.
 * @param {Array<Object>} inventory 
 * @param {string} [label='Baseline']
 * @returns {Promise<Snapshot>}
 */
export async function saveBaseline(inventory, label = 'Baseline') {
  const extensionMap = {};
  for (const ext of inventory) {
    extensionMap[ext.id] = ext;
  }

  // Canonicalize string representation for deterministic integrity hash
  const canonicalString = JSON.stringify(extensionMap, Object.keys(extensionMap).sort());
  const sha256 = await computeSha256(canonicalString);

  const snapshot = {
    id: `snap_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    schemaVersion: '1.0',
    sha256,
    timestamp: new Date().toISOString(),
    label,
    extensionCount: inventory.length,
    extensions: extensionMap
  };

  // Save as baseline
  await storageSet({ [STORAGE_KEYS.BASELINE]: snapshot });

  // Also append to snapshot history (limit to last 25 snapshots)
  await recordSnapshotInHistory(snapshot);

  return snapshot;
}

/**
 * Switch the active baseline to a previously saved snapshot from history.
 * @param {string} snapshotId 
 * @returns {Promise<Snapshot|null>}
 */
export async function switchActiveBaseline(snapshotId) {
  const target = await getSnapshotById(snapshotId);
  if (!target) return null;
  await storageSet({ [STORAGE_KEYS.BASELINE]: target });
  return target;
}

/**
 * Retrieve snapshot history
 * @returns {Promise<Array<Snapshot>>}
 */
export async function getSnapshotHistory() {
  const data = await storageGet(STORAGE_KEYS.SNAPSHOT_HISTORY);
  return data[STORAGE_KEYS.SNAPSHOT_HISTORY] || [];
}

/**
 * Record a snapshot into historical timeline
 * @param {Snapshot} snapshot 
 */
export async function recordSnapshotInHistory(snapshot) {
  const history = await getSnapshotHistory();
  // Prepend latest snapshot, deduplicate by ID
  const updated = [snapshot, ...history.filter(s => s.id !== snapshot.id)].slice(0, 25);
  await storageSet({ [STORAGE_KEYS.SNAPSHOT_HISTORY]: updated });
}

/**
 * Retrieve a specific snapshot by ID
 * @param {string} snapshotId 
 * @returns {Promise<Snapshot|null>}
 */
export async function getSnapshotById(snapshotId) {
  const history = await getSnapshotHistory();
  const found = history.find(s => s.id === snapshotId);
  if (found) return found;

  const baseline = await getBaseline();
  if (baseline && baseline.id === snapshotId) return baseline;

  return null;
}

/**
 * Delete a specific snapshot from history
 * @param {string} snapshotId 
 */
export async function deleteSnapshot(snapshotId) {
  const history = await getSnapshotHistory();
  const filtered = history.filter(s => s.id !== snapshotId);
  await storageSet({ [STORAGE_KEYS.SNAPSHOT_HISTORY]: filtered });
}

/**
 * Retrieve reviewed changes map
 * @returns {Promise<Record<string, { changeKey: string, status: string, reviewedAt: string, extensionId?: string, findingId?: string, note?: string }>>}
 */
export async function getReviewedChanges() {
  const data = await storageGet(STORAGE_KEYS.REVIEWED_CHANGES);
  return data[STORAGE_KEYS.REVIEWED_CHANGES] || {};
}

/**
 * Mark a specific change key as reviewed
 * @param {string} changeKey 
 * @param {string|Object} [meta='']
 * @returns {Promise<Object>}
 */
export async function markChangeAsReviewed(changeKey, meta = '') {
  const reviews = await getReviewedChanges();
  const metadata = typeof meta === 'string' ? { note: meta } : (meta || {});
  
  reviews[changeKey] = {
    changeKey,
    findingId: metadata.findingId || changeKey,
    extensionId: metadata.extensionId || '',
    status: 'reviewed',
    reviewedAt: new Date().toISOString(),
    note: metadata.note || ''
  };
  await storageSet({ [STORAGE_KEYS.REVIEWED_CHANGES]: reviews });
  return reviews[changeKey];
}

/**
 * Unmark a reviewed change (removes from reviewed map so it returns to pending review)
 * @param {string} changeKey 
 */
export async function unmarkChangeReviewed(changeKey) {
  const reviews = await getReviewedChanges();
  delete reviews[changeKey];
  await storageSet({ [STORAGE_KEYS.REVIEWED_CHANGES]: reviews });
}

/**
 * Reopen a reviewed change (sets status explicitly back to 'pending')
 * @param {string} changeKey 
 * @param {string|Object} [meta='']
 * @returns {Promise<Object>}
 */
export async function reopenChangeReview(changeKey, meta = '') {
  const reviews = await getReviewedChanges();
  const metadata = typeof meta === 'string' ? { note: meta } : (meta || {});
  
  reviews[changeKey] = {
    ...(reviews[changeKey] || {}),
    changeKey,
    findingId: metadata.findingId || changeKey,
    extensionId: metadata.extensionId || '',
    status: 'pending',
    reopenedAt: new Date().toISOString(),
    reviewedAt: null,
    note: metadata.note || ''
  };
  await storageSet({ [STORAGE_KEYS.REVIEWED_CHANGES]: reviews });
  return reviews[changeKey];
}

/**
 * Checks if a specific finding changeKey is currently reviewed
 * @param {string} changeKey 
 * @param {Record<string, Object>} [reviewsMap={}] 
 * @returns {boolean}
 */
export function isFindingReviewed(changeKey, reviewsMap = {}) {
  const entry = reviewsMap[changeKey];
  if (!entry) return false;
  return entry.status === 'reviewed' || (Boolean(entry.reviewedAt) && entry.status !== 'pending');
}

/**
 * Record a real browser extension lifecycle event
 * @param {Object} event
 * @param {string} event.type - INSTALLED | UNINSTALLED | ENABLED | DISABLED
 * @param {string} event.extensionId
 * @param {string} [event.extensionName]
 * @param {string} [event.version]
 * @param {string} [event.timestamp]
 */
export async function recordLifecycleEvent(event) {
  const events = await getLifecycleEvents();
  const entry = {
    id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    timestamp: event.timestamp || new Date().toISOString(),
    ...event
  };
  // Keep newest first, limit to last 50 events
  const updated = [entry, ...events].slice(0, 50);
  await storageSet({ [STORAGE_KEYS.LIFECYCLE_EVENTS]: updated });
  return entry;
}

/**
 * Retrieve all recorded lifecycle events
 * @returns {Promise<Array<Object>>}
 */
export async function getLifecycleEvents() {
  const data = await storageGet(STORAGE_KEYS.LIFECYCLE_EVENTS);
  return data[STORAGE_KEYS.LIFECYCLE_EVENTS] || [];
}

/**
 * Retrieve the analyst allowlist map
 * @returns {Promise<Record<string, { extensionId: string, trusted: boolean, note: string, taggedAt: string }>>}
 */
export async function getAllowlist() {
  const data = await storageGet(STORAGE_KEYS.ALLOWLIST);
  return data[STORAGE_KEYS.ALLOWLIST] || {};
}

/**
 * Add or update an extension on the analyst allowlist
 * @param {string} extensionId
 * @param {Object} options
 * @param {boolean} [options.trusted=true]
 * @param {string} [options.note='']
 */
export async function setExtensionAllowlist(extensionId, options = {}) {
  const list = await getAllowlist();
  list[extensionId] = {
    extensionId,
    trusted: options.trusted !== false,
    note: options.note || '',
    taggedAt: new Date().toISOString()
  };
  await storageSet({ [STORAGE_KEYS.ALLOWLIST]: list });
  return list[extensionId];
}

/**
 * Remove an extension from the analyst allowlist
 * @param {string} extensionId
 */
export async function removeExtensionAllowlist(extensionId) {
  const list = await getAllowlist();
  delete list[extensionId];
  await storageSet({ [STORAGE_KEYS.ALLOWLIST]: list });
}

/**
 * Check if an extension is currently allowlisted
 * @param {string} extensionId
 * @param {Record<string, Object>} [allowlistMap]
 * @returns {boolean}
 */
export function isExtensionAllowlisted(extensionId, allowlistMap = {}) {
  return Boolean(allowlistMap[extensionId]?.trusted);
}

/**
 * Export complete audit dossier bundle as a structured JSON object
 * @param {Object} contextData
 * @param {Array<Object>} [contextData.inventory=[]]
 * @param {Array<Object>} [contextData.changes=[]]
 * @returns {Promise<Object>}
 */
export async function exportAuditDossier(contextData = {}) {
  const baseline = await getBaseline();
  const history = await getSnapshotHistory();
  const reviews = await getReviewedChanges();
  const events = await getLifecycleEvents();
  const allowlist = await getAllowlist();

  return {
    exportVersion: '1.0',
    exportedAt: new Date().toISOString(),
    generator: 'ExtensionLedger Security Auditor',
    activeBaseline: baseline,
    baselineHistory: history,
    currentInventory: contextData.inventory || [],
    observedChanges: contextData.changes || [],
    analystReviews: reviews,
    lifecycleEvents: events,
    allowlist
  };
}

/**
 * Import a previously exported audit dossier bundle safely
 * @param {Object} bundle
 * @returns {Promise<{ success: boolean, message: string, baselineId?: string }>}
 */
export async function importAuditDossier(bundle) {
  if (!bundle || typeof bundle !== 'object') {
    throw new Error('Invalid audit bundle payload');
  }

  const updates = {};
  if (bundle.activeBaseline && bundle.activeBaseline.id) {
    updates[STORAGE_KEYS.BASELINE] = bundle.activeBaseline;
  }
  if (Array.isArray(bundle.baselineHistory)) {
    updates[STORAGE_KEYS.SNAPSHOT_HISTORY] = bundle.baselineHistory;
  }
  if (bundle.analystReviews && typeof bundle.analystReviews === 'object') {
    updates[STORAGE_KEYS.REVIEWED_CHANGES] = bundle.analystReviews;
  }
  if (Array.isArray(bundle.lifecycleEvents)) {
    updates[STORAGE_KEYS.LIFECYCLE_EVENTS] = bundle.lifecycleEvents;
  }
  if (bundle.allowlist && typeof bundle.allowlist === 'object') {
    updates[STORAGE_KEYS.ALLOWLIST] = bundle.allowlist;
  }

  await storageSet(updates);
  return {
    success: true,
    message: 'Audit dossier restored successfully.',
    baselineId: bundle.activeBaseline?.id
  };
}

/**
 * Generate a clean, readable Markdown security report
 * @param {Object} reportContext
 * @returns {string} Markdown text
 */
export function exportReportAsMarkdown(reportContext = {}) {
  const inventory = reportContext.inventory || [];
  const baseline = reportContext.baseline || null;
  const changes = reportContext.changes || [];
  const reviews = reportContext.reviews || {};
  const allowlist = reportContext.allowlist || {};
  const timestamp = new Date().toISOString();

  let md = `# ExtensionLedger — Security Audit Dossier\n\n`;
  md += `**Generated**: ${timestamp}  \n`;
  md += `**Total Extensions Monitored**: ${inventory.length}  \n`;
  md += `**Baseline Status**: ${baseline ? `${baseline.label} (${baseline.timestamp})` : 'No baseline recorded'}  \n`;
  md += `**Integrity Hash (SHA-256)**: \`${baseline?.sha256 || 'N/A'}\`  \n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `| Category | Metric |\n| :--- | :--- |\n`;
  md += `| Monitored Extensions | ${inventory.length} |\n`;
  md += `| Total Drift Findings | ${changes.length} |\n`;
  const pending = changes.filter(c => c.assessment.requiresReview && !reviews[c.changeKey]);
  md += `| Pending Investigation | ${pending.length} |\n`;
  md += `| Analyst Reviewed | ${Object.keys(reviews).length} |\n`;
  md += `| Allowlisted / Internal | ${Object.keys(allowlist).length} |\n\n`;

  md += `## 2. Monitored Extensions Roster\n\n`;
  md += `| Extension Name | ID | Version | Scope | Source | Status |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;
  for (const ext of inventory) {
    const isTrusted = allowlist[ext.id]?.trusted ? ' (Allowlisted)' : '';
    md += `| ${ext.name} | \`${ext.id}\` | v${ext.version} | ${ext.websiteScope} | ${ext.installType} | ${ext.enabled ? 'Active' : 'Disabled'}${isTrusted} |\n`;
  }
  md += `\n`;

  if (changes.length > 0) {
    md += `## 3. Detected Drift & Security Findings\n\n`;
    for (const c of changes) {
      const isRev = Boolean(reviews[c.changeKey]);
      md += `### [${c.assessment.severity}] ${c.assessment.title}\n`;
      md += `- **Extension**: ${c.extensionName} (\`${c.extensionId}\`)\n`;
      md += `- **What Changed**: ${c.assessment.whatChanged || c.summary}\n`;
      md += `- **Why It Matters**: ${c.assessment.whyItMatters || 'N/A'}\n`;
      md += `- **Evidence**: \`${JSON.stringify(c.assessment.evidence || {})}\`\n`;
      md += `- **Status**: ${isRev ? 'Reviewed by Analyst' : 'Pending Review'}\n\n`;
    }
  }

  return md;
}

/**
 * Generate a CSV export for spreadsheet analysis
 * @param {Object} reportContext
 * @returns {string} CSV text
 */
export function exportReportAsCSV(reportContext = {}) {
  const inventory = reportContext.inventory || [];
  const changes = reportContext.changes || [];
  const reviews = reportContext.reviews || {};

  const headers = ['Type', 'ExtensionName', 'ExtensionID', 'Version', 'Severity', 'Scope', 'Status', 'Summary'];
  const rows = [headers.join(',')];

  const escapeCsv = (str) => {
    if (str === null || str === undefined) return '""';
    const s = String(str).replace(/"/g, '""');
    return `"${s}"`;
  };

  // Extension inventory rows
  for (const ext of inventory) {
    rows.push([
      escapeCsv('INVENTORY'),
      escapeCsv(ext.name),
      escapeCsv(ext.id),
      escapeCsv(ext.version),
      escapeCsv('INFO'),
      escapeCsv(ext.websiteScope),
      escapeCsv(ext.enabled ? 'ENABLED' : 'DISABLED'),
      escapeCsv(`Permissions: ${ext.allPermissions.join('; ')}`)
    ].join(','));
  }

  // Findings rows
  for (const c of changes) {
    const isRev = Boolean(reviews[c.changeKey]);
    rows.push([
      escapeCsv('FINDING'),
      escapeCsv(c.extensionName),
      escapeCsv(c.extensionId),
      escapeCsv(c.extensionVersion || ''),
      escapeCsv(c.assessment?.severity || 'LOW'),
      escapeCsv(''),
      escapeCsv(isRev ? 'REVIEWED' : 'PENDING'),
      escapeCsv(c.assessment?.title || c.summary)
    ].join(','));
  }

  return rows.join('\n');
}

/**
 * Clear all stored data (reset audit state)
 */
export async function clearAllAuditData() {
  await storageSet({
    [STORAGE_KEYS.BASELINE]: null,
    [STORAGE_KEYS.SNAPSHOT_HISTORY]: [],
    [STORAGE_KEYS.REVIEWED_CHANGES]: {},
    [STORAGE_KEYS.LAST_SCAN]: null,
    [STORAGE_KEYS.LIFECYCLE_EVENTS]: [],
    [STORAGE_KEYS.ALLOWLIST]: {}
  });
}
