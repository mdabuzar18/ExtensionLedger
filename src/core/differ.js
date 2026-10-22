/**
 * ExtensionLedger - Extension Difference Engine
 * Compares two snapshots or current inventory against baseline.
 * Accurately categorizes functional changes from benign metadata updates.
 */

export const CHANGE_TYPES = {
  EXTENSION_ADDED: 'EXTENSION_ADDED',
  EXTENSION_REMOVED: 'EXTENSION_REMOVED',
  VERSION_CHANGED: 'VERSION_CHANGED',
  PERMISSIONS_EXPANDED: 'PERMISSIONS_EXPANDED',
  PERMISSIONS_REDUCED: 'PERMISSIONS_REDUCED',
  HOST_PERMISSIONS_EXPANDED: 'HOST_PERMISSIONS_EXPANDED',
  HOST_PERMISSIONS_REDUCED: 'HOST_PERMISSIONS_REDUCED',
  STATUS_ENABLED: 'STATUS_ENABLED',
  STATUS_DISABLED: 'STATUS_DISABLED',
  INSTALL_TYPE_CHANGED: 'INSTALL_TYPE_CHANGED',
  METADATA_UPDATED: 'METADATA_UPDATED'
};

/**
 * Computes set difference: elements in A not in B
 */
function setDiff(arrA = [], arrB = []) {
  const setB = new Set(arrB);
  return arrA.filter(x => !setB.has(x));
}

/**
 * Compares two versions string (e.g. "1.2.0" vs "1.2.1")
 * @returns {number} 1 if vA > vB, -1 if vA < vB, 0 if equal
 */
export function compareVersions(vA, vB) {
  if (vA === vB) return 0;
  const partsA = String(vA).split('.').map(p => parseInt(p, 10) || 0);
  const partsB = String(vB).split('.').map(p => parseInt(p, 10) || 0);
  const maxLen = Math.max(partsA.length, partsB.length);

  for (let i = 0; i < maxLen; i++) {
    const a = partsA[i] || 0;
    const b = partsB[i] || 0;
    if (a > b) return 1;
    if (a < b) return -1;
  }
  return 0;
}

/**
 * Compares two extension records (baseline vs current)
 * @param {Object} before Extension record from baseline
 * @param {Object} after Extension record from current
 * @returns {Array<Object>} List of discrete change items
 */
export function diffExtension(before, after) {
  const changes = [];
  const extId = after?.id || before?.id;
  const extName = after?.name || before?.name || 'Unknown Extension';
  const extVersion = after?.version || before?.version || '0.0.0';
  const iconUrl = after?.iconUrl || before?.iconUrl || null;
  const publisher = after?.publisher || before?.publisher || 'Unknown Publisher';
  const isSynthetic = Boolean(after?.isSynthetic || before?.isSynthetic);

  // Helper to push with common extension identity
  const pushChange = (change) => {
    changes.push({
      ...change,
      extensionVersion: extVersion,
      iconUrl,
      publisher,
      isSynthetic
    });
  };

  // 1. Version change
  if (before && after && before.version !== after.version) {
    const comp = compareVersions(after.version, before.version);
    const direction = comp > 0 ? 'upgrade' : (comp < 0 ? 'downgrade' : 'revised');
    pushChange({
      type: CHANGE_TYPES.VERSION_CHANGED,
      extensionId: extId,
      extensionName: extName,
      isFunctionalChange: true,
      direction,
      details: {
        from: before.version,
        to: after.version
      },
      summary: `Version changed from ${before.version} to ${after.version} (${direction})`
    });
  }

  // 2. Permission changes (API permissions)
  if (before && after) {
    const addedPerms = setDiff(after.apiPermissions, before.apiPermissions);
    const removedPerms = setDiff(before.apiPermissions, after.apiPermissions);

    if (addedPerms.length > 0) {
      pushChange({
        type: CHANGE_TYPES.PERMISSIONS_EXPANDED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: true,
        details: {
          added: addedPerms,
          before: before.apiPermissions || [],
          after: after.apiPermissions || [],
          current: after.apiPermissions || []
        },
        summary: `Added ${addedPerms.length} new API permission(s): ${addedPerms.join(', ')}`
      });
    }

    if (removedPerms.length > 0) {
      pushChange({
        type: CHANGE_TYPES.PERMISSIONS_REDUCED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: false, // reduction usually lowers risk
        details: {
          removed: removedPerms,
          before: before.apiPermissions || [],
          after: after.apiPermissions || [],
          current: after.apiPermissions || []
        },
        summary: `Removed ${removedPerms.length} API permission(s): ${removedPerms.join(', ')}`
      });
    }

    // 3. Host permissions (website access)
    const addedHosts = setDiff(after.hostPermissions, before.hostPermissions);
    const removedHosts = setDiff(before.hostPermissions, after.hostPermissions);

    if (addedHosts.length > 0) {
      pushChange({
        type: CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: true,
        details: {
          added: addedHosts,
          before: before.hostPermissions || [],
          after: after.hostPermissions || [],
          scopeFrom: before.websiteScope,
          scopeTo: after.websiteScope
        },
        summary: `Expanded website access: added ${addedHosts.join(', ')}`
      });
    }

    if (removedHosts.length > 0) {
      pushChange({
        type: CHANGE_TYPES.HOST_PERMISSIONS_REDUCED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: false,
        details: {
          removed: removedHosts,
          before: before.hostPermissions || [],
          after: after.hostPermissions || [],
          scopeFrom: before.websiteScope,
          scopeTo: after.websiteScope
        },
        summary: `Restricted website access: removed ${removedHosts.join(', ')}`
      });
    }

    // 4. Enabled/disabled state
    if (before.enabled !== after.enabled) {
      pushChange({
        type: after.enabled ? CHANGE_TYPES.STATUS_ENABLED : CHANGE_TYPES.STATUS_DISABLED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: true,
        details: {
          from: before.enabled,
          to: after.enabled
        },
        summary: after.enabled ? 'Extension was enabled' : 'Extension was disabled'
      });
    }

    // 5. Install type change (e.g. normal -> development/unpacked)
    if (before.installType !== after.installType) {
      pushChange({
        type: CHANGE_TYPES.INSTALL_TYPE_CHANGED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: true,
        details: {
          from: before.installType,
          to: after.installType
        },
        summary: `Install type changed from ${before.installType} to ${after.installType}`
      });
    }

    // 6. Benign metadata updates
    const metadataDiff = [];
    if (before.description !== after.description) metadataDiff.push('description');
    if (before.name !== after.name) metadataDiff.push('display name');
    if (before.homepageUrl !== after.homepageUrl) metadataDiff.push('homepage');
    if (before.updateUrl !== after.updateUrl) metadataDiff.push('update URL');

    if (metadataDiff.length > 0) {
      pushChange({
        type: CHANGE_TYPES.METADATA_UPDATED,
        extensionId: extId,
        extensionName: extName,
        isFunctionalChange: false,
        details: {
          changedFields: metadataDiff
        },
        summary: `Updated metadata fields: ${metadataDiff.join(', ')}`
      });
    }
  }

  return changes;
}

/**
 * Compare an entire target inventory/snapshot against a baseline snapshot.
 * @param {Record<string, Object>|Array<Object>} baselineMap 
 * @param {Record<string, Object>|Array<Object>} currentMap 
 * @returns {Array<Object>} All detected changes across all extensions
 */
export function diffSnapshots(baselineMap, currentMap) {
  // If baseline is not recorded, missing, or null/undefined, no drift can be evaluated.
  // Returning an empty array prevents treating all existing extensions as newly added false positives.
  if (!baselineMap) {
    return [];
  }

  // Normalize arrays to maps if needed
  const baseObj = Array.isArray(baselineMap)
    ? Object.fromEntries(baselineMap.map(e => [e.id, e]))
    : (baselineMap?.extensions || baselineMap || {});

  const currObj = Array.isArray(currentMap)
    ? Object.fromEntries(currentMap.map(e => [e.id, e]))
    : (currentMap?.extensions || currentMap || {});

  // If the baseline explicitly contains no extensions but current does, or vice versa
  const allChanges = [];
  const baseKeys = new Set(Object.keys(baseObj));
  const currKeys = new Set(Object.keys(currObj));

  // 1. Detect newly installed extensions
  for (const id of currKeys) {
    if (!baseKeys.has(id)) {
      const ext = currObj[id];
      allChanges.push({
        type: CHANGE_TYPES.EXTENSION_ADDED,
        extensionId: id,
        extensionName: ext.name,
        extensionVersion: ext.version,
        iconUrl: ext.iconUrl,
        publisher: ext.publisher,
        isSynthetic: Boolean(ext.isSynthetic),
        isFunctionalChange: true,
        details: {
          version: ext.version,
          permissions: ext.allPermissions,
          websiteScope: ext.websiteScope,
          installType: ext.installType
        },
        summary: `New extension installed: ${ext.name} (v${ext.version})`
      });
    }
  }

  // 2. Detect removed extensions
  for (const id of baseKeys) {
    if (!currKeys.has(id)) {
      const ext = baseObj[id];
      allChanges.push({
        type: CHANGE_TYPES.EXTENSION_REMOVED,
        extensionId: id,
        extensionName: ext.name,
        extensionVersion: ext.version,
        iconUrl: ext.iconUrl,
        publisher: ext.publisher,
        isSynthetic: Boolean(ext.isSynthetic),
        isFunctionalChange: true,
        details: {
          version: ext.version,
          lastKnownPermissions: ext.allPermissions
        },
        summary: `Extension removed: ${ext.name}`
      });
    }
  }

  // 3. Diff existing extensions
  for (const id of currKeys) {
    if (baseKeys.has(id)) {
      const extChanges = diffExtension(baseObj[id], currObj[id]);
      allChanges.push(...extChanges);
    }
  }

  // Attach a stable deterministic changeKey for reviewing
  return allChanges.map(c => ({
    ...c,
    changeKey: `${c.extensionId}_${c.type}_${c.summary.slice(0, 32).replace(/\s+/g, '_')}`
  }));
}
