/**
 * ExtensionLedger - Explainable Rule-Based Risk Engine
 * Analyzes detected extension changes and inventories against objective security criteria.
 * 
 * CORE PRINCIPLE:
 * Never labels an extension malicious based solely on its name, version update,
 * or permission change. Instead, provides severity, evidence, reasoning, and next steps.
 */

import { CHANGE_TYPES } from './differ.js';

export const SEVERITY_LEVELS = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO'
};

export const EXPOSURE_LEVELS = {
  EXTENSIVE: 'Extensive',
  BROAD: 'Broad',
  LIMITED: 'Limited'
};

export const SUSPICION_LEVELS = {
  SUSPICIOUS: 'Suspicious evidence detected',
  REVIEW_REQUIRED: 'Review required',
  NO_INDICATORS: 'No indicators observed'
};

/**
 * Explicit evidentiary rules that justify a CRITICAL severity or Critical Suspicion classification.
 * Under ExtensionLedger policy, broad host access alone or routine updates NEVER trigger CRITICAL.
 */
export const CRITICAL_EVIDENCE_RULES = {
  C1_ACTIVE_EXFILTRATION: 'Rule C1: Active Malicious Code / C2 Exfiltration Leads',
  C2_RUNTIME_INSTRUMENTATION: 'Rule C2: Full Runtime Instrumentation (debugger + tabs composite)',
  C3_OBFUSCATED_PAYLOAD: 'Rule C3: Obfuscated / High Entropy Payload with Outbound Transmission',
  C4_CRITICAL_SYSTEM_EXPANSION: 'Rule C4: Critical System Privilege Expansion (debugger/nativeMessaging/webRequestBlocking)'
};

// High-risk browser APIs that can intercept data, execute arbitrary code, or access credentials
export const SENSITIVE_PERMISSIONS = {
  // Critical exposure APIs
  debugger: { weight: 50, desc: 'Can attach debugging session to tabs and inspect/modify memory/network' },
  webRequestBlocking: { weight: 45, desc: 'Can inspect, block, or modify any in-flight HTTP/HTTPS request' },
  nativeMessaging: { weight: 40, desc: 'Can execute native binaries on the host operating system' },
  proxy: { weight: 35, desc: 'Can re-route browser traffic through custom proxy servers' },
  declarativeNetRequestFeedback: { weight: 35, desc: 'Can read URLs matching network filtering rules' },
  
  // High exposure APIs
  cookies: { weight: 30, desc: 'Can read, write, and export authentication session cookies' },
  scripting: { weight: 30, desc: 'Can inject arbitrary JavaScript or CSS into matching tabs' },
  webRequest: { weight: 25, desc: 'Can inspect network requests and URLs' },
  tabCapture: { weight: 25, desc: 'Can capture video/audio streams of browser tabs' },
  desktopCapture: { weight: 25, desc: 'Can record user screen or application windows' },
  privacy: { weight: 25, desc: 'Can toggle browser security and telemetry settings' },

  // Medium exposure APIs
  tabs: { weight: 15, desc: 'Can inspect tab URLs, titles, and navigate tabs' },
  downloads: { weight: 15, desc: 'Can initiate and monitor file downloads' },
  clipboardRead: { weight: 15, desc: 'Can read sensitive content from the system clipboard' },
  geolocation: { weight: 15, desc: 'Can access device physical location' },
  management: { weight: 15, desc: 'Can inspect or alter other installed extensions' },
  webNavigation: { weight: 10, desc: 'Can observe navigation lifecycle events and visited domains' },

  // Low / Utility APIs
  storage: { weight: 2, desc: 'Can store local data within extension sandbox' },
  alarms: { weight: 1, desc: 'Can schedule periodic background timer events' },
  notifications: { weight: 2, desc: 'Can display OS notifications' },
  contextMenus: { weight: 2, desc: 'Can add custom items to the right-click menu' }
};

export const BROAD_HOST_PATTERNS = [
  '<all_urls>',
  '*://*/*',
  'http://*/*',
  'https://*/*',
  'file://*/*'
];

/**
 * Checks if a permission string matches a broad website intercept pattern
 * @param {string} perm 
 * @returns {boolean}
 */
export function isBroadHostPermission(perm) {
  if (!perm) return false;
  return BROAD_HOST_PATTERNS.includes(perm) ||
         perm.includes('*://*.') ||
         perm.includes('https://*.');
}

/**
 * Evaluates the Exposure Level of an individual extension based on its declared permissions.
 * Exposure describes the potential blast radius and technical capabilities granted to the extension.
 * High exposure does NOT imply malicious intent.
 * 
 * @param {Object} extension Normalized extension record
 * @returns {Object} Exposure evaluation { level, score, hasBroadHost, criticalApis, sensitiveApis, moderateApis, utilityApis, factors, blastRadius, summary, siteAccessNote }
 */
export function evaluateExposure(extension) {
  const hostPerms = extension.hostPermissions || [];
  const apiPerms = extension.apiPermissions || [];
  const hasBroadHost = extension.hasBroadHost !== undefined 
    ? Boolean(extension.hasBroadHost) 
    : hostPerms.some(isBroadHostPermission);

  const criticalApis = apiPerms.filter(p => ['debugger', 'webRequestBlocking', 'nativeMessaging', 'proxy'].includes(p));
  const sensitiveApis = apiPerms.filter(p => [
    'cookies', 'scripting', 'webRequest', 'declarativeNetRequestFeedback',
    'privacy', 'tabCapture', 'desktopCapture'
  ].includes(p));
  const moderateApis = apiPerms.filter(p => [
    'tabs', 'downloads', 'clipboardRead', 'geolocation', 'management', 'webNavigation'
  ].includes(p));
  const utilityApis = apiPerms.filter(p => [
    'storage', 'alarms', 'notifications', 'contextMenus', 'activeTab'
  ].includes(p));

  const factors = [];
  let score = 0;

  // 1. Host permission factor
  if (hasBroadHost) {
    score += 40;
    factors.push({
      type: 'BROAD_HOST_SCOPE',
      description: 'Declared host permission covers all or broad websites (<all_urls> or *://*/*).',
      evidence: hostPerms.filter(isBroadHostPermission)
    });
  } else if (hostPerms.length > 0) {
    score += 15;
    factors.push({
      type: 'SPECIFIC_HOST_SCOPE',
      description: `Declared host permissions restricted to ${hostPerms.length} specific site pattern(s).`,
      evidence: hostPerms
    });
  } else {
    factors.push({
      type: 'NO_HOST_SCOPE',
      description: 'No website host permissions declared in manifest.',
      evidence: []
    });
  }

  // 2. API permissions factors
  if (criticalApis.length > 0) {
    score += 35;
    factors.push({
      type: 'CRITICAL_SYSTEM_APIS',
      description: 'System or native integration capabilities declared.',
      evidence: criticalApis.map(p => `${p} (${SENSITIVE_PERMISSIONS[p]?.desc || 'System API'})`)
    });
  }
  if (sensitiveApis.length > 0) {
    score += 25;
    factors.push({
      type: 'SENSITIVE_APIS',
      description: 'Page interaction, script execution, or traffic inspection APIs declared.',
      evidence: sensitiveApis.map(p => `${p} (${SENSITIVE_PERMISSIONS[p]?.desc || 'Sensitive API'})`)
    });
  }
  if (moderateApis.length > 0) {
    score += 10;
    factors.push({
      type: 'MODERATE_APIS',
      description: 'Standard browser management, tab, or download APIs declared.',
      evidence: moderateApis
    });
  }

  // 3. Composite Capability Combinations
  const apis = new Set(apiPerms);
  if (apis.has('cookies') && (apis.has('webRequest') || apis.has('webRequestBlocking') || hasBroadHost)) {
    score += 15;
    factors.push({
      type: 'COMPOSITE_CREDENTIAL_CAPABILITY',
      description: 'Composite capability: Can read session cookies alongside network interception or broad website scope.',
      evidence: ['cookies API combined with network interception or broad website scope']
    });
  }
  if (apis.has('nativeMessaging') && (hasBroadHost || apis.has('cookies') || apis.has('webRequest'))) {
    score += 15;
    factors.push({
      type: 'COMPOSITE_NATIVE_BRIDGE',
      description: 'Composite capability: Interfaces with local host OS binary while possessing web interception rights.',
      evidence: ['nativeMessaging combined with web interception or credential access']
    });
  }

  // 4. Determine Exposure Level
  // - Extensive: Broad host + (critical or sensitive APIs), OR critical APIs alone (e.g. debugger, nativeMessaging, webRequestBlocking)
  // - Broad: Broad host alone (without critical/sensitive APIs), OR sensitive APIs without broad host
  // - Limited: Only utility APIs (storage, alarms, contextMenus, activeTab) with specific or zero host access
  let level = EXPOSURE_LEVELS.LIMITED;
  let blastRadius = '';
  let summary = '';

  if ((hasBroadHost && (criticalApis.length > 0 || sensitiveApis.length > 0)) || criticalApis.length > 0) {
    level = EXPOSURE_LEVELS.EXTENSIVE;
    blastRadius = hasBroadHost
      ? 'Universal website access combined with privileged execution or data interception capabilities.'
      : 'Possesses low-level system or protocol inspection APIs (native messaging, debugger, or request blocking).';
    summary = `Extensive blast radius: Declared permissions grant access to ${hasBroadHost ? 'all websites' : 'system interfaces'} alongside privileged browser capabilities (${[...criticalApis, ...sensitiveApis].join(', ')}).`;
  } else if (hasBroadHost || sensitiveApis.length > 0 || moderateApis.length > 0) {
    level = EXPOSURE_LEVELS.BROAD;
    blastRadius = hasBroadHost
      ? 'Universal website scope declared, but restricted to standard utility APIs without privileged DOM/network injection or data extraction.'
      : 'Elevated browser APIs present, but operationally restricted to specific website scopes or user-initiated interactions.';
    summary = `Broad blast radius: ${hasBroadHost ? 'Broad website access without privileged execution APIs.' : 'Privileged capabilities scoped to specific websites.'}`;
  } else {
    level = EXPOSURE_LEVELS.LIMITED;
    blastRadius = 'Capabilities are confined to local sandbox storage and standard extension UI actions.';
    summary = 'Limited blast radius: Extension holds minimal attack surface with no universal website interception or critical APIs.';
  }

  return {
    level,
    score: Math.min(100, score),
    hasBroadHost,
    criticalApis,
    sensitiveApis,
    moderateApis,
    utilityApis,
    factors,
    blastRadius,
    summary,
    siteAccessNote: extension.siteAccessNote || (hasBroadHost
      ? 'Declared in manifest. Chrome allows users to restrict runtime site access (e.g. "On click" or "On specific sites"), but effective runtime access is not exposed via chrome.management.'
      : (hostPerms.length > 0 ? 'Declared in manifest for specific host patterns.' : 'No declared website host permissions.'))
  };
}

/**
 * Evaluates the Suspicion Level of an individual extension based on observed evidence.
 * Suspicion describes evidence that the extension may be behaving unexpectedly, maliciously, or has undergone unreviewed drift.
 * Never labels an extension "safe"; uses "No indicators observed" when no anomalies exist.
 * 
 * @param {Object} extension Normalized extension record
 * @param {Array<Object>} [extChanges=[]] Detected drift events for this extension
 * @param {Object} [options={}] Additional audit options (package report, reviewed map, allowlist)
 * @returns {Object} Suspicion evaluation { level, evidence, evidenceTypes, unreviewedChangesCount, summary }
 */
export function evaluateSuspicion(extension, extChanges = [], options = {}) {
  const isAllowlisted = Boolean(options.isAllowlisted || extension.isAllowlisted);
  const reviewedMap = options.reviewedMap || {};

  const evidence = [];
  const manifestEvidence = [];
  const baselineEvidence = [];
  const packageEvidence = [];
  const behavioralEvidence = [];

  // 1. Package Analysis evidence
  const leads = options.packageReport?.investigationLeads || options.packageReport?.newInvestigationLeads || [];
  if (leads.length > 0) {
    for (const lead of leads) {
      if (lead.severity === 'CRITICAL' || lead.severity === 'HIGH') {
        packageEvidence.push(`Package Audit: ${lead.category} (${lead.preview}) in ${lead.file}`);
      }
    }
  }

  if (options.packageReport?.newDiscoveredEndpoints?.length > 0) {
    packageEvidence.push(`Package Audit: Newly discovered outbound endpoints: ${options.packageReport.newDiscoveredEndpoints.join(', ')}`);
  }

  // Shannon Entropy / Obfuscation indicators from package analysis
  if (options.packageReport?.fileMetrics?.some(m => m.isElevatedEntropy)) {
    packageEvidence.push('Package Audit: Elevated Shannon Entropy detected (≥ 5.8), indicating possible packed or obfuscated payload.');
  }

  // 2. Manifest V3 Incompatibilities / Restricted Policy Violations
  if (extension.incompatibilities?.length > 0) {
    for (const inc of extension.incompatibilities) {
      manifestEvidence.push(`Manifest Policy Rule: ${inc.reason}`);
    }
  }

  // 3. Baseline Drift Evidence (Unreviewed changes relative to genuine baseline)
  const pendingChanges = extChanges.filter(c => {
    if (isAllowlisted) return false;
    if (reviewedMap[c.changeKey]) return false;
    return c.assessment ? c.assessment.requiresReview : evaluateChangeRisk(c).requiresReview;
  });

  for (const c of extChanges) {
    const isRev = Boolean(reviewedMap[c.changeKey] || isAllowlisted);
    const revTag = isRev ? ' (Reviewed)' : ' (Unreviewed Drift)';

    if (c.type === CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED) {
      baselineEvidence.push(`Baseline Drift: Host permissions expanded to include ${c.details.added?.join(', ')}${revTag}`);
    } else if (c.type === CHANGE_TYPES.PERMISSIONS_EXPANDED) {
      baselineEvidence.push(`Baseline Drift: Added API permissions: ${c.details.added?.join(', ')}${revTag}`);
    } else if (c.type === CHANGE_TYPES.VERSION_CHANGED && c.direction === 'downgrade') {
      baselineEvidence.push(`Version Anomaly: Version rolled backward from ${c.details.from} to ${c.details.to}${revTag}`);
    } else if (c.type === CHANGE_TYPES.INSTALL_TYPE_CHANGED) {
      baselineEvidence.push(`Distribution Anomaly: Install type modified from ${c.details.from} to ${c.details.to}${revTag}`);
    } else if (c.type === CHANGE_TYPES.EXTENSION_ADDED && !isRev) {
      baselineEvidence.push(`Inventory Drift: Extension newly installed since verified baseline was recorded${revTag}`);
    }
  }

  // 4. Non-Store Installation Awaiting Review
  if (!isAllowlisted && (extension.installType === 'development' || extension.installType === 'sideload')) {
    if (extChanges.length > 0 && extChanges.some(c => !reviewedMap[c.changeKey])) {
      manifestEvidence.push(`Non-Store Distribution: Installed via ${extension.installType} channel without Web Store automated screening.`);
    }
  }

  // 5. Determine Suspicion Level
  let level = SUSPICION_LEVELS.NO_INDICATORS;
  let summary = '';

  const hasSuspiciousPackage = packageEvidence.length > 0;
  const hasVersionDowngrade = extChanges.some(c => c.type === CHANGE_TYPES.VERSION_CHANGED && c.direction === 'downgrade');
  const hasInstallChannelChange = extChanges.some(c => c.type === CHANGE_TYPES.INSTALL_TYPE_CHANGED && c.details.to !== 'normal');
  const hasMV3Violation = (extension.incompatibilities && extension.incompatibilities.length > 0);

  if (hasSuspiciousPackage || hasVersionDowngrade || hasInstallChannelChange || hasMV3Violation) {
    level = SUSPICION_LEVELS.SUSPICIOUS;
    summary = 'Concrete suspicious indicators detected requiring immediate investigation.';
    evidence.push(...packageEvidence, ...behavioralEvidence);
    if (hasVersionDowngrade) evidence.push('Version rolled backward unexpectedly.');
    if (hasInstallChannelChange) evidence.push('Extension source switched to unpacked or sideloaded without store verification.');
    if (hasMV3Violation) evidence.push(...manifestEvidence);
  } else if (pendingChanges.length > 0) {
    level = SUSPICION_LEVELS.REVIEW_REQUIRED;
    summary = `${pendingChanges.length} unreviewed baseline drift event(s) detected.`;
    evidence.push(...baselineEvidence.filter(e => e.includes('Unreviewed')));
  } else {
    level = SUSPICION_LEVELS.NO_INDICATORS;
    if (isAllowlisted) {
      summary = `No indicators observed (Analyst allowlisted: ${extension.allowlistNote || 'Approved standard extension'}).`;
      evidence.push('Extension has been reviewed and verified by security analyst.');
    } else if (extChanges.length > 0 && extChanges.every(c => reviewedMap[c.changeKey])) {
      summary = 'All detected baseline changes have been reviewed and acknowledged.';
      evidence.push('All observed drift events have been marked as reviewed by analyst.');
    } else {
      summary = 'No anomalies, unreviewed drift, or suspicious patterns observed.';
      evidence.push('Matches verified baseline snapshot; no unexpected updates or behavioral leads detected.');
    }
  }

  return {
    level,
    evidence,
    evidenceTypes: {
      manifestEvidence,
      baselineEvidence,
      packageEvidence,
      behavioralEvidence
    },
    unreviewedChangesCount: pendingChanges.length,
    summary
  };
}

/**
 * Evaluates comprehensive extension assessment combining Exposure Level and Suspicion Level.
 * @param {Object} extension
 * @param {Array<Object>} [extChanges=[]]
 * @param {Record<string, Object>} [allowlist={}]
 * @param {Object} [options={}]
 * @returns {Object}
 */
export function evaluateExtensionAssessment(extension, extChanges = [], allowlist = {}, options = {}) {
  const isAllowlisted = Boolean(allowlist[extension.id]?.trusted);
  const exposure = evaluateExposure(extension);
  const suspicion = evaluateSuspicion(extension, extChanges, { ...options, isAllowlisted });

  // Build holistic security flags
  const flags = [];
  const broadHosts = (extension.hostPermissions || []).filter(isBroadHostPermission);
  if (broadHosts.length > 0) {
    flags.push({
      type: 'BROAD_HOST_ACCESS',
      severity: SEVERITY_LEVELS.MEDIUM,
      evidence: broadHosts,
      reasoning: 'Extension requests access to all or widespread websites, allowing it to interact with page content across domains.'
    });
  }

  const sensitiveFound = [];
  for (const perm of (extension.apiPermissions || [])) {
    const meta = SENSITIVE_PERMISSIONS[perm];
    if (meta) {
      sensitiveFound.push({ perm, ...meta });
    }
  }

  if (sensitiveFound.length > 0) {
    const highestWeight = Math.max(...sensitiveFound.map(s => s.weight));
    const sev = highestWeight >= 40 ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM;
    flags.push({
      type: 'SENSITIVE_APIS',
      severity: sev,
      evidence: sensitiveFound.map(s => `${s.perm} (${s.desc})`),
      reasoning: 'Extension holds permissions that allow elevated browser capabilities (inspecting traffic, cookies, or executing scripts).'
    });
  }

  // Composite attack vectors
  const apis = new Set(extension.apiPermissions || []);
  const hasBroadHosts = broadHosts.length > 0;

  if (apis.has('cookies') && (apis.has('webRequest') || apis.has('webRequestBlocking') || hasBroadHosts)) {
    flags.push({
      type: 'COMPOSITE_CREDENTIAL_HIJACKING',
      severity: SEVERITY_LEVELS.HIGH,
      evidence: ['cookies API combined with network interception or broad website scope'],
      reasoning: 'Composite capability: Can read session/auth cookies and intercept HTTP requests or DOM sessions, providing a viable pathway for silent credential exfiltration.'
    });
  }

  if (apis.has('offscreen') && hasBroadHosts) {
    flags.push({
      type: 'COMPOSITE_OFFSCREEN_SCRAPING',
      severity: SEVERITY_LEVELS.HIGH,
      evidence: ['offscreen API combined with broad website host access'],
      reasoning: 'Composite capability: Can instantiate hidden offscreen DOM instances to parse, scrape, or simulate actions across web origins, circumventing standard Manifest V3 background service worker constraints.'
    });
  }

  if (apis.has('debugger') && apis.has('tabs')) {
    flags.push({
      type: 'COMPOSITE_DEBUGGER_INSTRUMENTATION',
      severity: SEVERITY_LEVELS.CRITICAL,
      evidence: ['debugger attached alongside tabs control'],
      reasoning: 'Composite capability: Full browser runtime instrumentation. Can attach DevTools protocol sessions to active tabs, inject arbitrary code, and read memory/DOM structures directly.'
    });
  }

  if (apis.has('nativeMessaging') && (hasBroadHosts || apis.has('cookies') || apis.has('webRequest'))) {
    flags.push({
      type: 'COMPOSITE_NATIVE_EXFILTRATION',
      severity: SEVERITY_LEVELS.HIGH,
      evidence: ['nativeMessaging combined with web interception or credential access'],
      reasoning: 'Composite capability: Interfaces with local operating system binaries while possessing web/cookie interception rights, forming a potential bridge between browser sessions and local OS processes.'
    });
  }

  if (extension.installType === 'development' || extension.installType === 'sideload') {
    flags.push({
      type: 'NON_STORE_INSTALL',
      severity: SEVERITY_LEVELS.MEDIUM,
      evidence: [`installType: ${extension.installType}`],
      reasoning: 'Extension was installed outside the official store (unpacked or sideloaded), bypassing official store automated screening.'
    });
  }

  if (isAllowlisted) {
    flags.push({
      type: 'ANALYST_ALLOWLISTED',
      severity: SEVERITY_LEVELS.INFO,
      evidence: [allowlist[extension.id]?.note || 'Tagged as approved / internal tool'],
      reasoning: 'Extension has been explicitly allowlisted and approved by a security analyst.'
    });
  }

  // Calculate exposure score: broad host alone is 30 (MEDIUM, not HIGH or CRITICAL)
  let score = 0;
  if (broadHosts.length > 0) score += 30;
  for (const s of sensitiveFound) score += s.weight;
  if (apis.has('cookies') && (apis.has('webRequest') || apis.has('webRequestBlocking') || hasBroadHosts)) score += 25;
  if (apis.has('offscreen') && hasBroadHosts) score += 20;
  if (apis.has('debugger') && apis.has('tabs')) score += 30;
  if (apis.has('nativeMessaging') && (hasBroadHosts || apis.has('cookies') || apis.has('webRequest'))) score += 25;
  if (extension.installType === 'development' || extension.installType === 'sideload') score += 20;

  // Calibrate overall review severity while keeping Exposure and Suspicion decoupled
  let severity = SEVERITY_LEVELS.LOW;
  let criticalRuleTriggered = null;

  if (suspicion.level === SUSPICION_LEVELS.SUSPICIOUS) {
    // Concrete suspicious evidence detected under Rule C1
    const hasCriticalLead = options.packageReport?.investigationLeads?.some(l => l.severity === 'CRITICAL');
    if (hasCriticalLead || flags.some(f => f.severity === SEVERITY_LEVELS.CRITICAL)) {
      severity = SEVERITY_LEVELS.CRITICAL;
      criticalRuleTriggered = CRITICAL_EVIDENCE_RULES.C1_ACTIVE_EXFILTRATION;
    } else {
      severity = SEVERITY_LEVELS.HIGH;
    }
  } else if (flags.some(f => f.type === 'COMPOSITE_DEBUGGER_INSTRUMENTATION')) {
    // Explicit Rule C2: Runtime Instrumentation (debugger + tabs)
    severity = SEVERITY_LEVELS.CRITICAL;
    criticalRuleTriggered = CRITICAL_EVIDENCE_RULES.C2_RUNTIME_INSTRUMENTATION;
  } else if (suspicion.level === SUSPICION_LEVELS.REVIEW_REQUIRED) {
    // Unreviewed drift: severity reflects highest unreviewed change priority
    const changeSeverities = extChanges.map(c => c.assessment?.severity || evaluateChangeRisk(c).severity);
    if (changeSeverities.includes(SEVERITY_LEVELS.CRITICAL)) {
      severity = SEVERITY_LEVELS.CRITICAL;
      criticalRuleTriggered = CRITICAL_EVIDENCE_RULES.C4_CRITICAL_SYSTEM_EXPANSION;
    } else if (changeSeverities.includes(SEVERITY_LEVELS.HIGH)) {
      severity = SEVERITY_LEVELS.HIGH;
    } else {
      severity = SEVERITY_LEVELS.MEDIUM;
    }
  } else {
    // No indicators observed (No drift, no suspicious leads)
    // Exposure determines architectural attack surface without implying malice
    if (score >= 70 && exposure.criticalApis.length >= 2) {
      severity = SEVERITY_LEVELS.CRITICAL;
    } else if (score >= 45 || exposure.criticalApis.length > 0) {
      severity = SEVERITY_LEVELS.HIGH;
    } else if (broadHosts.length > 0 || score >= 20) {
      severity = SEVERITY_LEVELS.MEDIUM;
    } else {
      severity = SEVERITY_LEVELS.LOW;
    }
  }

  if (isAllowlisted) {
    severity = SEVERITY_LEVELS.INFO;
  }

  return {
    id: extension.id,
    name: extension.name,
    exposure,
    suspicion,
    exposureLevel: exposure.level,
    suspicionLevel: suspicion.level,
    severity,
    criticalRuleTriggered,
    score,
    flags,
    isAllowlisted,
    allowlistNote: allowlist[extension.id]?.note || ''
  };
}

/**
 * Evaluates the baseline/snapshot risk score of an individual extension.
 * Provides full backward compatibility while delegating to the dual Exposure/Suspicion assessment engine.
 * @param {Object} extension Normalized extension record
 * @param {Record<string, Object>} [allowlist={}] Optional analyst allowlist map
 * @param {Array<Object>} [extChanges=[]] Optional observed changes for this extension
 * @returns {Object} Unified risk and exposure assessment
 */
export function evaluateExtensionRisk(extension, allowlist = {}, extChanges = []) {
  return evaluateExtensionAssessment(extension, extChanges, allowlist);
}

/**
 * Evaluates a single detected change event against security rules.
 * Produces severity, evidence, reasoning, and recommended next steps.
 * @param {Object} change Detected change item from differ.js
 * @returns {Object} Complete explainable risk report
 */
export function evaluateChangeRisk(change) {
  const version = change.extensionVersion || change.details?.to || change.details?.version || 'Current build';

  switch (change.type) {
    // 1. Silent Permission Expansion: Broad Host Permissions
    case CHANGE_TYPES.HOST_PERMISSIONS_EXPANDED: {
      const added = change.details.added || [];
      const hasBroad = added.some(isBroadHostPermission);
      // Broad host expansion triggers an elevated HIGH investigation warning, NOT automatic CRITICAL malice
      const severity = hasBroad ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.MEDIUM;

      const whatChanged = hasBroad 
        ? `Acquired broad website host permissions (${added.join(', ')})`
        : `Added new site host permissions (${added.join(', ')})`;

      const whyItMatters = hasBroad
        ? 'The extension acquired universal web page access (<all_urls> or broad wildcard). While legitimate for ad blockers, reader themes, or developer utilities, universal website scope significantly expands technical attack surface across all browsing sessions. An investigation is required to verify developer intent, but broad host access alone is an exposure metric and does not establish malicious behavior.'
        : 'The extension expanded its website footprint to new domains. Ensure the new domains correspond with expected extension features.';

      const systemCannotDetermine = 'The system cannot inspect encrypted HTTPS payloads in flight or determine whether DOM reads are transmitted to remote third-party command-and-control servers.';

      const recommendations = [
        'Inspect the developer release notes or changelog explaining the new website access.',
        'Consider restricting the extension site access in browser settings to "On click" or specific sites only.',
        'If the extension does not need broad access for its stated purpose, consider keeping it disabled until verified.'
      ];

      return {
        changeKey: change.changeKey,
        severity,
        requiresReview: true,
        title: hasBroad ? 'Broad Website Scope Acquired (Investigation Warning)' : 'New Website Host Permissions Added',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        exposureImpact: hasBroad ? EXPOSURE_LEVELS.BROAD : EXPOSURE_LEVELS.LIMITED,
        suspicionImpact: SUSPICION_LEVELS.REVIEW_REQUIRED,
        evidence: [
          `Newly added hosts: ${added.join(', ')}`,
          `Baseline host permissions: ${change.details.before?.length ? change.details.before.join(', ') : 'None'}`,
          `Current host permissions: ${change.details.after?.length ? change.details.after.join(', ') : added.join(', ')}`,
          `Scope transition: ${change.details.scopeFrom} -> ${change.details.scopeTo}`
        ],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 2. Sensitive API Permissions Added
    case CHANGE_TYPES.PERMISSIONS_EXPANDED: {
      const added = change.details.added || [];
      const criticalAPIs = added.filter(p => ['debugger', 'webRequestBlocking', 'nativeMessaging', 'proxy'].includes(p));
      const highAPIs = added.filter(p => ['cookies', 'scripting', 'webRequest', 'declarativeNetRequestFeedback'].includes(p));
      const mediumAPIs = added.filter(p => ['tabs', 'downloads', 'clipboardRead', 'management', 'geolocation'].includes(p));

      let severity = SEVERITY_LEVELS.LOW;
      let title = 'New Permissions Declared';
      let criticalRule = null;
      if (criticalAPIs.length > 0) {
        severity = SEVERITY_LEVELS.CRITICAL;
        title = 'Critical System APIs Acquired';
        criticalRule = CRITICAL_EVIDENCE_RULES.C4_CRITICAL_SYSTEM_EXPANSION;
      } else if (highAPIs.length > 0) {
        severity = SEVERITY_LEVELS.HIGH;
        title = 'Elevated Privacy/Security APIs Added';
      } else if (mediumAPIs.length > 0) {
        severity = SEVERITY_LEVELS.MEDIUM;
        title = 'Additional Browser Capabilities Requested';
      }

      const whatChanged = `Added ${added.length} new API permission(s): ${added.join(', ')}`;
      const whyItMatters = `The extension added ${added.length} permission(s) that were absent in your saved baseline. Permission expansion is an objective change event indicating updated capabilities.`;
      const systemCannotDetermine = 'The system cannot determine if newly acquired APIs are active in memory or dormant, nor whether backend API credentials or tokens are being transmitted to external servers.';

      const recommendations = [
        'Verify whether the new capabilities align with newly advertised functionality in the extension.',
        'Review recent release notes or web store listing for details.',
        'Review permissions in Chrome Extension manager.'
      ];

      return {
        changeKey: change.changeKey,
        severity,
        criticalRule,
        requiresReview: severity !== SEVERITY_LEVELS.LOW,
        title,
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        exposureImpact: criticalAPIs.length > 0 ? EXPOSURE_LEVELS.EXTENSIVE : (highAPIs.length > 0 ? EXPOSURE_LEVELS.BROAD : EXPOSURE_LEVELS.LIMITED),
        suspicionImpact: severity !== SEVERITY_LEVELS.LOW ? SUSPICION_LEVELS.REVIEW_REQUIRED : SUSPICION_LEVELS.NO_INDICATORS,
        evidence: [
          `Newly added API permissions: ${added.join(', ')}`,
          `Baseline API permissions: ${change.details.before?.length ? change.details.before.join(', ') : 'None'}`,
          `Current API permissions: ${change.details.after?.length ? change.details.after.join(', ') : added.join(', ')}`,
          ...added.map(p => {
            const meta = SENSITIVE_PERMISSIONS[p];
            return meta ? `${p} - ${meta.desc}` : p;
          })
        ],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 3. Newly Installed Extension
    case CHANGE_TYPES.EXTENSION_ADDED: {
      const perms = change.details.permissions || [];
      const hasBroad = perms.some(isBroadHostPermission);
      const criticalAPIs = perms.filter(p => ['debugger', 'webRequestBlocking', 'nativeMessaging', 'proxy'].includes(p));
      const sensitiveAPIs = perms.filter(p => ['cookies', 'scripting', 'webRequest', 'declarativeNetRequestFeedback'].includes(p));
      const isNonStore = (change.details.installType === 'sideload' || change.details.installType === 'development');

      let severity = SEVERITY_LEVELS.LOW;
      let requiresReview = Boolean(hasBroad || criticalAPIs.length > 0 || isNonStore);
      let title = 'Standard Extension Installed';

      if (isNonStore && (hasBroad || criticalAPIs.length > 0)) {
        severity = SEVERITY_LEVELS.HIGH;
        title = 'Non-Store Extension Installed with Elevated Scope';
      } else if (hasBroad) {
        severity = SEVERITY_LEVELS.MEDIUM;
        title = 'New Extension Requests Broad Website Access';
      } else if (criticalAPIs.length > 0) {
        severity = SEVERITY_LEVELS.MEDIUM;
        title = 'New Extension Declares Critical System APIs';
      } else if (sensitiveAPIs.length > 0) {
        severity = SEVERITY_LEVELS.MEDIUM;
        title = 'New Extension Declares Elevated Capabilities';
      } else {
        severity = SEVERITY_LEVELS.LOW;
        title = 'Standard Extension Installed';
      }

      const whatChanged = `New extension detected in browser: ${change.extensionName} (v${change.details.version})`;
      const whyItMatters = hasBroad
        ? 'The extension requests broad or universal website access. Broad website access is an architectural risk indicator and increases attack surface, but is not proof of malicious behavior. Confirm whether broad domain access is expected for the extension stated features.'
        : 'A newly installed extension adds code to your browser environment. Confirm that this installation was intentional.';
      const systemCannotDetermine = 'The system cannot verify publisher business credibility, server-side backend behavior, or whether background scripts transmit encrypted payloads.';

      const recommendations = [
        'Confirm you intended to install this extension.',
        hasBroad 
          ? 'Review site access permissions in browser settings (e.g. restrict to "On click" if broad access is unnecessary).' 
          : 'Check that the extension publisher and store ID match the intended official author.',
        'Record a fresh baseline once you are satisfied with this installation.'
      ];

      return {
        changeKey: change.changeKey,
        severity,
        requiresReview,
        title,
        whatChanged,
        introducedInVersion: change.details.version || version,
        whyItMatters,
        reasoning: whyItMatters,
        exposureImpact: (hasBroad && criticalAPIs.length > 0) ? EXPOSURE_LEVELS.EXTENSIVE : (hasBroad ? EXPOSURE_LEVELS.BROAD : EXPOSURE_LEVELS.LIMITED),
        suspicionImpact: requiresReview ? SUSPICION_LEVELS.REVIEW_REQUIRED : SUSPICION_LEVELS.NO_INDICATORS,
        evidence: [
          `Version: ${change.details.version}`,
          `Website scope: ${change.details.websiteScope}`,
          `Declared permissions: ${perms.length > 0 ? perms.join(', ') : 'None'}`
        ],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 4. Version Update
    case CHANGE_TYPES.VERSION_CHANGED: {
      const isDowngrade = change.direction === 'downgrade';
      const severity = isDowngrade ? SEVERITY_LEVELS.HIGH : SEVERITY_LEVELS.LOW;

      const whatChanged = `Version transitioned from ${change.details.from} to ${change.details.to} (${change.direction})`;
      const whyItMatters = isDowngrade
        ? 'Version downgrading is unusual in browser extensions and could indicate replacement with an older vulnerable build or an unintended side-channel installation.'
        : 'Routine software update. Software updates are standard for bug fixes and feature enhancements, but code behavior should be monitored if permissions also changed.';

      const systemCannotDetermine = 'The system cannot decompile minified differences or observe runtime execution without performing a source package inspection in the Package Analyzer.';

      const recommendations = isDowngrade
        ? ['Investigate why the extension version rolled backward.', 'Re-install from the official Web Store if in doubt.']
        : ['No urgent action required unless accompanied by permission creep.'];

      return {
        changeKey: change.changeKey,
        severity,
        requiresReview: isDowngrade,
        title: isDowngrade ? 'Extension Version Downgraded' : 'Extension Updated',
        whatChanged,
        introducedInVersion: change.details.to || version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: [
          `Previous: ${change.details.from}`,
          `Current: ${change.details.to}`,
          `Direction: ${change.direction}`
        ],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 5. Install Type Changed (e.g. Normal -> Sideload/Dev)
    case CHANGE_TYPES.INSTALL_TYPE_CHANGED: {
      const whatChanged = `Distribution channel modified from ${change.details.from} to ${change.details.to}`;
      const whyItMatters = 'The extension source mechanism changed (for instance, converted to an unpacked developer directory or sideloaded from external software). Unpacked extensions do not receive official store verification.';
      const systemCannotDetermine = 'The system cannot identify which local application altered the extension registration in browser preferences or Windows Registry / macOS plist.';

      const recommendations = [
        'Verify if you loaded this extension in Developer Mode.',
        'Check local filesystem directory to ensure unauthorized modifications did not occur.'
      ];

      return {
        changeKey: change.changeKey,
        severity: SEVERITY_LEVELS.HIGH,
        requiresReview: true,
        title: 'Extension Install Type Modified',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: [
          `Previous source: ${change.details.from}`,
          `New source: ${change.details.to}`
        ],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 6. Extension Enabled
    case CHANGE_TYPES.STATUS_ENABLED: {
      const whatChanged = 'Extension transitioned from inactive/disabled to active';
      const whyItMatters = 'An extension that was previously inactive is now running and able to execute background code and inspect matched pages.';
      const systemCannotDetermine = 'The system cannot determine if re-enabling was triggered manually by the user or by an external automation tool.';
      const recommendations = [
        'Verify you intentionally enabled this extension.',
        'Ensure the extension remains relevant to your current workflow.'
      ];

      return {
        changeKey: change.changeKey,
        severity: SEVERITY_LEVELS.MEDIUM,
        requiresReview: true,
        title: 'Extension Re-enabled',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: ['Status transitioned from disabled to active'],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 7. Extension Disabled
    case CHANGE_TYPES.STATUS_DISABLED: {
      const whatChanged = 'Extension disabled and deactivated';
      const whyItMatters = 'The extension was turned off. Inactive extensions cannot execute background scripts or access web pages.';
      const systemCannotDetermine = 'The system cannot detect if the extension was disabled due to a crash, store deprecation, or manual user toggle.';
      const recommendations = ['No action required.'];

      return {
        changeKey: change.changeKey,
        severity: SEVERITY_LEVELS.INFO,
        requiresReview: false,
        title: 'Extension Disabled',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: ['Status transitioned from active to disabled'],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 8. Extension Removed
    case CHANGE_TYPES.EXTENSION_REMOVED: {
      const whatChanged = `Extension uninstalled: ${change.extensionName}`;
      const whyItMatters = 'The extension was removed from the browser. Attack surface has been reduced.';
      const systemCannotDetermine = 'The system cannot determine if local storage files or caches left behind on disk were completely purged.';
      const recommendations = ['Update your baseline to reflect the removal.'];

      return {
        changeKey: change.changeKey,
        severity: SEVERITY_LEVELS.INFO,
        requiresReview: false,
        title: 'Extension Uninstalled',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: [`Last known version: ${change.details.version}`],
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 9. Permissions Reduced
    case CHANGE_TYPES.PERMISSIONS_REDUCED:
    case CHANGE_TYPES.HOST_PERMISSIONS_REDUCED: {
      const whatChanged = change.summary;
      const whyItMatters = 'The extension reduced its permissions or website access, decreasing its exposure surface.';
      const systemCannotDetermine = 'The system cannot confirm whether this was a developer refactor or removal of an unused feature module.';
      const recommendations = ['Positive security hygiene; no action required.'];

      return {
        changeKey: change.changeKey,
        severity: SEVERITY_LEVELS.INFO,
        requiresReview: false,
        title: 'Permissions Restricted / Reduced',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: change.summary,
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }

    // 10. Benign Metadata Updates
    default: {
      const whatChanged = `Updated non-functional metadata (${change.details?.changedFields?.join(', ') || 'fields'})`;
      const whyItMatters = 'Non-functional metadata (e.g. extension description, homepage link) changed. This does not alter runtime execution permissions.';
      const systemCannotDetermine = 'The system cannot inspect marketing copy intent or translation nuances.';
      const recommendations = ['Routine update; no action required.'];

      return {
        changeKey: change.changeKey,
        severity: SEVERITY_LEVELS.INFO,
        requiresReview: false,
        title: 'Metadata Field Updated',
        whatChanged,
        introducedInVersion: version,
        whyItMatters,
        reasoning: whyItMatters,
        evidence: change.summary,
        systemCannotDetermine,
        whatToInvestigateNext: recommendations,
        recommendations
      };
    }
  }
}

/**
 * Evaluates an entire list of changes, attaching the explainable risk assessment to each.
 * @param {Array<Object>} changes 
 * @param {Record<string, Object>} [allowlist={}] Optional analyst allowlist map
 * @returns {Array<Object>} Enriched change items with full security audit metadata
 */
export function evaluateAllChanges(changes = [], allowlist = {}) {
  return changes.map(change => {
    const assessment = evaluateChangeRisk(change);
    const isAllowlisted = Boolean(allowlist[change.extensionId]?.trusted);
    if (isAllowlisted) {
      assessment.isAllowlisted = true;
      assessment.allowlistNote = allowlist[change.extensionId]?.note || '';
    }
    return {
      ...change,
      assessment
    };
  });
}
