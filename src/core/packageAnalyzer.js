/**
 * ExtensionLedger - Local Package Static Analysis Engine
 * Safely analyzes unpacked extension ZIP archives in-memory without executing code.
 * Detects manifest changes, file tree deltas, and sensitive pattern investigation leads.
 */

import { parseZip } from '../lib/zipReader.js';
import { calculateShannonEntropy } from './cryptoUtils.js';

export const PATTERN_CATEGORIES = {
  DYNAMIC_EXECUTION: 'Dynamic Code Execution',
  NETWORK_DESTINATION: 'Remote Network Endpoint',
  CREDENTIAL_ACCESS: 'Sensitive Data & Credential Access',
  BROWSER_INTERCEPTION: 'Browser API & DOM Interception',
  OBFUSCATION: 'Potential Code Obfuscation',
  DATA_EXFILTRATION: 'Data Exfiltration Webhook / Secret',
  CUSTOM_ANALYST_RULE: 'Custom Analyst Detection Rule'
};

// Security inspection pattern definitions
const STATIC_PATTERNS = [
  {
    category: PATTERN_CATEGORIES.DATA_EXFILTRATION,
    severity: 'CRITICAL',
    regex: /https:\/\/(?:discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot)[^\s'"`,;)]+/g,
    description: 'Embedded Discord Webhook or Telegram Bot API URL. Frequently weaponized by info-stealers and malicious extensions to exfiltrate stolen credentials.',
    recommendation: 'Immediate investigation required: verify why extension is transmitting data to messaging bots.'
  },
  {
    category: PATTERN_CATEGORIES.DYNAMIC_EXECUTION,
    severity: 'HIGH',
    regex: /\b(eval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*['"`]|setInterval\s*\(\s*['"`])/g,
    description: 'Dynamic JavaScript execution construct. Could allow runtime execution of arbitrary or remote code strings.',
    recommendation: 'Verify if input strings are statically defined or dynamically retrieved.'
  },
  {
    category: PATTERN_CATEGORIES.DYNAMIC_EXECUTION,
    severity: 'HIGH',
    regex: /\b(eval\s*\(\s*atob\s*\(|atob\s*\([^)]+\)\s*\[\s*['"`]constructor['"`]\s*\])/g,
    description: 'Dynamic decode-and-execute chain (eval + atob). Classic obfuscated dropper pattern.',
    recommendation: 'Decode and de-obfuscate payload to determine underlying intent.'
  },
  {
    category: PATTERN_CATEGORIES.DYNAMIC_EXECUTION,
    severity: 'HIGH',
    regex: /\b(document\.write\s*\(|innerHTML\s*=\s*[^;]+)/g,
    description: 'Raw HTML insertion into DOM without explicit escaping. Potential DOM XSS vulnerability vector.',
    recommendation: 'Check if sanitized via textContent or DOMPurify.'
  },
  {
    category: PATTERN_CATEGORIES.NETWORK_DESTINATION,
    severity: 'MEDIUM',
    regex: /https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:\/[^\s'"`,;)]*)?/g,
    description: 'Hardcoded external HTTP/HTTPS URL destination.',
    filter: (match) => {
      // Filter out standard schema/spec URLs
      const lower = match.toLowerCase();
      return !lower.includes('w3.org') &&
             !lower.includes('schema.org') &&
             !lower.includes('developer.chrome.com') &&
             !lower.includes('github.com');
    },
    recommendation: 'Verify that this remote endpoint is a legitimate API or telemetry server belonging to the extension author.'
  },
  {
    category: PATTERN_CATEGORIES.NETWORK_DESTINATION,
    severity: 'HIGH',
    regex: /\b(new\s+WebSocket\s*\(|navigator\.sendBeacon\s*\(|fetch\s*\(\s*`[^`]*\${)/g,
    description: 'WebSocket or dynamic outbound data beacon.',
    recommendation: 'Check whether telemetry or user actions are transmitted to third-party endpoints.'
  },
  {
    category: PATTERN_CATEGORIES.CREDENTIAL_ACCESS,
    severity: 'HIGH',
    regex: /\b(chrome\.cookies\.(get|getAll|set)|document\.cookie|sessionStorage|localStorage\.(getItem|setItem))\b/g,
    description: 'Direct access to authentication session cookies or local browser storage tokens.',
    recommendation: 'Ensure cookies are accessed solely for intended user session features and not exfiltrated.'
  },
  {
    category: PATTERN_CATEGORIES.BROWSER_INTERCEPTION,
    severity: 'HIGH',
    regex: /\b(chrome\.scripting\.executeScript|chrome\.tabs\.executeScript|chrome\.debugger|chrome\.webRequest)\b/g,
    description: 'Script injection or deep browser request interception API invocation.',
    recommendation: 'Examine injected scripts to confirm they perform user-demanded page enhancements only.'
  },
  {
    category: PATTERN_CATEGORIES.OBFUSCATION,
    severity: 'MEDIUM',
    regex: /\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}/g,
    description: 'Consecutive hexadecimal byte escapes. Often indicates obfuscated strings or encoded payloads.',
    recommendation: 'Decode hex literals to confirm harmless static text or asset strings.'
  },
  {
    category: PATTERN_CATEGORIES.OBFUSCATION,
    severity: 'MEDIUM',
    regex: /\batob\s*\(\s*['"`][A-Za-z0-9+/=]{24,}['"`]\s*\)/g,
    description: 'Decodes a hardcoded Base64 payload of significant length.',
    recommendation: 'Inspect decoded base64 contents.'
  }
];

/**
 * Scans source code text for static security pattern leads.
 * @param {string} code 
 * @param {string} filename 
 * @param {Array<Object>} [customRules=[]] Optional analyst-defined regex rules
 * @returns {Array<Object>}
 */
export function scanCodeForPatterns(code, filename, customRules = []) {
  if (!code || typeof code !== 'string') return [];
  const lines = code.split(/\r?\n/);
  const leads = [];

  const allRules = [...STATIC_PATTERNS];
  for (const cr of customRules) {
    if (cr && cr.regex) {
      allRules.push({
        category: cr.category || PATTERN_CATEGORIES.CUSTOM_ANALYST_RULE,
        severity: cr.severity || 'HIGH',
        regex: cr.regex instanceof RegExp ? cr.regex : new RegExp(cr.regex, 'g'),
        description: cr.description || 'Matched custom analyst rule.',
        recommendation: cr.recommendation || 'Inspect matched pattern in source code.'
      });
    }
  }

  for (const patternDef of allRules) {
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      // Skip excessively long compiled lines to prevent regex lockup
      if (line.length > 5000) continue;

      let match;
      const regex = new RegExp(patternDef.regex.source, patternDef.regex.flags);
      while ((match = regex.exec(line)) !== null) {
        const matchedText = match[0];
        if (patternDef.filter && !patternDef.filter(matchedText)) {
          continue;
        }

        leads.push({
          category: patternDef.category,
          severity: patternDef.severity,
          file: filename,
          line: lineIdx + 1,
          matched: matchedText.length > 80 ? matchedText.slice(0, 77) + '...' : matchedText,
          preview: line.trim().slice(0, 140),
          description: patternDef.description,
          recommendation: patternDef.recommendation
        });

        // Limit matches per line per pattern to 3
        if (leads.length > 150) break;
      }
    }
  }

  return leads;
}

/**
 * Inspects a single extension package buffer
 * @param {ArrayBuffer|Uint8Array} zipBuffer 
 * @param {string} filename 
 * @param {Object} [options={}]
 * @param {Array<Object>} [options.customRules=[]] Custom regex rules
 * @returns {Promise<Object>} Package audit summary
 */
export async function analyzeSinglePackage(zipBuffer, filename = 'extension.zip', options = {}) {
  const archive = await parseZip(zipBuffer);
  const manifest = await archive.readManifest();
  const fileNames = archive.getFileNames();

  const binaryOrSuspiciousFiles = fileNames.filter(f => {
    const ext = f.split('.').pop()?.toLowerCase();
    return ['exe', 'dll', 'so', 'dylib', 'bin', 'wasm', 'bat', 'sh', 'vbs'].includes(ext);
  });

  // Extract declared permissions & hosts from manifest
  const permissions = manifest?.permissions || [];
  const hostPermissions = manifest?.host_permissions || [];
  const contentScripts = manifest?.content_scripts || [];
  const background = manifest?.background || null;

  // Scan text/source files (limit to first 60 source files to keep fast)
  const sourceExtensions = ['.js', '.mjs', '.ts', '.html', '.htm', '.json'];
  const sourceFiles = fileNames.filter(f => 
    sourceExtensions.some(ext => f.toLowerCase().endsWith(ext))
  ).slice(0, 60);

  const allLeads = [];
  const endpoints = new Set();
  const fileMetrics = [];

  // Manifest V3 compatibility checks
  const isMV3 = (manifest?.manifest_version === 3);
  if (isMV3 && permissions.includes('webRequestBlocking')) {
    allLeads.push({
      category: 'Manifest V3 Compatibility',
      severity: 'HIGH',
      file: 'manifest.json',
      line: 1,
      matched: 'permissions: ["webRequestBlocking"]',
      preview: '"permissions": [..."webRequestBlocking"...]',
      description: 'Manifest V3 restricts "webRequestBlocking". In Google Chrome MV3, blocking web requests is restricted to enterprise-policy force-installed extensions; store extensions must migrate to declarativeNetRequest.',
      recommendation: 'Replace webRequestBlocking with declarativeNetRequest or declarativeNetRequestWithHostAccess for Chrome MV3 compliance.'
    });
  }

  for (const sf of sourceFiles) {
    try {
      const entry = archive.getEntry(sf);
      if (entry && entry.uncompressedSize < 1024 * 1024) { // only scan files < 1MB
        const text = await entry.readText();
        
        // Calculate Shannon Entropy
        const entropy = calculateShannonEntropy(text);
        const isElevatedEntropy = entropy >= 5.8;
        fileMetrics.push({
          file: sf,
          size: entry.uncompressedSize,
          entropy,
          isElevatedEntropy
        });

        if (isElevatedEntropy) {
          allLeads.push({
            category: PATTERN_CATEGORIES.OBFUSCATION,
            severity: entropy > 6.4 ? 'HIGH' : 'MEDIUM',
            file: sf,
            line: 1,
            matched: `High Shannon Entropy (${entropy})`,
            preview: `Information density score: ${entropy} / 8.0`,
            description: `File exhibits unusually high information entropy (${entropy}), characteristic of packed JavaScript, heavy string encryption, or embedded binary ciphertext.`,
            recommendation: 'Inspect file manually for eval unpackers, hexadecimal arrays, or steganographic scripts.'
          });
        }

        const fileLeads = scanCodeForPatterns(text, sf, options.customRules || []);
        allLeads.push(...fileLeads);

        // Collect URLs
        for (const lead of fileLeads) {
          if (lead.category === PATTERN_CATEGORIES.NETWORK_DESTINATION && lead.matched.startsWith('http')) {
            endpoints.add(lead.matched);
          }
        }
      }
    } catch {
      // Ignore unreadable entries
    }
  }

  return {
    filename,
    manifestFound: !!manifest,
    manifest: manifest || {},
    manifestVersion: manifest?.manifest_version || (manifest ? 2 : 'unknown'),
    extensionName: manifest?.name || filename,
    version: manifest?.version || 'unknown',
    permissions,
    hostPermissions,
    contentScriptsCount: contentScripts.length,
    hasBackgroundWorker: Boolean(background?.service_worker || background?.scripts),
    totalFiles: fileNames.length,
    fileNames,
    fileMetrics,
    binaryOrSuspiciousFiles,
    investigationLeads: allLeads,
    discoveredEndpoints: Array.from(endpoints),
    analyzedAt: new Date().toISOString()
  };
}

/**
 * Safely compares two extension ZIP packages (v1 vs v2).
 * Pinpoints added/removed permissions, manifest adjustments, modified files,
 * and newly introduced suspicious code patterns.
 * 
 * @param {ArrayBuffer|Uint8Array} bufferA Baseline package
 * @param {ArrayBuffer|Uint8Array} bufferB Target package
 * @param {string} nameA 
 * @param {string} nameB 
 * @returns {Promise<Object>} Differential analysis report
 */
export async function comparePackages(bufferA, bufferB, nameA = 'v1.zip', nameB = 'v2.zip', options = {}) {
  const [pkgA, pkgB] = await Promise.all([
    analyzeSinglePackage(bufferA, nameA, options),
    analyzeSinglePackage(bufferB, nameB, options)
  ]);

  // 1. Manifest permission diff
  const permsA = new Set([...(pkgA.permissions || []), ...(pkgA.hostPermissions || [])]);
  const permsB = new Set([...(pkgB.permissions || []), ...(pkgB.hostPermissions || [])]);

  const addedPermissions = [...permsB].filter(p => !permsA.has(p));
  const removedPermissions = [...permsA].filter(p => !permsB.has(p));

  // 2. Manifest fields diff
  const manifestFieldChanges = [];
  if (pkgA.version !== pkgB.version) {
    manifestFieldChanges.push({ field: 'version', from: pkgA.version, to: pkgB.version });
  }
  if (pkgA.manifestVersion !== pkgB.manifestVersion) {
    manifestFieldChanges.push({ field: 'manifest_version', from: pkgA.manifestVersion, to: pkgB.manifestVersion });
  }
  if (pkgA.contentScriptsCount !== pkgB.contentScriptsCount) {
    manifestFieldChanges.push({ field: 'content_scripts count', from: pkgA.contentScriptsCount, to: pkgB.contentScriptsCount });
  }

  // 3. File tree diff
  const filesA = new Set(pkgA.fileNames);
  const filesB = new Set(pkgB.fileNames);

  const addedFiles = [...filesB].filter(f => !filesA.has(f));
  const removedFiles = [...filesA].filter(f => !filesB.has(f));
  const retainedFiles = [...filesB].filter(f => filesA.has(f));

  // 4. Code Leads Delta: Leads present in B that were NOT in A
  const existingLeadSignatures = new Set(
    pkgA.investigationLeads.map(l => `${l.category}::${l.matched}`)
  );

  const newLeads = pkgB.investigationLeads.filter(
    l => !existingLeadSignatures.has(`${l.category}::${l.matched}`)
  );

  // New network endpoints
  const oldEndpoints = new Set(pkgA.discoveredEndpoints);
  const newEndpoints = pkgB.discoveredEndpoints.filter(ep => !oldEndpoints.has(ep));

  // Risk evaluation summary
  const hasAddedBroadHosts = addedPermissions.some(p => p === '<all_urls>' || p === '*://*/*');
  const hasAddedCriticalPerms = addedPermissions.some(p => ['debugger', 'webRequestBlocking', 'cookies', 'scripting', 'nativeMessaging'].includes(p));
  const hasNewDynamicCode = newLeads.some(l => l.category === PATTERN_CATEGORIES.DYNAMIC_EXECUTION);

  let overallSeverity = 'LOW';
  if (hasAddedBroadHosts || hasAddedCriticalPerms) {
    overallSeverity = 'CRITICAL';
  } else if (hasNewDynamicCode || addedPermissions.length > 0 || newEndpoints.length > 0) {
    overallSeverity = 'HIGH';
  } else if (addedFiles.length > 0 || manifestFieldChanges.length > 0) {
    overallSeverity = 'MEDIUM';
  }

  return {
    packageA: { name: nameA, version: pkgA.version, totalFiles: pkgA.totalFiles },
    packageB: { name: nameB, version: pkgB.version, totalFiles: pkgB.totalFiles },
    overallSeverity,
    addedPermissions,
    removedPermissions,
    manifestFieldChanges,
    addedFiles,
    removedFiles,
    modifiedOrRetainedCount: retainedFiles.length,
    newInvestigationLeads: newLeads,
    allLeadsVersionB: pkgB.investigationLeads,
    newDiscoveredEndpoints: newEndpoints,
    analyzedAt: new Date().toISOString()
  };
}
