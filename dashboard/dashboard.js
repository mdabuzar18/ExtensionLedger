/**
 * ExtensionLedger - Security Intelligence Dashboard Controller
 * Foundation: Watchlist, Change Intelligence, Version Diff Explorer, Security Investigation & Package Analyzer
 */

import { getInventory } from '../src/core/inventory.js';
import { 
  getBaseline, 
  saveBaseline, 
  getSnapshotHistory, 
  getReviewedChanges, 
  markChangeAsReviewed, 
  unmarkChangeReviewed,
  reopenChangeReview,
  isFindingReviewed,
  getLifecycleEvents,
  getAllowlist,
  setExtensionAllowlist,
  removeExtensionAllowlist,
  isExtensionAllowlisted,
  switchActiveBaseline,
  exportAuditDossier,
  importAuditDossier,
  exportReportAsMarkdown,
  exportReportAsCSV,
  clearAllAuditData 
} from '../src/core/storage.js';
import { diffSnapshots, CHANGE_TYPES } from '../src/core/differ.js';
import { evaluateAllChanges, evaluateExtensionRisk, evaluateExtensionAssessment, SEVERITY_LEVELS, EXPOSURE_LEVELS, SUSPICION_LEVELS } from '../src/core/riskEngine.js';
import { analyzeSinglePackage, comparePackages } from '../src/core/packageAnalyzer.js';
import { SYNTHETIC_SCENARIOS, base64ToUint8Array } from '../src/core/syntheticData.js';
import { 
  updateBadge, 
  detectRuntimeContext, 
  RUNTIME_CONTEXTS,
  detectBrowserIdentity,
  detectExecutionContext,
  getSystemStatus,
  checkExtensionConnection,
  isExtensionEnvironment,
  BROWSER_NAMES,
  EXECUTION_CONTEXTS,
  DATA_SOURCES,
  uninstallExtension,
  getBrowserManagementUrl 
} from '../src/core/browserApi.js';

// Application State
const state = {
  currentInventory: [],
  baseline: null,
  allChanges: [],
  reviewedMap: {},
  allowlist: {},
  baselineHistory: [],
  activeTab: 'tab-watchlist',
  selectedExtensionId: null,
  selectedFindingKey: null,
  activeReviewFindingKey: null,
  isUninstalling: false,
  runtimeContext: RUNTIME_CONTEXTS.WEB_STANDALONE,
  browser: { name: 'Unknown', displayName: 'Detecting...', isChromium: false },
  execContext: { context: 'STANDALONE_WEB', displayName: 'Standalone Dashboard', isExtensionContext: false },
  hasLiveConnection: false,
  analyzer: {
    mode: 'compare',
    fileA: null,
    fileB: null,
    customRules: []
  }
};

// DOM References
const elements = {
  // Topbar & Ticker
  environmentTag: document.getElementById('environmentTag'),
  standaloneContextBanner: document.getElementById('standaloneContextBanner'),
  standaloneBannerTitle: document.getElementById('standaloneBannerTitle'),
  standaloneBannerText: document.getElementById('standaloneBannerText'),
  tickerWatchlistCount: document.getElementById('tickerWatchlistCount'),
  tickerPendingCount: document.getElementById('tickerPendingCount'),
  tickerHighRiskCount: document.getElementById('tickerHighRiskCount'),
  tickerSuspiciousCount: document.getElementById('tickerSuspiciousCount'),
  tickerExtensiveCount: document.getElementById('tickerExtensiveCount'),
  tickerBaselineStatus: document.getElementById('tickerBaselineStatus'),
  btnCaptureBaseline: document.getElementById('btnCaptureBaseline'),
  btnManageBaselines: document.getElementById('btnManageBaselines'),
  btnExportImport: document.getElementById('btnExportImport'),
  btnScanRefresh: document.getElementById('btnScanRefresh'),
  spinIcon: document.querySelector('.spin-icon'),

  // Operational Notice Banner
  generalNoticeBanner: document.getElementById('generalNoticeBanner'),
  generalNoticeMsg: document.getElementById('generalNoticeMsg'),
  btnCloseGeneralNotice: document.getElementById('btnCloseGeneralNotice'),

  // Navigation Links
  navLinks: document.querySelectorAll('.nav-link'),
  panelSections: document.querySelectorAll('.panel-section'),
  navWatchlistBadge: document.getElementById('navWatchlistBadge'),
  navTimelineBadge: document.getElementById('navTimelineBadge'),
  navInvestigationBadge: document.getElementById('navInvestigationBadge'),

  // Section A: Watchlist
  watchlistSearchInput: document.getElementById('watchlistSearchInput'),
  watchlistScopeFilter: document.getElementById('watchlistScopeFilter'),
  watchlistRoster: document.getElementById('watchlistRoster'),
  watchlistDossier: document.getElementById('watchlistDossier'),

  // Section B: Change Intelligence Timeline
  timelineSeverityFilter: document.getElementById('timelineSeverityFilter'),
  timelineReviewFilter: document.getElementById('timelineReviewFilter'),
  timelineStreamContainer: document.getElementById('timelineStreamContainer'),

  // Section D: Security Investigation
  investigationSeverityFilter: document.getElementById('investigationSeverityFilter'),
  investigationStatusFilter: document.getElementById('investigationStatusFilter'),
  findingsRoster: document.getElementById('findingsRoster'),
  findingDossier: document.getElementById('findingDossier'),

  // Section C: Version Diff Explorer
  diffExtensionSelect: document.getElementById('diffExtensionSelect'),
  diffVersionMeta: document.getElementById('diffVersionMeta'),
  diffManifestBefore: document.getElementById('diffManifestBefore'),
  diffManifestAfter: document.getElementById('diffManifestAfter'),
  networkEndpointCountBadge: document.getElementById('networkEndpointCountBadge'),
  networkGraphCanvas: document.getElementById('networkGraphCanvas'),

  // Section E: Package Analyzer
  btnLoadFixturePackages: document.getElementById('btnLoadFixturePackages'),
  modeTabs: document.querySelectorAll('.mode-tab'),
  pkgDropA: document.getElementById('pkgDropA'),
  pkgDropB: document.getElementById('pkgDropB'),
  pkgFileInputA: document.getElementById('pkgFileInputA'),
  pkgFileInputB: document.getElementById('pkgFileInputB'),
  pkgDropTitleA: document.getElementById('pkgDropTitleA'),
  pkgDropTitleB: document.getElementById('pkgDropTitleB'),
  pkgFileNameA: document.getElementById('pkgFileNameA'),
  pkgFileNameB: document.getElementById('pkgFileNameB'),
  btnRunPackageAnalysis: document.getElementById('btnRunPackageAnalysis'),
  pkgAnalysisResultsArea: document.getElementById('pkgAnalysisResultsArea'),
  pkgCustomRuleRegex: document.getElementById('pkgCustomRuleRegex'),
  pkgCustomRuleDesc: document.getElementById('pkgCustomRuleDesc'),

  // Modals
  reviewDetailModal: document.getElementById('reviewDetailModal'),
  btnCloseReviewModal: document.getElementById('btnCloseReviewModal'),
  btnReviewModalDone: document.getElementById('btnReviewModalDone'),
  btnModalToggleReview: document.getElementById('btnModalToggleReview'),
  btnModalToggleAllowlist: document.getElementById('btnModalToggleAllowlist'),
  btnModalAllowlistText: document.getElementById('btnModalAllowlistText'),
  reviewModalIcon: document.getElementById('reviewModalIcon'),
  reviewModalTitle: document.getElementById('reviewModalTitle'),
  reviewModalOriginBadge: document.getElementById('reviewModalOriginBadge'),
  reviewModalSub: document.getElementById('reviewModalSub'),
  reviewModalStatusBadge: document.getElementById('reviewModalStatusBadge'),
  reviewModalTimestamp: document.getElementById('reviewModalTimestamp'),
  reviewModalScope: document.getElementById('reviewModalScope'),
  reviewModalInstallType: document.getElementById('reviewModalInstallType'),
  reviewModalApiChips: document.getElementById('reviewModalApiChips'),
  reviewModalHostChips: document.getElementById('reviewModalHostChips'),
  reviewModalDiffContent: document.getElementById('reviewModalDiffContent'),
  reviewModalFindingsContent: document.getElementById('reviewModalFindingsContent'),
  reviewModalUncertainty: document.getElementById('reviewModalUncertainty'),
  reviewModalRecommendations: document.getElementById('reviewModalRecommendations'),
  reviewModalUninstallSlot: document.getElementById('reviewModalUninstallSlot'),

  // Baseline Manager Modal
  baselineManagerModal: document.getElementById('baselineManagerModal'),
  btnCloseBaselineModal: document.getElementById('btnCloseBaselineModal'),
  btnCloseBaselineModalDone: document.getElementById('btnCloseBaselineModalDone'),
  btnBaselineModalCaptureNew: document.getElementById('btnBaselineModalCaptureNew'),
  baselineManagerActiveCard: document.getElementById('baselineManagerActiveCard'),
  baselineHistoryList: document.getElementById('baselineHistoryList'),

  // Export & Import Modal
  exportImportModal: document.getElementById('exportImportModal'),
  btnCloseExportModal: document.getElementById('btnCloseExportModal'),
  btnCloseExportModalDone: document.getElementById('btnCloseExportModalDone'),
  btnDownloadJsonDossier: document.getElementById('btnDownloadJsonDossier'),
  btnDownloadMarkdownReport: document.getElementById('btnDownloadMarkdownReport'),
  btnDownloadCsvReport: document.getElementById('btnDownloadCsvReport'),
  btnTriggerImportDossier: document.getElementById('btnTriggerImportDossier'),
  importDossierFileInput: document.getElementById('importDossierFileInput')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  handleUrlHashRouting();
  loadData();
});

function initEventListeners() {
  // Navigation Tabs
  elements.navLinks.forEach(link => {
    link.addEventListener('click', () => {
      switchTab(link.dataset.tab);
    });
  });

  // Top Actions
  elements.btnScanRefresh.addEventListener('click', () => loadData(true));
  elements.btnCaptureBaseline.addEventListener('click', handleCaptureBaseline);
  elements.btnManageBaselines?.addEventListener('click', openBaselineManager);
  elements.btnExportImport?.addEventListener('click', openExportImportModal);
  elements.btnCloseGeneralNotice.addEventListener('click', () => {
    elements.generalNoticeBanner.style.display = 'none';
  });

  // Watchlist Filters
  elements.watchlistSearchInput.addEventListener('input', renderWatchlist);
  elements.watchlistScopeFilter.addEventListener('change', renderWatchlist);

  // Timeline Filters
  elements.timelineSeverityFilter.addEventListener('change', renderTimeline);
  elements.timelineReviewFilter.addEventListener('change', renderTimeline);

  // Investigation Filters
  elements.investigationSeverityFilter.addEventListener('change', renderInvestigation);
  elements.investigationStatusFilter.addEventListener('change', renderInvestigation);

  // Version Diff Explorer Extension Selector
  elements.diffExtensionSelect.addEventListener('change', () => {
    state.selectedExtensionId = elements.diffExtensionSelect.value;
    renderDiffExplorer();
  });

  // Package Analyzer Handlers
  elements.modeTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      elements.modeTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      setAnalyzerMode(tab.dataset.mode);
    });
  });

  setupDropZone(elements.pkgDropA, elements.pkgFileInputA, (file) => {
    state.analyzer.fileA = file;
    elements.pkgFileNameA.textContent = `${file.name} (${formatBytes(file.size)})`;
    elements.pkgFileNameA.style.display = 'inline-block';
    checkAnalyzerReady();
  });

  setupDropZone(elements.pkgDropB, elements.pkgFileInputB, (file) => {
    state.analyzer.fileB = file;
    elements.pkgFileNameB.textContent = `${file.name} (${formatBytes(file.size)})`;
    elements.pkgFileNameB.style.display = 'inline-block';
    checkAnalyzerReady();
  });

  elements.btnRunPackageAnalysis.addEventListener('click', handleExecutePackageAnalysis);
  elements.btnLoadFixturePackages.addEventListener('click', handleLoadSampleFixtures);

  // Review Modal Handlers
  elements.btnCloseReviewModal?.addEventListener('click', closeReviewModal);
  elements.btnReviewModalDone?.addEventListener('click', closeReviewModal);
  elements.btnModalToggleReview?.addEventListener('click', handleModalToggleReview);
  elements.btnModalToggleAllowlist?.addEventListener('click', handleModalToggleAllowlist);

  // Baseline Manager Handlers
  elements.btnCloseBaselineModal?.addEventListener('click', closeBaselineManager);
  elements.btnCloseBaselineModalDone?.addEventListener('click', closeBaselineManager);
  elements.btnBaselineModalCaptureNew?.addEventListener('click', () => {
    closeBaselineManager();
    handleCaptureBaseline();
  });

  // Export / Import Handlers
  elements.btnCloseExportModal?.addEventListener('click', closeExportImportModal);
  elements.btnCloseExportModalDone?.addEventListener('click', closeExportImportModal);
  elements.btnDownloadJsonDossier?.addEventListener('click', handleDownloadJsonDossier);
  elements.btnDownloadMarkdownReport?.addEventListener('click', handleDownloadMarkdownReport);
  elements.btnDownloadCsvReport?.addEventListener('click', handleDownloadCsvReport);
  elements.btnTriggerImportDossier?.addEventListener('click', () => elements.importDossierFileInput.click());
  elements.importDossierFileInput?.addEventListener('change', handleImportDossierFile);

  // Global Key & Backdrop Handlers
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeReviewModal();
      closeBaselineManager();
      closeExportImportModal();
    }
  });

  elements.reviewDetailModal?.addEventListener('click', (e) => {
    if (e.target === elements.reviewDetailModal) closeReviewModal();
  });

  elements.baselineManagerModal?.addEventListener('click', (e) => {
    if (e.target === elements.baselineManagerModal) closeBaselineManager();
  });

  elements.exportImportModal?.addEventListener('click', (e) => {
    if (e.target === elements.exportImportModal) closeExportImportModal();
  });
}

function handleUrlHashRouting() {
  if (!window.location.hash) return;
  const hash = window.location.hash.substring(1);

  if (hash.startsWith('tab-')) {
    switchTab(hash);
  } else if (hash.includes('finding=')) {
    const params = new URLSearchParams(hash);
    const findingKey = params.get('finding');
    const extId = params.get('ext');

    if (extId) state.selectedExtensionId = extId;
    if (findingKey) state.selectedFindingKey = findingKey;

    switchTab('tab-investigation');
  }
}

function switchTab(tabId) {
  state.activeTab = tabId;
  elements.navLinks.forEach(link => {
    link.classList.toggle('active', link.dataset.tab === tabId);
  });
  elements.panelSections.forEach(section => {
    section.classList.toggle('active', section.id === tabId);
  });

  // Sync specific view selections when tab activated
  if (tabId === 'tab-diff-explorer') {
    renderDiffExplorer();
  }
}

function showNotice(msg) {
  elements.generalNoticeMsg.textContent = msg;
  elements.generalNoticeBanner.style.display = 'flex';
}

function updateSystemStatusBadge() {
  if (!elements.environmentTag) return;
  const status = getSystemStatus({
    hasLiveConnection: state.hasLiveConnection || isExtensionEnvironment(),
    browser: state.browser,
    context: state.execContext
  });
  elements.environmentTag.textContent = status.fullStatusText;
  elements.environmentTag.className = `platform-tag ${status.statusClass}`;
}

/**
 * Main Data Loader: Loads inventory, baselines, and computes drift
 */
async function loadData(showToast = false) {
  elements.spinIcon?.classList.add('spinning');

  try {
    // 1. Detect browser identity and execution context
    state.browser = detectBrowserIdentity();
    state.execContext = detectExecutionContext();
    state.runtimeContext = detectRuntimeContext();

    // 2. Check for live extension connection (direct or messaging handshake)
    const connInfo = await checkExtensionConnection();
    state.hasLiveConnection = connInfo.connected || isExtensionEnvironment();

    // 3. Update dynamic three-part status pill
    updateSystemStatusBadge();

    // 4. Update context banner
    if (state.hasLiveConnection || isExtensionEnvironment()) {
      if (elements.standaloneContextBanner) elements.standaloneContextBanner.style.display = 'none';
    } else {
      if (elements.standaloneContextBanner) {
        elements.standaloneContextBanner.style.display = 'flex';
        if (elements.standaloneBannerTitle) {
          elements.standaloneBannerTitle.textContent = `${state.browser.displayName} \u00B7 Running Outside Extension Context`;
        }
        if (elements.standaloneBannerText) {
          elements.standaloneBannerText.innerHTML = `Direct extension inspection requires Chrome or Edge with ExtensionLedger loaded as an unpacked extension. Open <code>chrome://extensions</code> or <code>edge://extensions</code>, enable Developer Mode, and click "Load unpacked" pointing to this directory.`;
        }
      }
    }

    // 5. Query real extensions & baseline
    if (state.hasLiveConnection || isExtensionEnvironment()) {
      state.currentInventory = await getInventory();
      state.baseline = await getBaseline();
    } else {
      // Standalone web without extension connection - do NOT populate fake demo data
      state.currentInventory = [];
      state.baseline = null;
    }

    state.reviewedMap = await getReviewedChanges();
    state.allowlist = await getAllowlist();
    state.baselineHistory = await getSnapshotHistory();

    // Compute diffs against baseline if one exists
    if (state.baseline) {
      const rawChanges = diffSnapshots(state.baseline, state.currentInventory);
      state.allChanges = evaluateAllChanges(rawChanges, state.allowlist);
    } else {
      state.allChanges = [];
    }

    // Ensure a selected extension is set
    if (!state.selectedExtensionId && state.currentInventory.length > 0) {
      state.selectedExtensionId = state.currentInventory[0].id;
    }

    // Ensure a selected finding is set if findings exist
    if (!state.selectedFindingKey && state.allChanges.length > 0) {
      state.selectedFindingKey = state.allChanges[0].changeKey;
    }

    updateTelemetryTicker();
    renderWatchlist();
    renderTimeline();
    renderInvestigation();
    renderDiffExplorer();

    if (showToast) {
      showNotice(`Audit refresh completed: ${state.currentInventory.length} extension(s) surveyed.`);
    }
  } catch (err) {
    console.error('Audit Load Error:', err);
    if (elements.tickerBaselineStatus) {
      elements.tickerBaselineStatus.textContent = 'Scan Error';
    }
    showNotice(`Security scan interrupted: ${err.message}`);
  } finally {
    elements.spinIcon?.classList.remove('spinning');
  }
}

/**
 * Updates Topbar Telemetry Bar and Badges
 */
function updateTelemetryTicker() {
  const total = state.currentInventory.length;
  elements.tickerWatchlistCount.textContent = total;
  elements.navWatchlistBadge.textContent = total;

  // Pending reviews
  const pending = state.allChanges.filter(c => 
    c.assessment.requiresReview && !state.reviewedMap[c.changeKey]
  );
  elements.tickerPendingCount.textContent = pending.length;
  elements.navTimelineBadge.textContent = `${state.allChanges.length} Events`;

  if (pending.length > 0) {
    elements.navInvestigationBadge.textContent = `${pending.length} Pending`;
    elements.navInvestigationBadge.style.display = 'inline-block';
    updateBadge(String(pending.length));
  } else {
    elements.navInvestigationBadge.style.display = 'none';
    updateBadge('');
  }

  // Dual assessment counts across inventory
  let suspiciousCount = 0;
  let extensiveCount = 0;
  for (const ext of state.currentInventory) {
    const extChanges = state.allChanges.filter(c => c.extensionId === ext.id);
    const assessment = evaluateExtensionAssessment(ext, extChanges, state.allowlist, { reviewedMap: state.reviewedMap });
    if (assessment.suspicion.level === SUSPICION_LEVELS.SUSPICIOUS) {
      suspiciousCount++;
    }
    if (assessment.exposure.level === EXPOSURE_LEVELS.EXTENSIVE) {
      extensiveCount++;
    }
  }

  if (elements.tickerSuspiciousCount) elements.tickerSuspiciousCount.textContent = suspiciousCount;
  if (elements.tickerExtensiveCount) elements.tickerExtensiveCount.textContent = extensiveCount;
  if (elements.tickerHighRiskCount) elements.tickerHighRiskCount.textContent = suspiciousCount;

  // Baseline state indicator
  if (state.baseline) {
    const baselineDate = new Date(state.baseline.timestamp).toLocaleDateString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
    });
    elements.tickerBaselineStatus.textContent = `Baseline: ${state.baseline.label || baselineDate}`;
  } else {
    elements.tickerBaselineStatus.textContent = 'Baseline not created';
  }
}

// ==========================================================================
// SECTION A: EXTENSION WATCHLIST (MASTER-DETAIL)
// ==========================================================================
function renderWatchlist() {
  const searchQuery = elements.watchlistSearchInput.value.trim().toLowerCase();
  const scopeFilter = elements.watchlistScopeFilter.value;

  const filtered = state.currentInventory.filter(ext => {
    // Search filter
    if (searchQuery) {
      const matchName = ext.name.toLowerCase().includes(searchQuery);
      const matchId = ext.id.toLowerCase().includes(searchQuery);
      const matchPublisher = (ext.publisher || '').toLowerCase().includes(searchQuery);
      const matchPerm = ext.allPermissions.some(p => p.toLowerCase().includes(searchQuery));
      if (!matchName && !matchId && !matchPublisher && !matchPerm) return false;
    }

    // Scope filter
    if (scopeFilter === 'ALL_URLS' && ext.websiteScope !== 'All Websites') return false;
    if (scopeFilter === 'SPECIFIC' && !ext.websiteScope.includes('Specific Site')) return false;
    if (scopeFilter === 'NONE' && ext.websiteScope !== 'None') return false;

    return true;
  });

  if (state.currentInventory.length === 0) {
    const isLive = state.hasLiveConnection || isExtensionEnvironment();
    elements.watchlistRoster.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <h4>${isLive ? 'No Monitored Extensions Found' : 'Extension Not Connected'}</h4>
        <p>${isLive 
          ? 'No third-party extensions are installed in this browser profile. Internal browser components and ExtensionLedger itself are excluded from the threat monitor.'
          : 'To audit your real installed browser extensions, load ExtensionLedger as an unpacked extension in Developer Mode at chrome://extensions or edge://extensions.'
        }</p>
      </div>
    `;
    elements.watchlistDossier.innerHTML = '';
    return;
  }

  if (filtered.length === 0) {
    elements.watchlistRoster.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <h4>No Extensions Match Filter</h4>
        <p>No installed extensions match your search criteria or scope parameters.</p>
      </div>
    `;
    elements.watchlistDossier.innerHTML = '';
    return;
  }

  // Ensure selected extension exists in filtered list
  if (!filtered.some(e => e.id === state.selectedExtensionId)) {
    state.selectedExtensionId = filtered[0].id;
  }

  const defaultIcon = '../icons/icon-48.png';
  let html = '';

  for (const ext of filtered) {
    const isSelected = ext.id === state.selectedExtensionId;
    const extChanges = state.allChanges.filter(c => c.extensionId === ext.id);
    const assessment = evaluateExtensionAssessment(ext, extChanges, state.allowlist, { reviewedMap: state.reviewedMap });
    const exp = assessment.exposure;
    const susp = assessment.suspicion;

    const expClass = exp.level === 'Extensive' ? 'exposure-extensive' : (exp.level === 'Broad' ? 'exposure-broad' : 'exposure-limited');
    const suspClass = susp.level === 'Suspicious evidence detected' ? 'suspicion-detected' : (susp.level === 'Review required' ? 'suspicion-review' : 'suspicion-none');

    const chips = ext.apiPermissions.slice(0, 3).map(p => {
      const isSens = ['cookies', 'webRequest', 'webRequestBlocking', 'debugger', 'scripting'].includes(p);
      return `<span class="micro-chip ${isSens ? 'host-alert' : ''}">${escapeHtml(p)}</span>`;
    }).join('');

    const moreChip = ext.apiPermissions.length > 3 
      ? `<span class="micro-chip">+${ext.apiPermissions.length - 3}</span>` 
      : '';

    html += `
      <div class="watchlist-item ${isSelected ? 'selected' : ''}" data-id="${escapeAttr(ext.id)}">
        <div class="item-main-row">
          <div class="item-identity">
            <img class="item-icon" src="${ext.iconUrl || defaultIcon}" onerror="this.src='${defaultIcon}'" alt="">
            <div class="item-name-group">
              <span class="item-name">${escapeHtml(ext.name)}</span>
              <span class="item-publisher">${escapeHtml(ext.publisher || 'Verified Store Extension')}</span>
            </div>
          </div>
          <div class="item-badges-group">
            ${ext.isSynthetic ? '<span class="badge-pill info" style="font-size: 0.62rem; background: rgba(147, 51, 234, 0.15); color: #C084FC; border-color: rgba(147, 51, 234, 0.3);">Test Fixture</span>' : ''}
            ${state.allowlist?.[ext.id] ? '<span class="badge-pill reviewed" style="font-size: 0.62rem; background: rgba(52, 211, 153, 0.15); color: #34D399; border-color: rgba(52, 211, 153, 0.3);">Allowlisted</span>' : ''}
            <span class="badge-pill ${expClass}" title="${escapeAttr(exp.summary)}">${escapeHtml(exp.level)}</span>
            <span class="badge-pill ${suspClass}" title="${escapeAttr(susp.summary)}">${escapeHtml(susp.level)}</span>
            <button class="btn-item-review" data-id="${escapeAttr(ext.id)}" title="Open review details">Review</button>
          </div>
        </div>

        <div class="item-meta-row">
          <div class="item-permissions-chips">
            ${chips || '<span class="micro-chip">No APIs</span>'}
            ${moreChip}
          </div>
          <span style="font-weight: 600; color: ${ext.websiteScope === 'All Websites' ? '#22D3EE' : 'var(--text-muted)'}">
            ${escapeHtml(ext.websiteScope)}
          </span>
        </div>
      </div>
    `;
  }

  elements.watchlistRoster.innerHTML = html;

  // Bind clicks
  elements.watchlistRoster.querySelectorAll('.watchlist-item').forEach(item => {
    item.addEventListener('click', () => {
      state.selectedExtensionId = item.dataset.id;
      renderWatchlist();
    });
  });

  elements.watchlistRoster.querySelectorAll('.btn-item-review').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openReviewModal(btn.dataset.id);
    });
  });

  renderExtensionDossier();
}

function renderExtensionDossier() {
  const ext = state.currentInventory.find(e => e.id === state.selectedExtensionId);
  if (!ext) {
    elements.watchlistDossier.innerHTML = `
      <div class="dossier-placeholder">
        <h4>No Extension Selected</h4>
      </div>
    `;
    return;
  }

  const defaultIcon = '../icons/icon-48.png';
  const extChanges = state.allChanges.filter(c => c.extensionId === ext.id);
  const assessment = evaluateExtensionAssessment(ext, extChanges, state.allowlist, { reviewedMap: state.reviewedMap });
  const exp = assessment.exposure;
  const susp = assessment.suspicion;
  const pendingChanges = extChanges.filter(c => c.assessment.requiresReview && !state.reviewedMap[c.changeKey]);

  const expClass = exp.level === 'Extensive' ? 'exposure-extensive' : (exp.level === 'Broad' ? 'exposure-broad' : 'exposure-limited');
  const suspClass = susp.level === 'Suspicious evidence detected' ? 'suspicion-detected' : (susp.level === 'Review required' ? 'suspicion-review' : 'suspicion-none');

  const apiPills = ext.apiPermissions.length > 0
    ? ext.apiPermissions.map(p => {
        const isSens = ['cookies', 'webRequest', 'webRequestBlocking', 'debugger', 'scripting', 'nativeMessaging'].includes(p);
        return `<span class="permission-pill ${isSens ? 'sensitive' : ''}">${escapeHtml(p)}</span>`;
      }).join('')
    : '<span style="color: var(--text-dim); font-size: 0.8rem;">No privileged API permissions declared.</span>';

  const hostPills = ext.hostPermissions.length > 0
    ? ext.hostPermissions.map(h => `<span class="permission-pill sensitive">${escapeHtml(h)}</span>`).join('')
    : '<span style="color: var(--text-dim); font-size: 0.8rem;">No host / website permissions declared in manifest.</span>';

  // Events history for this extension
  const historyHtml = extChanges.length > 0
    ? extChanges.map(c => `
        <div style="background: var(--bg-base); border: 1px solid var(--border-subtle); padding: 10px 12px; border-radius: 6px; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between;">
          <div>
            <div style="font-weight: 600; font-size: 0.8rem; color: #FFF;">${escapeHtml(c.assessment.title)}</div>
            <div style="font-size: 0.74rem; color: var(--text-muted);">${escapeHtml(c.summary)}</div>
          </div>
          <span class="badge-pill ${c.assessment.severity.toLowerCase()}">${c.assessment.severity}</span>
        </div>
      `).join('')
    : '<div style="color: var(--text-muted); font-size: 0.8rem; padding: 6px 0;">No drift observed since baseline snapshot was recorded.</div>';

  elements.watchlistDossier.innerHTML = `
    <div class="dossier-header">
      <div class="dossier-identity">
        <img class="dossier-icon" src="${ext.iconUrl || defaultIcon}" onerror="this.src='${defaultIcon}'" alt="">
        <div>
          <h3 class="dossier-title">${escapeHtml(ext.name)}</h3>
          <div class="dossier-id-code">ID: ${escapeHtml(ext.id)} &bull; v${escapeHtml(ext.version)}</div>
        </div>
      </div>
      <div style="display: flex; gap: 8px;">
        ${ext.isSynthetic ? '<span class="badge-pill info" style="background: rgba(147, 51, 234, 0.15); color: #C084FC; border-color: rgba(147, 51, 234, 0.3);">Test Fixture</span>' : '<span class="badge-pill reviewed">Live Scan</span>'}
        ${state.allowlist?.[ext.id] ? '<span class="badge-pill reviewed" style="background: rgba(52, 211, 153, 0.15); color: #34D399; border-color: rgba(52, 211, 153, 0.3);">Allowlisted</span>' : ''}
        <span class="badge-pill ${expClass}">${escapeHtml(exp.level)} Exposure</span>
        <span class="badge-pill ${suspClass}">${escapeHtml(susp.level)}</span>
        <span class="badge-pill ${ext.enabled ? 'reviewed' : 'info'}">${ext.enabled ? 'Active' : 'Disabled'}</span>
      </div>
    </div>

    <!-- Metrics Grid -->
    <div class="dossier-grid">
      <div class="dossier-card-metric">
        <div class="metric-label">Publisher / Origin</div>
        <div class="metric-value" style="color: var(--accent-cyan); font-size: 0.82rem;">${escapeHtml(ext.publisher)}</div>
      </div>
      <div class="dossier-card-metric">
        <div class="metric-label">Declared Host Scope</div>
        <div class="metric-value" style="color: ${ext.websiteScope === 'All Websites' ? '#22D3EE' : '#FFFFFF'};">
          ${escapeHtml(ext.websiteScope)}
        </div>
      </div>
      <div class="dossier-card-metric">
        <div class="metric-label">Exposure Blast Radius</div>
        <div class="metric-value" style="color: ${exp.level === 'Extensive' ? '#C084FC' : (exp.level === 'Broad' ? '#22D3EE' : '#94A3B8')};">
          ${escapeHtml(exp.level)}
        </div>
      </div>
      <div class="dossier-card-metric">
        <div class="metric-label">Suspicion Assessment</div>
        <div class="metric-value" style="color: ${susp.level === 'Suspicious evidence detected' ? '#F87171' : (susp.level === 'Review required' ? '#FBBF24' : '#34D399')}; font-size: 0.78rem;">
          ${escapeHtml(susp.level)}
        </div>
      </div>
    </div>

    <!-- Security Assessment: Capabilities & Blast Radius -->
    <div class="dossier-section">
      <div class="dossier-section-title">
        <span>Declared Capabilities &amp; Exposure Analysis</span>
      </div>
      <div style="background: var(--bg-base); border: 1px solid var(--border-subtle); padding: 10px 12px; border-radius: 6px; font-size: 0.8rem; color: var(--text-secondary); line-height: 1.5; margin-bottom: 6px;">
        ${escapeHtml(exp.summary)}
      </div>
      <div style="font-size: 0.76rem; color: var(--text-muted); line-height: 1.4;">
        <strong>Blast Radius:</strong> ${escapeHtml(exp.blastRadius)}
      </div>
    </div>

    <!-- Declared API Permissions -->
    <div class="dossier-section">
      <div class="dossier-section-title">
        <span>Declared API Permissions (${ext.apiPermissions.length})</span>
      </div>
      <div class="chips-cloud">${apiPills}</div>
    </div>

    <!-- Declared Host Permissions -->
    <div class="dossier-section">
      <div class="dossier-section-title">
        <span>Declared Host Permissions (${ext.hostPermissions.length})</span>
      </div>
      <div class="chips-cloud">${hostPills}</div>
      <div style="font-size: 0.74rem; color: var(--text-dim); margin-top: 6px; padding: 6px 10px; background: rgba(0,0,0,0.25); border-radius: 4px; line-height: 1.4;">
        <strong>Runtime Site Access:</strong> ${escapeHtml(ext.siteAccessNote)}
      </div>
    </div>

    <!-- Observed Event Ledger -->
    <div class="dossier-section">
      <div class="dossier-section-title">
        <span>Observed Drift History (${extChanges.length})</span>
      </div>
      ${historyHtml}
    </div>

    <!-- Action Shortcuts -->
    <div class="dossier-actions-row">
      <button class="btn-cyan-solid" id="btnDossierReview">
        Review Extension &rarr;
      </button>
      <button class="btn-ghost" id="btnDossierCompareDiff">
        Inspect Manifest Diff
      </button>
      ${!ext.isSynthetic ? `
        <button class="btn-danger-ghost" id="btnDossierUninstall">
          Uninstall Extension
        </button>
      ` : ''}
    </div>
  `;

  // Bind Dossier Actions
  document.getElementById('btnDossierReview')?.addEventListener('click', () => {
    openReviewModal(ext.id);
  });

  document.getElementById('btnDossierUninstall')?.addEventListener('click', (e) => {
    handleDirectUninstall(ext, e.currentTarget);
  });

  document.getElementById('btnDossierInvestigate')?.addEventListener('click', () => {
    const finding = extChanges[0];
    if (finding) state.selectedFindingKey = finding.changeKey;
    switchTab('tab-investigation');
  });

  document.getElementById('btnDossierCompareDiff')?.addEventListener('click', () => {
    switchTab('tab-diff-explorer');
  });
}

// ==========================================================================
// SECTION B: CHANGE INTELLIGENCE TIMELINE
// ==========================================================================
function renderTimeline() {
  if (!state.baseline) {
    elements.timelineStreamContainer.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
        <h4>Baseline Not Created</h4>
        <p>No baseline checkpoint has been recorded yet. Click <strong>Capture Baseline</strong> in the top command bar to establish your initial security snapshot.</p>
      </div>
    `;
    return;
  }

  const sevFilter = elements.timelineSeverityFilter.value;
  const reviewFilter = elements.timelineReviewFilter.value;

  const filtered = state.allChanges.filter(c => {
    if (sevFilter !== 'ALL' && c.assessment.severity !== sevFilter) return false;
    const isReviewed = !!state.reviewedMap[c.changeKey];
    if (reviewFilter === 'PENDING' && isReviewed) return false;
    if (reviewFilter === 'REVIEWED' && !isReviewed) return false;
    return true;
  });

  if (filtered.length === 0) {
    elements.timelineStreamContainer.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
        <h4>No Change Events Detected</h4>
        <p>Installed extensions match the active baseline checkpoint with zero unreviewed drift.</p>
      </div>
    `;
    return;
  }

  const defaultIcon = '../icons/icon-16.png';
  let html = '';

  for (const item of filtered) {
    const sev = item.assessment.severity.toLowerCase();
    const isReviewed = !!state.reviewedMap[item.changeKey];
    const icon = item.iconUrl || defaultIcon;

    html += `
      <div class="timeline-entry">
        <div class="timeline-node-dot ${sev}"></div>
        <div class="timeline-card">
          <div class="timeline-card-header">
            <div class="timeline-author-info">
              <img class="timeline-ext-icon" src="${icon}" onerror="this.src='${defaultIcon}'" alt="">
              <span class="timeline-ext-name">${escapeHtml(item.extensionName)}</span>
              ${item.isSynthetic ? '<span class="badge-pill info" style="font-size: 0.65rem; background: rgba(147, 51, 234, 0.15); color: #C084FC; border-color: rgba(147, 51, 234, 0.3);">Test Fixture</span>' : ''}
              <span class="badge-pill ${sev}">${item.assessment.severity}</span>
              ${isReviewed ? '<span class="badge-pill reviewed">Reviewed</span>' : ''}
            </div>
            <span class="timeline-timestamp">${item.isSynthetic ? 'Test Fixture' : 'Observed in Scan'}</span>
          </div>

          <div class="timeline-title">${escapeHtml(item.assessment.title)}</div>
          <div class="timeline-summary">${escapeHtml(item.assessment.whatChanged || item.summary)}</div>

          <div class="timeline-card-footer">
            <span style="color: var(--text-dim); font-family: monospace;">Introduced in: v${escapeHtml(item.extensionVersion || '1.0')}</span>
            <div style="display: flex; gap: 6px;">
              <button class="btn-item-review" data-key="${escapeAttr(item.changeKey)}" data-ext="${escapeAttr(item.extensionId)}">
                Review &rarr;
              </button>
              <button class="btn-timeline-jump" data-key="${escapeAttr(item.changeKey)}" data-ext="${escapeAttr(item.extensionId)}">
                Investigate &rarr;
              </button>
            </div>
          </div>
        </div>
      </div>
    `;
  }

  elements.timelineStreamContainer.innerHTML = html;

  elements.timelineStreamContainer.querySelectorAll('.btn-timeline-jump').forEach(btn => {
    btn.addEventListener('click', () => {
      state.selectedFindingKey = btn.dataset.key;
      state.selectedExtensionId = btn.dataset.ext;
      switchTab('tab-investigation');
    });
  });

  elements.timelineStreamContainer.querySelectorAll('.btn-item-review').forEach(btn => {
    btn.addEventListener('click', () => {
      openReviewModal(btn.dataset.ext, btn.dataset.key);
    });
  });
}

// ==========================================================================
// SECTION D: SECURITY INVESTIGATION WORKSPACE
// ==========================================================================
function renderInvestigation() {
  if (!state.baseline) {
    elements.findingsRoster.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z"/></svg>
        <h4>Baseline Not Created</h4>
        <p>No baseline checkpoint has been recorded yet. Click <strong>Capture Baseline</strong> in the top command bar to establish your initial security snapshot. Future drift will appear here.</p>
      </div>
    `;
    elements.findingDossier.innerHTML = '';
    return;
  }

  if (state.allChanges.length === 0) {
    elements.findingsRoster.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
        <h4>All Extensions Match Baseline</h4>
        <p>No permission expansions, unexpected updates, or new installations observed since baseline was captured.</p>
      </div>
    `;
    elements.findingDossier.innerHTML = '';
    return;
  }

  const sevFilter = elements.investigationSeverityFilter.value;
  const statusFilter = elements.investigationStatusFilter.value;

  const filtered = state.allChanges.filter(c => {
    if (sevFilter !== 'ALL' && c.assessment.severity !== sevFilter) return false;
    const isReviewed = !!state.reviewedMap[c.changeKey];
    if (statusFilter === 'PENDING' && isReviewed) return false;
    if (statusFilter === 'REVIEWED' && !isReviewed) return false;
    return true;
  });

  if (filtered.length === 0) {
    elements.findingsRoster.innerHTML = `
      <div class="empty-view-placeholder">
        <svg viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
        <h4>No Investigation Findings Match Filters</h4>
        <p>No extension drifts require review under current filter criteria.</p>
      </div>
    `;
    elements.findingDossier.innerHTML = '';
    return;
  }

  // Ensure selected finding is in filtered list
  if (!filtered.some(f => f.changeKey === state.selectedFindingKey)) {
    state.selectedFindingKey = filtered[0].changeKey;
  }

  const defaultIcon = '../icons/icon-16.png';
  let html = '';

  for (const item of filtered) {
    const isSelected = item.changeKey === state.selectedFindingKey;
    const isReviewed = !!state.reviewedMap[item.changeKey];
    const sev = item.assessment.severity.toLowerCase();

    html += `
      <div class="finding-card border-${sev} ${isSelected ? 'selected' : ''}" data-key="${escapeAttr(item.changeKey)}">
        <div class="finding-card-top">
          <div class="finding-ext-group">
            <img class="finding-ext-icon" src="${item.iconUrl || defaultIcon}" onerror="this.src='${defaultIcon}'" alt="">
            <span class="finding-ext-name">${escapeHtml(item.extensionName)}</span>
          </div>
          <div style="display: flex; gap: 4px; align-items: center;">
            <button class="btn-item-review" data-key="${escapeAttr(item.changeKey)}" data-ext="${escapeAttr(item.extensionId)}" title="Open review details">Review</button>
            <span class="badge-pill ${sev}">${item.assessment.severity}</span>
            ${isReviewed ? '<span class="badge-pill reviewed">&check;</span>' : ''}
          </div>
        </div>

        <div class="finding-card-title">${escapeHtml(item.assessment.title)}</div>
        <div class="finding-card-what">${escapeHtml(item.assessment.whatChanged || item.summary)}</div>
      </div>
    `;
  }

  elements.findingsRoster.innerHTML = html;

  elements.findingsRoster.querySelectorAll('.finding-card').forEach(card => {
    card.addEventListener('click', () => {
      state.selectedFindingKey = card.dataset.key;
      renderInvestigation();
    });
  });

  elements.findingsRoster.querySelectorAll('.btn-item-review').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openReviewModal(btn.dataset.ext, btn.dataset.key);
    });
  });

  renderFindingDossier();
}

function renderFindingDossier() {
  const item = state.allChanges.find(c => c.changeKey === state.selectedFindingKey);
  if (!item) {
    elements.findingDossier.innerHTML = `
      <div class="dossier-placeholder">
        <h4>No Finding Selected</h4>
      </div>
    `;
    return;
  }

  const assessment = item.assessment;
  const sev = assessment.severity.toLowerCase();
  const isReviewed = !!state.reviewedMap[item.changeKey];

  const evidenceItems = Array.isArray(assessment.evidence) 
    ? assessment.evidence 
    : [assessment.evidence];

  const evidenceHtml = evidenceItems.map(e => `<li>${escapeHtml(String(e))}</li>`).join('');

  const recItems = Array.isArray(assessment.whatToInvestigateNext || assessment.recommendations)
    ? (assessment.whatToInvestigateNext || assessment.recommendations)
    : ['Verify developer intent.'];

  const recsHtml = recItems.map(r => `<li>${escapeHtml(String(r))}</li>`).join('');

  elements.findingDossier.innerHTML = `
    <div class="finding-dossier-top">
      <div class="finding-headline-row">
        <h3 class="finding-dossier-title">${escapeHtml(assessment.title)}</h3>
        <div style="display: flex; gap: 8px;">
          ${item.isSynthetic ? '<span class="badge-pill info" style="background: rgba(147, 51, 234, 0.15); color: #C084FC; border-color: rgba(147, 51, 234, 0.3);">Test Fixture</span>' : '<span class="badge-pill reviewed">Live Scan Record</span>'}
          <span class="badge-pill ${sev}">${assessment.severity} SEVERITY</span>
          <span class="badge-pill ${isReviewed ? 'reviewed' : 'high'}">${isReviewed ? 'Reviewed' : 'Action Required'}</span>
        </div>
      </div>

      <div class="finding-attr-row">
        <span class="attr-item">Data Origin: <strong>${item.isSynthetic ? 'Test Fixture' : 'Live Browser Scan'}</strong></span>
        <span class="attr-item">Extension: <strong>${escapeHtml(item.extensionName)}</strong></span>
        <span class="attr-item">ID: <code>${escapeHtml(item.extensionId)}</code></span>
        <span class="attr-item">Introduced in: <strong>${escapeHtml(assessment.introducedInVersion || item.extensionVersion || 'Current build')}</strong></span>
      </div>
    </div>

    <!-- 1. What Changed -->
    <div class="finding-section">
      <div class="finding-section-title">1. What Changed</div>
      <div class="finding-content-box">
        ${escapeHtml(assessment.whatChanged || item.summary)}
      </div>
    </div>

    <!-- 2. Evidence Supporting the Finding -->
    <div class="finding-section">
      <div class="finding-section-title">2. Concrete Evidence Observed</div>
      <div class="finding-content-box evidence">
        <ul class="evidence-ul">${evidenceHtml}</ul>
      </div>
    </div>

    <!-- 3. Why It May Matter -->
    <div class="finding-section">
      <div class="finding-section-title">3. Security &amp; Privacy Impact (Why This Matters)</div>
      <div class="finding-content-box">
        ${escapeHtml(assessment.whyItMatters || assessment.reasoning)}
      </div>
    </div>

    <!-- 4. What the System Cannot Determine -->
    <div class="finding-section">
      <div class="finding-section-title">4. System Boundary &amp; What Cannot Be Determined</div>
      <div class="blindspot-box">
        <strong>Security Blind Spot Statement:</strong>
        ${escapeHtml(assessment.systemCannotDetermine || 'Client-side inspection cannot evaluate encrypted runtime HTTPS traffic without packet decryption.')}
      </div>
    </div>

    <!-- 5. What the User Should Investigate Next -->
    <div class="finding-section">
      <div class="finding-section-title">5. Recommended Investigation Checklist</div>
      <ol class="recommendations-ol">${recsHtml}</ol>
    </div>

    <!-- Footer Controls -->
    <div class="finding-dossier-actions">
      <div style="display: flex; gap: 8px;">
        <button class="btn-cyan-solid" id="btnToggleInvestigationReview">
          ${isReviewed ? 'Re-open Review' : 'Mark Finding as Reviewed'}
        </button>
        <button class="btn-ghost" id="btnOpenFindingReviewModal">
          Open Review Dossier &rarr;
        </button>
      </div>
      <div>
        <button class="btn-ghost" id="btnJumpToWatchlist">
          View in Extension Watchlist &rarr;
        </button>
      </div>
    </div>
  `;

  document.getElementById('btnToggleInvestigationReview')?.addEventListener('click', async () => {
    if (isFindingReviewed(item.changeKey, state.reviewedMap)) {
      await reopenChangeReview(item.changeKey, { extensionId: item.extensionId, findingId: item.changeKey });
    } else {
      await markChangeAsReviewed(item.changeKey, { extensionId: item.extensionId, findingId: item.changeKey });
    }
    state.reviewedMap = await getReviewedChanges();
    updateTelemetryTicker();
    renderInvestigation();
    renderTimeline();
    renderWatchlist();
  });

  document.getElementById('btnOpenFindingReviewModal')?.addEventListener('click', () => {
    openReviewModal(item.extensionId, item.changeKey);
  });

  document.getElementById('btnJumpToWatchlist')?.addEventListener('click', () => {
    state.selectedExtensionId = item.extensionId;
    switchTab('tab-watchlist');
  });
}

// ==========================================================================
// REVIEW MODAL CONTROLLER
// ==========================================================================

function openReviewModal(extensionId, findingKey = null) {
  const ext = state.currentInventory.find(e => e.id === extensionId) ||
              state.baseline?.extensions?.[extensionId] ||
              { id: extensionId, name: 'Extension', version: '0.0.0', allPermissions: [], apiPermissions: [], hostPermissions: [], websiteScope: 'None' };

  state.activeReviewExtId = extensionId;
  state.activeReviewFindingKey = findingKey;

  const defaultIcon = '../icons/icon-48.png';
  elements.reviewModalIcon.src = ext.iconUrl || defaultIcon;
  elements.reviewModalIcon.onerror = () => { elements.reviewModalIcon.src = defaultIcon; };
  elements.reviewModalTitle.textContent = ext.name;
  elements.reviewModalSub.textContent = `ID: ${ext.id} \u2022 v${ext.version} \u2022 ${ext.publisher || 'Store Extension'}`;

  // Data Origin Tag
  const isSynthetic = Boolean(ext.isSynthetic);
  elements.reviewModalOriginBadge.textContent = isSynthetic ? 'Test Fixture Record' : 'Live Browser Scan';
  elements.reviewModalOriginBadge.className = `badge-pill ${isSynthetic ? 'info' : 'reviewed'}`;

  // Permissions & Scope
  elements.reviewModalScope.textContent = ext.websiteScope || 'None';
  elements.reviewModalScope.className = `metric-value ${ext.websiteScope === 'All Websites' ? 'text-rose' : 'text-cyan'}`;
  elements.reviewModalInstallType.textContent = ext.installType || 'normal';

  // Privileged API Chips
  if (ext.apiPermissions && ext.apiPermissions.length > 0) {
    elements.reviewModalApiChips.innerHTML = ext.apiPermissions.map(p => {
      const isSens = ['cookies', 'webRequest', 'webRequestBlocking', 'debugger', 'scripting'].includes(p);
      return `<span class="permission-pill ${isSens ? 'sensitive' : ''}">${escapeHtml(p)}</span>`;
    }).join('');
  } else {
    elements.reviewModalApiChips.innerHTML = '<span style="color: var(--text-dim); font-size: 0.76rem;">No privileged API permissions declared.</span>';
  }

  // Host Chips
  if (ext.hostPermissions && ext.hostPermissions.length > 0) {
    elements.reviewModalHostChips.innerHTML = ext.hostPermissions.map(h => 
      `<span class="permission-pill sensitive">${escapeHtml(h)}</span>`
    ).join('');
  } else {
    elements.reviewModalHostChips.innerHTML = '<span style="color: var(--text-dim); font-size: 0.76rem;">No host permissions declared in manifest.</span>';
  }

  // Relevant Changes & Findings
  const extChanges = state.allChanges.filter(c => c.extensionId === extensionId);
  const primaryFinding = findingKey 
    ? extChanges.find(c => c.changeKey === findingKey) 
    : (extChanges[0] || null);

  // Review Status
  updateReviewModalStatus(ext, extChanges, findingKey);

  // Allowlist Status in Review Modal
  const isAllowlisted = Boolean(state.allowlist?.[extensionId]);
  if (elements.btnModalAllowlistText) {
    elements.btnModalAllowlistText.textContent = isAllowlisted ? 'Remove from Allowlist' : 'Trust / Allowlist';
  }

  // Baseline vs Current Differences
  const baseExt = state.baseline?.extensions?.[extensionId];
  if (baseExt) {
    const diffs = [];
    if (baseExt.version !== ext.version) {
      diffs.push(`Version transitioned from ${baseExt.version} to ${ext.version}`);
    }
    const addedPerms = ext.allPermissions.filter(p => !baseExt.allPermissions?.includes(p));
    const removedPerms = baseExt.allPermissions?.filter(p => !ext.allPermissions?.includes(p)) || [];
    if (addedPerms.length > 0) diffs.push(`Added permissions: ${addedPerms.join(', ')}`);
    if (removedPerms.length > 0) diffs.push(`Removed permissions: ${removedPerms.join(', ')}`);
    if (baseExt.enabled !== ext.enabled) {
      diffs.push(`Status changed: ${ext.enabled ? 'Enabled' : 'Disabled'}`);
    }

    elements.reviewModalDiffContent.innerHTML = diffs.length > 0
      ? `<ul style="padding-left: 18px; line-height: 1.6;">${diffs.map(d => `<li>${escapeHtml(d)}</li>`).join('')}</ul>`
      : 'Matches baseline snapshot. No version, permission, or scope drift observed since baseline was recorded.';
  } else if (state.baseline) {
    elements.reviewModalDiffContent.innerHTML = `
      <div style="color: #F59E0B; font-weight: 600; margin-bottom: 4px;">Newly Added Extension</div>
      <div>This extension was not present in the active baseline (${state.baseline.label || 'Saved Baseline'}). Added with ${ext.allPermissions.length} declared permissions.</div>
    `;
  } else {
    elements.reviewModalDiffContent.innerHTML = 'No baseline snapshot active. Capture a baseline to track historical drift over time.';
  }

  // Security Findings & Supporting Evidence
  if (extChanges.length > 0) {
    elements.reviewModalFindingsContent.innerHTML = extChanges.map((c, idx) => {
      const isTarget = findingKey ? (c.changeKey === findingKey) : (idx === 0);
      const isRev = isFindingReviewed(c.changeKey, state.reviewedMap);
      const sev = c.assessment.severity.toLowerCase();
      const evidence = Array.isArray(c.assessment.evidence) ? c.assessment.evidence : [c.assessment.evidence];

      return `
        <div class="finding-content-box ${isTarget ? 'evidence' : ''}" style="margin-bottom: 10px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <div style="font-weight: 700; color: #FFFFFF; font-size: 0.85rem;">
              ${escapeHtml(c.assessment.title)}
            </div>
            <div style="display: flex; gap: 6px; align-items: center;">
              <span class="badge-pill ${sev}">${c.assessment.severity}</span>
              <span class="badge-pill ${isRev ? 'reviewed' : 'high'}">${isRev ? 'Reviewed' : 'Action Required'}</span>
            </div>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 8px;">
            ${escapeHtml(c.assessment.whatChanged || c.summary)}
          </div>
          <div style="font-size: 0.74rem; font-weight: 600; color: var(--accent-cyan); margin-bottom: 4px;">Concrete Evidence Observed:</div>
          <ul class="evidence-ul">
            ${evidence.map(e => `<li>${escapeHtml(String(e))}</li>`).join('')}
          </ul>
          <div style="margin-top: 8px; font-size: 0.76rem; color: var(--text-muted); line-height: 1.4;">
            <strong>Risk Impact:</strong> ${escapeHtml(c.assessment.whyItMatters || c.assessment.reasoning)}
          </div>
        </div>
      `;
    }).join('');
  } else {
    elements.reviewModalFindingsContent.innerHTML = `
      <div class="modal-content-box" style="color: var(--text-muted);">
        No security anomalies or unreviewed drift items detected for this extension.
      </div>
    `;
  }

  // Uncertainty & Recommendations
  const uncertainty = primaryFinding?.assessment?.systemCannotDetermine ||
    'The system cannot inspect encrypted runtime HTTPS payloads in flight or determine whether DOM reads are transmitted to remote third-party command-and-control servers.';
  elements.reviewModalUncertainty.textContent = uncertainty;

  const recs = primaryFinding?.assessment?.whatToInvestigateNext || primaryFinding?.assessment?.recommendations || [
    'Verify developer publisher identity and verify extension permissions.',
    'Check if recent updates align with expected tool features.'
  ];
  elements.reviewModalRecommendations.innerHTML = recs.map(r => `<li>${escapeHtml(String(r))}</li>`).join('');

  // Uninstall Button Slot in Review Modal
  if (isSynthetic) {
    elements.reviewModalUninstallSlot.innerHTML = '';
  } else {
    elements.reviewModalUninstallSlot.innerHTML = `
      <button id="btnReviewModalUninstall" class="btn-danger-ghost">
        Uninstall Extension
      </button>
    `;
    document.getElementById('btnReviewModalUninstall')?.addEventListener('click', (e) => {
      handleDirectUninstall(ext, e.currentTarget);
    });
  }

  elements.reviewDetailModal.style.display = 'flex';
}

function updateReviewModalStatus(ext, extChanges, findingKey) {
  let isRev = false;
  let revDate = null;

  if (findingKey && state.reviewedMap[findingKey]) {
    const entry = state.reviewedMap[findingKey];
    isRev = isFindingReviewed(findingKey, state.reviewedMap);
    revDate = entry.reviewedAt;
  } else if (extChanges.length > 0) {
    const reviewedCount = extChanges.filter(c => isFindingReviewed(c.changeKey, state.reviewedMap)).length;
    isRev = (reviewedCount === extChanges.length);
    const lastEntry = extChanges.map(c => state.reviewedMap[c.changeKey]).filter(Boolean)[0];
    revDate = lastEntry?.reviewedAt;
  }

  if (isRev) {
    elements.reviewModalStatusBadge.className = 'badge-pill reviewed';
    elements.reviewModalStatusBadge.textContent = 'Reviewed';
    elements.reviewModalTimestamp.textContent = revDate ? `Reviewed: ${new Date(revDate).toLocaleString()}` : 'Reviewed';
    elements.btnModalToggleReview.textContent = 'Reopen Review (Set to Pending)';
    elements.btnModalToggleReview.className = 'btn-ghost';
  } else {
    elements.reviewModalStatusBadge.className = 'badge-pill high';
    elements.reviewModalStatusBadge.textContent = 'Pending Review';
    elements.reviewModalTimestamp.textContent = 'Awaiting analyst review';
    elements.btnModalToggleReview.textContent = 'Mark as Reviewed';
    elements.btnModalToggleReview.className = 'btn-cyan-solid';
  }
}

function closeReviewModal() {
  elements.reviewDetailModal.style.display = 'none';
  state.activeReviewExtId = null;
  state.activeReviewFindingKey = null;
}

async function handleModalToggleReview() {
  const extId = state.activeReviewExtId;
  const findingKey = state.activeReviewFindingKey;
  const extChanges = state.allChanges.filter(c => c.extensionId === extId);

  if (findingKey) {
    const isRev = isFindingReviewed(findingKey, state.reviewedMap);
    if (isRev) {
      await reopenChangeReview(findingKey, { extensionId: extId, findingId: findingKey });
    } else {
      await markChangeAsReviewed(findingKey, { extensionId: extId, findingId: findingKey });
    }
  } else if (extChanges.length > 0) {
    const allRev = extChanges.every(c => isFindingReviewed(c.changeKey, state.reviewedMap));
    for (const c of extChanges) {
      if (allRev) {
        await reopenChangeReview(c.changeKey, { extensionId: extId, findingId: c.changeKey });
      } else {
        await markChangeAsReviewed(c.changeKey, { extensionId: extId, findingId: c.changeKey });
      }
    }
  } else {
    // General extension review toggle
    const generalKey = `ext_review_${extId}`;
    if (state.reviewedMap[generalKey]) {
      await unmarkChangeReviewed(generalKey);
    } else {
      await markChangeAsReviewed(generalKey, { extensionId: extId, findingId: generalKey });
    }
  }

  state.reviewedMap = await getReviewedChanges();
  updateTelemetryTicker();
  renderWatchlist();
  renderTimeline();
  renderInvestigation();

  // Re-update modal status
  const ext = state.currentInventory.find(e => e.id === extId) || { id: extId };
  updateReviewModalStatus(ext, extChanges, findingKey);
}

async function handleModalToggleAllowlist() {
  const extId = state.activeReviewExtId;
  if (!extId) return;

  const isCurrentlyAllowlisted = Boolean(state.allowlist?.[extId]);
  if (isCurrentlyAllowlisted) {
    state.allowlist = await removeExtensionAllowlist(extId);
    showNotice(`Revoked trusted allowlist status for extension "${extId}".`);
  } else {
    const reason = prompt('Enter justification or notes for trusting this extension (e.g., "Approved enterprise tool"):', 'Analyst verified extension');
    if (reason === null) return; // User cancelled prompt
    state.allowlist = await setExtensionAllowlist(extId, reason || 'Analyst verified');
    showNotice(`Extension "${extId}" added to analyst trust allowlist.`);
  }

  // Recompute findings with updated allowlist
  if (state.baseline) {
    const rawChanges = diffSnapshots(state.baseline, state.currentInventory);
    state.allChanges = evaluateAllChanges(rawChanges, state.allowlist);
  }

  updateTelemetryTicker();
  renderWatchlist();
  renderTimeline();
  renderInvestigation();

  // Refresh review modal allowlist button text
  const isNowAllowlisted = Boolean(state.allowlist?.[extId]);
  if (elements.btnModalAllowlistText) {
    elements.btnModalAllowlistText.textContent = isNowAllowlisted ? 'Remove from Allowlist' : 'Trust / Allowlist';
  }
}

// ==========================================================================
// DIRECT BROWSER UNINSTALLATION CONTROLLER
// Uses Chrome/Edge native confirmation dialog as the sole confirmation.
// ==========================================================================

async function handleDirectUninstall(ext, triggerBtn) {
  if (!ext || !ext.id) return;
  if (state.isUninstalling) return; // Prevent duplicate clicks

  if (ext.isSynthetic) {
    showNotice('Uninstallation is prohibited on test fixtures.');
    return;
  }

  // Pre-flight check: Enterprise Policy Managed
  if (ext.mayDisable === false || ext.installType === 'admin') {
    showNotice(`Cannot uninstall "${ext.name}": Extension is managed by enterprise administrator policy.`);
    return;
  }

  // Pre-flight check: Extension context vs Standalone Web Mode
  const hasManagementUninstall = typeof chrome !== 'undefined' && Boolean(chrome.management?.uninstall);
  if (!hasManagementUninstall) {
    const mgmtUrl = getBrowserManagementUrl(ext.id);
    showNotice(`Direct uninstallation requires the Chrome/Edge extension context. Use ${mgmtUrl} to remove this extension.`);
    return;
  }

  state.isUninstalling = true;
  const dossierBtn = document.getElementById('btnDossierUninstall');
  const reviewBtn = document.getElementById('btnReviewModalUninstall');
  const activeBtns = [dossierBtn, reviewBtn].filter(Boolean);

  // Apply subtle loading state and disable to prevent duplicate clicks
  const originalLabels = new Map();
  for (const btn of activeBtns) {
    originalLabels.set(btn, btn.innerHTML);
    btn.disabled = true;
    btn.style.opacity = '0.75';
    btn.style.cursor = 'wait';
    btn.innerHTML = `
      <svg class="spin-icon spinning" width="13" height="13" viewBox="0 0 24 24" style="margin-right: 6px; vertical-align: -2px;"><path d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>
      Uninstalling...
    `;
  }

  try {
    const result = await uninstallExtension(ext.id, {
      isSynthetic: Boolean(ext.isSynthetic),
      mayDisable: ext.mayDisable,
      installType: ext.installType,
      showConfirmDialog: true
    });

    if (result.cancelled) {
      // User cancelled Chrome's native dialog:
      // Leave extension in inventory and return to normal interface without showing an alarming error.
      return;
    }

    if (!result.success) {
      // Uninstallation failed for another reason: concise, actionable error
      showNotice(`Uninstallation failed: ${result.message}`);
      return;
    }

    // Chrome confirmed successful uninstallation:
    closeReviewModal();
    showNotice(`Successfully uninstalled "${ext.name}". Extension inventory and security findings refreshed.`);
    await loadData(true);
  } catch (err) {
    showNotice(`Uninstallation error: ${err.message || 'Unexpected failure'}`);
  } finally {
    state.isUninstalling = false;
    for (const btn of activeBtns) {
      if (document.body.contains(btn)) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        const orig = originalLabels.get(btn);
        if (orig) btn.innerHTML = orig;
      }
    }
  }
}

// ==========================================================================
// SECTION C: VERSION DIFF EXPLORER & NETWORK DESTINATION GRAPH
// ==========================================================================
function renderDiffExplorer() {
  // Populate extension dropdown
  const options = state.currentInventory.map(ext => `
    <option value="${escapeAttr(ext.id)}" ${ext.id === state.selectedExtensionId ? 'selected' : ''}>
      ${escapeHtml(ext.name)} (v${escapeHtml(ext.version)})
    </option>
  `).join('');

  elements.diffExtensionSelect.innerHTML = options || '<option>No extensions</option>';

  const ext = state.currentInventory.find(e => e.id === state.selectedExtensionId);
  if (!ext) {
    elements.diffManifestBefore.textContent = '// No extension selected';
    elements.diffManifestAfter.textContent = '// No extension selected';
    elements.networkGraphCanvas.innerHTML = '<div style="color: var(--text-muted);">Select an extension above to inspect network scope.</div>';
    return;
  }

  // Get baseline version of this extension
  const baseExt = state.baseline?.extensions?.[ext.id];

  elements.diffVersionMeta.textContent = baseExt 
    ? `Baseline (v${baseExt.version}) &rarr; Current (v${ext.version})`
    : `Newly Installed (v${ext.version}) - No prior baseline`;

  const formatManifest = (record) => {
    if (!record) return '// Extension was not present in baseline snapshot\n{\n  "status": "NOT_INSTALLED"\n}';
    return JSON.stringify({
      id: record.id,
      name: record.name,
      version: record.version,
      publisher: record.publisher,
      installType: record.installType,
      websiteScope: record.websiteScope,
      declaredPermissions: record.apiPermissions,
      authorizedHosts: record.hostPermissions
    }, null, 2);
  };

  elements.diffManifestBefore.textContent = formatManifest(baseExt);
  elements.diffManifestAfter.textContent = formatManifest(ext);

  // Render Network Destination Graph / Matrix
  renderNetworkDestinationGraph(ext, baseExt);
}

function renderNetworkDestinationGraph(ext, baseExt) {
  const currentHosts = ext.hostPermissions || [];
  const baselineHosts = new Set(baseExt?.hostPermissions || []);

  elements.networkEndpointCountBadge.textContent = `${currentHosts.length} Host Destination${currentHosts.length !== 1 ? 's' : ''}`;

  if (currentHosts.length === 0) {
    elements.networkGraphCanvas.innerHTML = `
      <div style="text-align: center; padding: 24px; color: var(--text-muted);">
        <p style="color: #34D399; font-weight: 600;">Zero External Website Access Declared</p>
        <span style="font-size: 0.78rem;">This extension cannot observe or intercept requests to remote websites.</span>
      </div>
    `;
    return;
  }

  let html = '<div class="network-nodes-grid">';
  for (const host of currentHosts) {
    const isNew = !baselineHosts.has(host);
    const isWildcard = host === '<all_urls>' || host.includes('*');

    html += `
      <div class="network-endpoint-card ${isNew ? 'new-endpoint' : ''}">
        <div class="endpoint-host">${isWildcard ? '🌐 Broad Web Scope' : '🎯 Specific Domain Scope'}</div>
        <div class="endpoint-url">${escapeHtml(host)}</div>
        <div class="endpoint-meta">
          <span>${isNew ? '<strong style="color: #EF4444;">Newly Added in Current Version</strong>' : 'Baseline Approved'}</span>
          <span>${isWildcard ? 'High Exposure' : 'Targeted'}</span>
        </div>
      </div>
    `;
  }
  html += '</div>';

  elements.networkGraphCanvas.innerHTML = html;
}

// ==========================================================================
// SECTION E: PACKAGE ANALYZER
// ==========================================================================
function setAnalyzerMode(mode) {
  state.analyzer.mode = mode;
  if (mode === 'single') {
    elements.pkgDropB.style.display = 'none';
    elements.pkgDropTitleA.textContent = 'Extension Package (.zip / .crx)';
  } else {
    elements.pkgDropB.style.display = 'block';
    elements.pkgDropTitleA.textContent = 'Baseline Version (v1.zip)';
  }
  checkAnalyzerReady();
}

function setupDropZone(dropZone, fileInput, onFileSelected) {
  dropZone.addEventListener('click', () => fileInput.click());

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      onFileSelected(fileInput.files[0]);
    }
  });

  ['dragenter', 'dragover'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(name => {
    dropZone.addEventListener(name, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files.length > 0) {
      onFileSelected(e.dataTransfer.files[0]);
    }
  });
}

function checkAnalyzerReady() {
  if (state.analyzer.mode === 'single') {
    elements.btnRunPackageAnalysis.disabled = !state.analyzer.fileA;
  } else {
    elements.btnRunPackageAnalysis.disabled = !(state.analyzer.fileA && state.analyzer.fileB);
  }
}

async function handleExecutePackageAnalysis() {
  elements.btnRunPackageAnalysis.disabled = true;
  elements.btnRunPackageAnalysis.textContent = 'Analyzing packages in memory...';
  elements.pkgAnalysisResultsArea.style.display = 'block';
  elements.pkgAnalysisResultsArea.innerHTML = `
    <div style="text-align: center; padding: 36px; color: var(--text-muted);">
      <div class="spin-icon spinning" style="width: 24px; height: 24px; margin: 0 auto 10px auto;">
        <svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 4V1L8 5l4 4V6c3.31 0 6 2.69 6 6 0 1.01-.25 1.97-.7 2.8l1.46 1.46C19.54 15.03 20 13.57 20 12c0-4.42-3.58-8-8-8zm0 14c-3.31 0-6-2.69-6-6 0-1.01.25-1.97.7-2.8L5.24 7.74C4.46 8.97 4 10.43 4 12c0 4.42 3.58 8 8 8v3l4-4-4-4v3z"/></svg>
      </div>
      <p>Parsing local ZIP archives and scanning for static pattern leads...</p>
    </div>
  `;

  // Parse optional analyst custom regex rule
  const customRegex = elements.pkgCustomRuleRegex?.value?.trim();
  const customDesc = elements.pkgCustomRuleDesc?.value?.trim();
  const customRules = [];
  if (customRegex) {
    try {
      customRules.push({
        category: 'Custom Analyst Rule',
        severity: 'HIGH',
        regex: new RegExp(customRegex, 'g'),
        description: customDesc || `Matched custom pattern: ${customRegex}`
      });
    } catch (e) {
      showNotice(`Invalid custom regex: ${e.message}`);
    }
  }

  try {
    if (state.analyzer.mode === 'single') {
      const buffer = await state.analyzer.fileA.arrayBuffer();
      const report = await analyzeSinglePackage(buffer, state.analyzer.fileA.name, { customRules });
      renderSinglePackageReport(report);
    } else {
      const [bufA, bufB] = await Promise.all([
        state.analyzer.fileA.arrayBuffer(),
        state.analyzer.fileB.arrayBuffer()
      ]);
      const diffReport = await comparePackages(bufA, bufB, state.analyzer.fileA.name, state.analyzer.fileB.name, { customRules });
      renderComparePackageReport(diffReport);
    }
  } catch (err) {
    elements.pkgAnalysisResultsArea.innerHTML = `
      <div class="general-notice" style="border-color: #EF4444; color: #FCA5A5;">
        <strong>Analysis Error:</strong> ${escapeHtml(err.message)}
      </div>
    `;
  } finally {
    elements.btnRunPackageAnalysis.disabled = false;
    elements.btnRunPackageAnalysis.textContent = 'Execute In-Memory Package Analysis';
  }
}

function renderSinglePackageReport(report) {
  const leadsHtml = report.investigationLeads.length > 0
    ? report.investigationLeads.map(lead => `
        <div style="background: var(--bg-base); padding: 12px; border-radius: 6px; margin-bottom: 8px; border-left: 3px solid ${lead.severity === 'CRITICAL' ? '#EF4444' : (lead.severity === 'HIGH' ? '#F87171' : '#F59E0B')}">
          <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
            <span class="badge-pill ${lead.severity.toLowerCase()}">${lead.severity}</span>
            <span style="font-family: monospace; font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(lead.file)}: line ${lead.line}</span>
          </div>
          <div style="font-weight: 600; color: #FFF; font-size: 0.85rem;">${escapeHtml(lead.category)}</div>
          <code style="display: block; background: #0A0E17; padding: 6px 10px; border-radius: 4px; margin: 6px 0; font-size: 0.78rem; color: #38BDF8;">${escapeHtml(lead.preview)}</code>
          <div style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(lead.description)}</div>
          <div style="font-size: 0.78rem; color: #34D399; margin-top: 4px;">Guidance: ${escapeHtml(lead.recommendation)}</div>
        </div>
      `).join('')
    : '<div style="color: #34D399; padding: 10px;">Zero sensitive code patterns detected in this package.</div>';

  const entropyHtml = (report.fileMetrics && report.fileMetrics.length > 0)
    ? `
      <div style="margin-bottom: 16px;">
        <h4 style="color: #FFF; font-size: 0.85rem; margin-bottom: 6px;">Shannon Entropy &amp; Obfuscation Metrics:</h4>
        <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 8px;">
          ${report.fileMetrics.slice(0, 12).map(fm => `
            <div style="background: rgba(15,23,42,0.6); padding: 8px 10px; border-radius: 6px; border: 1px solid ${fm.isElevatedEntropy ? '#F59E0B' : 'rgba(255,255,255,0.06)'}; display: flex; justify-content: space-between; align-items: center;">
              <span style="font-size: 0.76rem; font-family: monospace; color: var(--text-muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 140px;" title="${escapeHtml(fm.file)}">${escapeHtml(fm.file)}</span>
              <span class="badge-pill ${fm.isElevatedEntropy ? 'high' : 'reviewed'}" style="font-size: 0.65rem;">H: ${fm.entropy}</span>
            </div>
          `).join('')}
        </div>
      </div>
    `
    : '';

  elements.pkgAnalysisResultsArea.innerHTML = `
    <h3 style="color: #FFF; margin-bottom: 12px;">Package Audit: ${escapeHtml(report.extensionName)} (v${escapeHtml(report.version)})</h3>
    <div style="margin-bottom: 16px; font-size: 0.82rem; color: var(--text-muted);">
      Manifest Version: <strong>MV${report.manifestVersion}</strong> &bull; Total Files: <strong>${report.totalFiles}</strong> &bull; Permissions: <strong>${report.permissions.join(', ') || 'None'}</strong>
    </div>

    ${entropyHtml}

    <div style="margin-bottom: 16px;">
      <h4 style="color: #FFF; font-size: 0.85rem; margin-bottom: 8px;">Investigation Leads Found (${report.investigationLeads.length}):</h4>
      ${leadsHtml}
    </div>
  `;
}

function renderComparePackageReport(diff) {
  const sev = diff.overallSeverity.toLowerCase();

  const leadsHtml = diff.newInvestigationLeads.length > 0
    ? diff.newInvestigationLeads.map(lead => `
        <div style="background: var(--bg-base); padding: 12px; border-radius: 6px; margin-bottom: 8px; border-left: 3px solid ${lead.severity === 'HIGH' ? '#EF4444' : '#F59E0B'}">
          <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
            <span class="badge-pill ${lead.severity.toLowerCase()}">${lead.severity}</span>
            <span style="font-family: monospace; font-size: 0.76rem; color: var(--text-muted);">${escapeHtml(lead.file)}: line ${lead.line}</span>
          </div>
          <div style="font-weight: 600; color: #FFF; font-size: 0.85rem;">${escapeHtml(lead.category)}</div>
          <code style="display: block; background: #0A0E17; padding: 6px 10px; border-radius: 4px; margin: 6px 0; font-size: 0.78rem; color: var(--accent-cyan);">${escapeHtml(lead.preview)}</code>
          <div style="font-size: 0.78rem; color: var(--text-muted);">${escapeHtml(lead.description)}</div>
          <div style="font-size: 0.78rem; color: #34D399; margin-top: 4px;">Guidance: ${escapeHtml(lead.recommendation)}</div>
        </div>
      `).join('')
    : '<div style="color: #34D399; padding: 10px;">No new suspicious code patterns introduced in this version update.</div>';

  elements.pkgAnalysisResultsArea.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 12px;">
      <div>
        <h3 style="color: #FFF;">Differential Audit: ${escapeHtml(diff.packageA.name)} &rarr; ${escapeHtml(diff.packageB.name)}</h3>
        <span style="font-size: 0.82rem; color: var(--text-muted);">Version ${diff.packageA.version} &rarr; Version ${diff.packageB.version}</span>
      </div>
      <div>
        <span class="badge-pill ${sev}" style="font-size: 0.8rem; padding: 5px 10px;">${diff.overallSeverity} RISK</span>
      </div>
    </div>

    <!-- Permission Deltas -->
    <div style="margin-bottom: 16px;">
      <h4 style="color: #FFF; font-size: 0.85rem; margin-bottom: 4px;">Permission Changes:</h4>
      ${diff.addedPermissions.length > 0 
        ? `<div style="color: #F87171; font-size: 0.82rem;"><strong>+ Added (${diff.addedPermissions.length}):</strong> ${diff.addedPermissions.join(', ')}</div>` 
        : '<div style="color: #34D399; font-size: 0.82rem;">No new permissions added.</div>'}
      ${diff.removedPermissions.length > 0 
        ? `<div style="color: var(--text-muted); font-size: 0.82rem; margin-top: 4px;"><strong>- Removed (${diff.removedPermissions.length}):</strong> ${diff.removedPermissions.join(', ')}</div>` 
        : ''}
    </div>

    <!-- File Tree Deltas -->
    <div style="margin-bottom: 16px;">
      <h4 style="color: #FFF; font-size: 0.85rem; margin-bottom: 4px;">File Structure Changes:</h4>
      <div style="font-size: 0.82rem; color: var(--text-muted);">
        Added: <strong>${diff.addedFiles.length}</strong> &bull; Removed: <strong>${diff.removedFiles.length}</strong> &bull; Unmodified/Retained: <strong>${diff.modifiedOrRetainedCount}</strong>
      </div>
      ${diff.addedFiles.length > 0 ? `<div style="font-size: 0.78rem; color: var(--text-dim); margin-top: 4px;">Added files: ${diff.addedFiles.slice(0, 5).join(', ')}${diff.addedFiles.length > 5 ? '...' : ''}</div>` : ''}
    </div>

    <!-- New Investigation Leads -->
    <div style="margin-bottom: 16px;">
      <h4 style="color: #FFF; font-size: 0.85rem; margin-bottom: 8px;">Newly Introduced Investigation Leads (${diff.newInvestigationLeads.length}):</h4>
      ${leadsHtml}
    </div>

    <!-- Discovered Endpoints -->
    ${diff.newDiscoveredEndpoints.length > 0 ? `
      <div>
        <h4 style="color: #FFF; font-size: 0.85rem; margin-bottom: 6px;">Newly Discovered Outbound Endpoints:</h4>
        <ul style="padding-left: 20px; font-size: 0.82rem; color: var(--accent-cyan);">
          ${diff.newDiscoveredEndpoints.map(ep => `<li>${escapeHtml(ep)}</li>`).join('')}
        </ul>
      </div>
    ` : ''}
  `;
}

async function handleLoadSampleFixtures() {
  try {
    const pkg = SYNTHETIC_SCENARIOS.FIXTURE_PACKAGES;
    const bytesA = base64ToUint8Array(pkg.SUSPICIOUS_V1_BASE64);
    const bytesB = base64ToUint8Array(pkg.SUSPICIOUS_V2_BASE64);

    state.analyzer.fileA = { 
      name: 'weather-widget-v2.1.0.zip', 
      size: bytesA.byteLength, 
      arrayBuffer: () => Promise.resolve(bytesA.buffer) 
    };
    state.analyzer.fileB = { 
      name: 'weather-widget-v2.2.0.zip', 
      size: bytesB.byteLength, 
      arrayBuffer: () => Promise.resolve(bytesB.buffer) 
    };

    elements.pkgFileNameA.textContent = `weather-widget-v2.1.0.zip (${formatBytes(bytesA.byteLength)})`;
    elements.pkgFileNameA.style.display = 'inline-block';
    elements.pkgFileNameB.textContent = `weather-widget-v2.2.0.zip (${formatBytes(bytesB.byteLength)})`;
    elements.pkgFileNameB.style.display = 'inline-block';

    checkAnalyzerReady();
    await handleExecutePackageAnalysis();
    showNotice('Loaded synthetic test fixture: Weather Widget v2.1.0 vs v2.2.0 (detecting silent <all_urls> and cookies permission expansion).');
  } catch (err) {
    showNotice(`Error loading sample fixtures: ${err.message}`);
  }
}

// ==========================================================================
// BASELINE & SNAPSHOT MANAGER
// ==========================================================================
async function handleCaptureBaseline() {
  if (state.currentInventory.length === 0) {
    showNotice('Cannot capture baseline: No installed extensions detected in current browser profile.');
    return;
  }

  const label = prompt('Enter a label for this baseline checkpoint:', `Baseline ${new Date().toLocaleDateString()}`);
  if (!label) return;

  state.baseline = await saveBaseline(state.currentInventory, label);
  showNotice(`Baseline checkpoint recorded: "${label}" with ${state.currentInventory.length} extension(s).`);
  await loadData(true);
}

function openBaselineManager() {
  renderBaselineManagerView();
  elements.baselineManagerModal.style.display = 'flex';
}

function closeBaselineManager() {
  elements.baselineManagerModal.style.display = 'none';
}

function renderBaselineManagerView() {
  // Active Baseline Card
  if (state.baseline) {
    const extCount = Object.keys(state.baseline.extensions || {}).length;
    const dateStr = new Date(state.baseline.timestamp).toLocaleString();
    const hash = state.baseline.integrityHash || 'Computing SHA-256...';

    elements.baselineManagerActiveCard.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
        <div>
          <span style="font-size: 0.74rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--accent-cyan);">Currently Active Baseline</span>
          <h4 style="color: #FFF; font-size: 1.05rem; margin: 2px 0 0 0;">${escapeHtml(state.baseline.label || 'Saved Baseline')}</h4>
        </div>
        <span class="badge-pill reviewed">ACTIVE</span>
      </div>
      <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 8px;">
        Recorded: <strong>${escapeHtml(dateStr)}</strong> &bull; Total Extensions: <strong>${extCount}</strong>
      </div>
      <div style="background: rgba(0,0,0,0.3); border: 1px solid var(--border-subtle); border-radius: 6px; padding: 6px 10px; font-family: monospace; font-size: 0.72rem; color: var(--accent-cyan); word-break: break-all;">
        <span style="color: var(--text-dim); user-select: none;">SHA-256: </span>${escapeHtml(hash)}
      </div>
    `;
  } else {
    elements.baselineManagerActiveCard.innerHTML = `
      <div style="color: #F59E0B; font-weight: 600; font-size: 0.88rem; margin-bottom: 4px;">No Baseline Checkpoint Recorded</div>
      <div style="font-size: 0.8rem; color: var(--text-muted);">Capture your first baseline snapshot to track changes, drift, and verify cryptographic snapshot integrity.</div>
    `;
  }

  // History Checkpoints List
  if (!state.baselineHistory || state.baselineHistory.length === 0) {
    elements.baselineHistoryList.innerHTML = `
      <div style="color: var(--text-muted); font-size: 0.8rem; padding: 16px; text-align: center; border: 1px dashed var(--border-subtle); border-radius: 6px;">
        No baseline checkpoint history found. Click "Capture New Checkpoint" to record one.
      </div>
    `;
    return;
  }

  elements.baselineHistoryList.innerHTML = state.baselineHistory.map(cp => {
    const isActive = cp.id === state.baseline?.id;
    const dateStr = new Date(cp.timestamp).toLocaleString();
    const extCount = Object.keys(cp.extensions || {}).length;
    const hash = cp.integrityHash || 'N/A';
    const shortHash = hash.length > 16 ? `${hash.substring(0, 10)}...${hash.substring(hash.length - 6)}` : hash;

    return `
      <div style="background: var(--bg-surface); border: 1px solid ${isActive ? 'var(--accent-cyan)' : 'var(--border-subtle)'}; border-radius: 6px; padding: 10px 12px; display: flex; justify-content: space-between; align-items: center;">
        <div>
          <div style="display: flex; align-items: center; gap: 8px;">
            <strong style="color: #FFF; font-size: 0.85rem;">${escapeHtml(cp.label || 'Checkpoint')}</strong>
            ${isActive ? '<span class="badge-pill reviewed" style="font-size: 0.65rem;">Active</span>' : ''}
          </div>
          <div style="font-size: 0.74rem; color: var(--text-muted); margin-top: 2px;">
            ${escapeHtml(dateStr)} &bull; ${extCount} extension(s) &bull; <span style="font-family: monospace;" title="SHA-256: ${escapeAttr(hash)}">Hash: ${escapeHtml(shortHash)}</span>
          </div>
        </div>
        <div>
          ${!isActive ? `
            <button class="btn-ghost btn-switch-baseline" data-id="${escapeAttr(cp.id)}" style="padding: 4px 10px; font-size: 0.74rem;">
              Switch to This
            </button>
          ` : '<span style="font-size: 0.75rem; color: var(--accent-cyan); font-weight: 600;">Current</span>'}
        </div>
      </div>
    `;
  }).join('');

  // Attach switch button listeners
  elements.baselineHistoryList.querySelectorAll('.btn-switch-baseline').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.dataset.id;
      const ok = await switchActiveBaseline(targetId);
      if (ok) {
        showNotice(`Switched active baseline checkpoint to "${targetId}".`);
        await loadData(true);
        renderBaselineManagerView();
      } else {
        showNotice('Failed to switch baseline checkpoint.');
      }
    });
  });
}

// ==========================================================================
// EXPORT & REPORTING MODAL CONTROLLER
// ==========================================================================
function openExportImportModal() {
  elements.exportImportModal.style.display = 'flex';
}

function closeExportImportModal() {
  elements.exportImportModal.style.display = 'none';
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function handleDownloadJsonDossier() {
  try {
    const dossier = await exportAuditDossier(state.currentInventory, state.allChanges);
    const filename = `extensionledger-audit-dossier-${new Date().toISOString().slice(0, 10)}.json`;
    downloadFile(filename, JSON.stringify(dossier, null, 2), 'application/json');
    showNotice('Exported machine-readable Audit Dossier JSON.');
  } catch (err) {
    showNotice(`Export failed: ${err.message}`);
  }
}

function handleDownloadMarkdownReport() {
  try {
    const md = exportReportAsMarkdown(state.currentInventory, state.baseline, state.allChanges, state.allowlist);
    const filename = `extensionledger-security-report-${new Date().toISOString().slice(0, 10)}.md`;
    downloadFile(filename, md, 'text/markdown');
    showNotice('Exported human-readable Executive Audit Report (.md).');
  } catch (err) {
    showNotice(`Report generation failed: ${err.message}`);
  }
}

function handleDownloadCsvReport() {
  try {
    const csv = exportReportAsCSV(state.currentInventory, state.allChanges);
    const filename = `extensionledger-findings-${new Date().toISOString().slice(0, 10)}.csv`;
    downloadFile(filename, csv, 'text/csv');
    showNotice('Exported findings spreadsheet (.csv).');
  } catch (err) {
    showNotice(`CSV export failed: ${err.message}`);
  }
}

async function handleImportDossierFile(e) {
  const file = e.target.files?.[0];
  if (!file) return;

  try {
    const text = await file.text();
    const json = JSON.parse(text);
    const result = await importAuditDossier(json);
    closeExportImportModal();
    showNotice(`Successfully restored dossier: ${result.baselineCount} baseline(s) imported.`);
    await loadData(true);
  } catch (err) {
    showNotice(`Failed to import dossier: ${err.message}`);
  } finally {
    e.target.value = '';
  }
}

// Safe formatting helpers
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function escapeAttr(str) {
  if (!str) return '';
  return String(str).replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
