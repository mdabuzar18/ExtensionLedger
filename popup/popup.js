/**
 * ExtensionLedger - Browser Toolbar Popup Controller
 * Connects directly to local storage and browser management API.
 * Never fabricates protection claims or mock states.
 */

import { getInventory } from '../src/core/inventory.js';
import { getBaseline, getReviewedChanges, saveBaseline, getAllowlist } from '../src/core/storage.js';
import { diffSnapshots } from '../src/core/differ.js';
import { evaluateAllChanges, SEVERITY_LEVELS } from '../src/core/riskEngine.js';
import { isExtensionEnvironment } from '../src/core/browserApi.js';

document.addEventListener('DOMContentLoaded', () => {
  const elements = {
    btnScanRefresh: document.getElementById('btnScanRefresh'),
    spinIcon: document.querySelector('.spin-icon'),
    statusStrip: document.getElementById('statusStrip'),
    statusStripPrimary: document.getElementById('statusStripPrimary'),
    statusStripSecondary: document.getElementById('statusStripSecondary'),
    statusBadgePill: document.getElementById('statusBadgePill'),

    // View States
    stateLoading: document.getElementById('stateLoading'),
    statePermissionDenied: document.getElementById('statePermissionDenied'),
    stateError: document.getElementById('stateError'),
    stateErrorMsg: document.getElementById('stateErrorMsg'),
    stateContent: document.getElementById('stateContent'),
    stateEmptyChanges: document.getElementById('stateEmptyChanges'),

    // Dynamic Lists
    pendingCountBadge: document.getElementById('pendingCountBadge'),
    priorityChangeList: document.getElementById('priorityChangeList'),
    popupInventoryCount: document.getElementById('popupInventoryCount'),
    popupBaselineDate: document.getElementById('popupBaselineDate'),

    // Buttons
    btnOpenFullDashboard: document.getElementById('btnOpenFullDashboard'),
    btnRetryScan: document.getElementById('btnRetryScan'),
    btnGrantPermission: document.getElementById('btnGrantPermission')
  };

  // Switch between visual UI states
  function showViewState(viewName) {
    elements.stateLoading.style.display = viewName === 'loading' ? 'block' : 'none';
    elements.statePermissionDenied.style.display = viewName === 'permission_denied' ? 'block' : 'none';
    elements.stateError.style.display = viewName === 'error' ? 'block' : 'none';
    elements.stateContent.style.display = viewName === 'content' ? 'block' : 'none';
  }

  /**
   * Main audit execution for popup
   */
  async function runAudit() {
    elements.spinIcon?.classList.add('spinning');
    showViewState('loading');

    try {
      // 1. Check management API availability in extension environment
      if (typeof chrome !== 'undefined' && chrome.runtime && !chrome.management) {
        showViewState('permission_denied');
        elements.spinIcon?.classList.remove('spinning');
        return;
      }

      // 2. Fetch real local inventory
      const inventory = await getInventory();
      elements.popupInventoryCount.textContent = `${inventory.length} Extension${inventory.length !== 1 ? 's' : ''} Monitored`;

      // 3. Fetch active baseline
      const baseline = await getBaseline();

      if (!baseline) {
        // Truthful initial state: baseline not yet captured by user
        setStripStatus('no_baseline', 'Baseline Not Created', 'Click Capture Baseline in dashboard to begin', 'Setup');
        elements.popupBaselineDate.textContent = 'Baseline: Not created';
        elements.pendingCountBadge.textContent = '0 Pending';
        elements.stateEmptyChanges.style.display = 'block';
        elements.priorityChangeList.innerHTML = '';
        showViewState('content');
        elements.spinIcon?.classList.remove('spinning');
        return;
      }

      const baselineDate = new Date(baseline.timestamp).toLocaleDateString(undefined, {
        month: 'short', day: 'numeric'
      });
      elements.popupBaselineDate.textContent = `Baseline: ${baseline.label || baselineDate}`;

      // 4. Compare current inventory with baseline
      const rawDiff = diffSnapshots(baseline, inventory);
      const allowlist = await getAllowlist();
      const changes = evaluateAllChanges(rawDiff, allowlist);
      const reviewedMap = await getReviewedChanges();

      // Filter unreviewed actionable changes
      const pendingChanges = changes.filter(c => 
        c.assessment.requiresReview && !reviewedMap[c.changeKey]
      );

      // Sort priority changes (Critical > High > Medium > Low)
      const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
      pendingChanges.sort((a, b) => (rank[b.assessment.severity] || 0) - (rank[a.assessment.severity] || 0));

      elements.pendingCountBadge.textContent = `${pendingChanges.length} Pending`;

      // 5. Update Status Strip
      if (pendingChanges.length > 0) {
        const hasCritical = pendingChanges.some(c => c.assessment.severity === SEVERITY_LEVELS.CRITICAL);
        const hasHigh = pendingChanges.some(c => c.assessment.severity === SEVERITY_LEVELS.HIGH);

        if (hasCritical) {
          setStripStatus(
            'critical',
            'Critical Permission Drift',
            `${pendingChanges.length} change(s) require security review`,
            'Critical'
          );
        } else if (hasHigh) {
          setStripStatus(
            'high',
            'Elevated Capabilities Added',
            `${pendingChanges.length} change(s) require review`,
            'Review'
          );
        } else {
          setStripStatus(
            'pending',
            'Extension Changes Observed',
            `${pendingChanges.length} unreviewed update(s) detected`,
            'Review'
          );
        }

        renderPriorityChanges(pendingChanges.slice(0, 4));
        elements.stateEmptyChanges.style.display = 'none';
      } else {
        setStripStatus(
          'synced',
          'Baseline Synchronized',
          `${inventory.length} extension(s) match approved baseline`,
          'Synced'
        );
        elements.priorityChangeList.innerHTML = '';
        elements.stateEmptyChanges.style.display = 'block';
      }

      showViewState('content');
    } catch (err) {
      console.error('[ExtensionLedger Popup Error]:', err);
      elements.stateErrorMsg.textContent = err.message || 'Error communicating with local storage.';
      showViewState('error');
    } finally {
      elements.spinIcon?.classList.remove('spinning');
    }
  }

  function setStripStatus(variant, primary, secondary, pillText) {
    elements.statusStrip.className = 'status-strip';
    if (variant === 'critical') {
      elements.statusStrip.classList.add('status-alert-critical');
    } else if (variant === 'high' || variant === 'pending') {
      elements.statusStrip.classList.add('status-alert-pending');
    } else {
      elements.statusStrip.classList.add('status-synced');
    }

    elements.statusStripPrimary.textContent = primary;
    elements.statusStripSecondary.textContent = secondary;
    elements.statusBadgePill.textContent = pillText;
  }

  /**
   * Renders the top priority change cards
   */
  function renderPriorityChanges(items) {
    const defaultIcon = '../icons/icon-16.png';
    let html = '';

    for (const item of items) {
      const sev = item.assessment.severity.toLowerCase();
      const icon = item.iconUrl || defaultIcon;

      html += `
        <div class="stream-card border-${sev}" data-finding="${escapeAttr(item.changeKey)}" data-ext="${escapeAttr(item.extensionId)}">
          <div class="stream-card-top">
            <div class="stream-ext-identity">
              <img class="stream-ext-icon" src="${icon}" onerror="this.src='${defaultIcon}'" alt="">
              <span class="stream-ext-name">${escapeHtml(item.extensionName)}</span>
            </div>
            <span class="badge-tag ${sev}">${item.assessment.severity}</span>
          </div>
          <div class="stream-card-title">${escapeHtml(item.assessment.title)}</div>
          <div class="stream-card-summary">${escapeHtml(item.assessment.whatChanged || item.summary)}</div>
          <div class="stream-card-footer">
            <span>v${escapeHtml(item.extensionVersion || '1.0')}</span>
            <span class="action-link-arrow">Investigate &rarr;</span>
          </div>
        </div>
      `;
    }

    elements.priorityChangeList.innerHTML = html;

    // Attach click listeners to deep-link into dashboard
    elements.priorityChangeList.querySelectorAll('.stream-card').forEach(card => {
      card.addEventListener('click', () => {
        const findingKey = card.dataset.finding;
        const extId = card.dataset.ext;
        openDashboard(`#finding=${encodeURIComponent(findingKey)}&ext=${encodeURIComponent(extId)}`);
      });
    });
  }

  function openDashboard(hash = '') {
    if (!hash && typeof chrome !== 'undefined' && typeof chrome.runtime?.openOptionsPage === 'function') {
      chrome.runtime.openOptionsPage();
      return;
    }
    const targetUrl = chrome.runtime?.getURL 
      ? chrome.runtime.getURL(`dashboard/dashboard.html${hash}`) 
      : `../dashboard/dashboard.html${hash}`;

    if (typeof chrome !== 'undefined' && chrome.tabs?.create) {
      chrome.tabs.create({ url: targetUrl });
    } else {
      window.open(targetUrl, '_blank');
    }
  }

  // Event Listeners
  elements.btnScanRefresh.addEventListener('click', () => runAudit());
  elements.btnRetryScan.addEventListener('click', () => runAudit());
  elements.btnOpenFullDashboard.addEventListener('click', () => openDashboard());
  elements.btnGrantPermission.addEventListener('click', () => {
    if (typeof chrome !== 'undefined' && chrome.runtime?.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      openDashboard();
    }
  });

  // Safe string helpers
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

  // Initial Execution
  runAudit();
});
