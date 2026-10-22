# ExtensionLedger

> **Browser Extension Security Auditing & Drift Detection System**  
> *Built for Google Chrome (Manifest V3) & Microsoft Edge*

ExtensionLedger is a defensive cybersecurity auditing extension designed to help security teams, privacy researchers, and conscious users track browser extension inventory, record immutable baseline snapshots, detect permission drift over time, and inspect extension packages locally for potential risks.

---

## Key Features

1. **Extension Inventory & Attack Surface Mapping**
   - Automatically surveys all installed extensions via `chrome.management`.
   - Normalizes declared capabilities, distinguishing broad website access (`<all_urls>`, `*://*/*`) from isolated APIs (`storage`, `alarms`).
   - Identifies installation mechanisms (Official Web Store, Unpacked / Developer Mode, Sideloaded, or Enterprise Admin).

2. **Baseline Snapshots & Drift Detection**
   - Allows users to record a clean baseline snapshot at any moment.
   - Detects functional drifts: version upgrades/downgrades, new installations, removals, enabled/disabled transitions, and permission expansions/reductions.
   - Accurately distinguishes functional security changes from benign metadata updates (description tweaks, localized titles, icon updates).

3. **Explainable, Rule-Based Risk Engine**
   - **Zero Black-Box Scoring**: Explains *why* a change or extension is flagged with specific evidence, security reasoning, and recommended user actions.
   - **Fair & Objective**: Never labels an extension "malicious" merely for requesting permissions or issuing an update.
   - Multi-tier severity classification: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, and `INFO`.

4. **100% Client-Side Package Analyzer (ZIP Diffing)**
   - Extract and inspect extension `.zip` packages entirely in-memory using native browser decompression (`DecompressionStream`).
   - **Never executes uploaded code**.
   - Compares two versions (v1 vs v2): highlights added permissions, manifest adjustments, modified files, and newly introduced sensitive code paths (dynamic `eval`, hardcoded external endpoints, cookie interception, high-entropy strings).

5. **Strict Privacy & Safety Guardrails**
   - **Zero Telemetry / Zero External Requests**: All snapshots, diffs, and package audits stay in local storage (`chrome.storage.local`).
   - **Minimal Justified Permissions**: Only requires `management` (for inventory) and `storage` (for persistence). Does not request `tabs`, `<all_urls>`, `webRequest`, or background cookies.
   - Does not collect browsing history, webpage content, credentials, or keystrokes.

---

## Architecture

```
ExtensionLedger/
├── manifest.json              # Chrome Extensions Manifest V3
├── service-worker.js          # Background lifecycle listener & badge updater
├── icons/                     # Standard extension icons (16px, 48px, 128px)
├── src/
│   ├── core/
│   │   ├── browserApi.js      # Cross-browser abstraction layer (Chrome/Edge/Mock)
│   │   ├── inventory.js       # chrome.management normalizer & permission parser
│   │   ├── storage.js         # Local snapshot persistence & review manager
│   │   ├── differ.js          # Semantic differ engine (functional vs metadata)
│   │   ├── riskEngine.js      # Explainable rule-based risk evaluation
│   │   ├── packageAnalyzer.js # Safe static ZIP parser & lexical pattern scanner
│   │   └── syntheticData.js   # Pre-built benchmark scenarios & fixture payloads
│   └── lib/
│       └── zipReader.js       # Native client-side ZIP extractor (zero npm dependencies)
├── dashboard/                 # Comprehensive Cybersecurity Dashboard
│   ├── dashboard.html
│   ├── dashboard.css
│   └── dashboard.js
├── popup/                     # Action toolbar popup
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── test-fixtures/             # Synthetic benign & suspicious extension archives
└── tests/                     # Automated unit test suite (Node.js test runner)
```

---

## Installation & Setup

### Prerequisites
- Google Chrome (version 100+) or Microsoft Edge (version 100+)
- Node.js (v18+) for running the test suite

### Loading Unpacked in Google Chrome
1. Open Google Chrome and navigate to `chrome://extensions`.
2. Enable **Developer mode** using the toggle switch in the top-right corner.
3. Click the **Load unpacked** button in the top-left corner.
4. Select the `ExtensionLedger` project root folder (`/path/to/ExtensionLedger`).
5. ExtensionLedger will appear in your extensions list and pin an action icon to your toolbar.

### Loading Unpacked in Microsoft Edge
1. Open Microsoft Edge and navigate to `edge://extensions`.
2. Enable **Developer mode** in the left sidebar.
3. Click **Load unpacked** and select the `ExtensionLedger` folder.

---

## User Workflow & Dashboard Sections

### 1. Browser Toolbar Popup (`popup/`)
- **Compact (~380px)**: Designed specifically for the Chrome/Edge toolbar dropdown.
- **Real Protection Status**: Displays active baseline synchronization status without fabricated security claims.
- **Change Intelligence Stream**: Shows up to 4 priority unreviewed drifts with extension icons, names, severity tags, and what changed.
- **Deep-Linking**: Clicking any item opens the full Security Dashboard directly focused on that finding (`#finding=<key>`).
- **Defensive Error Handling**: Displays explicit states for loading, empty verified baselines, scan errors, and missing browser `management` permissions.

### 2. Extension Watchlist (Section A)
- **Identifiable Extension Items**: Real extension icons, verified publisher attribution (Chrome Web Store, Edge Add-ons, Local Developer Build, Enterprise Policy, or Sideloaded), semantic versions, and granted permissions.
- **Master-Detail Security Dossier**: Selecting an extension reveals its complete attack surface footprint: declared API capabilities, authorized website interception scopes (`All Websites` vs `Specific Sites`), and its individual chronological drift history.

### 3. Change Intelligence Timeline (Section B)
- **Chronological Event Ledger**: Vertical timeline connecting every observable event: installations, version bumps, permission creep, and status toggles.
- **Severity Nodes**: Visual color-coded severity dots (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) with direct "Investigate Finding &rarr;" links.

### 4. Security Investigation Center (Section D)
- **Filterable Findings Roster**: Filter by severity and review state (Pending Investigation vs Reviewed).
- **Comprehensive Finding Dossier**: Every finding breaks down:
  1. **What Changed**: Technical summary of the delta.
  2. **Introduced in Version**: Exact version attribution.
  3. **Why It May Matter**: Security and privacy risk impact.
  4. **Evidence Panel**: Concrete proof (wildcard patterns, elevated API keys).
  5. **System Boundary & Blind Spots**: Transparent statement of what client-side analysis cannot observe (e.g. inability to decrypt runtime HTTPS traffic or verify server-side databases).
  6. **Recommended Investigation Checklist**: Actionable steps for the analyst.

### 5. Version Diff Explorer & Network Destination Graph (Section C)
- **Manifest Diff**: Side-by-side baseline vs current manifest state.
- **Network Destination Graph / Map**: Only rendered when actual destination data is declared or extracted. Categorizes broad wildcards vs targeted domains and highlights newly introduced endpoints in red.

### 6. Local Package Analyzer (Section E)
- **100% In-Memory ZIP Inspection**: Extract and inspect extension `.zip` packages without executing code.
- **Differential Code Inspection**: Identifies added/removed files, manifest deltas, and newly introduced code investigation leads (`eval`, dynamic `Function`, external beacon endpoints, and credential access).
- **One-Click Fixtures**: "Load Pre-Built Test Fixture" enables instant offline evaluation.

---

## Automated Testing & Verification

ExtensionLedger includes an automated test suite verifying version ranking, permission categorizations, delta detection, explainable risk scoring, and zip package static analysis.

### Running Automated Tests
```bash
npm test
```
The test suite currently includes 46 automated unit tests validating browser detection, native extension behavior, self-exclusion, baseline capture & storage, permission diffing, rule-based risk evaluation, package ZIP parsing, review persistence, and uninstall safety.

### Pre-Built Test Fixtures for Package Analyzer
Pre-built synthetic test fixtures are available in `test-fixtures/` and can be loaded directly inside the **Package Analyzer** tab:
1. **Benign Update (`benign-v1.zip` &rarr; `benign-v2.zip`)**: Routine patch bump (1.0.0 &rarr; 1.0.1) with no new permissions; verifies that risk engine evaluates to `LOW` and avoids false positive alert spam.
2. **Suspicious Permission Expansion (`suspicious-expansion-v1.zip` &rarr; `suspicious-expansion-v2.zip`)**: Weather widget adding `<all_urls>`, `cookies`, and `webRequest`; triggers `CRITICAL` risk rating.
3. **Stealth Code Modification (`stealth-code-v1.zip` &rarr; `stealth-code-v2.zip`)**: Permissions remain identical, but source introduces dynamic `eval()` and remote telemetry endpoint; flags investigation leads without false claims.
4. **False Positive Check (`false-positive-check-v1.zip` &rarr; `false-positive-check-v2.zip`)**: Benign description and locale updates; verifies classification as `INFO` metadata update.

To test package inspection, navigate to the **Package Analyzer** tab in the dashboard and click **Load Pre-Built Test Fixture**, or drag and drop any `.zip`/`.crx` package.

---

## Testing ExtensionLedger in Google Chrome & Microsoft Edge

### Step 1: Load Extension as Unpacked
1. Open Google Chrome (`chrome://extensions`) or Microsoft Edge (`edge://extensions`).
2. Turn on the **Developer mode** toggle in the top-right corner (Chrome) or left sidebar (Edge).
3. Click **Load unpacked** and select this directory: `/path/to/ExtensionLedger`.
4. Verify that `ExtensionLedger - Extension Security Auditor` appears with its shield icon and Manifest V3 metadata.

### Step 2: Open the Toolbar Popup
1. Click the puzzle icon in your browser toolbar and pin **ExtensionLedger**.
2. Click the ExtensionLedger shield icon to open the compact toolbar popup (`popup/popup.html`).
3. If no baseline has been captured, the popup displays **"Baseline Not Created"** with a setup badge.

### Step 3: Open the Full Security Dashboard
1. In the popup, click **Open Security Dashboard** (or right-click the extension icon and select **Options**).
2. The dashboard opens at `chrome-extension://<id>/dashboard/dashboard.html`.
3. The dashboard surveys all real installed extensions via `chrome.management.getAll()`, excluding ExtensionLedger itself to prevent self-auditing noise.

### Step 4: Capture a Real Baseline
1. Click **Capture Baseline** in the top command bar.
2. Enter an optional baseline label (e.g. `My Initial Baseline`).
3. ExtensionLedger saves an immutable snapshot of all installed extensions, versions, permissions, and scopes to `chrome.storage.local`.
4. The baseline state updates to display the verified timestamp and baseline label.

### Step 5: Test Drift Detection
1. In `chrome://extensions`, install any new extension from the Chrome Web Store, or toggle an existing extension off/on, or load an updated unpacked extension.
2. ExtensionLedger's background service worker (`service-worker.js`) automatically detects the lifecycle event (`onInstalled`, `onEnabled`, `onDisabled`, `onUninstalled`) and records it to storage.
3. Re-open ExtensionLedger's dashboard or popup: the Change Intelligence Timeline displays the real observed delta, and the Security Investigation center generates an evidence-backed finding explaining the security impact.

### Step 6: Test Review & Uninstall Actions
1. **Review**: Click **Review** on any finding or extension row. View the complete dossier, permissions, and uncertainty notes. Click **Mark as Reviewed** to persist review status.
2. **Uninstall**: Open the detail view for any non-policy extension and click **Uninstall Extension**. The browser will show its native uninstallation confirmation prompt. Cancellation or completion is safely handled and immediately updates inventory.

---

## Limitations & Security Boundaries

Transparency is essential in defensive security tooling:

1. **Static Analysis Limitations**: ExtensionLedger analyzes manifest declarations, filesystem differences, and static lexical patterns. It does not execute untrusted extensions in an isolated dynamic sandbox.
2. **Encrypted / Obfuscated Payloads**: Heavily obfuscated code or encrypted steganographic blobs loaded from remote origins cannot be statically reversed in pure browser-side regex/lexical passes.
3. **Host-Level Native Messaging**: An extension declared with `nativeMessaging` communicates with local OS binaries. ExtensionLedger alerts users to this capability (`CRITICAL`), but cannot monitor native operating system process memory outside the browser.
4. **No Network Traffic Interception**: In accordance with the project's zero-leakage, minimal-permission architecture, ExtensionLedger intentionally does not intercept raw network packets or decrypt HTTPS sessions.
5. **Investigative Leads vs Proof**: Findings produced by the rule engine and package analyzer are investigation indicators to assist human verification, not conclusive proof of malicious intent.

---

## License
Apache License 2.0. Built for security auditing and transparency.
