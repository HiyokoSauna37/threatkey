// ===== Actions =====
const ACTIONS = {
  TOGGLE: 'toggle',
  COPY: 'copy-to-clipboard',
  FETCH_NVD: 'fetch-nvd',
};

// ===== Context Menu: Base64 Encode/Decode =====
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'base64-encode',
    title: 'Base64 Encode',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'base64-decode',
    title: 'Base64 Decode',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const text = info.selectionText;
  if (!text) return;

  let result;
  if (info.menuItemId === 'base64-encode') {
    try {
      const bytes = new TextEncoder().encode(text);
      let binary = '';
      for (const b of bytes) binary += String.fromCharCode(b);
      result = btoa(binary);
    } catch {
      result = '[Encode error]';
    }
  } else if (info.menuItemId === 'base64-decode') {
    try {
      const binary = atob(text.trim());
      const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
      result = new TextDecoder().decode(bytes);
    } catch {
      result = '[Invalid Base64]';
    }
  } else {
    return;
  }

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: (text, label) => {
      window.__tk.showBase64Result(text, label);
    },
    args: [result, info.menuItemId === 'base64-encode' ? 'Encoded' : 'Decoded'],
  });
});

// ===== Threat-intel lookups (content script sends {lookup, text}) =====
const LOOKUPS = {
  nvd(text) {
    const cveMatch = text.match(/CVE-\d{4}-\d{4,}/i);
    if (cveMatch) {
      chrome.tabs.create({ url: 'https://nvd.nist.gov/vuln/detail/' + cveMatch[0].toUpperCase() });
    }
  },
  ransomlook(text) {
    const group = text.toLowerCase().replace(/\s+/g, '');
    chrome.tabs.create({ url: 'https://www.ransomlook.io/group/' + encodeURIComponent(group) });
  },
  malpedia(text) {
    const actor = text.toLowerCase().replace(/\s+/g, '_');
    chrome.tabs.create({ url: 'https://malpedia.caad.fkie.fraunhofer.de/actor/' + encodeURIComponent(actor) });
  },
  virustotal(text) {
    const hash = text.replace(/\s+/g, '');
    chrome.tabs.create({ url: 'https://www.virustotal.com/gui/search/' + encodeURIComponent(hash) });
  },
};

// ===== Keyboard Shortcut =====
chrome.commands.onCommand.addListener((command) => {
  if (command !== 'activate') return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) return;
    chrome.tabs.sendMessage(tabs[0].id, { action: ACTIONS.TOGGLE }).catch((err) => {
      console.debug('[ThreatKey] KeySelect toggle failed (restricted page?):', err.message);
    });
  });
});

// ===== Icon Click: Copy Highlighted Tabs' URLs =====
chrome.action.onClicked.addListener(async () => {
  let tabs;
  try {
    tabs = await chrome.tabs.query({ highlighted: true, currentWindow: true });
  } catch (e) {
    return;
  }
  if (!tabs || tabs.length === 0) return;

  const urls = tabs.map((t) => t.url).filter(Boolean).join('\n');
  if (!urls) return;

  const activeTab = tabs.find((t) => t.active) || tabs[0];

  // Try content script message first
  try {
    await chrome.tabs.sendMessage(activeTab.id, {
      action: ACTIONS.COPY,
      text: urls,
      count: tabs.length,
    });
    return; // Success
  } catch (e) {
    // Content script not available — fall back to script injection
  }

  // Fallback: inject a one-shot script to perform the copy
  try {
    await chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      func: (text, count) => {
        navigator.clipboard.writeText(text).then(() => {
          // Create inline toast since tk-utils may not be loaded
          const toast = document.createElement('div');
          toast.textContent = count + ' 件のURLをコピーしました';
          toast.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);' +
            'background:#1a1a2e;color:#00c8ff;border:1px solid #00c8ff;padding:8px 20px;' +
            'border-radius:8px;font-size:13px;font-weight:600;z-index:2147483645;' +
            'pointer-events:none;font-family:-apple-system,sans-serif;';
          (document.documentElement || document.body).appendChild(toast);
          setTimeout(() => {
            toast.style.transition = 'opacity 0.3s';
            toast.style.opacity = '0';
            setTimeout(() => { toast.remove(); }, 300);
          }, 2000);
        }).catch(() => {
          // Clipboard write failed on this page
        });
      },
      args: [urls, tabs.length],
    });
  } catch (e) {
    // Restricted page (chrome://, etc.) — cannot inject
    console.debug('[ThreatKey] URL copy failed (restricted page):', e.message);
  }
});

// ===== Message Dispatch =====
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return false;

  if (msg.action === ACTIONS.FETCH_NVD) {
    if (!/^CVE-\d{4}-\d{4,}$/i.test(msg.cveId || '')) {
      sendResponse({ error: 'Invalid CVE ID' });
      return false;
    }
    fetchNvd(msg.cveId).then(sendResponse);
    return true; // Keep message channel open for async sendResponse
  }

  if (msg.lookup) {
    const handler = LOOKUPS[msg.lookup];
    const text = (msg.text || '').trim();
    if (handler && text) handler(text);
  }
  return false;
});

// ===== NVD API Fetch for CVE Tooltip =====
const CVSS_METRIC_KEYS = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];

async function fetchNvd(cveId) {
  const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + encodeURIComponent(cveId);

  let json;
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error('HTTP ' + r.status);
    json = await r.json();
  } catch (err) {
    return { error: 'API error: ' + err.message };
  }

  try {
    const vuln = json.vulnerabilities && json.vulnerabilities[0] && json.vulnerabilities[0].cve;
    if (!vuln) return { error: 'Not found' };

    const descs = vuln.descriptions || [];
    const en = descs.find((d) => d.lang === 'en');
    const desc = en ? en.value : (descs[0] ? descs[0].value : '');

    let score = null;
    let severity = null;
    const metrics = vuln.metrics || {};
    for (const key of CVSS_METRIC_KEYS) {
      const m = metrics[key] && metrics[key][0];
      if (!m) continue;
      score = m.cvssData.baseScore;
      // CVSS v2 keeps baseSeverity on the metric object, v3.x inside cvssData
      severity = key === 'cvssMetricV2' ? m.baseSeverity : m.cvssData.baseSeverity;
      break;
    }

    return { description: desc, score: score, severity: severity };
  } catch (parseErr) {
    return { error: 'Parse error' };
  }
}
