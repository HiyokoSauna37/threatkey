/*
 * ThreatKey service worker.
 *
 * Owns everything the content scripts cannot do themselves: cross-origin
 * lookups (NVD / EPSS / CISA KEV), their cache and rate limiting, the context
 * menu, the activation command and the tab-URL copy.
 */

// ===== Actions =====
const ACTIONS = {
  TOGGLE: 'toggle',
  COPY: 'copy-to-clipboard',
  FETCH_CVE: 'fetch-cve',
};

const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_SEARCH = 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=';
const EPSS_API = 'https://api.first.org/data/v1/epss';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const CVE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const CVE_ERROR_TTL_MS = 10 * 60 * 1000;
const KEV_TTL_MS = 24 * 60 * 60 * 1000;
const FETCH_TIMEOUT_MS = 12000;

// NVD allows 5 requests / 30 s anonymously and 50 / 30 s with an API key.
const NVD_GAP_ANON_MS = 6500;
const NVD_GAP_KEY_MS = 700;
const NVD_QUEUE_MAX = 8;

// ===== Context menu =====

const MENU_ITEMS = [
  { id: 'base64-encode', title: 'Base64 Encode' },
  { id: 'base64-decode', title: 'Base64 Decode' },
  { id: 'defang', title: 'Defang IOC' },
  { id: 'refang', title: 'Refang IOC' },
];

chrome.runtime.onInstalled.addListener(() => {
  // removeAll first: without it an update re-runs create() on ids that already
  // exist and Chrome rejects the whole batch.
  chrome.contextMenus.removeAll(() => {
    for (const item of MENU_ITEMS) {
      chrome.contextMenus.create({ id: item.id, title: item.title, contexts: ['selection'] });
    }
  });
});

const TRANSFORMS = {
  'base64-encode': (text) => {
    const bytes = new TextEncoder().encode(text);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  },
  'base64-decode': (text) => {
    let value = text.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (value.length % 4) value += '='.repeat(4 - (value.length % 4));
    const binary = atob(value);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  },
  defang: (text) => text
    .replace(/\./g, '[.]')
    .replace(/:\/\//g, '[://]')
    .replace(/\bhttp/gi, (m) => (m[0] === 'H' ? 'HXXP' : 'hxxp'))
    .replace(/@/g, '[at]'),
  refang: (text) => text
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, '.')
    .replace(/\[:\/\/\]|\[:\]\/\//g, '://')
    .replace(/\bhxxp/gi, (m) => (m[0] === 'H' ? 'HTTP' : 'http'))
    .replace(/\[at\]|\[@\]/gi, '@'),
};

const RESULT_LABEL = {
  'base64-encode': 'Base64 Encoded',
  'base64-decode': 'Base64 Decoded',
  defang: 'Defanged',
  refang: 'Refanged',
};

chrome.contextMenus.onClicked.addListener((info, tab) => {
  const transform = TRANSFORMS[info.menuItemId];
  const text = info.selectionText;
  if (!transform || !text || !tab) return;

  let result;
  try {
    result = transform(text);
  } catch (e) {
    result = '[' + RESULT_LABEL[info.menuItemId] + ' failed: ' + e.message + ']';
  }

  chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: (value, label) => {
      if (window.__tk) window.__tk.showBase64Result(value, label);
      else console.warn('[ThreatKey] content script not loaded on this page');
    },
    args: [result, RESULT_LABEL[info.menuItemId]],
  }).catch((e) => {
    console.debug('[ThreatKey] transform injection failed:', e.message);
  });
});

// ===== Threat-intel lookups (content script sends {lookup, text}) =====

const LOOKUPS = {
  nvd(text) {
    const cve = text.match(/CVE-\d{4}-\d{4,7}/i);
    // No CVE in the selection: fall back to NVD's keyword search.
    return cve
      ? 'https://nvd.nist.gov/vuln/detail/' + cve[0].toUpperCase()
      : NVD_SEARCH + encodeURIComponent(text);
  },
  ransomlook(text) {
    return 'https://www.ransomlook.io/group/' + encodeURIComponent(text.toLowerCase().replace(/\s+/g, ''));
  },
  malpedia(text) {
    return 'https://malpedia.caad.fkie.fraunhofer.de/actor/' +
      encodeURIComponent(text.toLowerCase().replace(/\s+/g, '_'));
  },
  virustotal(text) {
    return 'https://www.virustotal.com/gui/search/' + encodeURIComponent(text.replace(/\s+/g, ''));
  },
};

// ===== Keyboard shortcut =====

chrome.commands.onCommand.addListener((command) => {
  if (command !== 'activate') return;
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || !tabs[0]) return;
    chrome.tabs.sendMessage(tabs[0].id, { action: ACTIONS.TOGGLE }).catch((err) => {
      console.debug('[ThreatKey] KeySelect toggle failed (restricted page?):', err.message);
    });
  });
});

// ===== Icon click: copy highlighted tabs' URLs =====

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

  try {
    await chrome.tabs.sendMessage(activeTab.id, {
      action: ACTIONS.COPY,
      text: urls,
      count: tabs.length,
    });
    return;
  } catch (e) {
    // Content script not available — fall back to script injection.
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      func: (text, count) => {
        navigator.clipboard.writeText(text).then(() => {
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
            setTimeout(() => toast.remove(), 300);
          }, 2000);
        }).catch(() => {});
      },
      args: [urls, tabs.length],
    });
  } catch (e) {
    console.debug('[ThreatKey] URL copy failed (restricted page):', e.message);
  }
});

// ===== Message dispatch =====

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return false;

  if (msg.action === ACTIONS.FETCH_CVE) {
    if (!/^CVE-\d{4}-\d{4,7}$/i.test(msg.cveId || '')) {
      sendResponse({ error: 'CVE番号の形式が正しくありません。' });
      return false;
    }
    fetchCve(msg.cveId.toUpperCase())
      .then(sendResponse, (err) => sendResponse({
        error: 'CVE情報の取得に失敗しました: ' + String(err && err.message || err),
      }));
    return true; // keep the channel open for the async reply
  }

  if (msg.lookup) {
    const build = LOOKUPS[msg.lookup];
    const text = (msg.text || '').trim();
    if (build && text) chrome.tabs.create({ url: build(text) });
  }
  return false;
});

// ===== Fetch plumbing =====

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchJson(url, headers) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { headers: headers, signal: controller.signal });
    if (!response.ok) {
      const err = new Error('HTTP ' + response.status);
      err.status = response.status;
      throw err;
    }
    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

// Serial queue that spaces NVD calls out; without it a page full of CVEs trips
// the public rate limit and every tooltip fails at once.
let nvdTail = Promise.resolve();
let nvdDepth = 0;
let nvdLastAt = 0;

function enqueueNvd(task, gapMs) {
  if (nvdDepth >= NVD_QUEUE_MAX) {
    return Promise.reject(new Error('Too many pending NVD lookups'));
  }
  nvdDepth++;
  const result = nvdTail.then(async () => {
    const wait = nvdLastAt + gapMs - Date.now();
    if (wait > 0) await sleep(wait);
    nvdLastAt = Date.now();
    return task();
  });
  nvdTail = result.then(() => {}, () => {});
  result.then(() => { nvdDepth--; }, () => { nvdDepth--; });
  return result;
}

// ===== CISA KEV =====

let kevPromise = null;

function getKev() {
  if (!kevPromise) {
    kevPromise = loadKev().finally(() => {
      // Allow a retry on the next hover, but not a stampede during this one.
      setTimeout(() => { kevPromise = null; }, 60000);
    });
  }
  return kevPromise;
}

async function loadKev() {
  const stored = (await chrome.storage.local.get('kev')).kev;
  if (stored && Date.now() - stored.t < KEV_TTL_MS) return stored.ids;

  try {
    const json = await fetchJson(KEV_URL);
    const ids = {};
    for (const v of json.vulnerabilities || []) {
      ids[v.cveID] = {
        dateAdded: v.dateAdded,
        dueDate: v.dueDate,
        ransomware: /known/i.test(v.knownRansomwareCampaignUse || ''),
      };
    }
    await chrome.storage.local.set({ kev: { t: Date.now(), ids: ids } });
    return ids;
  } catch (e) {
    console.debug('[ThreatKey] KEV refresh failed:', e.message);
    return stored ? stored.ids : null; // stale data beats no data
  }
}

// ===== EPSS =====

/** Returns the score, `null` when FIRST has no score for this CVE, or
 *  `undefined` when the request failed and is worth retrying. */
async function fetchEpss(cveId) {
  try {
    const json = await fetchJson(EPSS_API + '?cve=' + encodeURIComponent(cveId));
    const row = json.data && json.data[0];
    if (!row) return null;
    return { score: parseFloat(row.epss), percentile: parseFloat(row.percentile) };
  } catch (e) {
    return undefined;
  }
}

// ===== NVD =====

// CVSS v4.0 first: NVD started publishing cvssMetricV40 alongside v3.1.
const CVSS_METRIC_KEYS = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'];

async function fetchNvd(cveId, apiKey) {
  const url = NVD_API + '?cveId=' + encodeURIComponent(cveId);
  const headers = apiKey ? { apiKey: apiKey } : undefined;
  const gap = apiKey ? NVD_GAP_KEY_MS : NVD_GAP_ANON_MS;

  let json;
  try {
    json = await enqueueNvd(() => fetchJson(url, headers), gap);
  } catch (err) {
    return { error: describeNvdError(err) };
  }

  const vuln = json.vulnerabilities && json.vulnerabilities[0] && json.vulnerabilities[0].cve;
  if (!vuln) return { error: 'NVDに該当するCVE情報がありません。' };

  const descriptions = vuln.descriptions || [];
  const japanese = descriptions.find((d) => d.lang === 'ja');
  const english = descriptions.find((d) => d.lang === 'en') || descriptions[0];
  const description = japanese || english;

  const result = {
    description: description ? description.value : '',
    descriptionLang: description ? description.lang : null,
    published: vuln.published || null,
    score: null,
    severity: null,
    vector: null,
  };

  const metrics = vuln.metrics || {};
  for (const key of CVSS_METRIC_KEYS) {
    const list = metrics[key];
    if (!list || !list.length) continue;
    const metric = list.find((m) => m.type === 'Primary') || list[0];
    result.score = metric.cvssData.baseScore;
    // CVSS v2 keeps baseSeverity on the metric object; v3.x and v4.0 nest it.
    result.severity = key === 'cvssMetricV2' ? metric.baseSeverity : metric.cvssData.baseSeverity;
    result.vector = metric.cvssData.vectorString || null;
    break;
  }
  return result;
}

function describeNvdError(err) {
  if (err.name === 'AbortError') return 'NVDへの接続がタイムアウトしました。';
  if (err.status === 403 || err.status === 429) {
    return 'NVDのレート制限に達しました。拡張機能のオプションでNVD APIキーを設定してください。';
  }
  if (err.status === 404) return 'NVDに該当するCVE情報がありません。';
  if (/Too many pending/i.test(err.message || '')) {
    return 'NVDへの取得待ちが多すぎます。しばらく待ってから再度ホバーしてください。';
  }
  return 'NVDからの取得に失敗しました: ' + err.message;
}

// ===== Combined lookup =====

async function fetchCve(cveId) {
  const key = 'cve:' + cveId;
  const stored = (await chrome.storage.local.get(key))[key];
  if (stored) {
    // A partial answer (NVD failed, or the KEV catalog was unreachable) expires
    // quickly so the next hover can fill in what is missing.
    const complete = stored.d && !stored.d.error && !stored.partial;
    if (Date.now() - stored.t < (complete ? CVE_TTL_MS : CVE_ERROR_TTL_MS)) return stored.d;
  }

  const { nvdApiKey } = await chrome.storage.local.get({ nvdApiKey: '' });
  const [nvd, epss, kev] = await Promise.all([
    fetchNvd(cveId, nvdApiKey),
    fetchEpss(cveId),
    getKev(),
  ]);

  const data = Object.assign({}, nvd);
  if (epss) data.epss = epss;
  if (kev && kev[cveId]) data.kev = kev[cveId];

  await chrome.storage.local.set({
    [key]: { t: Date.now(), d: data, partial: !kev || epss === undefined },
  });
  pruneCveCache();
  return data;
}

const CVE_CACHE_MAX = 800;
const PRUNE_EVERY = 50;
let writesSincePrune = 0;

/** Drop the oldest cached CVEs so storage cannot grow without bound. */
async function pruneCveCache() {
  if (++writesSincePrune < PRUNE_EVERY) return;
  writesSincePrune = 0;
  try {
    const all = await chrome.storage.local.get(null);
    const keys = Object.keys(all).filter((k) => k.startsWith('cve:'));
    if (keys.length <= CVE_CACHE_MAX) return;
    keys.sort((a, b) => (all[a].t || 0) - (all[b].t || 0));
    await chrome.storage.local.remove(keys.slice(0, keys.length - CVE_CACHE_MAX));
  } catch (e) {
    console.debug('[ThreatKey] cache prune failed:', e.message);
  }
}
