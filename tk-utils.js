/*
 * Shared helpers for every ThreatKey content script.
 * Loaded first, so everything else can assume `window.__tk` exists.
 */
(function () {
  'use strict';

  // Our own UI lives on <html>, outside the <body> subtree we walk, but a page
  // could still reparent things — reject these ids defensively.
  const TK_UI_IDS = {
    __ks_bar: 1,
    __ks_overlay: 1,
    __tk_cve_tooltip: 1,
    __tk_attack_tooltip: 1,
    __tk_toast: 1,
    __tk_b64_popup: 1,
  };

  // Tags whose text is never page content worth scanning.
  const SKIP_TAGS = {
    SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEMPLATE: 1, TITLE: 1,
    TEXTAREA: 1, INPUT: 1, SELECT: 1, OPTION: 1,
    IFRAME: 1, OBJECT: 1, EMBED: 1, CANVAS: 1, SVG: 1, VIDEO: 1, AUDIO: 1,
  };

  const SETTING_DEFAULTS = {
    cveHighlight: true,
    attackHighlight: true,
    attackShowRetired: true,
    nvdApiKey: '',
  };

  let settingsCache = null;
  const settingsListeners = [];

  window.__tk = {
    SETTING_DEFAULTS: SETTING_DEFAULTS,

    /**
     * Collect text nodes under <body> that satisfy `matchFn`.
     *
     * Visibility is deliberately NOT checked here: `getComputedStyle` per node
     * dominated the old scan, and almost no node ever matches. Callers filter
     * the few hits with `isVisible()` instead.
     *
     * @param {function(Text): boolean} matchFn
     * @param {number} max - stop after this many matched nodes
     * @returns {Array<Text>}
     */
    walkTextNodes(matchFn, max) {
      if (!document.body) return [];
      const results = [];
      const walker = document.createTreeWalker(
        document.body,
        NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT,
        {
          acceptNode(node) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // FILTER_REJECT on an element prunes the whole subtree, which is
              // what makes this cheaper than a text-only walk.
              if (SKIP_TAGS[node.tagName]) return NodeFilter.FILTER_REJECT;
              if (node.id && TK_UI_IDS[node.id]) return NodeFilter.FILTER_REJECT;
              return NodeFilter.FILTER_SKIP;
            }
            return matchFn(node) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
          },
        }
      );

      let node;
      while ((node = walker.nextNode())) {
        results.push(node);
        if (results.length >= max) break;
      }
      return results;
    },

    /** Is this node rendered? Used to filter the handful of nodes that matched. */
    isVisible(node) {
      const el = node.parentElement;
      if (!el) return false;
      if (el.checkVisibility) {
        return el.checkVisibility({ checkVisibilityCSS: true });
      }
      try {
        const cs = getComputedStyle(el);
        return cs.display !== 'none' && cs.visibility !== 'hidden';
      } catch (e) {
        return false;
      }
    },

    /** Apply DOMRect position to a fixed element */
    setRect(el, rect) {
      el.style.left = rect.left + 'px';
      el.style.top = rect.top + 'px';
      el.style.width = rect.width + 'px';
      el.style.height = rect.height + 'px';
    },

    // ===== Settings =====

    /** Read settings (cached after the first call). */
    async getSettings() {
      if (settingsCache) return settingsCache;
      try {
        const stored = await chrome.storage.local.get(SETTING_DEFAULTS);
        settingsCache = Object.assign({}, SETTING_DEFAULTS, stored);
      } catch (e) {
        settingsCache = Object.assign({}, SETTING_DEFAULTS);
      }
      return settingsCache;
    },

    /** Run `cb(settings)` whenever the options page changes something. */
    onSettingsChanged(cb) {
      settingsListeners.push(cb);
    },

    // ===== UI =====

    /** Show Base64 encode/decode result popup */
    showBase64Result(text, label) {
      const root = document.documentElement || document.body;
      if (!root) return;

      const existing = document.getElementById('__tk_b64_popup');
      if (existing) existing.remove();

      const popup = document.createElement('div');
      popup.id = '__tk_b64_popup';

      const header = document.createElement('div');
      header.className = '__tk_b64_header';

      const labelEl = document.createElement('span');
      labelEl.className = '__tk_b64_label';
      labelEl.textContent = label + '  ·  ' + text.length + ' chars';

      const copyBtn = document.createElement('button');
      copyBtn.className = '__tk_b64_copy';
      copyBtn.textContent = 'Copy';
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(text).then(
          () => { copyBtn.textContent = 'Copied!'; },
          () => { copyBtn.textContent = 'Failed'; }
        );
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
      });

      const closeBtn = document.createElement('button');
      closeBtn.className = '__tk_b64_copy';
      closeBtn.textContent = '×';
      closeBtn.addEventListener('click', () => popup.remove());

      header.append(labelEl, copyBtn, closeBtn);

      const body = document.createElement('div');
      body.className = '__tk_b64_body';
      body.textContent = text;

      popup.append(header, body);
      root.appendChild(popup);

      const onKey = (e) => {
        if (e.key !== 'Escape') return;
        popup.remove();
        document.removeEventListener('keydown', onKey, true);
      };
      document.addEventListener('keydown', onKey, true);

      setTimeout(() => {
        if (!popup.isConnected) return;
        popup.style.opacity = '0';
        setTimeout(() => popup.remove(), 300);
      }, 15000);
    },

    /** Show a toast notification */
    showToast(message) {
      const root = document.documentElement || document.body;
      if (!root) return;

      const existing = document.getElementById('__tk_toast');
      if (existing) existing.remove();

      const toast = document.createElement('div');
      toast.id = '__tk_toast';
      toast.textContent = message;
      root.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
      }, 2000);
    },
  };

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (!settingsCache) settingsCache = Object.assign({}, SETTING_DEFAULTS);
    let touched = false;
    for (const key in changes) {
      if (key in SETTING_DEFAULTS) {
        settingsCache[key] = changes[key].newValue;
        touched = true;
      }
    }
    if (!touched) return;
    for (const cb of settingsListeners) {
      try {
        cb(settingsCache);
      } catch (e) {
        console.warn('[ThreatKey] settings listener failed:', e);
      }
    }
  });
})();
