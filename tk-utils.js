(function () {
  'use strict';

  const TK_UI_SELECTORS = '#__ks_bar, #__ks_overlay, #__tk_cve_overlay, #__tk_cve_tooltip, #__tk_attack_overlay, #__tk_attack_tooltip, #__tk_toast';
  const SKIP_TAGS = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEXTAREA: 1, INPUT: 1 };

  window.__tk = {
    /**
     * Collect visible text nodes under document.body that match a filter.
     * Skips the extension's own UI, non-content tags, and hidden elements.
     * @param {function(Text): boolean} matchFn - return true if text node matches
     * @param {number} max - max results
     * @returns {Array<Text>} matched text nodes
     */
    walkTextNodes(matchFn, max) {
      if (!document.body) return [];
      const results = [];
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode(node) {
          const p = node.parentElement;
          if (!p) return NodeFilter.FILTER_SKIP;
          if (p.closest(TK_UI_SELECTORS)) return NodeFilter.FILTER_REJECT;
          if (SKIP_TAGS[p.tagName]) return NodeFilter.FILTER_REJECT;
          try {
            const cs = getComputedStyle(p);
            if (cs.display === 'none' || cs.visibility === 'hidden') return NodeFilter.FILTER_REJECT;
          } catch (e) {
            return NodeFilter.FILTER_SKIP;
          }
          return matchFn(node) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
        },
      });

      let node;
      while ((node = walker.nextNode())) {
        results.push(node);
        if (results.length >= max) break;
      }
      return results;
    },

    /** Apply DOMRect position to a fixed element */
    setRect(el, rect) {
      el.style.left = rect.left + 'px';
      el.style.top = rect.top + 'px';
      el.style.width = rect.width + 'px';
      el.style.height = rect.height + 'px';
    },

    /** Show Base64 encode/decode result popup */
    showBase64Result(text, label) {
      const existing = document.getElementById('__tk_b64_popup');
      if (existing) existing.remove();

      const root = document.documentElement || document.body;
      if (!root) return;

      const popup = document.createElement('div');
      popup.id = '__tk_b64_popup';

      const header = document.createElement('div');
      header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;';

      const labelEl = document.createElement('span');
      labelEl.textContent = label;
      labelEl.style.cssText = 'color:#888;font-size:11px;';

      const copyBtn = document.createElement('button');
      copyBtn.textContent = 'Copy';
      copyBtn.style.cssText = 'background:#333;color:#ccc;border:1px solid #555;border-radius:4px;padding:2px 10px;cursor:pointer;font-size:11px;';
      copyBtn.onclick = () => {
        navigator.clipboard.writeText(text);
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1000);
      };

      header.append(labelEl, copyBtn);

      const body = document.createElement('div');
      body.textContent = text;
      body.style.cssText = 'user-select:all;';

      popup.append(header, body);
      root.appendChild(popup);

      setTimeout(() => {
        popup.style.opacity = '0';
        setTimeout(() => { if (popup.parentNode) popup.remove(); }, 300);
      }, 10000);
      popup.addEventListener('click', (e) => {
        if (e.target === popup) popup.remove();
      });
    },

    /** Show a toast notification */
    showToast(message) {
      const existing = document.getElementById('__tk_toast');
      if (existing) existing.remove();

      const root = document.documentElement || document.body;
      if (!root) return;

      const toast = document.createElement('div');
      toast.id = '__tk_toast';
      toast.textContent = message;
      root.appendChild(toast);

      setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => { if (toast.parentNode) toast.remove(); }, 300);
      }, 2000);
    },
  };
})();
