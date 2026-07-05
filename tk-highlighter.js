/*
 * Shared highlight engine for ThreatKey.
 * Scans text nodes for a regex, draws fixed-position overlay highlights,
 * and shows a tooltip on hover. cve-highlight.js / attack-highlight.js
 * instantiate this with their own config.
 */
(function () {
  'use strict';

  const DEBOUNCE_MS = 50;
  const TOOLTIP_EST_HEIGHT = 200; // assumed height for viewport-flip positioning

  /**
   * @param {Object} config
   * @param {RegExp} config.regex - global regex matching IDs in text
   * @param {number} config.maxMatches - cap on rendered matches
   * @param {number} config.walkMax - cap on text nodes walked
   * @param {string} config.overlayId - id for the highlight container
   * @param {string} config.tooltipId - id for the tooltip element
   * @param {string} config.hlClass - class for each highlight rect
   * @param {number} config.tooltipWidth - assumed width for viewport clamping
   * @param {function(string): ?string} config.normalizeId - matched text -> id (null = skip match)
   * @param {function(string): {bg: string, border: string}} config.getColor - id -> highlight color
   * @param {function(string, HTMLElement, function(): boolean)} config.renderTooltip
   *        - (id, tooltipEl, isCurrent) fill tooltipEl for id; isCurrent() tells async
   *          renderers whether the id is still hovered
   * @returns {{start: function()}} call start() once the page (and any data) is ready
   */
  window.__tk.createHighlighter = function (config) {
    const state = {
      overlay: null,
      tooltip: null,
      hlElements: [],
      hoveredId: null,
      mutationTimer: null,
      rafId: null,
      observer: null,
    };

    function start() {
      const root = document.documentElement || document.body;
      if (!root || state.overlay) return;

      state.overlay = document.createElement('div');
      state.overlay.id = config.overlayId;
      root.appendChild(state.overlay);

      state.tooltip = document.createElement('div');
      state.tooltip.id = config.tooltipId;
      state.tooltip.style.display = 'none';
      root.appendChild(state.tooltip);

      scan();

      document.addEventListener('mousemove', onMouseMove);
      window.addEventListener('scroll', repositionOnFrame, true);
      window.addEventListener('resize', repositionOnFrame);

      if (document.body) {
        state.observer = new MutationObserver(scheduleScan);
        state.observer.observe(document.body, {
          childList: true,
          subtree: true,
          characterData: true,
        });
      }

      window.addEventListener('beforeunload', cleanup);
    }

    function cleanup() {
      if (state.observer) {
        state.observer.disconnect();
        state.observer = null;
      }
      clearTimeout(state.mutationTimer);
      if (state.rafId) {
        cancelAnimationFrame(state.rafId);
        state.rafId = null;
      }
    }

    // ===== Scan =====

    function scan() {
      if (!state.overlay) return;
      render(findEntries());
    }

    function scheduleScan() {
      clearTimeout(state.mutationTimer);
      state.mutationTimer = setTimeout(scan, DEBOUNCE_MS);
    }

    function findEntries() {
      const results = [];

      const nodes = window.__tk.walkTextNodes((node) => {
        config.regex.lastIndex = 0;
        return config.regex.test(node.textContent);
      }, config.walkMax);

      for (const node of nodes) {
        const text = node.textContent;
        config.regex.lastIndex = 0;
        let m;
        while ((m = config.regex.exec(text))) {
          if (results.length >= config.maxMatches) return results;
          const id = config.normalizeId(m[0]);
          if (!id) continue;
          try {
            const range = document.createRange();
            range.setStart(node, m.index);
            range.setEnd(node, m.index + m[0].length);
            if (range.getClientRects().length > 0) {
              results.push({ id: id, range: range });
            }
          } catch (e) {
            // Node modified between walk and range creation
          }
        }
      }
      return results;
    }

    // ===== Render =====

    function render(entries) {
      state.overlay.innerHTML = '';
      state.hlElements = [];
      const frag = document.createDocumentFragment();

      for (const entry of entries) {
        const color = config.getColor(entry.id);
        let rects;
        try {
          rects = entry.range.getClientRects();
        } catch (e) {
          continue; // Detached range
        }

        for (let r = 0; r < rects.length; r++) {
          const hl = document.createElement('div');
          hl.className = config.hlClass;
          window.__tk.setRect(hl, rects[r]);
          hl.style.background = color.bg;
          hl.style.borderBottomColor = color.border;
          frag.appendChild(hl);
          state.hlElements.push({ el: hl, range: entry.range, rectIdx: r, id: entry.id });
        }
      }
      state.overlay.appendChild(frag);
    }

    function repositionOnFrame() {
      if (state.rafId) return;
      state.rafId = requestAnimationFrame(() => {
        state.rafId = null;
        for (const item of state.hlElements) {
          try {
            const rects = item.range.getClientRects();
            if (item.rectIdx < rects.length) {
              window.__tk.setRect(item.el, rects[item.rectIdx]);
            }
          } catch (e) {
            item.el.style.display = 'none'; // Detached range
          }
        }
      });
    }

    // ===== Tooltip =====

    function onMouseMove(e) {
      const x = e.clientX;
      const y = e.clientY;
      let hit = null;

      for (const item of state.hlElements) {
        const rect = item.el.getBoundingClientRect();
        if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) {
          hit = item;
          break;
        }
      }

      if (!hit) {
        if (state.hoveredId) {
          state.hoveredId = null;
          state.tooltip.style.display = 'none';
        }
        return;
      }

      const hitRect = hit.el.getBoundingClientRect();
      if (state.hoveredId === hit.id) {
        positionTooltip(hitRect);
        return;
      }

      const id = hit.id;
      state.hoveredId = id;
      positionTooltip(hitRect);
      state.tooltip.style.display = 'block';
      config.renderTooltip(id, state.tooltip, () => state.hoveredId === id);
    }

    function positionTooltip(rect) {
      let left = rect.left;
      if (left + config.tooltipWidth > window.innerWidth) {
        left = window.innerWidth - config.tooltipWidth - 10;
      }
      if (left < 5) left = 5;

      let top = rect.bottom + 6;
      // Flip above if tooltip would overflow viewport bottom
      if (top + TOOLTIP_EST_HEIGHT > window.innerHeight) {
        top = rect.top - TOOLTIP_EST_HEIGHT - 6;
        if (top < 5) top = 5;
      }

      state.tooltip.style.left = left + 'px';
      state.tooltip.style.top = top + 'px';
    }

    return { start: start };
  };
})();
