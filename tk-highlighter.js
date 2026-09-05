/*
 * Shared highlight engine for ThreatKey.
 *
 * Every registered source (CVE, ATT&CK) contributes a regex; the engine walks
 * the document ONCE per scan, paints matches with the CSS Custom Highlight API,
 * and resolves hovers through the caret API.
 *
 * Why no overlay <div>s any more: the previous version drew one absolutely
 * positioned box per match, re-measured every box on every scroll frame, and
 * called getBoundingClientRect() on every box on every mousemove. Custom
 * highlights are painted by the browser with the text, so scrolling, reflow and
 * line wrapping cost us nothing.
 */
(function () {
  'use strict';

  const SCAN_DEBOUNCE_MS = 300;   // quiet period after a DOM mutation
  const SCAN_MAX_WAIT_MS = 1500;  // ...but never starve a busy page
  const WALK_NODE_MAX = 20000;    // text nodes inspected per scan
  const HIT_SLOP_PX = 1;

  const supported =
    typeof CSS !== 'undefined' &&
    CSS.highlights &&
    typeof Highlight === 'function' &&
    typeof StaticRange === 'function';

  let warnedUnsupported = false;

  const engine = {
    sources: [],
    listening: false,
    scanTimer: 0,
    maxWaitTimer: 0,
    pendingScan: false,
    index: new Map(),      // Text node -> [{start, end, id, source}]
    pointer: { x: -1, y: -1 },
    hoverRaf: 0,
    hover: null,           // the entry currently described by a tooltip
  };

  // ===== Registration =====

  /**
   * @param {Object} config
   * @param {string} config.name - short id, used for the CSS highlight names
   * @param {RegExp} config.regex - global regex matching IDs in text
   * @param {number} config.maxMatches - cap on painted matches
   * @param {number} config.buckets - number of colour buckets (CSS names)
   * @param {function(string): ?string} config.normalizeId - match -> id (null = skip)
   * @param {function(string): number} [config.bucketFor] - id -> bucket index
   * @param {string} config.tooltipId - element id for this source's tooltip
   * @param {number} config.tooltipWidth - fallback width before first layout
   * @param {function(string, HTMLElement, function(): boolean)} config.renderTooltip
   * @returns {{start: function(), stop: function(), refresh: function()}}
   */
  window.__tk.createHighlighter = function (config) {
    const source = {
      name: config.name,
      regex: config.regex,
      maxMatches: config.maxMatches,
      normalizeId: config.normalizeId,
      bucketFor: config.bucketFor || (() => 0),
      tooltipId: config.tooltipId,
      tooltipWidth: config.tooltipWidth,
      renderTooltip: config.renderTooltip,
      cssNames: [],
      tooltip: null,
      active: false,
    };
    for (let i = 0; i < (config.buckets || 1); i++) {
      source.cssNames.push('tk-' + config.name + '-' + i);
    }
    engine.sources.push(source);

    return {
      start() {
        if (source.active) return;
        if (!supported) {
          if (!warnedUnsupported) {
            warnedUnsupported = true;
            console.warn('[ThreatKey] CSS Custom Highlight API unavailable; ' +
              'highlighting needs Chrome 105+.');
          }
          return;
        }
        source.active = true;
        listen();
        scheduleScan(true);
      },
      stop() {
        if (!source.active) return;
        source.active = false;
        clearSource(source);
        scheduleScan(true);
      },
      refresh() {
        if (source.active) scheduleScan(true);
      },
    };
  };

  // ===== Scheduling =====

  function listen() {
    if (engine.listening) return;
    engine.listening = true;

    document.addEventListener('mousemove', onPointerMove, { passive: true });
    document.addEventListener('scroll', hideTooltips, { capture: true, passive: true });
    window.addEventListener('resize', hideTooltips, { passive: true });
    document.addEventListener('visibilitychange', onVisibilityChange);
    window.addEventListener('pagehide', teardown);

    if (document.body) {
      engine.observer = new MutationObserver(() => scheduleScan(false));
      engine.observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
      });
    }
  }

  function teardown() {
    if (engine.observer) {
      engine.observer.disconnect();
      engine.observer = null;
    }
    clearTimeout(engine.scanTimer);
    clearTimeout(engine.maxWaitTimer);
    if (engine.hoverRaf) cancelAnimationFrame(engine.hoverRaf);
    engine.scanTimer = engine.maxWaitTimer = engine.hoverRaf = 0;
    engine.listening = false;
  }

  function scheduleScan(immediate) {
    if (document.hidden) {
      engine.pendingScan = true;
      return;
    }
    clearTimeout(engine.scanTimer);
    if (immediate) {
      clearTimeout(engine.maxWaitTimer);
      engine.maxWaitTimer = 0;
      engine.scanTimer = setTimeout(runScan, 0);
      return;
    }
    engine.scanTimer = setTimeout(runScan, SCAN_DEBOUNCE_MS);
    if (!engine.maxWaitTimer) {
      engine.maxWaitTimer = setTimeout(runScan, SCAN_MAX_WAIT_MS);
    }
  }

  function onVisibilityChange() {
    if (document.hidden || !engine.pendingScan) return;
    engine.pendingScan = false;
    scheduleScan(true);
  }

  function runScan() {
    clearTimeout(engine.scanTimer);
    clearTimeout(engine.maxWaitTimer);
    engine.scanTimer = engine.maxWaitTimer = 0;
    try {
      scan();
    } catch (e) {
      console.warn('[ThreatKey] scan failed:', e);
    }
  }

  // ===== Scan =====

  function scan() {
    const active = engine.sources.filter((s) => s.active);
    if (!active.length || !document.body) {
      engine.index = new Map();
      for (const s of engine.sources) clearSource(s);
      return;
    }

    const index = new Map();
    const buckets = new Map();  // css highlight name -> StaticRange[]
    const budget = new Map();   // source -> remaining matches
    for (const s of active) budget.set(s, s.maxMatches);

    const nodes = window.__tk.walkTextNodes((node) => {
      const text = node.nodeValue;
      if (!text || text.length < 5) return false;
      for (const s of active) {
        s.regex.lastIndex = 0;
        if (budget.get(s) > 0 && s.regex.test(text)) return true;
      }
      return false;
    }, WALK_NODE_MAX);

    for (const node of nodes) {
      if (!window.__tk.isVisible(node)) continue;
      const text = node.nodeValue;
      let entries = null;

      for (const s of active) {
        let left = budget.get(s);
        if (left <= 0) continue;
        s.regex.lastIndex = 0;

        let m;
        while ((m = s.regex.exec(text))) {
          if (m[0].length === 0) {          // paranoia: never spin on an empty match
            s.regex.lastIndex++;
            continue;
          }
          const id = s.normalizeId(m[0]);
          if (!id) continue;

          const start = m.index;
          const end = start + m[0].length;
          const cssName = s.cssNames[s.bucketFor(id)] || s.cssNames[0];

          let ranges = buckets.get(cssName);
          if (!ranges) buckets.set(cssName, (ranges = []));
          ranges.push(new StaticRange({
            startContainer: node, startOffset: start,
            endContainer: node, endOffset: end,
          }));

          if (!entries) index.set(node, (entries = []));
          entries.push({ start: start, end: end, id: id, source: s, node: node });

          if (--left <= 0) break;
        }
        budget.set(s, left);
      }
    }

    engine.index = index;
    paint(buckets);

    // Only drop the tooltip when its anchor really left the document; a match
    // can fall out of the index for benign reasons (budget, transient hiding).
    if (engine.hover && !engine.hover.node.isConnected) hideTooltips();
  }

  function paint(buckets) {
    if (!supported) return;
    for (const s of engine.sources) {
      for (const cssName of s.cssNames) {
        const ranges = s.active && buckets.get(cssName);
        if (!ranges || !ranges.length) {
          CSS.highlights.delete(cssName);
          continue;
        }
        const highlight = new Highlight();
        for (const r of ranges) highlight.add(r);
        CSS.highlights.set(cssName, highlight);
      }
    }
  }

  function clearSource(source) {
    if (!supported) return;
    for (const cssName of source.cssNames) CSS.highlights.delete(cssName);
    if (engine.hover && engine.hover.source === source) hideTooltips();
  }

  // ===== Hover =====

  function onPointerMove(e) {
    engine.pointer.x = e.clientX;
    engine.pointer.y = e.clientY;
    if (engine.hoverRaf) return;
    engine.hoverRaf = requestAnimationFrame(resolveHover);
  }

  function resolveHover() {
    engine.hoverRaf = 0;
    if (!engine.index.size) {
      if (engine.hover) hideTooltips();
      return;
    }

    const hit = hitTest(engine.pointer.x, engine.pointer.y);
    if (!hit) {
      if (engine.hover) hideTooltips();
      return;
    }
    if (engine.hover && engine.hover.id === hit.id && engine.hover.source === hit.source) {
      // Same ID, different occurrence: move the tooltip, keep its content.
      if (engine.hover.entry !== hit.entry) {
        engine.hover = hit;
        position(hit.source, hit.rect);
      }
      return;
    }
    showTooltip(hit);
  }

  /** Which match, if any, sits under the pointer. */
  function hitTest(x, y) {
    if (x < 0) return null;
    const caret = caretAt(x, y);
    if (!caret) return null;

    const entries = engine.index.get(caret.node);
    if (!entries) return null;

    for (const entry of entries) {
      if (caret.offset < entry.start || caret.offset > entry.end) continue;
      const rect = entryRect(entry, x, y);
      if (rect) return { entry: entry, rect: rect, id: entry.id, source: entry.source, node: entry.node };
    }
    return null;
  }

  function caretAt(x, y) {
    try {
      if (document.caretPositionFromPoint) {
        const pos = document.caretPositionFromPoint(x, y);
        if (pos && pos.offsetNode && pos.offsetNode.nodeType === Node.TEXT_NODE) {
          return { node: pos.offsetNode, offset: pos.offset };
        }
        return null;
      }
      if (document.caretRangeFromPoint) {
        const range = document.caretRangeFromPoint(x, y);
        if (range && range.startContainer.nodeType === Node.TEXT_NODE) {
          return { node: range.startContainer, offset: range.startOffset };
        }
      }
    } catch (e) {
      // Some pages throw from inside shadow DOM / detached trees.
    }
    return null;
  }

  /** Rect of `entry` containing (x, y), or null when the pointer is off it. */
  function entryRect(entry, x, y) {
    let range;
    try {
      range = document.createRange();
      range.setStart(entry.node, entry.start);
      range.setEnd(entry.node, entry.end);
    } catch (e) {
      return null;
    }
    const rects = range.getClientRects();
    for (let i = 0; i < rects.length; i++) {
      const r = rects[i];
      if (x >= r.left - HIT_SLOP_PX && x <= r.right + HIT_SLOP_PX &&
          y >= r.top - HIT_SLOP_PX && y <= r.bottom + HIT_SLOP_PX) {
        return r;
      }
    }
    return null;
  }

  // ===== Tooltip =====

  function ensureTooltip(source) {
    if (source.tooltip && source.tooltip.isConnected) return source.tooltip;
    const root = document.documentElement || document.body;
    const el = document.createElement('div');
    el.id = source.tooltipId;
    el.style.display = 'none';
    root.appendChild(el);
    // The tooltip grows when async data lands; keep it anchored.
    if (typeof ResizeObserver === 'function') {
      new ResizeObserver(() => {
        if (engine.hover && engine.hover.source === source) position(source, engine.hover.rect);
      }).observe(el);
    }
    source.tooltip = el;
    return el;
  }

  function showTooltip(hit) {
    const source = hit.source;
    for (const s of engine.sources) {
      if (s !== source && s.tooltip) s.tooltip.style.display = 'none';
    }

    const el = ensureTooltip(source);
    engine.hover = hit;

    el.style.visibility = 'hidden';
    el.style.display = 'block';
    // isCurrent() compares id + source (not object identity) so an async render
    // still lands when the pointer moved to another occurrence of the same ID.
    const isCurrent = () =>
      engine.hover !== null && engine.hover.id === hit.id && engine.hover.source === source;
    try {
      source.renderTooltip(hit.id, el, isCurrent);
    } catch (e) {
      el.textContent = hit.id;
    }
    position(source, hit.rect);
    el.style.visibility = '';
  }

  function hideTooltips() {
    if (!engine.hover) return;
    engine.hover = null;
    for (const s of engine.sources) {
      if (s.tooltip) s.tooltip.style.display = 'none';
    }
  }

  function position(source, rect) {
    const el = source.tooltip;
    if (!el) return;
    const width = el.offsetWidth || source.tooltipWidth;
    const height = el.offsetHeight || 160;

    let left = rect.left;
    if (left + width > window.innerWidth - 8) left = window.innerWidth - width - 8;
    if (left < 8) left = 8;

    let top = rect.bottom + 8;
    if (top + height > window.innerHeight - 8) {
      const above = rect.top - height - 8;
      top = above >= 8 ? above : Math.max(8, window.innerHeight - height - 8);
    }

    el.style.left = left + 'px';
    el.style.top = top + 'px';
  }
})();
