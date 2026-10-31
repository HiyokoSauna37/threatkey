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
  const TOOLTIP_HIDE_DELAY_MS = 450;

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
    hideTimer: 0,
    tooltipPointerDown: false,
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
   * @param {boolean} [config.draggableTooltip] - dragging the header pins a movable card
   * @param {boolean} [config.closeableTooltip] - add a close button to the card
   * @param {function(string[]): void} [config.onIdsChanged] - visible ids after a scan
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
      draggableTooltip: !!config.draggableTooltip,
      closeableTooltip: !!config.closeableTooltip,
      onIdsChanged: config.onIdsChanged,
      renderTooltip: config.renderTooltip,
      cssNames: [],
      tooltip: null,
      pinnedTooltips: new Map(),
      tooltipSerial: 0,
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
    document.addEventListener('mouseup', onPointerUp, { passive: true });
    document.addEventListener('scroll', onScroll, { capture: true, passive: true });
    window.addEventListener('resize', onResize, { passive: true });
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
    clearTimeout(engine.hideTimer);
    if (engine.hoverRaf) cancelAnimationFrame(engine.hoverRaf);
    engine.scanTimer = engine.maxWaitTimer = engine.hoverRaf = engine.hideTimer = 0;
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
    const ids = new Map();      // source -> Set of ids found in this scan
    for (const s of active) {
      budget.set(s, s.maxMatches);
      ids.set(s, new Set());
    }

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
          ids.get(s).add(id);

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

    for (const s of active) {
      if (typeof s.onIdsChanged !== 'function') continue;
      try {
        s.onIdsChanged(Array.from(ids.get(s)));
      } catch (e) {
        console.warn('[ThreatKey] id callback failed:', e);
      }
    }

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
    if (source.tooltip) source.tooltip.style.display = 'none';
    for (const tooltip of source.pinnedTooltips.values()) tooltip.remove();
    source.pinnedTooltips.clear();
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
    if (engine.tooltipPointerDown || pointerInsideVisibleTooltip()) {
      cancelScheduledHide();
      return;
    }
    if (!engine.index.size) {
      if (engine.hover) scheduleHide();
      return;
    }

    const hit = hitTest(engine.pointer.x, engine.pointer.y);
    if (!hit) {
      if (engine.hover) scheduleHide();
      return;
    }
    cancelScheduledHide();
    if (engine.hover && engine.hover.id === hit.id && engine.hover.source === hit.source) {
      // Same ID, different occurrence: move the tooltip, keep its content.
      if (engine.hover.entry !== hit.entry) {
        const pinned = !!engine.hover.pinned;
        engine.hover = Object.assign({}, hit, { pinned: pinned });
        if (!pinned) position(hit.source, hit.rect);
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
    el.dataset.tkTooltip = source.name;
    el.style.display = 'none';

    const content = document.createElement('div');
    content.className = '__tk_tt_content';
    el.appendChild(content);
    el.__tkContent = content;

    if (source.closeableTooltip || source.draggableTooltip) {
      const close = document.createElement('button');
      close.type = 'button';
      close.className = '__tk_tt_close';
      close.setAttribute('aria-label', '閉じる');
      close.title = '閉じる';
      close.textContent = '×';
      close.addEventListener('pointerdown', (event) => event.stopPropagation());
      close.addEventListener('mousedown', (event) => event.stopPropagation());
      close.addEventListener('click', (event) => {
        event.preventDefault();
        event.stopPropagation();
        closeTooltip(source, el);
      });
      el.appendChild(close);
    }

    el.addEventListener('mouseenter', cancelScheduledHide);
    el.addEventListener('mouseleave', scheduleHide);
    el.addEventListener('mousedown', (event) => {
      if (event.button !== 0) return;
      engine.tooltipPointerDown = true;
      cancelScheduledHide();
    });
    if (source.draggableTooltip) installTooltipDrag(source, el);
    root.appendChild(el);

    // The tooltip grows when async data lands; keep it anchored.
    if (typeof ResizeObserver === 'function') {
      new ResizeObserver(() => {
        if (source.tooltip === el && engine.hover && !engine.hover.pinned &&
            engine.hover.source === source) position(source, engine.hover.rect);
        else if (source.pinnedTooltips.get(el.dataset.tkId) === el) constrainTooltip(el);
      }).observe(el);
    }
    source.tooltip = el;
    return el;
  }

  function showTooltip(hit) {
    cancelScheduledHide();
    const source = hit.source;
    const existing = source.pinnedTooltips.get(hit.id);
    if (existing && existing.isConnected) {
      for (const s of engine.sources) {
        if (s.tooltip) s.tooltip.style.display = 'none';
      }
      engine.hover = Object.assign({}, hit, { pinned: true });
      bringToFront(existing);
      return;
    }
    if (existing) source.pinnedTooltips.delete(hit.id);

    for (const s of engine.sources) {
      if (s !== source && s.tooltip) s.tooltip.style.display = 'none';
    }

    const el = ensureTooltip(source);
    const content = el.__tkContent || el;
    engine.hover = Object.assign({}, hit, { pinned: false });
    el.dataset.tkId = hit.id;
    el.dataset.tkPinned = 'false';
    el.classList.remove('__tk_tt_pinned', '__tk_tt_dragging');

    el.style.visibility = 'hidden';
    el.style.display = 'block';
    // isCurrent() compares id + source (not object identity) so an async render
    // still lands when the pointer moved to another occurrence of the same ID.
    // A card that became pinned must also keep receiving its async CVE data.
    const isCurrent = () =>
      (source.tooltip === el && engine.hover !== null && !engine.hover.pinned &&
        engine.hover.id === hit.id && engine.hover.source === source) ||
      source.pinnedTooltips.get(hit.id) === el;
    try {
      source.renderTooltip(hit.id, content, isCurrent);
    } catch (e) {
      content.textContent = hit.id;
    }
    position(source, hit.rect);
    el.style.visibility = '';
  }

  function installTooltipDrag(source, el) {
    let drag = null;

    el.addEventListener('pointerdown', (event) => {
      if (event.button !== 0 || !(event.target instanceof Element)) return;
      if (event.target.closest('.__tk_tt_close')) return;
      const header = event.target.closest('.__tk_tt_header');
      if (!header || !el.contains(header)) return;

      const rect = el.getBoundingClientRect();
      drag = {
        pointerId: event.pointerId,
        startX: event.clientX,
        startY: event.clientY,
        left: rect.left,
        top: rect.top,
        width: rect.width,
        height: rect.height,
        moved: false,
      };
      engine.tooltipPointerDown = true;
      cancelScheduledHide();
      bringToFront(el);
      try { el.setPointerCapture(event.pointerId); } catch (e) { /* no-op */ }
      event.preventDefault();
    });

    el.addEventListener('pointermove', (event) => {
      if (!drag || event.pointerId !== drag.pointerId) return;
      const dx = event.clientX - drag.startX;
      const dy = event.clientY - drag.startY;
      if (!drag.moved && Math.hypot(dx, dy) < 4) return;

      if (!drag.moved) {
        drag.moved = true;
        if (pinTooltip(source, el) !== el) {
          drag = null;
          engine.tooltipPointerDown = false;
          return;
        }
        el.classList.add('__tk_tt_dragging');
      }

      const maxLeft = Math.max(8, window.innerWidth - drag.width - 8);
      const maxTop = Math.max(8, window.innerHeight - drag.height - 8);
      const left = Math.min(maxLeft, Math.max(8, drag.left + dx));
      const top = Math.min(maxTop, Math.max(8, drag.top + dy));
      el.style.left = left + 'px';
      el.style.top = top + 'px';
      event.preventDefault();
    });

    const finishDrag = (event) => {
      if (!drag || event.pointerId !== drag.pointerId) return;
      const moved = drag.moved;
      try { el.releasePointerCapture(event.pointerId); } catch (e) { /* no-op */ }
      drag = null;
      engine.tooltipPointerDown = false;
      el.classList.remove('__tk_tt_dragging');
      if (moved) {
        engine.hover = null;
        cancelScheduledHide();
        event.preventDefault();
      }
    };
    el.addEventListener('pointerup', finishDrag);
    el.addEventListener('pointercancel', finishDrag);
  }

  function pinTooltip(source, el) {
    const id = el.dataset.tkId;
    if (!id) return null;
    const existing = source.pinnedTooltips.get(id);
    if (existing && existing !== el && existing.isConnected) {
      if (source.tooltip === el) source.tooltip = null;
      el.remove();
      bringToFront(existing);
      return existing;
    }

    source.pinnedTooltips.set(id, el);
    if (source.tooltip === el) source.tooltip = null;
    el.id = source.tooltipId + '--pinned-' + (++source.tooltipSerial);
    el.dataset.tkPinned = 'true';
    el.classList.add('__tk_tt_pinned');
    bringToFront(el);
    return el;
  }

  function closeTooltip(source, el) {
    cancelScheduledHide();
    const id = el.dataset.tkId;
    if (id && source.pinnedTooltips.get(id) === el) {
      source.pinnedTooltips.delete(id);
      el.remove();
    } else if (source.tooltip === el) {
      el.style.display = 'none';
    } else {
      el.remove();
    }
    if (engine.hover && engine.hover.source === source && engine.hover.id === id) {
      engine.hover = null;
    }
    engine.tooltipPointerDown = false;
  }

  function bringToFront(el) {
    if (el && el.parentNode) el.parentNode.appendChild(el);
  }

  function hideTooltips() {
    cancelScheduledHide();
    if (!engine.hover) return;
    engine.hover = null;
    engine.tooltipPointerDown = false;
    for (const s of engine.sources) {
      if (s.tooltip) s.tooltip.style.display = 'none';
    }
  }

  function scheduleHide() {
    if (!engine.hover || engine.tooltipPointerDown || engine.hideTimer) return;
    engine.hideTimer = setTimeout(() => {
      engine.hideTimer = 0;
      if (!engine.tooltipPointerDown && !pointerInsideVisibleTooltip() &&
          !selectionInsideVisibleTooltip()) hideTooltips();
    }, TOOLTIP_HIDE_DELAY_MS);
  }

  function cancelScheduledHide() {
    clearTimeout(engine.hideTimer);
    engine.hideTimer = 0;
  }

  function onPointerUp() {
    if (!engine.tooltipPointerDown) return;
    engine.tooltipPointerDown = false;
    if (selectionInsideVisibleTooltip()) return;
    if (!pointerInsideVisibleTooltip() && !hitTest(engine.pointer.x, engine.pointer.y)) {
      scheduleHide();
    }
  }

  function onScroll(event) {
    for (const s of engine.sources) {
      if (s.tooltip && s.tooltip.contains(event.target)) {
        cancelScheduledHide();
        return;
      }
    }
    hideTooltips();
  }

  function onResize() {
    hideTooltips();
    for (const source of engine.sources) {
      for (const tooltip of source.pinnedTooltips.values()) constrainTooltip(tooltip);
    }
  }

  function pointerInsideVisibleTooltip() {
    const x = engine.pointer.x;
    const y = engine.pointer.y;
    if (x < 0 || y < 0) return false;
    for (const s of engine.sources) {
      const el = s.tooltip;
      if (!el || el.style.display === 'none') continue;
      const rect = el.getBoundingClientRect();
      if (x >= rect.left && x <= rect.right && y >= rect.top && y <= rect.bottom) return true;
    }
    return false;
  }

  function selectionInsideVisibleTooltip() {
    const selection = window.getSelection && window.getSelection();
    if (!selection || selection.isCollapsed) return false;
    for (const s of engine.sources) {
      const el = s.tooltip;
      if (!el || el.style.display === 'none') continue;
      if (el.contains(selection.anchorNode) || el.contains(selection.focusNode)) return true;
    }
    return false;
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

  function constrainTooltip(el) {
    if (!el || !el.isConnected) return;
    const rect = el.getBoundingClientRect();
    const maxLeft = Math.max(8, window.innerWidth - rect.width - 8);
    const maxTop = Math.max(8, window.innerHeight - rect.height - 8);
    const left = Math.min(maxLeft, Math.max(8, rect.left));
    const top = Math.min(maxTop, Math.max(8, rect.top));
    if (left !== rect.left) el.style.left = left + 'px';
    if (top !== rect.top) el.style.top = top + 'px';
  }
})();
