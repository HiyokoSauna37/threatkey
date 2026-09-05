/*
 * KeySelect: keyboard-only text selection, plus the threat-intel lookup
 * shortcuts. Match highlighting uses the CSS Custom Highlight API; only the
 * hint labels are real elements, so scrolling repositions at most 81 nodes.
 */
(function () {
  'use strict';

  // ===== Config =====
  const HINT_CHARS = 'asdfghjkl';
  const MIN_QUERY = 2;
  const MAX_MATCHES = 81; // 9*9 two-char hints
  const SEARCH_HELP = 'Tab:モード切替  Enter:確定  Esc:閉じる';
  const HINT_HELP = 'Backspace:戻る  Esc:閉じる';

  const HL_MATCH = 'tk-ks-match';
  const HL_START = 'tk-ks-start';
  const canHighlight = typeof CSS !== 'undefined' && CSS.highlights && typeof Highlight === 'function';

  // ===== State =====
  // null = inactive
  let state = null;

  // ===== Activation =====
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg) return;
    if (msg.action === 'toggle') {
      if (state) deactivate(); else activate();
    } else if (msg.action === 'copy-to-clipboard') {
      navigator.clipboard.writeText(msg.text).then(
        () => window.__tk.showToast(msg.count + ' 件のURLをコピーしました'),
        () => window.__tk.showToast('コピーに失敗しました')
      );
    }
  });

  // ===== Lookup shortcuts (Ctrl+Shift+key) =====
  const LOOKUP_KEYS = {
    Z: 'nvd',
    L: 'ransomlook',
    E: 'malpedia',
    V: 'virustotal',
  };

  /** Never shadow the browser's own editing shortcuts (Ctrl+Shift+V especially). */
  function isEditable(node) {
    if (!node || node.nodeType !== Node.ELEMENT_NODE) return false;
    const tag = node.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || node.isContentEditable;
  }

  document.addEventListener('keydown', (e) => {
    if (!e.ctrlKey || !e.shiftKey || e.altKey || e.metaKey) return;
    if (state) return; // KeySelect owns the keyboard while it is open
    const lookup = LOOKUP_KEYS[e.key.toUpperCase()];
    if (!lookup) return;
    if (isEditable(e.target) || isEditable(document.activeElement)) return;

    const selection = window.getSelection();
    const text = selection ? selection.toString().trim() : '';
    if (!text) return;

    e.preventDefault();
    e.stopImmediatePropagation();
    try {
      chrome.runtime.sendMessage({ lookup: lookup, text: text });
    } catch (err) {
      // Extension was reloaded — context invalidated.
    }
  }, true);

  // ===== Activate / Deactivate =====

  function activate() {
    if (state || !document.body) return;
    state = {
      mode: 'select',   // 'select' | 'range'
      phase: 'search',  // 'search' | 'hint'
      query: '',
      matches: [],
      hintLabels: [],
      hintBuffer: '',
      rangeStart: null,
      refreshRaf: 0,
      labels: [],
      els: {},
    };
    buildUI();
    document.addEventListener('keydown', onEscapeGuard, true);
    state.els.input.focus();
  }

  function deactivate() {
    if (!state) return;
    if (state.refreshRaf) cancelAnimationFrame(state.refreshRaf);
    clearHighlights();
    if (state.els.bar) state.els.bar.remove();
    if (state.els.overlay) state.els.overlay.remove();
    document.removeEventListener('keydown', onEscapeGuard, true);
    document.removeEventListener('keydown', onHintKey, true);
    window.removeEventListener('scroll', onScroll, true);
    window.removeEventListener('resize', onScroll);
    state = null;
  }

  function onEscapeGuard(e) {
    if (e.key !== 'Escape') return;
    e.stopImmediatePropagation();
    e.preventDefault();
    deactivate();
  }

  // ===== UI =====

  function buildUI() {
    const bar = el('div', { id: '__ks_bar' });
    const mode = el('span', { id: '__ks_mode', textContent: 'SELECT' });
    const input = el('input', {
      id: '__ks_input',
      type: 'text',
      placeholder: '検索...',
      autocomplete: 'off',
    });
    const status = el('span', { id: '__ks_status' });
    const help = el('span', { id: '__ks_help', textContent: SEARCH_HELP });
    bar.append(mode, input, status, help);

    const root = document.documentElement || document.body;
    root.appendChild(bar);

    const overlay = el('div', { id: '__ks_overlay' });
    root.appendChild(overlay);

    state.els = { bar, mode, input, status, help, overlay };

    input.addEventListener('input', onInput);
    input.addEventListener('keydown', onInputKey);
    window.addEventListener('scroll', onScroll, { capture: true, passive: true });
    window.addEventListener('resize', onScroll, { passive: true });
  }

  function el(tag, props) {
    const node = document.createElement(tag);
    for (const k in props) {
      if (k === 'textContent') node.textContent = props[k];
      else node.setAttribute(k, props[k]);
    }
    return node;
  }

  // ===== Search phase =====

  function onInput() {
    state.query = state.els.input.value;
    if (state.query.length >= MIN_QUERY) {
      findAndShow();
      return;
    }
    state.matches = [];
    state.hintLabels = [];
    state.els.status.textContent = '';
    render();
  }

  function onInputKey(e) {
    e.stopPropagation();
    if (e.key === 'Escape') {
      e.preventDefault();
      deactivate();
    } else if (e.key === 'Tab') {
      e.preventDefault();
      toggleMode();
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (state.matches.length > 0) enterHintPhase();
    }
  }

  function toggleMode() {
    state.mode = state.mode === 'select' ? 'range' : 'select';
    state.els.mode.textContent = state.mode.toUpperCase();
    state.rangeStart = null;
    state.els.input.placeholder = '検索...';
    render();
  }

  // ===== Find =====

  function findAndShow() {
    state.matches = findMatches(state.query);
    state.hintLabels = genLabels(state.matches.length);
    state.els.status.textContent = state.matches.length === 0
      ? '0 件'
      : state.matches.length + ' 件  [Enter で確定]';
    render();
  }

  function findMatches(query) {
    const results = [];
    const needle = query.toLowerCase();

    // Overfetch: one text node can hold several matches.
    const nodes = window.__tk.walkTextNodes(
      (node) => node.nodeValue.toLowerCase().indexOf(needle) !== -1,
      MAX_MATCHES * 10
    );

    for (const node of nodes) {
      if (!window.__tk.isVisible(node)) continue;
      const text = node.nodeValue.toLowerCase();
      let idx = text.indexOf(needle);
      while (idx !== -1) {
        const range = document.createRange();
        range.setStart(node, idx);
        range.setEnd(node, idx + query.length);
        if (range.getClientRects().length > 0) results.push({ range: range });
        if (results.length >= MAX_MATCHES) return results;
        idx = text.indexOf(needle, idx + 1);
      }
    }
    return results;
  }

  // ===== Hint labels =====

  function genLabels(count) {
    const chars = HINT_CHARS.split('');
    const labels = [];
    if (count <= chars.length) {
      for (let i = 0; i < count; i++) labels.push(chars[i]);
      return labels;
    }
    for (let a = 0; a < chars.length && labels.length < count; a++) {
      for (let b = 0; b < chars.length && labels.length < count; b++) {
        labels.push(chars[a] + chars[b]);
      }
    }
    return labels;
  }

  // ===== Render =====

  /** Repaint highlights and hint labels from the current state. */
  function render() {
    if (!state) return;
    state.els.overlay.textContent = '';
    state.labels = [];

    const matchHighlight = canHighlight ? new Highlight() : null;
    const frag = document.createDocumentFragment();

    for (let i = 0; i < state.matches.length; i++) {
      const range = state.matches[i].range;
      if (matchHighlight) matchHighlight.add(range);
      state.labels.push({
        el: addLabel(frag, range, state.hintLabels[i].toUpperCase(), '__ks_hint'),
        range: range,
      });
    }

    if (state.rangeStart) {
      state.labels.push({
        el: addLabel(frag, state.rangeStart, 'START', '__ks_start_label'),
        range: state.rangeStart,
      });
    }

    state.els.overlay.appendChild(frag);

    if (!canHighlight) return;
    if (state.matches.length) CSS.highlights.set(HL_MATCH, matchHighlight);
    else CSS.highlights.delete(HL_MATCH);

    if (state.rangeStart) {
      const startHighlight = new Highlight();
      startHighlight.add(state.rangeStart);
      CSS.highlights.set(HL_START, startHighlight);
    } else {
      CSS.highlights.delete(HL_START);
    }
  }

  function addLabel(frag, range, text, className) {
    const label = document.createElement('span');
    label.className = className;
    label.textContent = text;
    frag.appendChild(label);
    moveLabel(label, range);
    return label;
  }

  function clearHighlights() {
    if (!canHighlight) return;
    CSS.highlights.delete(HL_MATCH);
    CSS.highlights.delete(HL_START);
  }

  function onScroll() {
    // Highlights follow the text for free; only the labels need repositioning.
    if (!state || state.refreshRaf) return;
    state.refreshRaf = requestAnimationFrame(() => {
      state.refreshRaf = 0;
      repositionLabels();
    });
  }

  function repositionLabels() {
    if (!state || !state.labels) return;
    for (const item of state.labels) moveLabel(item.el, item.range);
  }

  function moveLabel(label, range) {
    const rects = range.getClientRects();
    if (rects.length === 0) {
      label.style.display = 'none';
      return;
    }
    label.style.display = '';
    label.style.left = rects[0].left + 'px';
    label.style.top = Math.max(0, rects[0].top - 18) + 'px';
  }

  // ===== Hint phase =====

  function enterHintPhase() {
    state.phase = 'hint';
    state.hintBuffer = '';
    state.els.input.readOnly = true;
    state.els.input.focus(); // keep focus to suppress Vimium
    state.els.status.textContent = state.matches.length + ' 件 - ヒントキーを入力';
    state.els.help.textContent = HINT_HELP;
    document.addEventListener('keydown', onHintKey, true);
  }

  function exitHintPhase() {
    state.hintBuffer = '';
    state.phase = 'search';
    state.els.input.readOnly = false;
    state.els.input.value = '';
    state.els.help.textContent = SEARCH_HELP;
    document.removeEventListener('keydown', onHintKey, true);
    state.els.input.focus();
  }

  function onHintKey(e) {
    // stopImmediatePropagation blocks Vimium (also on the document capture phase)
    e.stopImmediatePropagation();

    if (e.key === 'Escape') {
      e.preventDefault();
      deactivate();
      return;
    }

    if (e.key === 'Backspace') {
      e.preventDefault();
      if (state.hintBuffer.length > 0) state.hintBuffer = state.hintBuffer.slice(0, -1);
      else exitHintPhase();
      return;
    }

    if (e.ctrlKey || e.altKey || e.metaKey) return; // ignore modifier combos

    const key = e.key.toLowerCase();
    if (HINT_CHARS.indexOf(key) === -1) return;
    e.preventDefault();

    state.hintBuffer += key;

    const idx = state.hintLabels.indexOf(state.hintBuffer);
    if (idx !== -1) {
      onHintPicked(idx);
      return;
    }
    if (!state.hintLabels.some((l) => l.indexOf(state.hintBuffer) === 0)) {
      state.hintBuffer = ''; // dead end
    }
  }

  // ===== Selection =====

  function onHintPicked(idx) {
    const match = state.matches[idx];

    if (state.mode === 'select') {
      selectRange(match.range.cloneRange());
      deactivate();
      return;
    }

    // Range mode: first pick = start, second pick = end.
    if (!state.rangeStart) {
      state.rangeStart = match.range;
      startEndpointSearch();
    } else {
      selectRange(unionRange(state.rangeStart, match.range));
      deactivate();
    }
  }

  /** After the range start is picked, reset the search UI to find the end. */
  function startEndpointSearch() {
    document.removeEventListener('keydown', onHintKey, true);

    state.query = '';
    state.matches = [];
    state.hintLabels = [];
    state.hintBuffer = '';
    state.phase = 'search';
    state.els.input.value = '';
    state.els.input.readOnly = false;
    state.els.input.placeholder = '終点を検索...';
    state.els.status.textContent = '始点を確定 → 終点を検索';
    state.els.help.textContent = SEARCH_HELP;
    render();
    state.els.input.focus();
  }

  /** Merge two ranges into one spanning from the earlier start to the later end. */
  function unionRange(a, b) {
    const range = document.createRange();
    if (a.compareBoundaryPoints(Range.START_TO_START, b) <= 0) {
      range.setStart(a.startContainer, a.startOffset);
      range.setEnd(b.endContainer, b.endOffset);
    } else {
      range.setStart(b.startContainer, b.startOffset);
      range.setEnd(a.endContainer, a.endOffset);
    }
    return range;
  }

  function selectRange(range) {
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
})();
