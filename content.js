(function () {
  'use strict';

  // ===== Config =====
  const HINT_CHARS = 'asdfghjkl';
  const MIN_QUERY = 2;
  const MAX_MATCHES = 81; // 9*9 two-char hints
  const SEARCH_HELP = 'Tab:モード切替  Enter:確定  Esc:閉じる';

  // ===== State =====
  // null = inactive
  let state = null;

  // ===== Activation =====
  // Chrome commands API 経由（background.js からのメッセージ）
  chrome.runtime.onMessage.addListener((msg) => {
    if (!msg) return;
    if (msg.action === 'toggle') {
      if (state) deactivate(); else activate();
    } else if (msg.action === 'copy-to-clipboard') {
      navigator.clipboard.writeText(msg.text).then(() => {
        window.__tk.showToast(msg.count + ' 件のURLをコピーしました');
      }).catch(() => {
        window.__tk.showToast('コピーに失敗しました');
      });
    }
  });

  // ===== Lookup shortcuts (Ctrl+Shift+key) =====
  const LOOKUP_KEYS = {
    Z: 'nvd',
    L: 'ransomlook',
    E: 'malpedia',
    V: 'virustotal',
  };

  document.addEventListener('keydown', (e) => {
    if (!e.ctrlKey || !e.shiftKey || e.altKey || e.metaKey) return;
    const lookup = LOOKUP_KEYS[e.key.toUpperCase()];
    if (!lookup) return;
    // Don't fire while KeySelect is active
    if (state) return;
    const sel = window.getSelection();
    const text = sel ? sel.toString().trim() : '';
    if (!text) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    try {
      chrome.runtime.sendMessage({ lookup: lookup, text: text });
    } catch (err) {
      // Extension was reloaded — context invalidated
    }
  }, true);

  // ===== Activate / Deactivate =====

  function activate() {
    if (state) return;
    state = {
      mode: 'select',   // 'select' | 'range'
      phase: 'search',  // 'search' | 'hint' | 'range-hint'
      query: '',
      matches: [],
      hintLabels: [],
      hintBuffer: '',
      rangeStart: null,
      els: {},
    };
    buildUI();
    document.addEventListener('keydown', onEscapeGuard, true);
    state.els.input.focus();
  }

  function deactivate() {
    if (!state) return;
    clearOverlay();
    if (state.els.bar) state.els.bar.remove();
    if (state.els.overlay) state.els.overlay.remove();
    document.removeEventListener('keydown', onEscapeGuard, true);
    document.removeEventListener('keydown', onHintKey, true);
    window.removeEventListener('scroll', onScroll, true);
    window.removeEventListener('resize', onScroll);
    state = null;
  }

  function onEscapeGuard(e) {
    if (e.key === 'Escape') {
      e.stopImmediatePropagation();
      e.preventDefault();
      deactivate();
    }
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
    window.addEventListener('scroll', onScroll, true);
    window.addEventListener('resize', onScroll);
  }

  function el(tag, props) {
    const node = document.createElement(tag);
    for (const k in props) {
      if (k === 'textContent') node.textContent = props[k];
      else node.setAttribute(k, props[k]);
    }
    return node;
  }

  // ===== Search Phase =====

  function onInput() {
    state.query = state.els.input.value;
    if (state.query.length >= MIN_QUERY) {
      findAndShow();
    } else {
      clearOverlay();
      state.matches = [];
      state.els.status.textContent = '';
    }
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
  }

  // ===== Find & Highlight =====

  function findAndShow() {
    clearOverlay();
    state.matches = findMatches(state.query);
    state.hintLabels = genLabels(state.matches.length);

    if (state.matches.length === 0) {
      state.els.status.textContent = '0 件';
      return;
    }
    state.els.status.textContent = state.matches.length + ' 件  [Enter で確定]';
    renderHints();
  }

  function findMatches(query) {
    const results = [];
    const lower = query.toLowerCase();

    // overfetch since one node can contain multiple matches
    const nodes = window.__tk.walkTextNodes(
      (node) => node.textContent.toLowerCase().indexOf(lower) !== -1,
      MAX_MATCHES * 10
    );

    for (const node of nodes) {
      const text = node.textContent.toLowerCase();
      let idx = text.indexOf(lower);
      while (idx !== -1) {
        const range = document.createRange();
        range.setStart(node, idx);
        range.setEnd(node, idx + query.length);
        if (range.getClientRects().length > 0) {
          results.push({ range: range });
        }
        if (results.length >= MAX_MATCHES) return results;
        idx = text.indexOf(lower, idx + 1);
      }
    }
    return results;
  }

  // ===== Hint Labels =====

  function genLabels(count) {
    const chars = HINT_CHARS.split('');
    const labels = [];
    if (count <= chars.length) {
      for (let i = 0; i < count; i++) labels.push(chars[i]);
    } else {
      for (let a = 0; a < chars.length && labels.length < count; a++) {
        for (let b = 0; b < chars.length && labels.length < count; b++) {
          labels.push(chars[a] + chars[b]);
        }
      }
    }
    return labels;
  }

  // ===== Render =====

  /** Append highlight rects for a range plus a label above its first rect. */
  function appendRangeOverlay(frag, range, rectClass, labelText, labelClass, markStart) {
    const rects = range.getClientRects();
    if (rects.length === 0) return;

    for (const rect of rects) {
      const hl = document.createElement('div');
      hl.className = rectClass;
      if (markStart) hl.setAttribute('data-start', '1');
      window.__tk.setRect(hl, rect);
      frag.appendChild(hl);
    }

    const label = document.createElement('span');
    label.className = labelClass;
    label.textContent = labelText;
    if (markStart) label.setAttribute('data-start', '1');
    label.style.left = rects[0].left + 'px';
    label.style.top = (rects[0].top - 18) + 'px';
    frag.appendChild(label);
  }

  function renderHints() {
    const frag = document.createDocumentFragment();
    for (let i = 0; i < state.matches.length; i++) {
      appendRangeOverlay(
        frag, state.matches[i].range,
        '__ks_hl', state.hintLabels[i].toUpperCase(), '__ks_hint', false
      );
    }
    state.els.overlay.appendChild(frag);
  }

  function renderStartMarker() {
    if (!state.rangeStart) return;
    const frag = document.createDocumentFragment();
    appendRangeOverlay(frag, state.rangeStart, '__ks_start', 'START', '__ks_start_label', true);
    state.els.overlay.appendChild(frag);
  }

  function clearOverlay() {
    if (!state || !state.els.overlay) return;
    if (state.rangeStart) {
      // Keep the start marker (data-start), remove the rest
      const toRemove = [];
      for (const child of state.els.overlay.childNodes) {
        if (!child.getAttribute || !child.getAttribute('data-start')) toRemove.push(child);
      }
      toRemove.forEach((n) => n.remove());
    } else {
      state.els.overlay.innerHTML = '';
    }
  }

  function refreshPositions() {
    if (!state || state.matches.length === 0) return;
    clearOverlay();
    if (state.rangeStart) renderStartMarker();
    if (state.phase === 'hint' || state.phase === 'range-hint') renderHints();
  }

  function onScroll() {
    if (state) refreshPositions();
  }

  // ===== Hint Phase =====

  function enterHintPhase() {
    state.phase = state.rangeStart ? 'range-hint' : 'hint';
    state.hintBuffer = '';
    state.els.input.readOnly = true;
    state.els.input.focus(); // Keep focus to suppress Vimium
    state.els.status.textContent = state.matches.length + ' 件 - ヒントキーを入力';
    state.els.help.textContent = 'Backspace:戻る  Esc:閉じる';
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
    // stopImmediatePropagation blocks Vimium (also on document capture phase)
    e.stopImmediatePropagation();

    if (e.key === 'Escape') {
      e.preventDefault();
      deactivate();
      return;
    }

    if (e.key === 'Backspace') {
      e.preventDefault();
      if (state.hintBuffer.length > 0) {
        state.hintBuffer = state.hintBuffer.slice(0, -1);
      } else {
        exitHintPhase();
      }
      return;
    }

    // Ignore modifier combos
    if (e.ctrlKey || e.altKey || e.metaKey) return;

    const key = e.key.toLowerCase();
    if (HINT_CHARS.indexOf(key) === -1) return;
    e.preventDefault();

    state.hintBuffer += key;

    // Exact match?
    const idx = state.hintLabels.indexOf(state.hintBuffer);
    if (idx !== -1) {
      onHintPicked(idx);
      return;
    }

    // Valid prefix?
    const isPrefix = state.hintLabels.some((l) => l.indexOf(state.hintBuffer) === 0);
    if (!isPrefix) {
      state.hintBuffer = '';
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

    // Range mode: first pick = start, second pick = end
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
    clearOverlay();
    renderStartMarker();

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
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
})();
