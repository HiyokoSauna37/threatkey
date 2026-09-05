/*
 * MITRE ATT&CK technique highlighting.
 *
 * attack-data.json is ~270 KB, so it is fetched lazily: the page is probed for
 * anything that looks like a technique ID first, and most pages never pay for
 * the download or the parse.
 */
(function () {
  'use strict';

  const MAX_TECHNIQUES = 2000;
  const PROBE_RE = /\bT[01]\d{3}\b/;
  const PROBE_DEBOUNCE_MS = 1000;

  // Highlight buckets: 0 = current technique, 1 = deprecated / revoked.
  const BUCKET_ACTIVE = 0;
  const BUCKET_RETIRED = 1;

  const STATUS_LABEL = { 1: 'DEPRECATED', 2: 'REVOKED' };
  const MATRIX_LABEL = { E: 'Enterprise', M: 'Mobile', I: 'ICS' };

  // ATT&CK v19 split Enterprise's "Defense Evasion" into "Stealth" and
  // "Defense Impairment"; Mobile and ICS keep their own tactic names.
  const TACTIC_COLORS = {
    // Enterprise
    'Reconnaissance': '#8d6e63',
    'Resource Development': '#78909c',
    'Initial Access': '#ef5350',
    'Execution': '#ff9800',
    'Persistence': '#fbc02d',
    'Privilege Escalation': '#ff7043',
    'Stealth': '#ab47bc',
    'Defense Impairment': '#7b1fa2',
    'Credential Access': '#e91e63',
    'Discovery': '#29b6f6',
    'Lateral Movement': '#26a69a',
    'Collection': '#66bb6a',
    'Command and Control': '#7e57c2',
    'Exfiltration': '#ec407a',
    'Impact': '#d32f2f',
    // Mobile
    'Defense Evasion': '#ab47bc',
    'Network Effects': '#5c6bc0',
    'Remote Service Effects': '#00897b',
    // ICS
    'Evasion': '#9575cd',
    'Impair Process Control': '#ff5722',
    'Inhibit Response Function': '#c62828',
  };

  let techniques = null;   // id -> [name, tactics, desc, platforms, matrix, status?, supersededBy?]
  let meta = null;
  let settings = null;
  let started = false;

  // ===== Tooltip =====

  function renderTooltip(techId, tooltip) {
    const info = techniques && techniques[techId];
    if (!info) {
      tooltip.textContent = techId + ' — Unknown';
      return;
    }

    const status = info[5] || 0;
    tooltip.textContent = '';

    const header = document.createElement('div');
    header.className = '__tk_tt_header';

    const title = document.createElement('span');
    title.className = '__tk_attack_tt_title';
    title.textContent = techId;
    header.appendChild(title);

    const name = document.createElement('span');
    name.className = '__tk_attack_tt_name';
    name.textContent = info[0];
    header.appendChild(name);

    if (status) {
      const badge = document.createElement('span');
      badge.className = '__tk_badge __tk_retired';
      badge.textContent = STATUS_LABEL[status];
      header.appendChild(badge);
    }
    tooltip.appendChild(header);

    if (info[6]) {
      const moved = document.createElement('div');
      moved.className = '__tk_tt_moved';
      const replacement = techniques[info[6]];
      moved.textContent = '→ ' + info[6] + (replacement ? ' ' + replacement[0] : '');
      tooltip.appendChild(moved);
    }

    if (info[1]) {
      const tactics = document.createElement('div');
      tactics.className = '__tk_tt_tactics';
      for (const tactic of info[1].split(', ')) {
        const badge = document.createElement('span');
        badge.className = '__tk_badge __tk_tactic';
        badge.textContent = tactic;
        badge.style.background = TACTIC_COLORS[tactic] || '#546e7a';
        tactics.appendChild(badge);
      }
      tooltip.appendChild(tactics);
    }

    const metaParts = [
      Array.from(info[4], (code) => MATRIX_LABEL[code] || code).join(' / '),
    ];
    if (info[3]) metaParts.push(info[3]);
    const metaEl = document.createElement('div');
    metaEl.className = '__tk_tt_meta';
    metaEl.textContent = metaParts.join('  ·  ');
    tooltip.appendChild(metaEl);

    if (info[2]) {
      const desc = document.createElement('div');
      desc.className = '__tk_tt_desc';
      desc.textContent = info[2];
      tooltip.appendChild(desc);
    }

    const link = document.createElement('div');
    link.className = '__tk_tt_link';
    link.textContent = 'https://attack.mitre.org/techniques/' + techId.replace('.', '/') +
      (meta ? '   (ATT&CK v' + meta.attack_version + ')' : '');
    tooltip.appendChild(link);
  }

  // ===== Highlighter =====

  const highlighter = window.__tk.createHighlighter({
    name: 'attack',
    regex: /\bT[01]\d{3}(?:\.\d{3})?\b/g,
    maxMatches: MAX_TECHNIQUES,
    buckets: 2,
    tooltipId: '__tk_attack_tooltip',
    tooltipWidth: 400,
    normalizeId: (text) => {
      const info = techniques && techniques[text];
      if (!info) return null;
      if (info[5] && !(settings && settings.attackShowRetired)) return null;
      return text;
    },
    bucketFor: (techId) => (techniques[techId][5] ? BUCKET_RETIRED : BUCKET_ACTIVE),
    renderTooltip: renderTooltip,
  });

  // ===== Lazy load =====

  /** Cheap check for anything shaped like a technique ID, without building a
   *  multi-megabyte textContent string. */
  function pageMentionsTechnique() {
    return window.__tk.walkTextNodes((node) => PROBE_RE.test(node.nodeValue), 1).length > 0;
  }

  function loadAndStart() {
    if (started) return;
    started = true;

    fetch(chrome.runtime.getURL('attack-data.json'))
      .then((r) => {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then((json) => {
        if (!json || !json.techniques) throw new Error('Invalid data');
        techniques = json.techniques;
        meta = json.meta || null;
        highlighter.start();
      })
      .catch((err) => {
        started = false;
        console.warn('[ThreatKey] Failed to load ATT&CK data:', err);
      });
  }

  function watchForTechniques() {
    if (pageMentionsTechnique()) {
      loadAndStart();
      return;
    }
    if (!document.body) return;

    let timer = 0;
    const observer = new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (!pageMentionsTechnique()) return;
        observer.disconnect();
        loadAndStart();
      }, PROBE_DEBOUNCE_MS);
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
    window.addEventListener('pagehide', () => observer.disconnect());
  }

  // ===== Init =====

  window.__tk.getSettings().then((loaded) => {
    settings = loaded;

    window.__tk.onSettingsChanged((next) => {
      settings = next;
      if (!next.attackHighlight) {
        highlighter.stop();
      } else if (techniques) {
        highlighter.start();
        highlighter.refresh();
      } else {
        watchForTechniques();
      }
    });

    if (!settings.attackHighlight) return;
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', watchForTechniques, { once: true });
    } else {
      watchForTechniques();
    }
  });
})();
