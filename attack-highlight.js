(function () {
  'use strict';

  // ===== Config =====
  const MAX_TECHNIQUES = 500;
  const COLOR = { bg: 'rgba(63,81,181,0.18)', border: '#3f51b5' };

  const TACTIC_COLORS = {
    'Initial Access':    '#ef5350',
    'Execution':         '#ff9800',
    'Persistence':       '#fbc02d',
    'Priv Escalation':   '#ff7043',
    'Defense Evasion':   '#ab47bc',
    'Credential Access': '#e91e63',
    'Discovery':         '#29b6f6',
    'Lateral Movement':  '#26a69a',
    'Collection':        '#66bb6a',
    'C2':                '#7e57c2',
    'Exfiltration':      '#ec407a',
    'Impact':            '#d32f2f',
    'Resource Dev':      '#78909c',
    'Reconnaissance':    '#8d6e63',
  };

  // ===== Data (attack-data.json: { techId: [name, tactic, desc] }) =====
  let data = null;

  // ===== Tooltip =====
  function renderTooltip(techId, tooltip) {
    const info = data && data[techId];
    if (!info) {
      tooltip.textContent = techId + ' — Unknown';
      return;
    }

    const name = info[0];
    const tactic = info[1];
    const desc = info[2];

    tooltip.innerHTML = '';

    const header = document.createElement('div');
    header.className = '__tk_attack_tt_header';

    const title = document.createElement('span');
    title.className = '__tk_attack_tt_title';
    title.textContent = techId;
    header.appendChild(title);

    const nameSpan = document.createElement('span');
    nameSpan.className = '__tk_attack_tt_name';
    nameSpan.textContent = name;
    header.appendChild(nameSpan);

    tooltip.appendChild(header);

    if (tactic) {
      const badge = document.createElement('span');
      badge.className = '__tk_attack_tactic';
      badge.textContent = tactic;
      badge.style.background = TACTIC_COLORS[tactic] || '#78909c';
      badge.style.color = '#fff';
      tooltip.appendChild(badge);
    }

    if (desc) {
      const descEl = document.createElement('div');
      descEl.className = '__tk_attack_tt_desc';
      descEl.textContent = desc;
      tooltip.appendChild(descEl);
    }

    const link = document.createElement('div');
    link.className = '__tk_attack_tt_link';
    link.textContent = 'https://attack.mitre.org/techniques/' + techId.replace('.', '/');
    tooltip.appendChild(link);
  }

  // ===== Init =====
  const highlighter = window.__tk.createHighlighter({
    regex: /\bT\d{4}(?:\.\d{3})?\b/g,
    maxMatches: MAX_TECHNIQUES,
    walkMax: MAX_TECHNIQUES * 10, // overfetch: matches not in the dataset are skipped
    overlayId: '__tk_attack_overlay',
    tooltipId: '__tk_attack_tooltip',
    hlClass: '__tk_attack_hl',
    tooltipWidth: 380,
    normalizeId: (text) => (data && data[text] ? text : null),
    getColor: () => COLOR,
    renderTooltip: renderTooltip,
  });

  fetch(chrome.runtime.getURL('attack-data.json'))
    .then((r) => {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.json();
    })
    .then((json) => {
      if (!json || typeof json !== 'object') throw new Error('Invalid data');
      data = json;
      if (document.body) {
        highlighter.start();
      } else {
        document.addEventListener('DOMContentLoaded', () => highlighter.start());
      }
    })
    .catch((err) => {
      console.warn('[ThreatKey] Failed to load ATT&CK data:', err);
    });
})();
