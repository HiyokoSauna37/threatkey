'use strict';

const DEFAULTS = {
  cveHighlight: true,
  cveTranslateJapanese: true,
  attackHighlight: true,
  attackShowRetired: true,
  nvdApiKey: '',
};

const CHECKBOXES = [
  'cveHighlight',
  'cveTranslateJapanese',
  'attackHighlight',
  'attackShowRetired',
];

const $ = (id) => document.getElementById(id);

async function load() {
  const settings = await chrome.storage.local.get(DEFAULTS);
  $('extensionVersion').textContent = 'v' + chrome.runtime.getManifest().version;
  for (const key of CHECKBOXES) $(key).checked = !!settings[key];
  $('nvdApiKey').value = settings.nvdApiKey || '';
}

async function save() {
  const values = { nvdApiKey: $('nvdApiKey').value.trim() };
  for (const key of CHECKBOXES) values[key] = $(key).checked;
  await chrome.storage.local.set(values);
  flash('保存しました');
}

function flash(message) {
  const el = $('status');
  el.textContent = message;
  setTimeout(() => { el.textContent = ''; }, 2000);
}

async function showDataStats() {
  try {
    const response = await fetch(chrome.runtime.getURL('attack-data.json'));
    const json = await response.json();
    const meta = json.meta || {};
    const counts = meta.counts || {};
    $('attackVersion').textContent = 'v' + (meta.attack_version || '?') +
      (meta.generated ? '  (' + meta.generated + ')' : '');
    $('attackCount').textContent = (counts.total || Object.keys(json.techniques || {}).length) +
      ' (' + (counts.active || '?') + ' active)';
  } catch (e) {
    $('attackVersion').textContent = '読み込み失敗';
    $('attackCount').textContent = '-';
  }

  const all = await chrome.storage.local.get(null);
  $('cacheCount').textContent = Object.keys(all).filter((k) => k.startsWith('cve:')).length + ' 件';
  $('translationCacheCount').textContent =
    Object.keys(all).filter((k) => k.startsWith('cve-ja:')).length + ' 件';
  if (all.kev && all.kev.t) {
    const hours = Math.floor((Date.now() - all.kev.t) / 3600000);
    $('kevAge').textContent = Object.keys(all.kev.ids || {}).length + ' 件 / ' + hours + ' 時間前に取得';
  } else {
    $('kevAge').textContent = '未取得';
  }
}

async function clearCache() {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter((k) =>
    k.startsWith('cve:') || k.startsWith('cve-ja:') || k === 'kev');
  if (keys.length) await chrome.storage.local.remove(keys);
  flash('キャッシュを削除しました');
  showDataStats();
}

$('save').addEventListener('click', save);
$('clearCache').addEventListener('click', clearCache);
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    save();
  }
});

load();
showDataStats();
