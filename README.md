<p align="right"><b>English</b> | <a href="README.ja.md">日本語</a></p>

<p align="center">
  <img src="icons/icon-128.png" width="96" alt="ThreatKey logo">
</p>

<h1 align="center">ThreatKey</h1>

<p align="center">A Chrome extension for keyboard-only text selection and instant threat-intel lookups.</p>

---

ThreatKey combines **KeySelect** — selecting on-page text without touching the mouse — with one-key lookups against common threat-intelligence services, plus automatic highlighting of CVE IDs and MITRE ATT&CK technique IDs as you read. It's built for reading advisories, incident reports, and threat write-ups faster.

## Features

| Feature | Trigger |
|---|---|
| KeySelect (keyboard text selection) | `Ctrl+Shift+F` |
| Threat-intel lookup on selected text | Select text + `Ctrl+Shift+Z/L/E/V` |
| CVE highlighting + NVD / CISA KEV / EPSS tooltip | Automatic (hover for details) |
| MITRE ATT&CK highlighting + tooltip | Automatic (hover for details) |
| Copy URLs of all highlighted tabs | Click the toolbar icon |
| Base64 encode/decode, defang/refang | Right-click a selection |
| Settings (toggles, NVD API key, cache) | Extension options page |

## KeySelect (keyboard text selection)

Select text on any page without touching the mouse.

### Activate

Press `Ctrl+Shift+F` to start. Press it again to close.

### SELECT mode (select a single match)

1. Type a search string (2+ characters).
2. Matches are highlighted with hint labels (`A`, `S`, `D`, ...).
3. Press `Enter` to confirm the match list.
4. Press a hint key → that text becomes the page selection.

### RANGE mode (select a span)

1. Press `Tab` to switch to RANGE mode.
2. Search for the start point → `Enter` → pick a hint key to set the start.
3. Search for the end point → `Enter` → pick a hint key to set the end.
4. Everything from start to end becomes the page selection.

### Keys

| Key | Action |
|---|---|
| `Ctrl+Shift+F` | Activate / deactivate (rebindable) |
| `Tab` | Switch SELECT / RANGE mode |
| `Enter` | Confirm search → enter hint mode |
| `Backspace` | While in hint mode: back to search |
| `Esc` | Close |

## Threat-intel lookup

Select text on a page and press a shortcut to open the matching service's search in a new tab.

| Key | Service | Used for |
|---|---|---|
| `Ctrl+Shift+Z` | NVD | CVE details (`CVE-XXXX-XXXX` from the selection; keyword search otherwise) |
| `Ctrl+Shift+L` | RansomLook | Ransomware group name |
| `Ctrl+Shift+E` | Malpedia | Threat actor name |
| `Ctrl+Shift+V` | VirusTotal | Hash / IOC |

> These are fixed in the content script and can't be rebound from `chrome://extensions/shortcuts`. They are ignored while the caret is in a text field, so `Ctrl+Shift+V` still pastes as plain text where you'd expect it to.

## Automatic highlighting

Highlighting uses the [CSS Custom Highlight API](https://developer.mozilla.org/docs/Web/API/CSS_Custom_Highlight_API), so the browser paints matches together with the text — there are no overlay elements to keep aligned, and scrolling costs nothing.

- **CVE** — `CVE-XXXX-XXXX` patterns are highlighted automatically, and the same CVE always gets the same colour on a page. Hovering shows:
  - CVSS score and severity from the NVD API (v4.0 metrics preferred, falling back to v3.1 → v3.0 → v2), plus the vector string and publication date
  - a **KEV** badge when the CVE is in the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog, flagged separately when it is linked to ransomware campaigns
  - the **EPSS** exploitation probability from [FIRST](https://www.first.org/epss/)
- **ATT&CK** — technique IDs in `T1234` / `T1234.001` form are highlighted from the bundled `attack-data.json` (no network request). Hovering shows the name, every tactic, matrix, platforms and description. Deprecated and revoked IDs are struck through and, where MITRE defines a replacement, the tooltip points at it (`T0803 → T1691.001 Command Message`), which is what you want when reading older reports.

Responses are cached in `chrome.storage.local` (7 days for a hit, 10 minutes for an error) and NVD requests are queued and spaced out so a page full of CVEs cannot trip the public rate limit.

## Options

Open the extension's options page (`chrome://extensions/` → ThreatKey → *Extension options*) to:

- turn CVE or ATT&CK highlighting on and off
- include or exclude deprecated / revoked ATT&CK IDs
- set an **NVD API key** — optional, but it raises the limit from 5 to 50 requests per 30 seconds ([request one here](https://nvd.nist.gov/developers/request-an-api-key))
- see which ATT&CK version is bundled and clear the CVE / KEV caches

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest |
| `background.js` | Service worker (shortcuts, lookups, NVD/EPSS/KEV fetching + cache + rate limit, URL copy, context menu) |
| `content.js` | KeySelect itself + lookup shortcuts |
| `tk-utils.js` | Shared utilities (text node walking, settings, toasts) |
| `tk-highlighter.js` | Shared scan / paint / hover engine used by CVE and ATT&CK |
| `cve-highlight.js` | CVE colour buckets + NVD/KEV/EPSS tooltip |
| `attack-highlight.js` | ATT&CK lookup + tooltip, lazily loading the dataset |
| `attack-data.json` | ATT&CK technique data (see below) |
| `options.html` / `options.js` | Settings page |
| `styles.css` | All UI styling, including the `::highlight()` rules |
| `build_attack_data.py` | Regenerates `attack-data.json` from MITRE's STIX bundles |
| `generate_icons.py` | Icon generation script |

## ATT&CK data

`attack-data.json` is generated from the official [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) bundles and currently carries **ATT&CK v19.2** — 1140 techniques (918 current) across Enterprise, Mobile and ICS.

```json
{
  "meta": { "attack_version": "19.2", "generated": "2026-09-05", ... },
  "techniques": {
    "T1055": ["Process Injection", "Stealth, Privilege Escalation", "Adversaries may inject...",
              "Linux, macOS, Windows", "E"]
  }
}
```

Each row is `[name, tactics, description, platforms, matrix, status?, supersededBy?]`. `status` (`1` deprecated, `2` revoked) and `supersededBy` are omitted for current techniques, so read them as `row[5] || 0`.

To refresh it:

```sh
python build_attack_data.py            # latest version of every matrix
python build_attack_data.py --version 19.2
```

The script downloads the STIX bundles into `.attack-cache/` (git-ignored) and rewrites `attack-data.json`. Note that v19 reorganised Enterprise's tactics — `Defense Evasion` was split into `Stealth` and `Defense Impairment` — so a data refresh can change the tactic labels shown in tooltips.

## Install

1. Open `chrome://extensions/`.
2. Turn on **Developer mode**.
3. Click **Load unpacked**.
4. Select this repository's folder.

Or grab the packaged zip from [Releases](../../releases) and load the extracted folder the same way.

Requires **Chrome 105+** (CSS Custom Highlight API).

## Rebinding the activation shortcut

1. Open `chrome://extensions/shortcuts`.
2. Change **ThreatKey**'s "Activate KeySelect" entry to whatever key you'd like.

(The four lookup shortcuts are handled inside the content script and aren't affected by this page.)

## License

[MIT](LICENSE)
