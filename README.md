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
| Automatic CVE highlighting + NVD tooltip | Automatic (hover for details) |
| Automatic MITRE ATT&CK highlighting + tooltip | Automatic (hover for details) |
| Copy URLs of all highlighted tabs | Click the toolbar icon |
| Base64 encode/decode | Right-click a selection |

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
| `Ctrl+Shift+Z` | NVD | CVE details (extracts `CVE-XXXX-XXXX` from the selection) |
| `Ctrl+Shift+L` | RansomLook | Ransomware group name |
| `Ctrl+Shift+E` | Malpedia | Threat actor name |
| `Ctrl+Shift+V` | VirusTotal | Hash / IOC |

> These are fixed in the content script and can't be rebound from `chrome://extensions/shortcuts`.

## Automatic highlighting

- **CVE** — `CVE-XXXX-XXXX` patterns on the page are highlighted automatically (the same CVE always gets the same color). Hover to fetch CVSS score, severity, and description from the NVD API.
- **ATT&CK** — technique IDs in `T1234` / `T1234.001` form are highlighted automatically. Hover to see the name, tactic, description, and a link to MITRE, using the bundled `attack-data.json` (derived from [MITRE ATT&CK](https://attack.mitre.org/), no network request needed).

## Files

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest |
| `background.js` | Service worker (shortcuts, lookups, NVD API, URL copy, Base64 context menu) |
| `content.js` | KeySelect itself + lookup shortcuts |
| `tk-utils.js` | Shared utilities (text node walking, toasts, etc.) |
| `tk-highlighter.js` | Shared highlight engine used by CVE / ATT&CK |
| `cve-highlight.js` | CVE highlight config + NVD tooltip |
| `attack-highlight.js` | ATT&CK highlight config + tooltip |
| `attack-data.json` | ATT&CK technique data (`{id: [name, tactic, description]}`) |
| `styles.css` | All UI styling |
| `generate_icons.py` | Icon generation script |

## Install

1. Open `chrome://extensions/`.
2. Turn on **Developer mode**.
3. Click **Load unpacked**.
4. Select this repository's folder.

Or grab the packaged zip from [Releases](../../releases) and load the extracted folder the same way.

## Rebinding the activation shortcut

1. Open `chrome://extensions/shortcuts`.
2. Change **ThreatKey**'s "Activate KeySelect" entry to whatever key you'd like.

(The four lookup shortcuts are handled inside the content script and aren't affected by this page.)

## License

[MIT](LICENSE)
