<p align="right"><a href="README.md">English</a> | <b>日本語</b></p>

<p align="center">
  <img src="icons/icon-128.png" width="96" alt="ThreatKey logo">
</p>

<h1 align="center">ThreatKey</h1>

<p align="center">キーボードでのテキスト選択（KeySelect）と脅威インテリジェンス即時検索を組み合わせたChrome拡張機能。</p>

---

アドバイザリやインシデントレポート、脅威分析記事をマウス無しで速く読むための拡張機能です。ページ内テキストの選択をキーボードだけで行うKeySelectに加え、選択テキストからの脅威インテリジェンス検索、CVE/MITRE ATT&CKの自動ハイライトを提供します。

## 機能一覧

| 機能 | トリガー |
|------|---------|
| KeySelect（キーボードでテキスト選択） | `Ctrl+Shift+F` |
| 脅威インテリジェンス検索 | テキスト選択 + `Ctrl+Shift+Z/L/E/V` |
| CVE 自動ハイライト + NVDツールチップ | 自動（ホバーで詳細表示） |
| MITRE ATT&CK 自動ハイライト + ツールチップ | 自動（ホバーで詳細表示） |
| 選択タブのURL一括コピー | ツールバーアイコンをクリック |
| Base64 エンコード/デコード | テキスト選択して右クリック |

## KeySelect（テキスト選択）

マウス操作不要でページ内テキストを選択する。

### 起動

`Ctrl+Shift+F` で起動。もう一度押すと閉じる。

### SELECT モード（テキスト単体選択）

1. 検索文字を入力（2文字以上）
2. マッチ箇所がハイライトされ、ヒントキー（A, S, D...）が表示される
3. `Enter` で確定
4. ヒントキーを押す → そのテキストが選択状態になる

### RANGE モード（範囲選択）

1. `Tab` で RANGE モードに切り替え
2. 始点の検索文字を入力 → `Enter` → ヒントキーで始点を確定
3. 終点の検索文字を入力 → `Enter` → ヒントキーで終点を確定
4. 始点から終点までのテキストが選択状態になる

### キー操作

| キー | 動作 |
|------|------|
| `Ctrl+Shift+F` | 起動/終了（変更可能） |
| `Tab` | SELECT / RANGE モード切り替え |
| `Enter` | 検索確定 → ヒントモードへ |
| `Backspace` | ヒントモード中: 検索に戻る |
| `Esc` | 閉じる |

## 脅威インテリジェンス検索

ページ上でテキストを選択した状態でショートカットを押すと、対応サービスの検索結果を新しいタブで開く。

| キー | サービス | 用途 |
|------|---------|------|
| `Ctrl+Shift+Z` | NVD | CVE番号の詳細（選択テキストから CVE-XXXX-XXXX を抽出） |
| `Ctrl+Shift+L` | RansomLook | ランサムウェアグループ名 |
| `Ctrl+Shift+E` | Malpedia | 脅威アクター名 |
| `Ctrl+Shift+V` | VirusTotal | ハッシュ / IOC |

※ これらのキーは content script 内で固定（`chrome://extensions/shortcuts` では変更不可）。

## 自動ハイライト

- **CVE**: ページ内の `CVE-XXXX-XXXX` を自動ハイライト（同じCVEは同じ色）。ホバーすると NVD API から CVSS スコア・深刻度・説明をツールチップ表示。
- **ATT&CK**: `T1234` / `T1234.001` 形式のテクニックIDを自動ハイライト。ホバーで名称・戦術・説明・MITRE URLを表示（データは同梱の `attack-data.json`、[MITRE ATT&CK](https://attack.mitre.org/)由来・ネットワーク通信不要）。

## ファイル構成

| ファイル | 役割 |
|---------|------|
| `manifest.json` | MV3 マニフェスト |
| `background.js` | サービスワーカー（ショートカット・ルックアップ・NVD API・URLコピー・Base64コンテキストメニュー） |
| `content.js` | KeySelect 本体 + ルックアップショートカット |
| `tk-utils.js` | 共有ユーティリティ（テキストノード走査・トースト等） |
| `tk-highlighter.js` | CVE / ATT&CK 共用のハイライトエンジン |
| `cve-highlight.js` | CVE ハイライト設定 + NVD ツールチップ |
| `attack-highlight.js` | ATT&CK ハイライト設定 + ツールチップ |
| `attack-data.json` | ATT&CK テクニックデータ（`{ID: [名称, 戦術, 説明]}`） |
| `styles.css` | 全UIスタイル |
| `generate_icons.py` | アイコン生成スクリプト |

## インストール

1. `chrome://extensions/` を開く
2. 「デベロッパーモード」をON
3. 「パッケージ化されていない拡張機能を読み込む」
4. このリポジトリのフォルダを選択

または [Releases](../../releases) からパッケージ済みのzipを取得し、展開したフォルダを同様に読み込んでください。

## ショートカットキーの変更

1. `chrome://extensions/shortcuts` を開く
2. 「ThreatKey」の「KeySelect を起動」欄で好みのキーに変更

（脅威インテリジェンス検索の4つのショートカットはcontent script内で固定のため、この画面では変更できません）

## ライセンス

[MIT](LICENSE)
