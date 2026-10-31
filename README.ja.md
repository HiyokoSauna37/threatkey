<p align="right"><a href="README.md">English</a> | <b>日本語</b></p>

<p align="center">
  <img src="icons/threatkey.svg" width="96" height="96" alt="ThreatKey — radar and key logo">
</p>

<h1 align="center">ThreatKey</h1>

<p align="center">キーボードでのテキスト選択（KeySelect）と脅威インテリジェンス即時参照を組み合わせたChrome拡張機能。</p>

---

アドバイザリやインシデントレポート、脅威分析記事をマウス無しで速く読むための拡張機能です。ページ内テキストの選択をキーボードだけで行うKeySelectに加え、選択テキストからの脅威インテリジェンス検索、CVE/MITRE ATT&CKの自動ハイライトを提供します。

## 最新の更新 — 2026年10月31日

**v3.1.0** では、CVEの背景色を従来どおりCVEごとに分けたまま、太い下線をCVSS severity（緊急・高・中・低・なし）で色分けします。CVE情報を順次先読みするため、severityはホバー前から確認できます。ホバー内のラベルと説明文は日本語化し、ツールチップへマウスを移動して説明文を選択・コピーできるようにしました。ツールチップと設定画面も、暖色・大きな角丸・控えめな境界線を使った読みやすいデザインに刷新しています。

## 機能一覧

| 機能 | トリガー |
|------|---------|
| KeySelect（キーボードでテキスト選択） | `Ctrl+Shift+F` |
| 脅威インテリジェンス検索 | テキスト選択 + `Ctrl+Shift+Z/L/E/V` |
| CVE 自動ハイライト + severity下線 + 日本語ツールチップ | 自動（ホバー前にseverity、ホバーで詳細表示） |
| MITRE ATT&CK 自動ハイライト + ツールチップ | 自動（ホバーで詳細表示） |
| 選択タブのURL一括コピー | ツールバーアイコンをクリック |
| Base64 エンコード/デコード、Defang/Refang | テキスト選択して右クリック |
| 設定（ON/OFF・NVD APIキー・キャッシュ） | 拡張機能のオプションページ |

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
| `Ctrl+Shift+Z` | NVD | CVE番号の詳細（選択テキストから `CVE-XXXX-XXXX` を抽出、無ければキーワード検索） |
| `Ctrl+Shift+L` | RansomLook | ランサムウェアグループ名 |
| `Ctrl+Shift+E` | Malpedia | 脅威アクター名 |
| `Ctrl+Shift+V` | VirusTotal | ハッシュ / IOC |

※ これらのキーは content script 内で固定（`chrome://extensions/shortcuts` では変更不可）。入力欄にフォーカスがある間は横取りしないため、`Ctrl+Shift+V`（書式なし貼り付け）は従来どおり動作する。

## 自動ハイライト

ハイライトは [CSS Custom Highlight API](https://developer.mozilla.org/docs/Web/API/CSS_Custom_Highlight_API) で描画している。ブラウザがテキストと一緒に塗るため、位置合わせ用のオーバーレイ要素が不要で、スクロール時の再計算コストがゼロになる。

- **CVE**: ページ内の `CVE-XXXX-XXXX` を自動ハイライトする。背景色は同じCVEで同じ色を維持し、太い下線はCVSS severity（緊急=赤、高=橙、中=黄、低=緑、なし=灰、取得中/不明=灰色の点線）を示す。CVE情報は順序付きキューで先読みし、取得できたものからホバー前に下線色を更新する。ホバーで以下を表示する。
  - NVD API の CVSS スコアと深刻度（v4.0 を優先し、v3.1 → v3.0 → v2 の順にフォールバック）、ベクター文字列、公開日
  - [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) 収載時は **KEV** バッジ（ランサムウェア利用が確認されている場合は区別して表示）
  - [FIRST](https://www.first.org/epss/) の **EPSS**（悪用可能性スコア）
  - NVDの英語説明はChrome内蔵の端末内Translator APIで日本語化する。翻訳結果はローカルにキャッシュし、外部の翻訳APIやClaude APIへは送信しない
  - ツールチップへマウスを移動しても閉じないため、説明文やURLを選択・コピーできる
- **ATT&CK**: `T1234` / `T1234.001` 形式のテクニックIDを同梱の `attack-data.json` から解決してハイライト（通信不要）。ホバーで名称・全戦術・マトリクス・プラットフォーム・説明を表示。廃止（deprecated）・統合（revoked）済みのIDは打ち消し線で描画し、MITRE が後継を定義していればツールチップに移行先を示す（`T0803 → T1691.001 Command Message`）。古いレポートを読むときに効く。

取得結果は `chrome.storage.local` にキャッシュし（成功7日 / エラー10分）、NVD へのリクエストは順序付きキューで間隔を空けて送るため、CVEが大量にあるページでもレート制限に当たらない。

## オプション

`chrome://extensions/` → ThreatKey → 「拡張機能のオプション」で以下を設定できる。

- CVE / ATT&CK ハイライトの ON / OFF
- CVE説明文の日本語化 ON / OFF（Chrome 138以降）
- 廃止・統合済み ATT&CK ID を対象に含めるか
- **NVD API キー**（任意）: 未設定でも動くが、設定すると 30 秒あたり 5 → 50 リクエストに緩和される（[取得はこちら](https://nvd.nist.gov/developers/request-an-api-key)）
- 同梱している ATT&CK のバージョン確認と、CVE / 日本語翻訳 / KEV キャッシュの削除

## ファイル構成

| ファイル | 役割 |
|---------|------|
| `manifest.json` | MV3 マニフェスト |
| `background.js` | サービスワーカー（ショートカット・ルックアップ・NVD/EPSS/KEV 取得とキャッシュ・レート制限・URLコピー・コンテキストメニュー） |
| `content.js` | KeySelect 本体 + ルックアップショートカット |
| `tk-utils.js` | 共有ユーティリティ（テキストノード走査・設定・トースト） |
| `tk-highlighter.js` | CVE / ATT&CK 共用のスキャン・描画・ホバーエンジン |
| `cve-highlight.js` | CVE の色割り当て + NVD/KEV/EPSS ツールチップ |
| `attack-highlight.js` | ATT&CK 解決 + ツールチップ（データは遅延ロード） |
| `attack-data.json` | ATT&CK テクニックデータ（下記参照） |
| `options.html` / `options.js` | 設定ページ |
| `styles.css` | 全UIスタイル（`::highlight()` ルール含む） |
| `build_attack_data.py` | MITRE の STIX バンドルから `attack-data.json` を再生成 |
| `icons/threatkey.svg` | この README にも使用する編集用ロゴ原稿 |
| `icons/icon-*.png` | 拡張機能用のアイコン（16・32・48・128px） |
| `icons/preview.html` | 明暗背景でのアイコン実寸プレビュー |
| `generate_icons.py` | SVG 原稿から PNG アイコンを生成 |

### アイコン

`icons/threatkey.svg` が編集用の原稿です。開いたレーダーの輪と鍵を一つの形にし、背景を透明にしています。拡張機能には 16・32・48・128px の PNG を使用し、32px 版で高密度ディスプレイのツールバー表示にも対応します。

再生成するには [librsvg](https://gitlab.gnome.org/GNOME/librsvg) をインストール（macOS では `brew install librsvg`）して、`python3 generate_icons.py` を実行してください。`icons/preview.html` をローカルで開くと、明るい背景・暗い背景で各サイズを実寸確認できます。Python と librsvg が必要なのは画像を再生成するときだけです。拡張機能のインストール・更新には同梱の PNG をそのまま使用できます。

## ATT&CK データ

`attack-data.json` は公式の [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) から生成しており、現在は **ATT&CK v19.2**（Enterprise / Mobile / ICS の 1140 テクニック、うち現行 918）を収録している。

```json
{
  "meta": { "attack_version": "19.2", "generated": "2026-09-05", ... },
  "techniques": {
    "T1055": ["Process Injection", "Stealth, Privilege Escalation", "Adversaries may inject...",
              "Linux, macOS, Windows", "E"]
  }
}
```

各行は `[名称, 戦術, 説明, プラットフォーム, マトリクス, ステータス?, 移行先?]`。現行テクニックでは `ステータス`（`1` 廃止 / `2` 統合）と `移行先` を省略しているので、`row[5] || 0` として読む。

更新方法:

```sh
python build_attack_data.py            # 各マトリクスの最新版を取得
python build_attack_data.py --version 19.2
```

STIX バンドルは `.attack-cache/`（git 管理外）にダウンロードされ、`attack-data.json` が書き換わる。なお v19 で Enterprise の戦術構成が変わり、`Defense Evasion` が `Stealth` と `Defense Impairment` に分割された。データ更新でツールチップの戦術名が変わることがある。

## インストール

1. [最新 main の ZIP](https://github.com/HiyokoSauna37/threatkey/archive/refs/heads/main.zip) をダウンロードして展開するか、このリポジトリを clone する
2. `chrome://extensions/` を開き、「デベロッパーモード」を ON にする
3. 「パッケージ化されていない拡張機能を読み込む」をクリックする
4. 展開・clone したフォルダのうち、`manifest.json` があるフォルダを選択する

[Releases](https://github.com/HiyokoSauna37/threatkey/releases) にはバージョンごとのパッケージを掲載しています。リリースの ZIP はそのタグ時点の内容で、以降の `main` の変更は自動では入りません。最新のアイコン・機能を使う場合は、上記の main の ZIP を取得してください。

**Chrome 105 以降**が必要です（CSS Custom Highlight API を使用）。CVE説明文の端末内日本語翻訳には **Chrome 138以降**が必要です。Windows・macOS ともにビルドは不要です。

### インストール済みの場合の更新

1. Chrome に読み込ませているフォルダを更新します。Git の `main` を使っている場合は、そのフォルダで `git pull --ff-only` を実行します。ZIP で入れた場合は最新 main の ZIP を展開し、読み込み済みフォルダの拡張機能ファイルを置き換えます。
2. `chrome://extensions/` を開き、ThreatKey のカードにある再読み込みボタンをクリックします。
3. ThreatKey を使う既存の Web ページも再読み込みして、content script を更新します。

ツールバーに新アイコンが見当たらない場合は、Chrome の拡張機能メニューから ThreatKey を固定してください。パッケージ化されていない拡張機能はローカルのファイルを使うため、GitHub の更新だけではインストール済みのコピーには反映されません。

## ショートカットキーの変更

1. `chrome://extensions/shortcuts` を開く
2. 「ThreatKey」の「KeySelect を起動」欄で好みのキーに変更

（脅威インテリジェンス検索の4つのショートカットはcontent script内で固定のため、この画面では変更できません）

## ライセンス

[MIT](LICENSE)
