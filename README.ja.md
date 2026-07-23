# deepsec

[English](README.md) | [简体中文](README.zh-CN.md) | **日本語**

`deepsec` は、自社のインフラストラクチャで実行できるエージェント駆動型の脆弱性スキャナーです。
既存の大規模リポジトリに含まれるすべてのコードをオンデマンドでレビューできるよう最適化されています。

`deepsec` は、アプリケーションに長期間潜んでいる、見つけにくい問題を明らかにするために設計されています。最高のモデルを最大の思考レベルで使用するよう構成されており（`--thinking-level` で調整可能。詳細は [docs/models.md](./docs/models.md) を参照）、大規模なコードベースではスキャンに数千ドル、場合によっては数万ドルかかることがあります。お客様からは、そうでなければ未修正のままだった脆弱性を迅速に修正できることを考えれば、その費用には価値があるとの評価をいただいています。

大規模なコードベースでは、作業が複数のワーカーマシンへ並列に分散されます。
実行が中断した場合や途中でエラーが発生した場合は、同じ
コマンドを再実行するだけです。deepsec は中断した箇所から再開し、
解析済みのファイルをスキップして残りだけを調査します。

## はじめに

スキャンするリポジトリのルートへ移動し、次を実行します：

```bash
npx deepsec init       # creates .deepsec/ with this repo as the first project
cd .deepsec
pnpm install           # installs deepsec from npm

# Proceed as instructed by `init` output
```

次に、コーディングエージェントにインストールの初期設定を行わせます。
使用するエージェントを開き、次のように指示します：

> `.deepsec/node_modules/deepsec/SKILL.md` を読み、このツールを理解してください。
> 次に `.deepsec/data/<id>/SETUP.md` を読み、その手順に従ってください：
> このリポジトリの README、AGENTS.md/CLAUDE.md（存在する場合）、
> および代表的なコードファイルをいくつか確認し、
> `.deepsec/data/<id>/INFO.md` の各セクションを置き換えてください。
>
> 必ず簡潔にし、全体で 50～100 行を目安にしてください。各セクションは
> 網羅せず、3～5 個の例を選びます。プリミティブ（認証ヘルパー、
> ミドルウェア）の名前は示しますが、行番号は不要です。一般的な CWE
> カテゴリは組み込みマッチャーが扱うため省略し、プロジェクト固有の
> 内容だけを記載してください。INFO.md はすべてのスキャンバッチに
> 注入されるため、冗長なコンテキストはシグナルを弱めます。

その後、`.deepsec/` 内からスキャンを実行します：

```bash
pnpm deepsec scan
pnpm deepsec process
pnpm deepsec revalidate # optional, cuts FP rate
pnpm deepsec export --format md-dir --out ./findings
```

`deepsec` にコードのより多くの箇所を調べさせたい場合は、価値のある開始点をさらに見つけられるよう、[マッチャーの作成](docs/writing-matchers.md)ドキュメントを渡してください。

## ドキュメント

- [docs/getting-started.md](docs/getting-started.md) — 初回スキャンの手順
- [docs/reviewing-changes.md](docs/reviewing-changes.md) — PR レビューと CI ゲート向けの `process --diff`
- [docs/supported-tech.md](docs/supported-tech.md) — deepsec が標準で認識するフレームワークとエコシステム
- [docs/writing-matchers.md](docs/writing-matchers.md) — **コーディングエージェントにマッチャーセットを拡張させる**
- [docs/configuration.md](docs/configuration.md) — `deepsec.config.ts` リファレンス
- [docs/plugins.md](docs/plugins.md) — プラグイン作成リファレンス
- [docs/models.md](docs/models.md) — モデルの選択、既定値、拒否、将来のモデル
- [docs/vercel-setup.md](docs/vercel-setup.md) — AI Gateway と Vercel Sandbox のキー/トークン
- [docs/architecture.md](docs/architecture.md) — パイプライン内部
- [docs/data-layout.md](docs/data-layout.md) — `data/` スキーマ（FileRecord、RunMeta など）
- [docs/faq.md](docs/faq.md) — 費用、モデル選択、サンドボックスモード、誤検知率
- [samples/](samples/) — コピーして使える開始例（現在は `webapp/`）
- [CONTRIBUTING.md](CONTRIBUTING.md) — リポジトリ構成と開発ワークフロー

## AI プロバイダー

ローカルで実行する場合、このマシンでログイン済みであれば、`deepsec` は既存の `claude` /
`codex` サブスクリプションへフォールバックします。サブスクリプション
（Claude Pro/Max、ChatGPT Plus）は deepsec の評価には役立ちますが、
通常はリポジトリ全体をスキャンできるほどの余裕はありません。

実際のスキャンには Vercel AI Gateway を使用してください。1 つのキーで Claude と
Codex の両方を利用でき、ゲートウェイの既定クォータは高い同時実行性を
伴う調査に適した規模です。

```
AI_GATEWAY_API_KEY=vck_...
```

キーの取得方法については [docs/vercel-setup.md](docs/vercel-setup.md) を参照し、
Vercel Sandbox を設定してください。ゲートウェイを経由しない場合は、
`ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`（または対応する OpenAI の組み合わせ）を
明示的に設定します。明示的な値は常に `AI_GATEWAY_API_KEY` の
展開より優先されます。

`process` または `revalidate` の実行が、上流の認証情報の
クォータやクレジット切れで停止した場合、deepsec は正常に停止し、
補充先を案内します。その後同じコマンドを再実行すると、
中断した箇所から再開します。

## 分散実行（任意）

大規模なモノリポでは、処理を [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) の microVM に分散できます：

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 10 --concurrency 4
```

Vercel アカウントが必要です。ローカルのワーキングツリーは tar にまとめて
アップロードされ、`.git` は除外されます。OIDC トークン（ローカル）と
アクセストークン（CI）の両方に対応しています。詳細は
[docs/vercel-setup.md](docs/vercel-setup.md) を参照してください。

## deepsec 自体のセキュリティモデル

`deepsec` は、実行環境への完全な shell アクセス権を持つコーディングエージェントとして扱ってください。
信頼できる入力（自分のソースコード）で実行するよう設計されていますが、外部依存関係や
ベンダーコードによるプロンプトインジェクションが気になる場合もあります。

サンドボックスで実行すると（上記参照）、潜在的な露出を大幅に制限できます：

- コーディングエージェント用の API キーはサンドボックス外部で注入されるため、持ち出すことはできません
- ワーカーサンドボックスからのネットワーク送信先はコーディングエージェントのホストに限定されます（ブートストラップ中は外向き通信が許可されますが、この処理ではコーディングエージェントを実行しません）

## ワークフローリファレンス

| コマンド | 動作 |
|-----------------|----------------------------------------------------------|
| `scan` | 正規表現マッチャーで候補箇所を探す（高速、AI 不使用） |
| `process` | AI による調査。検出結果と推奨事項を出力 |
| `process --diff` | PR モード：差分で変更されたファイルだけをスキャンして調査 |
| `triage` | 軽量な P0/P1/P2 分類（低コストのモデル） |
| `revalidate` | 既存の検出結果を再確認し、Git 履歴から修正を確認 |
| `enrich` | Git コミッター情報と（プラグインを使用する場合）所有者データを追加 |
| `report` | 1 プロジェクトの Markdown + JSON サマリー |
| `export` | 検出結果ごとの JSON、または Markdown ファイルのディレクトリ |
| `metrics` | プロジェクト横断の集計：重大度、種類別の脆弱性、TP |
| `status` | プロジェクトミラーのスナップショット |
| `sandbox <cmd>` | 上記の任意のコマンドを Vercel Sandbox microVM 上で実行 |

## ライセンス

Apache 2.0。詳細は [LICENSE](LICENSE) と [NOTICE](NOTICE) を参照してください。
