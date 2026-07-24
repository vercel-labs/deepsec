# deepsec

[English](README.md) | **简体中文** | [日本語](README.ja.md)

`deepsec` 是一款由智能体驱动的漏洞扫描器，可在你自己的基础设施中运行，经过优化，能够按需审查
现有大型仓库中的全部代码。

`deepsec` 旨在发现长期潜藏在应用程序中、难以察觉的问题。它被配置为使用最高思考等级的最佳模型（可通过 `--thinking-level` 调整，参阅 [docs/models.md](./docs/models.md)），这意味着对大型代码库的扫描可能花费数千甚至数万美元。我们的客户发现，与快速修补那些原本可能一直得不到修复的漏洞相比，这些成本是值得的。

对于大型代码库，工作会并行分散到多台工作机上。
如果运行中断或在中途出错，只需重新运行相同的
命令——deepsec 会从上次停止的位置继续，跳过已经
分析的文件，只调查其余部分。

## 开始使用

进入要扫描的仓库根目录，然后运行：

```bash
npx deepsec init       # creates .deepsec/ with this repo as the first project
cd .deepsec
pnpm install           # installs deepsec from npm

# Proceed as instructed by `init` output
```

现在让你的编码智能体引导完成安装。打开你选择的智能体
并输入以下提示：

> 阅读 `.deepsec/node_modules/deepsec/SKILL.md` 以了解该工具。
> 然后阅读 `.deepsec/data/<id>/SETUP.md` 并按照说明操作：
> 浏览此仓库的 README、任何 AGENTS.md/CLAUDE.md，以及一些
> 具有代表性的代码文件，然后替换
> `.deepsec/data/<id>/INFO.md` 的每个章节。
>
> 内容务必简短——总计以 50–100 行为目标。每个章节选择 3–5 个
> 示例，不要穷举。说出具体原语（身份验证辅助函数、
> 中间件），但不要写行号。跳过通用 CWE 类别——
> 内置匹配器已覆盖这些内容。只介绍项目特有的部分。
> INFO.md 会注入每个扫描批次；冗长的上下文
> 会稀释信号。

然后在 `.deepsec/` 中运行扫描：

```bash
pnpm deepsec scan
pnpm deepsec process
pnpm deepsec revalidate # optional, cuts FP rate
pnpm deepsec export --format md-dir --out ./findings
```

如果你希望 `deepsec` 检查代码的更多部分，请向它提供[编写匹配器](docs/writing-matchers.md)文档，以寻找更多有价值的起始位置。

## 文档

- [docs/getting-started.md](docs/getting-started.md)——首次扫描演练
- [docs/reviewing-changes.md](docs/reviewing-changes.md)——用于 PR 审查和 CI 门禁的 `process --diff`
- [docs/supported-tech.md](docs/supported-tech.md)——deepsec 开箱即用所识别的框架与生态系统
- [docs/writing-matchers.md](docs/writing-matchers.md)——**提示你的编码智能体扩展匹配器集合**
- [docs/configuration.md](docs/configuration.md)——`deepsec.config.ts` 参考
- [docs/plugins.md](docs/plugins.md)——插件编写指南
- [docs/models.md](docs/models.md)——模型选择、默认设置、拒绝情况和未来模型
- [docs/vercel-setup.md](docs/vercel-setup.md)——AI Gateway 与 Vercel Sandbox 密钥/令牌
- [docs/architecture.md](docs/architecture.md)——流水线内部原理
- [docs/data-layout.md](docs/data-layout.md)——`data/` 架构（FileRecord、RunMeta 等）
- [docs/faq.md](docs/faq.md)——成本、模型选择、沙箱模式和误报率
- [samples/](samples/)——可直接复制的起始示例（目前为 `webapp/`）
- [CONTRIBUTING.md](CONTRIBUTING.md)——仓库布局与开发工作流

## AI 提供商

在本地运行时，如果你已在这台机器上登录，`deepsec` 会回退到现有的 `claude` /
`codex` 订阅。订阅（Claude Pro/Max、ChatGPT Plus）
适合用于评估 deepsec，但通常没有足够的额度
完成整个仓库的扫描。

对于实际扫描，请使用 Vercel AI Gateway。一个密钥同时覆盖 Claude 和
Codex，而且网关的默认配额适合高并发
研究。

```
AI_GATEWAY_API_KEY=vck_...
```

获取密钥及设置 Vercel Sandbox 的方法，请参阅 [docs/vercel-setup.md](docs/vercel-setup.md)，
要绕过网关，请显式设置
`ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL`（或对应的 OpenAI 变量对）。
显式值始终优先于 `AI_GATEWAY_API_KEY`
展开。

如果 `process` 或 `revalidate` 运行因上游凭据耗尽
配额或余额而停止，deepsec 会正常退出，并告知你
在哪里充值。随后重新运行相同命令，它会从
上次停止的位置继续。

## 分布式执行（可选）

大型单体仓库可以将工作分散到 [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) 微型虚拟机：

```bash
pnpm deepsec sandbox process --project-id my-app --sandboxes 10 --concurrency 4
```

需要 Vercel 账户。本地工作树会被打包并
上传；`.git` 会被排除。OIDC 令牌（本地）和访问
令牌（CI）均受支持——参阅
[docs/vercel-setup.md](docs/vercel-setup.md)。

## deepsec 自身的安全模型

请将 `deepsec` 视为一个在运行环境中拥有完整 shell 访问权限的编码智能体。
它设计为在可信输入（你的源代码）上运行，但由于存在外部依赖项或
供应商代码，你仍可能担心提示注入。

在沙箱中运行（见上文）可以大幅限制潜在暴露：

- 编码智能体的 API 密钥在沙箱之外注入，因此无法被窃取
- 对于工作器沙箱，沙箱的网络出口仅限编码智能体主机（引导过程中允许出口，但该过程不会运行编码智能体）

## 工作流参考

| 命令 | 作用 |
|-----------------|----------------------------------------------------------|
| `scan` | 使用正则表达式匹配器查找候选位置（快速，不使用 AI） |
| `process` | AI 调查；输出发现与建议 |
| `process --diff` | PR 模式：仅扫描并调查差异中变更的文件 |
| `triage` | 轻量级 P0/P1/P2 分类（使用成本较低的模型） |
| `revalidate` | 重新检查现有发现；查看 Git 历史记录以确认修复 |
| `enrich` | 添加 Git 提交者信息及（通过插件）所有权数据 |
| `report` | 单个项目的 Markdown + JSON 摘要 |
| `export` | 每项发现的 JSON，或包含 Markdown 文件的目录 |
| `metrics` | 跨项目计数：严重性、按类型划分的漏洞、TP |
| `status` | 项目镜像快照 |
| `sandbox <cmd>` | 在 Vercel Sandbox 微型虚拟机上运行上述任意命令 |

## 许可证

Apache 2.0。详情请参阅 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。
