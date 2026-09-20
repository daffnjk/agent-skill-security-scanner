<div align="center">

# Agent Skill Security Scanner

### 安装或运行 Agent Skill 前，先审查提示词、代码与权限风险

`skillscan` 是面向 AI Agent Skill、MCP 工具、IDE 规则和插件包的离线静态安全扫描器。它使用 Go 标准库实现，通过规则匹配、跨文件关联和有界行为流分析，输出可复核的风险证据，并为 CI 提供扫描完整性与报告一致性校验。

[![CI](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Offline](https://img.shields.io/badge/runtime-offline-1f883d)](Dockerfile)
[![License](https://img.shields.io/badge/license-AGPL--3.0-663399)](LICENSE)

[English](README_EN.md)

</div>

## 版本与适用范围

| 版本 | 状态 | 使用说明 |
| --- | --- | --- |
| `main`：`v0.3.0-dev` / `v41-hardening.1` | 未发布开发版 | 本页命令、输入模式和报告校验说明对应此版本 |
| `v0.2.0` / `v41` | 已发布 | 使用 [该版本文档](https://github.com/daffnjk/agent-skill-security-scanner/blob/v0.2.0/README.md)；不包含当前主线的新完整性契约 |
| `competition/v38-final` | 冻结参赛快照 | 仅用于历史复现，赛事成绩不代表当前主线 |

从 v0.2.0 升级时，请先阅读 [安全边界与迁移说明](docs/hardening.md)。历史 v41 公开评测尚未针对当前开发版重跑。

## 什么是 `skillscan`？

一个 Skill 不只有提示词，还可能包含脚本、权限清单、安装钩子、CI 工作流和自动运行配置。真正的风险往往分散在多个文件里，单看其中一个文件并不够。

`skillscan` 将待测包视为**不可信数据**：不安装、不导入、不执行其中的代码，也不访问包内声明的 URL。它会关联权限、命令执行、敏感数据访问和网络行为，给出可复核的风险结论与证据。

> [!NOTE]
> 这是启发式静态分析工具。扫描结果是安全评审线索，不是“安全”或“恶意”的最终证明。

## 适用场景

- **安装前审查**：检查第三方 Skill 的说明、脚本、权限和依赖声明。
- **仓库与 PR 门禁**：扫描完整 Skill 目录，按风险策略阻断，并拒绝不完整的扫描结果。
- **安全评审与回归**：结合规则 ID、行为证据和覆盖信息，复核误报、漏报与版本变化。

MCP 工具、IDE 规则和插件需要以本地文件目录提供；扫描器不连接运行中的 MCP 服务，也不安装或启动插件。

## 工作原理

| 阶段 | 做什么 |
| --- | --- |
| **Collect** | 按安全优先级读取受支持的代码、文档、清单和配置，并限制单个 Skill 的资源占用 |
| **Correlate** | 结合单文件规则与跨文件行为链，减少只凭关键词判断带来的误报 |
| **Report** | 输出风险等级、AST 主类别、证据，以及独立的扫描完整性信息 |

```text
Skill 目录
   ↓
有界文件收集
   ↓
规则检查 + 跨文件关联
   ↓
风险结论 ───→ results.jsonl
扫描状态 ───→ scan-metadata.jsonl
触发审计 ───→ analysis-metadata.jsonl
报告校验 ───→ scan-complete.json
```

## 能发现什么

- 凭据、浏览器、钱包、云令牌和工作区数据外传
- 安装钩子、依赖混淆、CI 下载执行和项目自动运行风险
- 过宽的文件、网络、Shell、主机和容器权限
- 隐藏提示词、工具描述注入、品牌冒充及声明与行为矛盾
- 不安全反序列化、编码载荷、动态加载和扫描规避
- 远程更新漂移、隔离边界突破和跨平台安全配置丢失

非良性结果使用 `skillscan-legacy-v41` 分类体系中的 `ast01`–`ast10`。它保留历史含义，不等同于未指定版本的 OWASP 分类；例如历史 `ast05` 仍表示反序列化与配置注入。分类及外部指令映射见 [设计文档](docs/design.md) 与 [迁移说明](docs/hardening.md)。

## 快速开始

源码语言最低要求为 Go 1.23；CI、Action 和 Docker 构建当前固定使用 Go 1.27.1。以下从 `main` 构建开发版：

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
make build

./skillscan --collection ./testdata/skills ./out
cat ./out/results.jsonl
```

扫描一组 Skills 时，使用 `--collection`，每个可见一级子目录代表一个完整 Skill：

```text
skills/
├── calendar-helper/
│   ├── SKILL.md
│   └── manifest.json
└── code-reviewer/
    ├── package.json
    └── index.js
```

```bash
./skillscan --collection ./skills ./out

# 单个 Skill，即使内部包含 scripts/ 等子目录也作为整体扫描
./skillscan --single --timeout 5m ./skills/calendar-helper ./out-single
```

参数必须放在两个路径之前。默认 `--mode auto`：根目录有 `SKILL.md` 时按单个 Skill 扫描，否则以可见一级子目录为集合；没有此类目录时回退到单个根目录。布局不明确时使用显式模式，`--collection` 不接受空集合。

输入和输出目录不得相同或互相包含。也可以通过 `SKILLS_DIR` 和 `OUTPUT_DIR` 指定路径，位置参数优先；默认路径为 `/data/skills` 和 `/output`。扫描期限默认 `5m`，从输出准备完成后覆盖发现与分析阶段。

## 输出

`results.jsonl` 每行对应一个 Skill：

```json
{"skill_id":"chain-supply-update","verdict":"malicious","engine_category":"ast02","evidence_text":"OWASP AST02 ..."}
```

| 字段 | 含义 |
| --- | --- |
| `skill_id` | Skill 目录名 |
| `verdict` | `benign`、`suspicious` 或 `malicious` |
| `engine_category` | 主 `ast01`–`ast10` 类别；良性时为 `benign` |
| `evidence_text` | 命中的行为链、相关文件和判断依据 |

三个 JSONL 报告与一个校验文件共同组成一次扫描输出：

| 文件 | 内容 |
| --- | --- |
| `results.jsonl` | 上述稳定四字段分类结果 |
| `scan-metadata.jsonl` | 收集、内容和分析覆盖情况，以及采样、读取失败、跳过项和资源限制 |
| `analysis-metadata.jsonl` | 触发条件、分数、稳定规则 ID、可用的语句位置、扫描器身份和外部指令清单 |
| `scan-complete.json` | 最后写入的报告校验文件，包含运行 ID、Skill 数量和三个报告的 SHA-256 |

校验文件存在不等于扫描完整；需要同时检查报告哈希、运行 ID、Skill ID 与覆盖信息。它用于检查报告是否混用或被改动，不是数字签名。自动门禁可直接复用仓库脚本：

```bash
python3 scripts/github_action_gate.py --results ./out/results.jsonl --fail-on malicious
```

门禁返回 `0` 表示校验和策略通过，`1` 表示风险策略阻断，`2` 表示报告无效或不完整。`--fail-on never` 只关闭风险阻断，不跳过完整性校验。

CLI 退出码与风险门禁分开：

| CLI 退出码 | 含义 |
| --- | --- |
| `0` | 扫描完整结束；不代表没有风险发现 |
| `2` | 参数、输入输出、发现阶段或扫描期限错误 |
| `3` | 至少一个 Skill 的本地内容、分析或外部指令覆盖不完整 |

扫描不完整时，原本的 `benign` 会变为 `suspicious / ast08`，已有非良性结论保留并添加完整性警告。单独出现 `suspicious` 或 `malicious` 不改变 CLI 退出码。仅限独立 CLI 的 `SKILLSCAN_ALLOW_PARTIAL=1` 可压制退出码 `3`，但不会修复覆盖信息或让 Action 通过。

## Docker

```bash
docker build -t skillscan:local .
mkdir -p out

docker run --rm --network none \
  -v "$PWD/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  skillscan:local --collection
```

运行时镜像为 `scratch`，使用 UID `1000`，不包含 Shell 或包管理器。宿主机 `out` 目录需允许 UID `1000` 写入。镜像构建可能需要网络；扫描过程无需联网，上例显式禁用容器网络。

## GitHub Actions 门禁

以下固定到包含当前完整性契约的主线提交；它是开发版快照，不是 `v0.2.0`。Action 使用 Ubuntu runner 上的 Bash、Python 3 和 Go 构建环境：

```yaml
name: Scan Agent Skills

on:
  pull_request:

permissions:
  contents: read

jobs:
  skill-security:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: daffnjk/agent-skill-security-scanner@9a69854cbcbd1dd2d092f2f3ec0409ed50868932 # v0.3.0-dev snapshot
        with:
          path: skills
          mode: collection
          output: .skillscan
          timeout: 5m
          fail_on: malicious
```

| 输入 | 默认值 | 含义 |
| --- | --- | --- |
| `path` | `skills` | 工作区内的 Skill 或集合目录 |
| `mode` | `auto` | `auto`、`single` 或 `collection` |
| `output` | `.skillscan` | 工作区内的报告目录，须与输入路径互不包含 |
| `timeout` | `5m` | 发现与扫描期限，采用 Go duration 格式 |
| `fail_on` | `malicious` | `malicious` 阻断恶意判定；`suspicious` 阻断可疑和恶意判定；`never` 仅关闭风险阻断 |

扫描错误、不完整覆盖和报告校验失败始终阻断。Action 不执行目标 Skill；PR 检查应扫描完整 Skill 目录，以保留跨文件关联。步骤输出包括 `malicious`、`suspicious`、`benign` 数量和 `results` 路径，并写入任务摘要。完整契约见 [CI 集成说明](docs/v41-integration.md)。

## 公开评测

以下为历史 v41 提交 `6dae4d982223e4bb6528f300f607d163a00b21d5` 的冻结评测，严格口径仅将 `malicious` 视为阳性，不代表当前 `v41-hardening.1` 的效果：

| 数据集 | 样本数 | 严格精确率 | 严格召回率 | 严格 F2 |
| --- | ---: | ---: | ---: | ---: |
| Agent Skill Malware | 347 | 90.98% | 97.58% | 96.18% |
| SkillTrustBench | 5,520 | 77.64% | 94.59% | 90.63% |
| SkillsBench 1,650 | 1,650 | 38.57% | 93.33% | 72.69% |

这只是部分结果：完整评测中 SkillGuard v2 严格召回率为 **6.22%**，SkillTrustBench 误报率为 **47.47%**。SkillTrustBench 的 5,520 个输入中有 1,014 个非二分类标签，未计入精确率、召回率等指标。56,004 个输入中有 7 个扫描不完整，不能视为完整通过。

不同数据集可能重叠，不计算跨数据集总分。完整的 TP/FP/TN/FN、误报率、准确率、完整性统计与材料化口径见 [`benchmarks/v41`](benchmarks/v41/README.md)；历史 v38 快照仍保留在 [`benchmarks/v38`](benchmarks/v38/README.md)。

项目起源于 2026 首届火山引擎 AI 安全攻防挑战赛赛道 B。最终参赛快照保存在 [`competition/v38-final`](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final)，赛事得分为 **7.27 / 10**；当前 `main` 是赛后持续迭代版本，尚未在同一赛事环境中重新评测。详情见 [赛事说明](docs/competition.md)。

## 边界

- 静态规则与有界行为关系可能产生误报或漏报，不提供完整的跨语言程序语义或污点分析。
- 外部 URL 不会被访问；普通引用不直接判恶意，识别到未审查的外部指令委托会使扫描不完整。
- 超大文本采样、分析截断、符号链接和不透明可执行文件会影响完整性；普通不支持格式和排除目录不属于覆盖范围。
- 加密、动态生成、深度混淆、二进制或暂不支持的内容可能无法被完整解释。
- `benign` 只表示当前扫描未发现足够的风险证据，不代表安全保证。
- 本工具不是运行时沙箱，也不应成为执行不可信 Skill 的唯一依据。

## 开发与文档

```bash
make verify
```

- [安全边界与迁移说明](docs/hardening.md)
- [设计与规则演进](docs/design.md)
- [CI 集成与报告校验](docs/v41-integration.md)
- [完整评测数据](benchmarks/README.md)
- [性能与资源限制](PERFORMANCE.md)
- [贡献指南](CONTRIBUTING.md)
- [安全问题报告](SECURITY.md)

## 许可证

本项目的公开版本依据 [GNU Affero General Public License v3.0（AGPL-3.0-only）](LICENSE) 授权，包括个人和教育用途。遵守 AGPL-3.0 条款时，也可用于商业或专有环境。

**商业用途**：如果您希望在不承担 AGPL-3.0 开源义务的商业或专有环境中使用本项目，**请联系我以获得单独的商业许可证。**

**贡献**：通过提交 Pull Request，您同意您的贡献可以在 GNU AGPLv3 和项目的商业许可证下使用。
