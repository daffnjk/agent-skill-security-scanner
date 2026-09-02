<div align="center">

# Agent Skill Security Scanner

### 运行 Agent Skill 之前，先看清它会做什么

`skillscan` 是一个离线、快速、可解释的静态安全扫描器，用于检查 Agent Skill、MCP 工具、IDE 规则和插件包。

[![CI](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/daffnjk/agent-skill-security-scanner/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![Offline](https://img.shields.io/badge/runtime-offline-1f883d)](Dockerfile)
[![License](https://img.shields.io/badge/license-AGPL--3.0-663399)](LICENSE)

[English](README_EN.md)

</div>

## 什么是 `skillscan`？

一个 Skill 不只有提示词，还可能包含脚本、权限清单、安装钩子、CI 工作流和自动运行配置。真正的风险往往分散在多个文件里，单看其中一个文件并不够。

`skillscan` 将待测包视为**不可信数据**：不安装、不导入、不执行其中的代码，也不访问包内声明的 URL。它会关联权限、命令执行、敏感数据访问和网络行为，给出可复核的风险结论与证据。

> [!NOTE]
> 这是启发式静态分析工具。扫描结果是安全评审线索，不是“安全”或“恶意”的最终证明。

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
```

## 能发现什么

- 凭据、浏览器、钱包、云令牌和工作区数据外传
- 安装钩子、依赖混淆、CI 下载执行和项目自动运行风险
- 过宽的文件、网络、Shell、主机和容器权限
- 隐藏提示词、工具描述注入、品牌冒充及声明与行为矛盾
- 不安全反序列化、编码载荷、动态加载和扫描规避
- 远程更新漂移、隔离边界突破和跨平台安全配置丢失

非良性结果会映射到项目采用的 `AST01`–`AST10` 风险类别。完整规则说明见 [设计文档](docs/design.md)。

## 快速开始

需要 Go 1.23 或更高版本：

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
make build

./skillscan ./testdata/skills ./out
cat ./out/results.jsonl
```

扫描自己的 Skills 时，输入目录下每个一级子目录代表一个 Skill：

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
./skillscan ./skills ./out
```

也可以通过 `SKILLS_DIR` 和 `OUTPUT_DIR` 指定路径；命令行位置参数优先。

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

`scan-metadata.jsonl` 记录读取错误、资源截断、采样文件、符号链接和不透明载荷等完整性信息。不完整扫描不会继续保留可信的 `benign` 结论。

退出码为：`0` 表示扫描完整结束，`2` 表示启动、输入或输出错误，`3` 表示至少一个 Skill 扫描不完整。发现 `suspicious` 或 `malicious` 本身不会改变退出码。

## Docker

```bash
docker build -t skillscan:local .
mkdir -p out

docker run --rm \
  -v "$PWD/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  skillscan:local
```

运行时镜像使用非 root 用户，扫描过程无需联网。

## 公开评测

冻结的 v38 版本在公开数据集上的部分结果如下：

| 数据集 | 样本数 | 严格精确率 | 严格召回率 | 严格 F2 |
| --- | ---: | ---: | ---: | ---: |
| Agent Skill Malware | 347 | 71.18% | 97.58% | 90.84% |
| SkillTrustBench | 5,520 | 73.52% | 96.40% | 90.75% |
| PoisonedSkills | 1,070 | 不适用* | 83.18% | 86.07%* |

\* PoisonedSkills 在该评测中只有恶意正样本，不能用于评价误报率。不同数据集可能重叠，不计算跨数据集总分。完整指标与材料化口径见 [`benchmarks/v38`](benchmarks/v38/README.md)。

项目起源于 2026 首届火山引擎 AI 安全攻防挑战赛赛道 B。最终参赛快照保存在 [`competition/v38-final`](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final)，赛事得分为 **7.27 / 10**；当前 `main` 是赛后持续迭代版本，尚未在同一赛事环境中重新评测。详情见 [赛事说明](docs/competition.md)。

## 边界

- 静态规则与行为链分析可能产生误报或漏报。
- 加密、动态生成、深度混淆、二进制或暂不支持的内容可能无法被完整解释。
- `benign` 只表示当前扫描未发现足够的风险证据，不代表安全保证。
- 本工具不是运行时沙箱，也不应成为执行不可信 Skill 的唯一依据。

## 开发与文档

```bash
make verify
```

- [设计与规则演进](docs/design.md)
- [完整评测数据](benchmarks/README.md)
- [性能与资源限制](PERFORMANCE.md)
- [贡献指南](CONTRIBUTING.md)
- [安全问题报告](SECURITY.md)

## 许可证

本项目的公开版本依据 [GNU Affero General Public License v3.0（AGPL-3.0-only）](LICENSE) 授权，包括个人和教育用途。遵守 AGPL-3.0 条款时，也可用于商业或专有环境。

**商业用途**：如果您希望在不承担 AGPL-3.0 开源义务的商业或专有环境中使用本项目，**请联系我以获得单独的商业许可证。**

**贡献**：通过提交 Pull Request，您同意您的贡献可以在 GNU AGPLv3 和项目的商业许可证下使用。
