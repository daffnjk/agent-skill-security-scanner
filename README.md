<div align="center">

# Agent Skill Security Scanner

### Competition v38 Snapshot · 比赛最终版本快照

首届火山引擎 AI 安全攻防挑战赛 · 赛道 B 最终提交版本的历史复现分支。

[![Competition](https://img.shields.io/badge/competition-v38%20final-8250df)](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final)
[![Score](https://img.shields.io/badge/final%20score-7.27%20%2F%2010-1f883d)](https://github.com/daffnjk/agent-skill-security-scanner/blob/main/docs/competition.md)
[![Exact source](https://img.shields.io/badge/exact%20source-4d78e38-0969da)](https://github.com/daffnjk/agent-skill-security-scanner/commit/4d78e38f50a1195139827150de70406008af5b5c)
[![Current development](https://img.shields.io/badge/current%20development-main-f0b429)](https://github.com/daffnjk/agent-skill-security-scanner/tree/main)
[![Dataset baseline](https://img.shields.io/badge/dataset%20baseline-v38-0a7ea4)](https://github.com/daffnjk/agent-skill-security-scanner/tree/main/benchmarks/v38)

[中文说明](#中文说明) · [数据集基线](#数据集基线) · [English](#english)

</div>

## 中文说明

> [!IMPORTANT]
> 本分支用于保存和复现 **v38 / recall micro-loop 115** 比赛最终版本。检测器源代码、Docker 运行方式、测试脚本和输出协议仍以提交 [`4d78e38f50a1195139827150de70406008af5b5c`](https://github.com/daffnjk/agent-skill-security-scanner/commit/4d78e38f50a1195139827150de70406008af5b5c) 为准。本 README 是赛后的文档说明更新，不表示比赛代码经过重写或重新评测。

### 版本关系

| 位置 | 用途 | 维护方式 |
| --- | --- | --- |
| [`competition/v38-final`](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final) | 比赛版本的历史说明与复现入口 | 不接收检测能力、规则或运行语义更新 |
| [`4d78e38`](https://github.com/daffnjk/agent-skill-security-scanner/commit/4d78e38f50a1195139827150de70406008af5b5c) | 比赛源代码的精确提交 | 使用提交哈希进行字节级代码复现 |
| [`main`](https://github.com/daffnjk/agent-skill-security-scanner/tree/main) | 基于 v38 持续演进的赛后版本 | 接收代码质量、安全语义、规则、测试和发布工程改进 |

除本 README 的版本说明外，本分支的扫描器实现与比赛源代码提交保持一致。需要精确复现当时仓库内容时，请直接检出固定提交：

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
git checkout 4d78e38f50a1195139827150de70406008af5b5c
```

需要使用当前维护版本时，请使用 `main`：

```bash
git switch main
git pull --ff-only
```

### 项目简介

`skillscan` 是一个快速、离线、确定性的 Agent Skill 静态安全扫描器。它将待测包作为数据读取，不安装、不导入、不执行其中的脚本，也不访问包内声明的 URL。

v38 联合分析 Agent Skill、MCP 工具包、IDE 规则、插件包中的 manifest、代码、文档、CI、容器配置和项目自动运行配置，重点识别：

- 凭据、浏览器数据、钱包、云令牌和工作区数据外传；
- 面向 Agent 的提示词注入与隐藏指令；
- 安装钩子、CI 下载执行、可变依赖和供应链风险；
- 过宽的文件、网络、Shell、主机和容器权限；
- 不安全反序列化及编码载荷执行链；
- 本地 Agent 控制、容器边界和远程插件加载风险；
- 元数据与代码行为矛盾及跨平台安全策略弱化。

扫描结果使用 `benign`、`suspicious` 或 `malicious` 判定，并选择一个主 `ast01`–`ast10` 类别，附带可人工复核的文本证据。

> [!WARNING]
> 这是比赛期间形成的启发式静态检测器。结果是安全审查线索，不是包安全或恶意性的证明。请勿通过直接执行不可信 Skill 来验证扫描结果。

### 数据集基线

为支持赛后版本按固定口径回归，使用精确源代码提交 `4d78e38` 另行建立了 [`v38 数据集基线`](https://github.com/daffnjk/agent-skill-security-scanner/tree/main/benchmarks/v38)。该基线记录检测器与数据源哈希，只提交汇总指标，不提交恶意样本正文或逐样本证据。

| 评测套件 | 评估单元 | 实际扫描 | 结果摘要 |
| --- | ---: | ---: | --- |
| 本地 malicious-skills corpus | 13 | 63,707 | 11 个单元完成，2 个仅含元数据 |
| PoisonedSkills | 1 | 1,070 | 890 个判为 `malicious`，180 个漏检；严格召回率 83.18%，F2 86.07% |

不同数据集存在重叠，部分单元只有恶意正样本，因此不计算跨数据集总分，也不把正样本单元的数学精确率解释为误报能力。完整指标、来源固定版本与口径见 [`metrics.csv`](https://github.com/daffnjk/agent-skill-security-scanner/blob/main/benchmarks/v38/metrics.csv) 和 [`manifest.json`](https://github.com/daffnjk/agent-skill-security-scanner/blob/main/benchmarks/v38/manifest.json)。

> [!NOTE]
> 这些是赛后使用公开数据集得到的可复现基线，不是赛事官方重新评分，也不代表当前 `main` 的检测能力。

### 比赛成绩

该版本用于 **2026 首届火山引擎 AI 安全攻防挑战赛 · 赛道 B（蓝队检测挑战）** 的最终提交。

| 检测质量 | 可解释性 | 运行稳健性 | 性能 | 总分 | 最终排名 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4.34 / 5.50 | 1.10 / 2.00 | 0.83 / 1.50 | 1.00 / 1.00 | **7.27 / 10** | **20+** |

这些成绩只对应比赛提交版本，不延伸代表 `main` 或其他赛后分支。详细口径见 [`main` 分支的赛事说明](https://github.com/daffnjk/agent-skill-security-scanner/blob/main/docs/competition.md)。

### 快速开始

需要 Go 1.23 或更高版本：

```bash
make build
make test
make selftest
```

输入目录下每个子目录代表一个 Skill：

```text
skills/
├── calendar-helper/
│   ├── SKILL.md
│   └── manifest.json
└── code-reviewer/
    ├── package.json
    └── index.js
```

执行扫描：

```bash
mkdir -p out
./skillscan ./skills ./out
cat ./out/results.jsonl
```

也可以使用 `SKILLS_DIR` 和 `OUTPUT_DIR` 指定路径；命令行位置参数优先。

### 输出协议

每个 Skill 输出一行 JSON：

```json
{"skill_id":"calendar-helper","verdict":"suspicious","engine_category":"ast03","evidence_text":"OWASP AST03 ..."}
```

| 字段 | 说明 |
| --- | --- |
| `skill_id` | 输入目录名 |
| `verdict` | `benign`、`suspicious` 或 `malicious` |
| `engine_category` | 主 `ast01`–`ast10` 类别；良性时为 `benign` |
| `evidence_text` | 简要行为依据和相关文件上下文 |

结果原子写入输出目录的 `results.jsonl`。

> [!NOTE]
> v38 比赛版本只定义上述四字段 `results.jsonl`。当前 `main` 中新增的 `scan-metadata.jsonl`、扫描完整性状态和严格模式退出码 `3` 属于赛后加固能力，不存在于本比赛快照中。

### Docker

```bash
docker build -t agent-skill-security-scanner:v38 .
mkdir -p out
docker run --rm \
  -v "$PWD/skills:/data/skills:ro" \
  -v "$PWD/out:/output" \
  agent-skill-security-scanner:v38
```

运行容器默认离线，并使用非 root 用户。

### 已知边界

- 静态字符串和行为链分析可能产生误报或漏报；
- 混淆、加密、动态生成和不支持的二进制内容可能逃逸检测；
- 大文件采用采样，并限制单 Skill 保留的数据量和文件数量；
- `benign` 不代表安全保证，也不能替代沙箱、来源校验、签名验证和人工审查；
- 生产或持续集成使用应优先评估当前 [`main`](https://github.com/daffnjk/agent-skill-security-scanner/tree/main) 的赛后版本。

---

## English

> [!IMPORTANT]
> This branch documents and preserves the final **v38 / recall micro-loop 115** competition line. The exact detector source, Docker behavior, test scripts, and output contract are anchored at commit [`4d78e38f50a1195139827150de70406008af5b5c`](https://github.com/daffnjk/agent-skill-security-scanner/commit/4d78e38f50a1195139827150de70406008af5b5c). This README is a post-competition documentation clarification; it does not imply that the competition code was rewritten or re-evaluated.

`skillscan` is a fast, offline, deterministic static scanner for Agent Skills, MCP-style tool packages, IDE rules, and plugin bundles. It reads packages as untrusted data without installing, importing, or executing embedded scripts and without contacting package-declared URLs.

The v38 detector looks for high-signal behavior chains involving credential exfiltration, prompt injection, unsafe install hooks, overly broad permissions, unsafe deserialization, isolation-boundary violations, remote updates, and cross-platform policy weakening. Each Skill receives a `benign`, `suspicious`, or `malicious` verdict, one primary `ast01`–`ast10` category, and concise review evidence.

### Version lineage

| Reference | Purpose |
| --- | --- |
| [`competition/v38-final`](https://github.com/daffnjk/agent-skill-security-scanner/tree/competition/v38-final) | Historical competition documentation and reproduction entry point |
| [`4d78e38`](https://github.com/daffnjk/agent-skill-security-scanner/commit/4d78e38f50a1195139827150de70406008af5b5c) | Exact competition source commit |
| [`main`](https://github.com/daffnjk/agent-skill-security-scanner/tree/main) | Actively maintained post-competition development line |

For exact reproduction:

```bash
git clone https://github.com/daffnjk/agent-skill-security-scanner.git
cd agent-skill-security-scanner
git checkout 4d78e38f50a1195139827150de70406008af5b5c
make build
make test
make selftest
```

Run the scanner with one Skill directory per input child:

```bash
mkdir -p out
./skillscan ./skills ./out
cat ./out/results.jsonl
```

The competition version emits only the four-field `results.jsonl` contract. The `scan-metadata.jsonl` sidecar, explicit completeness status, and strict exit status `3` available on `main` are post-competition hardening features and are not part of this snapshot.

### Dataset benchmark baseline

A separate [`v38 dataset baseline`](https://github.com/daffnjk/agent-skill-security-scanner/tree/main/benchmarks/v38) was produced after the competition from the exact `4d78e38` source. It records 63,707 static scans across 13 local-corpus evaluation units plus all 1,070 canonical PoisonedSkills samples. On PoisonedSkills, v38 detected 890 samples and missed 180, for 83.18% strict recall and 86.07% F2.

The snapshot pins detector and upstream dataset hashes and commits only aggregate metrics. It is a reproducible post-competition benchmark, not an official competition re-score and not a measurement of current `main`. Dataset overlap and positive-only units prevent a meaningful global score. See [`metrics.csv`](https://github.com/daffnjk/agent-skill-security-scanner/blob/main/benchmarks/v38/metrics.csv) and [`manifest.json`](https://github.com/daffnjk/agent-skill-security-scanner/blob/main/benchmarks/v38/manifest.json).

### Competition result

| Detection quality | Explainability | Runtime robustness | Performance | Total | Final rank |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4.34 / 5.50 | 1.10 / 2.00 | 0.83 / 1.50 | 1.00 / 1.00 | **7.27 / 10** | **20+** |

The score applies only to the final competition submission. It must not be attributed to `main` or other post-competition revisions.

### Limitations

- Static heuristics can produce false positives and false negatives.
- Obfuscated, encrypted, generated, binary, or unsupported content may evade inspection.
- Large files are sampled and per-Skill retained data is bounded.
- A `benign` verdict is not a security guarantee or a substitute for sandboxing, provenance verification, signatures, and human review.

This project is independently maintained and is not affiliated with or endorsed by OWASP, Volcengine, the competition organizers, or any package/provider brand referenced by its rules.
