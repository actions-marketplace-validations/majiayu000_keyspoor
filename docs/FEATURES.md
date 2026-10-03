# 功能实现与竞品覆盖

核查日期：2026-10-03。本文依据当前源码、已有测试文件、竞品官方研究和本机安装 manifest；不是“60 项全部完成”的声明，也不依据规则条数推导准确率。

本项目的扫描调度、规则编译组织、候选筛选、匹配过滤、坐标映射、指纹、Git 获取、归档和接口由本仓库实现。底层使用通用 `regex`、`aho-corasick`、`zip`、`tar`、`flate2` 等库，**没有依赖或调用其他 secrets scanner SDK**。规则数据包含固定 Gitleaks v8.30.1 的 221 条 MIT 规则、本仓库 3 条通用赋值规则及 1 条 URI userinfo 密码规则，默认共 225 条。第三方规则与自研运行时的边界见 [RULE_SOURCES.md](RULE_SOURCES.md)。这不是从零编写正则引擎，也不是全部规则原创。

## 当前公开能力

| 入口 | 已实现范围 | 主要边界与证据 |
| --- | --- | --- |
| Rust `Engine::new` / `scan_bytes` | 编译后复用；线程安全字节扫描；关键词预筛；provider 正则、通用赋值、熵、占位符及规则 allowlist | 正则与启发式，不是 AST/数据流或自研 SIMD 引擎；[engine.rs](../src/engine.rs)、[rules.rs](../src/rules.rs) |
| 自定义规则 | JSON 文件或规则目录；捕获组、关键词、置信度、熵、路径包含/排除、secret/match/line allowlist、AND/OR、stopwords | 不兼容全部 Gitleaks/Kingfisher 格式；没有复合近邻、checksum、验证器插件；[rules.rs](../src/rules.rs) |
| 通用赋值与 URI 密码 | quoted/unquoted 赋值；赋值后最多一个换行的相邻 quoted literal；postgres/postgresql/mysql/http/https/redis/rediss URI 中非空密码 | 不跨空行或常量拼接；URI 保留 percent-encoded 密码原始字节位置，不进行连接/验证；[rules.rs](../src/rules.rs) |
| `scan` / stdin | 路径遍历、有界单文件读取、可配置线程数、ignore 控制、收集接口确定性排序、JSONL 事件流 | 有界文件队列；每个 worker 仍持有一个文件及其 findings；[scan.rs](../src/scan.rs) |
| 编码 | BOM 标记 UTF-16 LE/BE 与原始位置映射；仅按 finding 边界保留回映信息；可选单层标准/URL-safe Base64 | Base64 不是递归解码；无 hex/URL 编码/UTF-32/无 BOM 字符集自动推断；[engine.rs](../src/engine.rs) |
| 归档 | ZIP/tar/gzip，最多四层；累计解压量限制；不落盘、不执行、不跟随 tar 链接；成员来源和成员字节坐标 | 文件/stdin/staged/history 共用解包入口；Git 历史保留 `git:commit:path!member` 来源。无 PDF 文本/OCR、SQLite 行、pyc 常量或 OCI 层解析；[archive.rs](../src/archive.rs)、[archive 测试](../tests/archive.rs) |
| `staged` | 读取 changed staged 文件的完整 index 内容，不误读 worktree | 不是仅新增行模式；不读取子模块内容；[scan.rs](../src/scan.rs)、[scan 测试](../tests/scan.rs) |
| `history` | 本地可达 refs；每 blob 读取一次；每 blob/精确路径检测一次；投射所有 commit/path 出现位置 | 不拉取远程、LFS 或子模块；不发现 GitHub 删除/隐藏对象；没有跨运行缓存；[scan.rs](../src/scan.rs) |
| `--baseline` / `--write-baseline` | 指纹差分、保留已有人工标签、完整扫描才可写基线；schema 2 绑定范围、ignore 和检测配置；不完整扫描不推断 resolved | CLI 仅输出新增；库可返回 resolved；没有交互审计器、统计调参 UI、自动修复；[baseline.rs](../src/baseline.rs) |
| JSON / JSONL / SARIF | finding 默认脱敏、规则/位置/解释/置信度/指纹；完整性、错误与统计；退出码 0/1/2 分离 | 无原始秘密或代码片段回显；普通指纹不是低熵值保密机制，可选私有 key 的 BLAKE3；[report.rs](../src/report.rs)、[lib.rs](../src/lib.rs) |
| `serve` | 常驻 JSONL 请求/响应；复用规则；单请求 8 MiB 限制 | 串行执行；无取消、进度、任务持久化、HTTP 服务；[main.rs](../src/main.rs) |
| `mcp --root ...` | stdio MCP 握手、tools/list、scan_text、scan_paths；JSON Schema、只读提示、structuredContent、目录边界、进度及取消、限额预览 | 不是 LSP 或完整 Agent 平台；路径限制不是对并发文件变更的 OS 沙箱；无验证/撤销工具；[mcp.rs](../src/mcp.rs) |

源码存在和已有测试不等于所有环境均通过。实际测试与 benchmark 结论以本次执行记录为准；新一轮执行记录见 [RESULTS.md](RESULTS.md)。

## 原 60 项候选的实现状态

“实现”仅指该行限定的能力已有源码；“部分”表示只完成子集；“未实现”不把通用 regex 可能偶然匹配计为专门能力。没有按项目宣传推导本项目能力。

按以下限定逐项计数为 **20 项实现、17 项部分实现、23 项未实现**。这不是成熟度百分比，也不是 60 项交付验收完成。

### P：性能与资源

| ID | 原候选 | 状态 | 实际边界 |
| --- | --- | --- | --- |
| P01 | 规则编译一次、多次 bytes 扫描 | 实现 | `Engine` 可反复复用，不需子进程。 |
| P02 | 多模式前缀/关键词预筛 | 实现 | Aho–Corasick 关键词候选规则分发；无关键词规则始终执行。 |
| P03 | SIMD 候选 + 局部精确捕获 | 未实现 | 候选规则仍在全内容运行 regex；无本项目 SIMD 多规则候选窗口引擎。 |
| P04 | 有界并行、反压、缓冲复用 | 部分 | 固定 workers、有界文件/结果队列、sink 反压；尚无 worker scratch 复用，单文件 findings 仍收集。 |
| P05 | Git 对象去重并保留位置 | 实现 | blob 只读取一次；为路径规则正确性按 blob/path 检测；保留 commit/path occurrence。 |
| P06 | 内容 + 规则配置身份缓存 | 未实现 | 无跨运行扫描缓存。 |
| P07 | 读取与检测流水线 | 部分 | 不同文件的 worker 可重叠读取/检测；单文件先完整读入，无分块流水线。 |
| P08 | 检测/验证独立并发、请求去重 | 未实现 | 没有网络验证阶段。 |
| P09 | 常驻进程 | 实现 | JSONL `serve` 和 stdio MCP 复用 Engine；每个接口均单扫描；MCP 读协议线程可处理 ping/取消。 |
| P10 | GPU 后端与一致性 | 未实现 | 无 GPU 后端。 |

### D：检测与准确率

| ID | 原候选 | 状态 | 实际边界 |
| --- | --- | --- | --- |
| D01 | Provider 格式 | 实现 | 221 条导入规则是格式规则数，不是 221 个 provider 或 validator。 |
| D02 | 通用赋值 | 实现 | 3 条独立引号/无引号规则，支持赋值后一个换行的相邻 quoted literal；不跨空行，不承诺所有语法。 |
| D03 | 候选 entropy | 实现 | Shannon 字节熵，按规则阈值或全局覆盖。 |
| D04 | BPE 稀有度 | 未实现 | 无 tokenizer/BPE 模型。 |
| D05 | 结构 checksum | 未实现 | 无 token 内部校验和验证。 |
| D06 | 多字段配对 | 未实现 | 无 key ID/secret/endpoint 的依赖规则和近邻组合。 |
| D07 | Lexer 上下文 | 未实现 | 赋值 regex 不是 lexer、AST 或语言语义。 |
| D08 | 结构化配置解析 | 未实现 | 对 JSON/YAML/env 扫字节，不构建配置结构。 |
| D09 | 私钥、证书、连接串 | 部分 | 有私钥格式和 7 种 scheme 的 URI userinfo 密码规则，保留原始密码 span；无证书语义解析和全部连接串格式覆盖。 |
| D10 | 递归编码解码 | 部分 | 单层 Base64 + BOM UTF-16；不递归，不含 URL/hex。归档递归见 S07。 |
| D11 | 已知秘密 hash 匹配 | 未实现 | finding 指纹用于身份/基线，不是已知秘密匹配器。 |
| D12 | Placeholder/词典/变量引用过滤 | 部分 | 固定占位符、重复字符、导入 allowlist、通用赋值变量引用过滤；无可训练词典/gibberish。 |
| D13 | ML 降误报 | 未实现 | 无 ML 模型。 |
| D14 | 常量传播、跨函数分析 | 未实现 | 无跨语句/跨函数数据流。 |

### S：输入范围

| ID | 原候选 | 状态 | 实际边界 |
| --- | --- | --- | --- |
| S01 | Bytes/string/stdin | 实现 | Rust 字节 API、`str.as_bytes()`、CLI stdin、JSONL/MCP text。 |
| S02 | 文件树与 ignore | 实现 | 文件/目录、ignore/gitignore 控制；`.git` 固定排除。 |
| S03 | Staged/patch/commit range | 部分 | staged index 完整文件；支持完整快照 commit range；无独立 patch/仅变更行输入。 |
| S04 | Git 历史/refs | 实现 | 本地可达 refs；不等于托管平台隐藏/删除 commit 全覆盖。 |
| S05 | 托管平台枚举 | 未实现 | 无 GitHub/GitLab/org/user 枚举。 |
| S06 | Issue/PR/log 等外围资产 | 未实现 | 无平台连接器。 |
| S07 | 递归归档 | 实现 | ZIP/tar/gzip 四层 + 累计预算；文件/stdin/staged/history 共用；Git 报告保留 commit/归档成员来源。 |
| S08 | PDF/Office/邮件 | 部分 | ZIP 容器中的 Office XML 可作为成员字节扫描；无文档语义抽取、PDF、邮件解析或 OCR。 |
| S09 | SQLite/bytecode/APK | 部分 | ZIP 格式 APK 可扫成员字节；无 SQLite 行、pyc/DEX 常量等专门解析。 |
| S10 | OCI 容器 | 未实现 | 普通 tar 解包不等于 OCI manifest/config/layer 语义和 registry 获取。 |
| S11 | 云/协作平台连接器 | 未实现 | 无对象存储、Slack/Jira/Teams 等连接器。 |
| S12 | HTTP/browser/proxy | 未实现 | 无抓取器或浏览器/Burp 扩展。 |

### A：Agent 与开发接口

| ID | 原候选 | 状态 | 实际边界 |
| --- | --- | --- | --- |
| A01 | Rust SDK | 实现 | 当前 crate 公共 API；并非已发布稳定版本承诺。 |
| A02 | JSON/JSONL | 实现 | 版本化 ScanReport；JSONL finding/error/progress + summary；常规进度按 100ms 节流，首末快照保留。 |
| A03 | 默认遮盖 | 实现 | 结果无 raw secret、捕获值或源代码片段；保留调用方路径/ID。 |
| A04 | Secret ID 与 occurrence 分离 | 部分 | 有稳定指纹、多个位置和基线代表记录；同视图精确 span 跨规则合并并保留 matched_rule_ids；指纹含主规则和路径，不是跨路径统一 secret 实体模型。 |
| A05 | 确定性排序、指纹语义 | 实现 | 规则/路径/值指纹，行移位不变；路径或规则变化会变；可选 keyed BLAKE3。 |
| A06 | 精确位置与转换 map | 部分 | 原始字节/UTF-16 回映/归档成员坐标；Base64 指向整个编码段，没有内部字符映射。 |
| A07 | 命中、错误、未完成区分 | 实现 | complete/errors/exit 0、1、2；失败不伪装 clean。 |
| A08 | 规则原因、confidence、风险分离 | 部分 | 规则说明、静态 confidence、not live-validated；无风险评分/权限评估，confidence 不是实测概率。 |
| A09 | 摘要、数量与按需详情 | 部分 | JSONL summary 有数量和统计；MCP 有总数、截断标志、100 findings/100 errors/512 KiB 预览；无分页详情接口。 |
| A10 | 取消、超时、部分结果 | 部分 | 边界协作取消、MCP progress/cancel；单次正则不可中断，无总超时。 |
| A11 | SARIF/CI | 实现 | SARIF 导出及非交互退出码可接 CI；不代表已发布 GitHub Action。 |
| A12 | MCP | 实现 | 最小只读 stdio MCP，两工具；不是所有 MCP 可选能力实现。 |
| A13 | Agent hooks | 部分 | CLI staged 可被外部 hook 调用；没有专用 Agent hook 安装/策略集成。 |
| A14 | Python SDK | 未实现 | CLI 能被 Python 调用不等于进程内 Python SDK。 |
| A15 | JS/WASM/C ABI/LSP | 未实现 | 无这些绑定或协议服务。 |
| A16 | 改写提案/补丁 | 未实现 | 不生成修复补丁，不更改扫描目标。 |

### G：治理

| ID | 原候选 | 状态 | 实际边界 |
| --- | --- | --- | --- |
| G01 | Baseline 新增/resolved | 实现 | 库返回新增/解决；CLI支持仅新增；不完整扫描不给 resolved。 |
| G02 | 人工标签与统计 | 部分 | 标签随指纹保留；无交互标注、质量统计/调参报表。 |
| G03 | Inline/path/rule ignore 与复审 | 部分 | JSON 规则 allowlist、路径包含/排除、ignore；无 inline pragma 或例外复审流程。 |
| G04 | 规则扩展、来源、版本 | 实现 | 自定义 JSON；导入来源固定 commit/hash/license 与显式排除记录。 |
| G05 | 独立网络验证 | 未实现 | 完全离线检测；无 provider 请求。 |
| G06 | 权限/scope 分析 | 未实现 | 无身份或影响范围查询。 |
| G07 | 显式撤销 | 未实现 | 无凭据修改操作。 |
| G08 | 持久调查、跨工具导入、报告 | 部分 | 可持久化本项目报告/基线；无调查 datastore、跨工具导入或浏览器 viewer。 |

## 22 个研究对象与本机比较边界

“官方范围”来自链接的一手文档或本次保存的 CLI help；可以超出安装版本。尤其 Betterleaks 官方 main/v2 的功能不能自动赋予本机 v1.9.0。下表的本机模式来自 [manifest](../bench/tools/manifest.json)：F=filesystem，H=Git history，I=staged index；它们表示**配置了离线比较命令**，不是完整功能认证或性能获胜。`available` 也不代表所有 corpus 执行成功，具体运行还须查看最终 [JSON 数据](../bench/results/final.json) 与 [报告](../bench/results/final.md)。

| 项目及官方来源 | 官方输入/接口优势 | 在线活性验证边界 | 本机版本、模式与状态 | 已核实主项目许可 |
| --- | --- | --- | --- | --- |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | 文件、staged hook、Python API、baseline/audit | 部分插件支持；本机比较禁用 | 1.5.0；F；available | [Apache-2.0](https://github.com/Yelp/detect-secrets/blob/master/LICENSE) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 文件/stdin/Git、编码/归档、TOML、JSON/SARIF | 静态核心，无内置活性验证 | v8.30.1；F/H/I；available | [MIT](../bench/tools/source/gitleaks/LICENSE) |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Git、对象存储、容器、CI/Postman 等连接器；自定义 detector/webhook | 支持；离线比较关闭；Enterprise 连接器不混算 OSS | v3.97.9；F/H；available | [AGPL-3.0](../bench/tools/source/trufflehog/LICENSE) |
| [Kingfisher](https://github.com/mongodb/kingfisher) | 多平台、文档/归档、容器、Rust/Python API、结构化输出、报告 UI | 支持；另有权限分析和显式撤销；本机关闭 | v2.9.1；F/H/I；available | [Apache-2.0](https://github.com/mongodb/kingfisher/blob/main/LICENSE) |
| [Betterleaks](https://github.com/betterleaks/betterleaks) | 文件/Git/托管平台/对象存储；Go SDK；BPE/上下文过滤 | 当前 main/v2 支持验证、分析、显式撤销；不能据此认定安装版同功能 | v1.9.0；F/H/I；available | [MIT](../bench/tools/source/betterleaks/LICENSE) |
| [Titus](https://github.com/praetorian-inc/titus) | 文件/Git/OCI、二进制文本抽取、Go API、Burp/Chrome、streaming server | 支持；本机关闭 | v1.2.10；F/H；available | [Apache-2.0](https://github.com/praetorian-inc/titus/blob/main/LICENSE) |
| [Nosey Parker](https://github.com/praetorian-inc/noseyparker) | 文件/Git、datastore、跨位置归并与报告 | 此处未确认本地活性验证 | v0.24.0；F/H；available；官方已退休 | [Apache-2.0](../bench/tools/source/noseyparker/LICENSE) |
| [ripsecrets](https://github.com/sirwart/ripsecrets) | 文件/pre-commit、轻量 Rust CLI、概率随机性过滤 | 官方明确 local-only | v0.1.11；F；available | [MIT](https://github.com/sirwart/ripsecrets/blob/main/LICENSE) |
| [Talisman](https://github.com/thoughtworks/talisman) | Git hooks、目录/Git 扫描；本机 help 已保存 | 此轮未验证 | v1.37.0；H/I；available；仅文件级位置，无行号 | [MIT](https://github.com/thoughtworks/talisman/blob/main/LICENSE) |
| [Trivy](https://github.com/aquasecurity/trivy) | filesystem/image 等安全扫描接口；本次仅 secrets filesystem | 本次仅离线静态规则；未验证活性能力 | v0.75.0；F；available | [Apache-2.0](../bench/tools/source/trivy/LICENSE) |
| [LeakFerret](https://github.com/leakferrethq/leakferret) | 文件/Git/org、baseline、rewrite 建议、MCP；[本机 help](../bench/tools/leakferret-help.txt) | help 显示 provider 验证，`scan` 默认为 regex；本次不启用验证 | v0.1.9；F/H；available | [MIT](../bench/tools/source/leakferret/leakferret-0.1.9-aarch64-apple-darwin/LICENSE.txt) |
| [Rusty Hog](https://github.com/newrelic/rusty-hog) | Rust 扫描器集合；本机测试其中 duroc 文件扫描器 | 未验证 | 1.0.11；F；available；旧二进制缺 OpenSSL 后由固定源码构建恢复 | [Apache-2.0](../bench/tools/source/rusty-hog-build/LICENSE) |
| [DeepSecrets](https://github.com/ntoskernel/deepsecrets) | 目录、regex/变量语义、已知值 hash、自定义评分；[本机 help](../bench/tools/deepsecrets-scan-help.txt) | 本次静态扫描；未验证在线能力 | 2.2.0；F；available | [MIT](https://github.com/ntoskernel/deepsecrets/blob/master/LICENSE) |
| [Whispers](https://github.com/Skyscanner/whispers) | 结构化文本文件/目录、规则/严重度过滤；[本机 help](../bench/tools/whispers-scan-help.txt) | 本次静态扫描；未验证在线能力 | 2.2.1；F；available | [BSD-3-Clause](../bench/tools/venvs/python/lib/python3.12/site-packages/whispers-2.2.1.dist-info/LICENSE) |
| [Secretlint](https://github.com/secretlint/secretlint) | 文件/glob/stdin、JS 规则插件、默认脱敏、lint 集成 | 本次静态 preset；不能推断所有插件均不验证 | 13.0.6；F；available | [MIT](https://github.com/secretlint/secretlint/blob/master/LICENSE) |
| [KeyHog](https://github.com/santhreal/keyhog) | 文件/Git、CPU/GPU 路线、daemon/缓存设计 | 本机命令关闭网络验证，未测 provider 覆盖 | 0.5.86；F/H；available；仅 CPU backend | [MIT OR Apache-2.0](../bench/tools/source/keyhog/LICENSE) |
| [git-secrets](https://github.com/awslabs/git-secrets) | Git hooks、文件/历史、注册 pattern/provider | 模式匹配；provider 指规则来源，不等于活性验证 | HEAD；F/H/I；available；隔离配置注册 AWS 规则 | [Apache-2.0](../bench/tools/source/git-secrets/LICENSE.txt) |
| [Credential Digger](https://github.com/SAP-archive/credential-digger) | Git/文件/PR/wiki、Python API、ML 降误报 | 此轮未验证 | 4.15.0；F；available；依赖 pin 恢复，SDK 模式关闭 ML/similarity；官方归档 | [Apache-2.0](../bench/tools/source/credential-digger/LICENSE) |
| [scratch-scanner-rs](https://github.com/ahrav/scratch-scanner-rs) | Rust 文件/Git 性能实验 | 此轮未验证 | 0.1.0；F/H；available；固定同期 Gossip-rs + 本地 Boost 恢复；官方归档 | [MIT](../bench/tools/source/scratch-scanner-rs/LICENSE) |
| [Deepfence SecretScanner](https://github.com/deepfence/SecretScanner) | 官方文件系统/容器 secrets 扫描 | 此轮未验证 | build_failed：补齐 YaraHunter/submodule 后仍缺 YARA，官方源码 bootstrap 受缺 autoreconf 阻断 | [MIT](../bench/tools/source/SecretScanner/LICENSE) |
| [ggshield](https://github.com/GitGuardian/ggshield) | 开源本地/CI CLI，检测通过 GitGuardian 服务 API | 云服务验证，非独立开源离线内核 | external_service_required；无凭据离线条件不测 | [MIT（CLI）](https://github.com/GitGuardian/ggshield/blob/main/LICENSE) |
| [Secrets Patterns DB](https://github.com/mazen160/secrets-patterns-db) | 可转换的 regex 规则资产 | 规则数量不是验证器数量 | not_executable；不是可独立排名的扫描器 | [CC-BY-SA-4.0 文件](https://github.com/mazen160/secrets-patterns-db/blob/master/LICENSE.md)；README 标注冲突，部分数据 AGPL |

最终安装记录为 19 个 available、1 个 build_failed（Deepfence）、1 个 external_service_required（ggshield）、1 个 not_executable（规则数据库）。追加恢复证据保存在 [安装 delta](../bench/tools/manifest.pending.json)，实际 benchmark 配置以合并后的 [manifest](../bench/tools/manifest.json) 为准。19 个可运行竞品加本项目共 20 个可执行比较对象，但每种输入模式各自受命令和输出位置能力限制。没有运行的项目不记作零准确率或无限耗时，不由其安装失败推断产品缺陷。

### 许可证与复用边界

许可列核对的是官方 LICENSE 或本机官方发行包/checkout 的许可正文；它不是依赖树和所有规则资产的完整许可审计。本地链接保留了实际核查的文本，远程链接可能随上游更新。

- 本仓库没有把这 22 个 scanner 作为 SDK 依赖或复制其扫描实现。benchmark 中作为独立进程运行竞品，与把其代码/库嵌入产品是不同的复用方式；若后续分发竞品二进制，需要单独保留相应许可和归属资料。
- 当前导入的是固定 Gitleaks 版本的 **MIT 规则数据**，不是其引擎；[THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES) 保留许可，来源和转换列在 [RULE_SOURCES.md](RULE_SOURCES.md)。把规则转成 JSON 或 Rust 不改变其来源，也不能据此把整份规则集称为原创。
- 主项目 MIT/Apache/BSD 标识不自动覆盖它依赖、捆绑或转入的其他项目内容。尤其 TruffleHog 的 AGPL 代码/规则，不应仅因其他项目收集过就按 MIT 数据导入；本项目未导入 TruffleHog 规则。具体复用需对所取文件及用途核对条款。
- Secrets Patterns DB 的 [LICENSE.md](https://github.com/mazen160/secrets-patterns-db/blob/master/LICENSE.md) 是 CC-BY-SA-4.0；[README](https://github.com/mazen160/secrets-patterns-db#license) 却称 CC-BY-4.0，并另列 TruffleHog 数据为 AGPL。这里保留冲突，不擅自选较宽松标注。本项目没有导入它。
- ggshield 的 MIT 范围是 CLI 代码，不能由此推导 GitGuardian 云检测服务的使用权、免费额度或服务端源码许可。KeyHog 的 `MIT OR Apache-2.0` 为二选一，不是两份许可同时强制。

## 比较解释

- 输入覆盖、规则覆盖、检测准确率、在线验证、治理和接口是不同维度。自研内核加规则数据不能自动继承上游扫描器的解码、抑制、连接器或验证能力。
- 默认 CLI benchmark 包含启动、规则编译、I/O 和序列化，不等于 regex 内核吞吐。常驻 API 的成本需要单独测量。
- 合成语料 P/R/F1 仅说明该标注集；公开无标注源码不能给出准确率。离线测试不能得出在线活性判断质量。
- 本轮没有实现云连接器、provider 活性验证/权限分析/撤销、GPU、ML/BPE、AST/跨文件数据流、C ABI、Python 绑定或 LSP。
