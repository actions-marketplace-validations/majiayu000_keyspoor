# Keyspoor

**面向 AI 编程工作流的离线密钥扫描器。**
支持文件、Git 暂存区、本地 Git 历史和 ZIP/tar/gzip 归档，输出默认脱敏的
JSON、JSONL 或 SARIF。既可作为原生 CLI 使用，也提供 Rust 库和只读 MCP 服务。
Agent 通过 MCP 调用扫描；Git hook 或必需的 CI 检查负责拦截提交或合并。

[English](README.md) · [官网](https://majiayu000.github.io/keyspoor/) ·
[Rust API](https://docs.rs/keyspoor) · [crates.io](https://crates.io/crates/keyspoor) ·
[npm](https://www.npmjs.com/package/keyspoor) ·
[发行版本](https://github.com/majiayu000/keyspoor/releases)

## 60 秒体验

需要 Node.js 20+。在 macOS/Linux 终端复制执行，下面的值是专为演示编造的，
不是真实凭据：

```sh
printf 'password=KspDemo_7zQ2mX9pL4vN6sR8\n' | npx -y keyspoor@0.1.3 scan - --format json
echo "exit=$?"
```

预期：退出码 `1`，一个发现。报告中的关键字段如下：

```json
{"complete":true,"findings":[{"rule_id":"generic-credential-unquoted","path":"stdin","line":1,"column":9,"redacted":"[REDACTED]"}],"errors":[]}
```

这里只展示字段节选，完整报告还有位置范围、指纹、统计和扫描上下文；
报告不会包含原值或源码片段。Windows PowerShell 可把同一个合成字符串传给
`npx.cmd -y keyspoor@0.1.3 scan - --format json`，用 `$LASTEXITCODE` 查看退出码。

### 完整演示：检出 → 拦截提交 → 修复 → 通过

![Keyspoor 检出合成凭据、拦截提交，并在修复后允许提交](site/first-scan.gif)

安装 Git 和 `keyspoor` CLI 后，在项目检出目录执行：

```sh
sh examples/first-scan.sh
```

脚本只操作自己的临时仓库，结束后删除。动画来自实际 0.1.3 运行，输入为编造的样例：
扫描退出码 `1`、提交被阻止；移除明文后退出码 `0`、提交成功。
这是 Git hook 演示。MCP 提供工具，不保证 Agent 每次提交前都会调用；
需要强制拦截时使用 [CI 或 hook](docs/CI_SETUP.md)。

| 你的目标 | 接入入口 |
| --- | --- |
| 扫描仓库、暂存区或历史 | [CLI 使用](#安装与-cli-使用) |
| 检查 PR 并保存报告 | [CI 完整指南](docs/CI_SETUP.md) · [可复制工作流](examples/github-actions/keyspoor.yml) |
| 给编程助手接入扫描工具 | [Codex、Claude Code、Cursor 配置](docs/AGENT_SETUP.md) |
| 在 Rust 中复用引擎 | [库示例](README.md#library-and-custom-rules) · [Rust API](https://docs.rs/keyspoor) |

## 安装与 CLI 使用

```sh
# Rust 1.96 或更新版本
cargo install keyspoor --version 0.1.3 --locked

# 或通过 Node.js 20+ 安装原生 Rust CLI
npm install -g keyspoor@0.1.3

# 或通过 Homebrew（macOS / Linux）
brew install majiayu000/tap/keyspoor

keyspoor scan . --format jsonl
keyspoor staged /path/to/repository
keyspoor history /path/to/repository --range main..HEAD
keyspoor scan . --format sarif
keyspoor mcp --root /path/to/project
```

当前版本为 **0.1.3**，Rust API 仍可能发生破坏性变更。npm 包内置 macOS
Apple Silicon/Intel、Linux GNU ARM64/x64、Windows x64 的原生二进制，
没有安装脚本或运行时二进制下载；它是 CLI 启动器，不是 JavaScript SDK。
首次 npm/npx 安装需要访问 registry，扫描过程离线。
也可从 [GitHub Releases](https://github.com/majiayu000/keyspoor/releases)
下载独立二进制，或通过 `cargo build --release --locked` 编译，执行
`target/release/keyspoor`。

退出码：`0` 表示完整扫描且没有报告命中，`1` 表示完整扫描且有命中，
`2` 表示错误或扫描未完成。可以再验证两个结果：

```sh
printf 'ordinary configuration\n' | npx -y keyspoor@0.1.3 scan - --format json
echo "exit=$?" # 0：complete=true，findings=[]
printf 'ordinary configuration\n' | npx -y keyspoor@0.1.3 scan - --max-bytes 4 --format json
echo "exit=$?" # 2：complete=false，errors 含 input exceeds 4 byte limit
```

发现问题后，根据路径和位置在本地检查文件，删除跟踪文件中的凭据；
真实凭据已暴露时应轮换。只有审查已知发现后才记录基线。
退出码 `2` 必须排查，不能当作检查通过。忽略项和基线会影响报告结果，
不能据此断言输入中没有密钥。

## 主要能力与边界

| 方向 | 已实现能力 | 边界 |
| --- | --- | --- |
| 检测 | 225 条默认规则、自定义 JSON 规则、熵和占位符过滤 | 221 条规则适配自 Gitleaks v8.30.1，4 条独立编写；不是全部规则原创 |
| Rust 库 | `Engine::scan_bytes`，规则编译后复用，可跨线程共享 | 使用通用 regex/Aho–Corasick 等依赖，不依赖其他密钥扫描 SDK |
| Git | 扫描暂存区 index 内容、本地可达历史，去重读取 blob | 不拉取远程、LFS 或子模块；不是只扫描新增行 |
| 编码与归档 | BOM UTF-16、单层 Base64；ZIP/tar/gzip 最多四层 | 限制展开预算，不将归档成员写入磁盘；不是文档语义解析器 |
| Agent | JSON/JSONL/SARIF、常驻 `serve`、MCP `scan_text` / `scan_paths` | MCP 支持进度和取消，结果预览有限额；不是完整 Agent 平台 |
| 报告与基线 | 默认脱敏、字节位置、指纹、解释、新增发现筛选 | 普通指纹不是加密；可使用私有 key 的 BLAKE3；不回显原始密钥或源码片段 |

扫描完全离线，不检查凭据是否有效，不执行撤销。云连接器、GPU/ML、跨函数分析、
Python/JS 进程内绑定未实现。完整范围见 [功能矩阵](docs/FEATURES.md)、
[规则来源](docs/RULE_SOURCES.md) 和 [英文使用说明](README.md)。

## GitHub Action 与自动发布

将 [完整工作流](examples/github-actions/keyspoor.yml) 复制到
`.github/workflows/keyspoor.yml`，再按 [CI 指南](docs/CI_SETUP.md) 配置报告和
必需检查。核心扫描步骤如下：

```yaml
- uses: majiayu000/keyspoor@v1
  id: secrets
  with:
    path: .
    format: sarif
```

默认生成 SARIF，也支持 JSON/JSONL。`report-path` 输出指向 runner 临时目录中的
脱敏报告；`exit-code` 保留 0/1/2 语义，发现密钥或扫描出错会让该步骤失败。
保存报告时用 `if: always()`；完整示例见 [英文说明](README.md#github-action)。
需要固定不可变版本时使用完整 commit SHA。安装会访问 npm，检测本身离线。

MCP 暴露只读工具，是否调用取决于客户端、权限和任务，不能保证每次提交都会扫描。
需要强制检查时，配置必需 CI 检查或 Git hook。

完整版本标签触发五平台构建和质量检查，再通过 OIDC 自动发布 npm、crates.io
及 GitHub Release。现有 Homebrew tap 每小时检查新版本，安装测试通过后自动更新；
GitHub 调度可能延迟。详见 [发布流程](docs/RELEASING.md)。

## Benchmark 与证据

[v6 报告](bench/results/v6/README.md) 在 Apple M2 Max/macOS 上采用 20 对交替运行。
单文件 10 万条合成命中的 JSONL 场景，扫描进程峰值 RSS 从 99.86 降至 59.59 MiB，
CPU 时间降低 8.74%；普通吞吐与 Git 场景基本持平。这是本项目两版之间的优化，
不是对所有竞品的性能排名。

已观察过的合成回归集保持 600 TP / 25 FP / 0 FN；不能据此推导真实项目准确率。
[竞品比较](bench/results/v4/quality-comparison.md)、[复现方法](bench/README.md) 和
[测量记录](docs/RESULTS.md) 保留版本、参数、硬件和不支持的场景。
旧记录中的 `secret-scan` 是更名前的项目名称，原始命令和二进制哈希未改写。

## 许可证与反馈

项目使用 [Apache-2.0](LICENSE)，导入的规则数据保留 MIT 许可与
[第三方归属声明](THIRD_PARTY_NOTICES)。
请在 [GitHub Issues](https://github.com/majiayu000/keyspoor/issues) 提交可复现的问题；
示例使用合成内容，不要附带真实凭据。
