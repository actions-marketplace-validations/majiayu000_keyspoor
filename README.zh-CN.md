# Keyspoor

**面向 Rust 应用、CI 和 AI 编程 Agent 的离线密钥扫描器。**
支持文件、Git 暂存区、本地 Git 历史和 ZIP/tar/gzip 归档，输出默认脱敏的
JSON、JSONL 或 SARIF。既可作为原生 CLI 使用，也提供 Rust 库和只读 MCP 服务。

[English](README.md) · [官网](https://majiayu000.github.io/keyspoor/) ·
[Rust API](https://docs.rs/keyspoor) · [crates.io](https://crates.io/crates/keyspoor) ·
[npm 安装包](npm/README.md) ·
[发行版本](https://github.com/majiayu000/keyspoor/releases)

## 安装与使用

```sh
# Rust 1.96 或更新版本
cargo install keyspoor --locked

# 或通过 Node.js 20+ 安装原生 Rust CLI
npm install -g https://github.com/majiayu000/keyspoor/releases/download/v0.1.1/keyspoor-0.1.1.tgz

keyspoor scan . --format jsonl
keyspoor staged /path/to/repository
keyspoor history /path/to/repository --range main..HEAD
keyspoor scan . --format sarif
keyspoor mcp --root /path/to/project
```

npm tarball 通过 GitHub Releases 提供；npm registry 上传仍待发布账号登录。

当前版本为 **0.1.1**，Rust API 仍可能发生破坏性变更。npm 包内置 macOS
Apple Silicon/Intel、Linux GNU ARM64/x64、Windows x64 的原生二进制，
没有安装脚本或运行时二进制下载；它是 CLI 启动器，不是 JavaScript SDK。
也可从 [GitHub Releases](https://github.com/majiayu000/keyspoor/releases)
下载独立二进制，或通过 `cargo build --release --locked` 编译，执行
`target/release/keyspoor`。

退出码：`0` 表示完整扫描且没有报告命中，`1` 表示完整扫描且有命中，
`2` 表示错误或扫描未完成。忽略项和基线会影响报告结果，不能据此断言输入中没有密钥。

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
