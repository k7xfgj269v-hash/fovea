# Fovea

面向 Linux 的 AI 原生系统内省与控制基础设施。

[![CI](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml/badge.svg)](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

Fovea 是运行在 Linux 之上的特权服务，为 AI operator 提供机器级系统接口。
它把海量内核与进程状态投影成有界、结构化、带置信度的数据，同时把可信控制面
与 guest 执行面隔离开。

## 当前状态

- D1 仓库许可与 BPF 许可声明门：已落地。
- M0 可执行 QEMU/KVM 宿主 harness：已落地。
- M1 只读 `introspect(pid)` Level 0 与 D7 功能验收：已落地。
- D5 Linux 默认 blazesym worker 接线与 wchan/栈顶双路校验：已落地。
  原始 Kallsyms 只作为显式、会写入置信度证据的降级路径保留。
- Linux fixture 已直接捕获 `R/S/D/Z/T/t/I`；仅内核可稳定制造或极短暂的
  `P/X` 仍明确标记为单字节派生，不冒充严格真机捕获。
- fixture 还覆盖 procfs 非 UTF-8、maps 降级、cgroup 变体、置信度、
  token 估算与实际快照跨度。
- CI 已包含 Ubuntu live `/proc`、D5 内核符号验收与 macOS 可移植门。
- D6 MCP 与 `/dev/kmsg`、D3 M6a 只读观测探针、D4 两档快照：待完成。
- Linux x86_64 KVM 主机上的 M0 物理验收：待完成。
- 内核写能力与 eBPF 干预能力：尚未暴露。

项目仍在开发中。当前实现是读侧基础设施，不是完整操作系统，也不是生产可用的
daemon。

## 目标

- 把进程和内核状态投影成紧凑、类型化、带置信度的数据。
- 将 host supervisor 与 guest agent 放在 VM 信任边界的两侧。
- 让副作用显式、可审计、可门控，并在可能时支持回滚。
- 在安全与审计层就位之前，不开放写能力。

Fovea 不是：

- Linux 的替代内核；
- 新的调度器、文件系统或设备驱动栈；
- 不受限制的 ring-0 接口；
- “可以无不确定性地观察全部内核状态”的承诺。

## 架构

```text
                         可信 host
                    +---------------------+
AI / MCP ingress -->| host-supervisor     |
                    | 审计 + 门控策略     |
                    +----------+----------+
                               |
                          typed vsock
                               |
                    +----------v----------+
                    | guest-agent        |
                    | procfs + 投影       |
                    | 符号化              |
                    +---------------------+
                         不可信 guest
```

workspace 由四个 crate 组成：

| Crate | 职责 |
|---|---|
| `introspect-schema` | 跨边界 `Level0`/`Level1` 数据合同。 |
| `vsock` | host/guest typed message、transport trait 与协议校验。 |
| `guest-agent` | Linux `/proc` adapter、Level 0 投影与符号化端口。 |
| `host-supervisor` | 可信侧审计 sink、人工门与控制面策略。 |

依赖方向：

```text
vsock            -> introspect-schema
guest-agent      -> introspect-schema
host-supervisor  -> vsock -> introspect-schema
```

guest agent 不引用 host supervisor。跨边界合同只有
`introspect-schema` 这一份。

## 仓库结构

```text
.
├── crates/
│   ├── introspect-schema/
│   ├── vsock/
│   ├── guest-agent/
│   └── host-supervisor/
├── docs/
│   ├── DESIGN.md
│   └── M0.md
├── scripts/m0/
├── Cargo.toml
├── Cargo.lock
└── rust-toolchain.toml
```

## 快速开始

基础要求：

- Rust stable，版本由 `rust-toolchain.toml` 选择。
- Python 3，用于 M0 合同测试与 Linux live procfs fixture。
- 物理 M0 验收需要 Linux x86_64、QEMU/KVM、GNU GDB 和明确提供的 guest artifact。

构建并测试 workspace：

```bash
cargo check --locked --all-targets --all-features
cargo test --locked --all
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
```

macOS job 用于验证可移植代码路径。Linux-only 的 `/proc`、QEMU、KVM 与符号化
路径由 Ubuntu CI 或真实 Linux 主机验证。

## M1 验收

D7 验收的目标是让“换一个常数”和“静默吞掉降级”无法通过。每份 fixture
都会记录它是 Linux 直接捕获、外部捕获还是明确派生；任何降级都必须出现在
`confidence.low_fields` 中。

`scripts/fixtures/capture-proc-states.c` 可复现 `R/S/D/Z/T/t/I` 的直接捕获。
`P` 需要 parked 内核线程，`X` 是退出阶段竞态，因此当前 parser fixture
明确标记为派生，不把它们伪装成真机 dump。

运行可移植的 parser 与 Level 0 合同：

```bash
cargo test --locked -p guest-agent --test d7_proc_view
cargo test --locked -p guest-agent --test d7_proc_source
cargo test --locked -p guest-agent --test d7_level0
```

在 Linux 上运行非 UTF-8 与全数字 `/proc` PID 真机门：

```bash
cargo test --locked -p guest-agent --test d7_linux_live -- \
  --ignored --nocapture --test-threads=1
```

全 PID 扫描只允许进程正常退出和权限不足；任何 parse failure 或其他错误类别
都会使验收失败。

在内核地址可见的 Linux 环境运行 D5 真机符号化门：

```bash
sudo sysctl -w kernel.kptr_restrict=0
cargo test --locked -p guest-agent --test d5_symbolization -- \
  --ignored --nocapture --test-threads=1
```

D5 gate 要求 `/proc/kallsyms` 至少提供两个不同的非零地址和两个不同的归一化
名字。对每个地址，blazesym 返回的名字必须属于该地址完整的 Kallsyms alias
集合。地址受限或全零属于前置条件失败，不能按跳过算通过。

## M0 Harness

M0 工具是可执行 harness，不会下载或创建 kernel、initrd、disk 或 symbol artifact。

| 工具 | 用途 |
|---|---|
| `scripts/m0/check-host.sh` | 检查 Linux x86_64、KVM、QEMU、路径、端口与资源。 |
| `scripts/m0/run-vm.sh` | 使用明确提供的输入启动 QEMU/KVM guest，并保留资源锁。 |
| `scripts/m0/qmp-smoke.py` | 执行有序的 QMP `savevm`/`loadvm` 请求。 |
| `scripts/m0/gdb-smoke.sh` | 连接 loopback GDB stub 并检查寄存器。 |
| `scripts/m0/guest-pt-probe.sh` | 在 guest 内探测 Intel PT 可用性。 |

运行合同测试：

```bash
scripts/m0/tests/test-check-host.sh
scripts/m0/tests/test-run-vm.sh
python3 scripts/m0/tests/test-qmp-smoke.py
```

物理验收与完整启动流程见 [`docs/M0.md`](docs/M0.md)。

QMP 与 GDB 都是未认证的控制接口。保持 socket 和端口只绑定 loopback，使用
`0700` 私有 runtime 目录；在收集完快照证据前，不要复用 guest disk。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | 架构、信任边界、合同、安全模型与里程碑。 |
| [`docs/M0.md`](docs/M0.md) | QEMU/KVM harness、前置条件、验收流程与清理规则。 |
| [`README.md`](README.md) | English project overview。 |

## 路线图

1. 在合格的 Linux x86_64 KVM 主机上完成 M0 物理验收。
2. 落地 D6：host-side MCP front、生成式能力文档与只读 `/dev/kmsg` 投影。
3. 落地 D3 M6a：固定模板的只读 eBPF 计数器，并同批交付 registry 与按
   owner flush。
4. 落地 D4：overlay 冷重置与原生 QMP snapshot job。
5. 用真实 vsock transport 替换 mock transport，打通 guest 端到端路径。
6. 审计与安全层就位后，再考虑 M7 干预、文件系统事务和参数化 LKM 原语。

## 当前限制

- Linux `introspect(pid)` 默认启动 blazesym worker。worker 初始化、单地址
  查询和关闭失败都会显式降级或写入 `confidence.low_fields`，不会静默吞掉。
- D5 的 debuginfod、build-ID 缓存、stripped binary 恢复与 JIT 符号仍属于
  后续优化。
- D6 MCP/内核日志投影、D3 M6a 探针和 D4 快照改造尚未实现。
- M0 脚本只是工具链证据，不等于物理 KVM 验收。
- Apple Silicon 和 CI 不等价于真实 Linux x86_64 KVM 主机。
- 写侧语义污染仍是开放设计风险。

## 贡献

保持改动与当前里程碑一致，并维护 host/guest 信任边界。提交前运行：

```bash
cargo fmt --all --check
cargo test --locked --all
cargo clippy --locked --all-targets --all-features -- -D warnings
```

涉及 Linux-only 行为的改动还应检查：

```bash
cargo check --locked --all-targets --all-features \
  --target x86_64-unknown-linux-gnu
```

## License

Fovea 使用 MIT License，见 [`LICENSE`](LICENSE)。BPF 源文件按仓库约定使用
Linux helper 兼容所需的 MIT/GPL 双许可声明。
