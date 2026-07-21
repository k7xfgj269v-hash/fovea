# Fovea

[English](README.md) · **中文**

[![CI](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml/badge.svg)](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml)

**Foveate the kernel** —— 名字取自视网膜中央凹（fovea）：视野巨大、带宽有限，于是眼睛只在你正注视的那一点高清、其余低清，靠扫视移动焦点。这正是本项目对海量内核状态所做的——`introspect(pid)` 不倾倒一切，只把「此刻该看的」投影给 AI。

> 把一台 Unix 机器改造成 AI 的「玻璃盒」——人照常用 shell，额外给 AI 一层能全内省、可操作内核的系统接口面。
>
> **状态**：设计收敛、骨架启动、M1 第一/第二刀已落。完整设计见 [`docs/DESIGN.md`](docs/DESIGN.md)。

## 这是什么

一个坐在 Unix 之上的特权 daemon（不是新内核，不是厚运行时框架），给 AI operator 暴露一套 **为 token 而非人眼设计** 的系统接口：

- **全内省**：看穿每个进程的线程/内存/fd/调用栈，粒度到运行时的函数（透到运行时边界，不是看穿一切）。
- **操作内核**：从 eBPF 安全干预，到受控的 LKM 无限改写。
- **安全信封**：让一个会幻觉的操作者安全地拥有 ring0——危险能力关在 eBPF verifier + 宿主侧人审门之后。

最接近的现成参照：**整机级、系统化的 MCP**。

## 为什么 — 真正新的是这两件事

不是「内核内省」（那是已知硬骨头、不 AI 特有）。真正新、真正难的是：

1. **上下文虚拟化 / 投影**：内核状态海量（进程内存 GB 级、ftrace 几百万条、kcore 是整个内核内存），AI 上下文装不下。难点不是抓数据，是喂之前「此刻该看什么」。这是全篇皇冠明珠，落在 [`introspect(pid)`](crates/introspect-schema/src/lib.rs) 上逼到可解小面：一个 pid 的「什么进 Level 0、什么藏 handle 后」就是投影策略的最小实例。
2. **怎么安全共享一台真机**：人 + AI 共用同一台真机、AI 手握 kcore + 内核写能力，逼出信任边界 / 仲裁 / 透明性 / 审计一整套。信任边界物理落地为 VM 边界 = 宿主/靶机边界。

完整公理与推演见 [`docs/DESIGN.md`](docs/DESIGN.md) §14。

## 仓库结构

**信任边界物理落地**——四 crate 分工、依赖图无环：

```
fovea/
├── Cargo.toml                       # workspace 根，依赖经 workspace.dependencies 集中
├── crates/
│   ├── introspect-schema/           # 跨 vsock 信任边界的合同：Level0/Level1 字段（§10/§13.4）
│   ├── vsock/                        # 宿主↔靶机控制通道抽象：Transport trait + MockTransport
│   ├── guest-agent/                 # 靶机侧（不可信数据面）：introspect 引擎 + proc_view + symbolize
│   └── host-supervisor/             # 宿主侧（可信控制面）：AuditSink + HumanGate trait
└── docs/
    └── DESIGN.md                    # 完整设计文档（架构/接口/难题/实现蓝图）
```

依赖方向（`A → B` = A 依赖 B，无环；`introspect-schema` 是唯一叶子）：

```
vsock            → introspect-schema
guest-agent      → introspect-schema
host-supervisor  → vsock → introspect-schema
```

guest-agent 与 host-supervisor 互不引用——跨边界契约只由 `introspect-schema` crate 锁死，不靠 crate 互引。

### 各 crate 当前定位

| crate | 角色 | 已落成 |
|---|---|---|
| **introspect-schema** | 跨边界合同，零运行时依赖 | Level0 全 9 字段（identity/state/resource/mem_shape/hotspot/recent/confidence/handles/cost_hint）字段级；§10 三断言钉死（per-frame 置信度、wchan 进 Level0、cost_hint §12 形状 `{token, api_cost?, overhead_est}`）；Level1 `view` enum 提前占位 |
| **vsock** | 信任边界的物理实现 | `Transport` trait + `MockTransport`；`Message`/`Request`/`Response`/`AuditEvent`/`ErrorReport` 形状；§13.6 单向 append-only、§13.8 副作用五档路由（`read`/`dry-runnable-write`/`intervention`/`kernel-write`/`irreversible`） |
| **guest-agent** | 靶机侧不可信数据面 | `introspect::engine::introspect` 已从 stub 转为真实现：`/proc` 解析（stat/status/maps/wchan/fd/stack）→ 组装 `Level0`；`proc_view` 6 个纯解析函数；`symbolize` trait + `FallbackSymbolizer`（非 Linux 诚实返 `NotFound`，**M1 引擎实际用的是它**）+ `BlazeSymbolizer`（Linux-only blazesym 接入**骨架**，尚未 wire 进 `introspect`、Mac 上 cfg-out 故未本地验证）；`ProcError` serde 内部标签加固 + 回归测试钉住 |
| **host-supervisor** | 宿主侧可信控制面 | `AuditSink` trait + `InMemoryAuditSink`（单测绿）；`HumanGate` trait + `GateDecision` + `LkmParamGate`（占位 `Allow`）；trait 位置在位，值待 M5 纳真 |

## 里程碑（M0–M9）

安全脚手架先于写能力——见 [`docs/DESIGN.md`](docs/DESIGN.md) §13.9。

| 里程碑 | 做什么 | 证明了什么 | 状态 |
|---|---|---|---|
| **M0** | VM harness：宿主+靶机、vsock、savevm/loadvm、gdb stub | 基座能跑、能秒回滚、能调内核 | ⬜ 未动 |
| **M1** | 只读 `introspect(pid)` Level 0：/proc + blazesym，零探针 | 投影成立（GB maps → 十几行） | ✅ 形态全长齐 |
| **M2** | MCP front：introspect 包成 MCP tool + 自描述目录 | 能力面形态成立 | ⬜ |
| **M3** | introspect Level 1 views + cost_hint + 置信度 | 投影/分页/成本可调度 | ⬜ |
| **M4** | 飞行记录仪：常驻 ring buffer，极低扰动 | 瞬态事件抓得到 | ⬜ |
| **M5** | **宿主侧审计 sink + 仲裁器（人优先 + flush 拆除）+ 干预门 hook** | **安全脚手架（含事前门）——在任何写能力之前** | 🟡 trait 全在位 |
| **M6** | eBPF 观测通道：按需挂探针 + 效果审计 | 读侧完整 | ⬜ |
| **M7** | eBPF 干预通道（override/丢包）+ 被动可发现 | 第一个写能力，verifier 兜底 | ⬜ |
| **M8** | fs 事务：dry-run diff + 定点回滚 | fs 写可预览可撤 | ⬜ |
| **M9** | LKM 参数化原语模块 + 人审门 | 最后、最危险、参数化 | ⬜ |

## 关键的诚实

**M1 已落的是「形态」**——纯函数解析层 + 引擎组装在 Mac 单测里跑通，真 `/proc` I/O cfg-gate 到 Linux 才编；blazesym 的真内核态路径（`vmlinux`/`kallsyms` 路径配置）仍标 `TODO(M0)`，等 VM 基座搭起来一次性补。

本地**无 Rust 工具链**，以上均为静态审读、未经 `cargo check`/`cargo test`。**CI（GitHub Actions, ubuntu）现在提供第一次真实编译**——包括 Mac 上永远 cfg-out、从没编过的 `#[cfg(target_os = "linux")]` 路径（`BlazeSymbolizer`、真 `/proc` I/O）。看上方徽章。

> ⚠️ **CI 现在是红的——预期之内。** 首次 Linux 编译逐出 40 个错，全在 WIP 的 `BlazeSymbolizer` 后端：blazesym 0.2.5 的 `Symbolizer` 是 `!Send + !Sync`（内部 `RefCell`/`Rc`），与本项目 `Symbolizer: Send + Sync` trait 冲突；外加一处 API 路径搬家（`Source`）和下方的 `ctxt_switches` 字段债务。M1 实际用的 `FallbackSymbolizer` 路径不受影响。blazesym 后端在 M0 接入——在那之前徽章保持红色。

**已知缺口（本轮审出的 M1 债务，M0 端到端前修）**：

- **`resource.ctxt_switches` 取错源**：读的是 `/proc/<pid>/stat` 字段 40/41，而那是 `rt_priority`/`policy`，**不是**上下文切换数——真源在 `/proc/<pid>/status` 的 `voluntary_ctxt_switches:` 行。真 Linux 上会静默给错数；Mac 单测用同构 fixture（把值放进 idx 37/38）恰好测不出。
- **`build_cmdline` 可 panic**：`String::truncate(256)` 落在非 UTF-8 字符边界会 panic；cmdline 是不可信输入，含多字节字符时可触发。
- **`confidence` 只做了一半**：实现了 §11 ①（wchan/顶帧交叉验证），未实现 ②（每帧符号化失败入 `low_fields`）。M1 用 Fallback 时每帧都符号化失败，`overall` 却报 1.0——与公理 11「告诉你它有多不确定」相悖。

> 讽刺点：这三条都是「读侧静默污染」（§11）——引擎自己先踩了它要防的坑。均不阻塞编译，M0 前修。

## 怎么跑

需要 Rust stable 工具链（edition 2021）。固定版本见 [`rust-toolchain.toml`](rust-toolchain.toml)。

```bash
cargo check --all-targets    # 编译全部 4 crate（含 bin stub）
cargo test                   # 跑单测（schema + vsock + guest-agent + host-supervisor）
cargo run -p guest-agent     # bin stub，当前无 daemon 逻辑
cargo run -p host-supervisor # bin stub，当前无 listener
```

> 非 Linux（含 Mac）上 `introspect()` cfg-gate 直接返 `NotImplemented`，不真读 `/proc`；纯函数形态由 `introspect_with_inputs` 在单测里盯住——这是「cfg-gate 到 Linux，但 Level0 组装形态在 Mac 单测」这一刀的实现。

## 怎么读

- **快速对齐**：`docs/DESIGN.md` §1（定位）、§2（心理模型、稀缺资源翻转表）、§14（公理）。
- **要动手**：§10（`introspect(pid)` 原语 + 钉死三断言）、§13（实现蓝图）、§13.9（里程碑）。
- **关心风险**：§8（信任/仲裁/透明性/三件套）、§9（回滚分层）、§11（静默污染读写两侧）。
- **本仓库代码契合点**：
  - 「皇冠明珠第一刀」 = [`crates/introspect-schema/src/lib.rs`](crates/introspect-schema/src/lib.rs) 的 `MemShape` 段（GB maps → 十几行的投影本体）
  - 信任边界两半物理实现 = [`crates/guest-agent/`](crates/guest-agent/) ↔ [`crates/host-supervisor/`](crates/host-supervisor/)、走 [`crates/vsock/`](crates/vsock/)
  - 公理 13「脚手架先于写能力」M1 最小实例 = [`crates/host-supervisor/src/audit.rs`](crates/host-supervisor/src/audit.rs) 的 `AuditSink` 在 M1 就 trait 在位
  - §10 三断言的代码归宿 = [`crates/guest-agent/src/introspect.rs`](crates/guest-agent/src/introspect.rs)（每次带 `cost_hint`、wchan 进 Level0、每帧 `SymbolConfidence`）

## 下一步

按 `docs/DESIGN.md` §15 留的路径（**0 号插队**：先清上面 3 条 M1 债务，尤其 `ctxt_switches`——M0 一上真 Linux 就冒静默错数）：

1. **M0 VM 基座**：QEMU/KVM + virtio-vsock + savevm/loadvm + gdb stub；之后 `vsock` 的真 `Transport` 实现就位，替掉 `MockTransport`，blazesym 的真内核态路径（`vmlinux`/`kallsyms`）一次性配置，`introspect` 在靶机内端到端跑通。
2. **M2 MCP front**：把 `introspect` 包成 MCP tool + 自描述目录（§13.8 副作用等级一等字段）。
3. **M5 纳真**：append-only 文件 sink + 真人审门 + 事前干预 hook（M7 伸手前栅栏先在位）——公理 13 的全落地。

> 顺序铁律（§13.9 / 公理 13）：**先造牢笼——含事前那道栅栏——AI 才被允许伸手。别让任何写能力 predate 它的容器。**
