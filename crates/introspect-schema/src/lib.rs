//! `introspect(pid)` 返回结构（§10 / §13.4）。
//!
//! 这层是 **跨 vsock 信任边界的合同**：guest-agent 在靶机侧填它、
//! 经 vsock ship 给 host-supervisor 的 Response::Ok，host-supervisor 读它。
//! 所以 schema 早一天锁死，跨边界少一天漂移——独立成包的原因（§13.1
//! 「内部强类型，出口 JSON」）。
//!
//! **皇冠明珠第一刀**（§1.3）：一个 pid 的「什么进 Level 0、什么藏 handle 后」
//! 就是上下文虚拟化投影策略的最小实例。GB 级 maps 直方图压成十几行——
//! 投影本体就在 [`MemShape`]，别把原始 maps 往 AI 送。
//!
//! ```text
//! Level0
//!  ├─ identity    pid/comm/exe/cmdline(截断)/uid/cgroup
//!  ├─ state       R|S|D|Z, last_cpu, nr_threads, wchan(符号化)
//!  ├─ resource    RSS/VSZ, fd 数, %cpu(短采样), ctxt-switch
//!  ├─ mem_shape   区段直方图 + top-N 大映射        ← 投影本体
//!  ├─ hotspot     D 态时内核栈顶 3-5 帧(每帧带置信度)
//!  ├─ recent      复用常驻飞行记录仪的事件聚合      ← 零新增探针
//!  ├─ confidence  本次快照整体可信度摘要(§11)
//!  ├─ handles     不透明游标 {threads,maps,stack,fds,env,symbols}
//!  └─ cost_hint   {token, api_cost?, overhead_est}  ← §12 已定形状
//! ```

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ════════════════════════════════════════════════════════════════════════════
// Level 0：恒定小体积，纯快照，零探针（§10）
// ════════════════════════════════════════════════════════════════════════════

/// §10 Level 0 —— introspect 一次返回的全部东西。
///
/// 「恒定小体积、纯快照、零探针」是 §10 标题三词：体积恒定 (无论目标 GB 级 maps
/// 都压成 mem_shape 的十几行)；快照 (顺序读取多个 `/proc` 文件形成的有界观察窗口，
/// 不是原子读)；零探针 (本次不新增探针、不 ptrace，纯读 `/proc`，见 §13.4 注释)。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Level0 {
    pub identity: Identity,
    pub state: ProcState,
    pub resource: Resource,
    pub mem_shape: MemShape,
    pub hotspot: Hotspot,
    /// `recent` 是§10 唯一「不是纯读 /proc」的字段——它复用常驻飞行记录仪
    /// 的数据。常驻记录仪自身是系统级探针、不是本调用引入的，所以「本调用
    /// 增量扰动为零」依然成立（§10「零探针」精确含义）。
    pub recent: RecentEvents,
    pub confidence: ConfidenceSummary,
    /// 不透明游标：按需展开成 Level 1 个别 view。AI 不需要时这些数据不进
    /// 上下文，正是上下文虚拟化的「投影」面。
    pub handles: Handles,
    pub cost_hint: CostHint,
}

// ─── identity ────────────────────────────────────────────────────────────────

/// §10 `identity` —— 进程身份。基本不投影，全进。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub pid: i32,
    /// `/proc/<pid>/comm`，受限 15 字符。
    pub comm: String,
    /// `/proc/<pid>/exe` 的符号链接目标。可能为空（zombie / kernel thread）。
    pub exe: Option<String>,
    /// `/proc/<pid>/cmdline`——以 `\0` 分隔，解开后**截断**成有限长度。
    /// 不投影（identity 是 KV 不是大块）但截断是必须的：cmdline 可以很长很怪。
    pub cmdline: Cmdline,
    pub uid: u32,
    /// cgroup 路径——给 "这个进程在什么容器/层级里" 的语义。
    pub cgroup: Option<String>,
}

/// cmdline 的截断策略：原始全长 + 投影给 AI 的截短副本。
///
/// AI 默认看截短的；想看全的就 introspect Level 1 view=cmdline。
/// 这是 §10 「藏 handle 后」的最简单一例。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cmdline {
    /// 截断到 N 字符（M1 取 256）的版本——这是 Level 0 默认看的。
    pub short: String,
    /// 原始全长。Level 0 默认**不**送 AI（防止超长 injecting 攻上下文），
    /// 仅记录长度。展开走 view=cmdline。
    pub full_len: usize,
}

// ─── state ────────────────────────────────────────────────────────────────────

/// §10 `state` —— 调度状态 + wchan。
///
/// `wchan` 是§10「单位 token 语义密度最高」的字段——D 态几乎直接答「卡在哪」。
/// 它本身就是符号化过的 kernel 函数名（如 `futex_wait_queue_me`），不是裸地址。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcState {
    /// 对应 `/proc/<pid>/stat` 的单字符 state 字段。已知内核状态强类型化，
    /// 新状态保留原字符落到 [`RunState::Unknown`]，避免整次内省失败。
    pub run_state: RunState,
    pub last_cpu: u32,
    pub nr_threads: u32,
    /// §10 wchan——符号化的阻塞点。None = 可运行（R 态）或没阻塞。
    /// 同时是 §11 验证①「双路交叉验证」的对象字段：wchan 符号化结果
    /// vs `/proc/<pid>/stack` 顶帧要自洽；不自洽会反映在 `confidence` 上。
    pub wchan: Option<Symbolized>,
}

/// Linux `/proc/<pid>/stat` 的单字符运行状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Running / Runnable。
    R,
    /// Interruptible sleep（等事件）。
    S,
    /// Disk sleep / uninterruptible——**§10 hotspot 触发条件**。
    D,
    /// Zombie。
    Z,
    /// Stopped (traced / stopped)。
    T,
    /// Tracing stop。
    TracingStop,
    /// Dead。
    X,
    /// Parked。
    P,
    /// Idle kernel thread。
    I,
    /// Forward-compatible fallback for a state unknown to this build.
    Unknown(char),
}

impl RunState {
    pub const fn as_char(self) -> char {
        match self {
            RunState::R => 'R',
            RunState::S => 'S',
            RunState::D => 'D',
            RunState::Z => 'Z',
            RunState::T => 'T',
            RunState::TracingStop => 't',
            RunState::X => 'X',
            RunState::P => 'P',
            RunState::I => 'I',
            RunState::Unknown(state) => state,
        }
    }

    pub const fn from_char(state: char) -> Self {
        match state {
            'R' => RunState::R,
            'S' => RunState::S,
            'D' => RunState::D,
            'Z' => RunState::Z,
            'T' => RunState::T,
            't' => RunState::TracingStop,
            'X' => RunState::X,
            'P' => RunState::P,
            'I' => RunState::I,
            state => RunState::Unknown(state),
        }
    }
}

impl Serialize for RunState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_char(self.as_char())
    }
}

impl<'de> Deserialize<'de> for RunState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        char::deserialize(deserializer).map(RunState::from_char)
    }
}

// ─── resource ───────────────────────────────────────────────────────────────

/// §10 `resource` —— 资源占用四件。
///
/// `%cpu` 是**短采样**（不是累计），这一步本身就添了一点点观察扰动，
/// 所以 cost_hint 的 overhead_est 会反映这点点开销。M1 走 /proc/stat
/// 两次读 + 时间差，不挂 perf probe。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// RSS，字节。
    pub rss_bytes: u64,
    /// VSZ，字节。（/proc/<pid>/stat 的 vsize 字段）
    pub vsz_bytes: u64,
    /// open fd 数（扫 /proc/<pid>/fd/ 计数）。
    pub nr_fds: u32,
    /// 短采样 %cpu（0-100，可能因多线程 >100）。
    pub pct_cpu: f32,
    /// voluntary/nonvoluntary 两个 ctxt-switch 计数。
    pub ctxt_switches: CtxtSwitches,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtxtSwitches {
    pub voluntary: u64,
    pub nonvoluntary: u64,
}

// ─── mem_shape ───────────────────────────────────────────────────────────────

/// §10 `mem_shape`——**皇冠明珠的投影本体**。
///
/// 把 GB 级 `/proc/<pid>/maps` 按段类型聚合成 `{count, total_size}` 直方图，
/// 加 top-N 大映射。绝不把原始 maps 表送 AI——「GB 级 maps → 十几行」就是这一步。
///
/// M1 把 maps 里的每个区段按 §10 列的 `kind` 分类：heap/stack/anon/file/x-lib。
/// 映射规则留到 `guest-agent/proc_view` 实现，schema 这层只定形状。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemShape {
    /// 按 kind 聚合的直方图。const 几种 kind → 永远十几行 = 投影成立。
    pub histogram: Vec<MapKindBucket>,
    /// top-N（M1 取 N=5）大映射。每条带 kind、起止地址、size、可能带 backing 文件名。
    /// 这是「投影剩的渣」——大映射的元信息保留，但完整映射表不送。
    pub top_n: Vec<TopMap>,
}

/// §10 mem_shape 的区段按 kind 分桶。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapKindBucket {
    pub kind: MapKind,
    pub count: u64,
    pub total_size: u64,
}

/// §10 mem_shape 中的 kind 枚举：heap / stack / anon / file / shared-lib。
///
/// `x-lib`（executable-backed shared lib）和 `file`（普通 file-backed 映射）
/// 分开——区分价值在：lib 是「这个进程 link 了哪些库」的语义，普通的 file
/// 映射只是「它 mmap 了哪些数据文件」，混一起掉语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MapKind {
    /// brk 堆。
    Heap,
    /// 主/次栈。
    Stack,
    /// 匿名映射（MAP_ANONYMOUS）。
    Anon,
    /// 普通 file-backed 映射。
    File,
    /// file-backed 但带可执行位（共享库 / dlopen 出来的）。
    XLib,
}

/// §10 mem_shape a top-N 里的一条最大映射。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopMap {
    /// 起始地址（/proc/<pid>/maps 的左边界）。hex 字符串、零填充、按数值排过序。
    pub start: String,
    /// 终止地址。
    pub end: String,
    pub size: u64,
    pub kind: MapKind,
    /// 若 file-backed，producer 按固定 UTF-8 字节上限投影后的路径片段。
    /// schema 只承载结果，不在序列化层执行截断。
    pub backing: Option<String>,
}

// ─── hotspot ─────────────────────────────────────────────────────────────────

/// §10 `hotspot`——D 态时给内核栈顶 3-5 帧（符号化 + 每帧置信度）。
///
/// 只有 D 态才有；非 D 态 [`Hotspot::NotBlocked`]，省回溯成本。
/// 这是 §10 「为什么卡」压进 5 个符号——把"卡在哪"投影成 5 行结构化帧，
/// 而不是吐完整 kernel stack。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Hotspot {
    /// 非 D 态，不需要 hotspot。空结构表明「没触发」。
    NotBlocked,
    /// D 态：给 §10 内核栈顶 3-5 帧，每帧带置信度。
    Blocked { frames: Vec<StackFrame> },
}

/// §10 hotspot 单帧 + §11 每帧置信度。
///
/// `symbol` 是符号化结果（函数名+offset），可能为 None（符号化失败但地址能读出）。
/// `confidence` 落到 §11 「DWARF 命中 / kallsyms 命中 / 动态符号 / 反汇编恢复」分级。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// 帧序号（0 = 顶帧，最深的最近调用；和 /proc/<pid>/stack 顺序一致）。
    pub idx: u32,
    /// 原始 PC 地址（hex 字符串，零填充）。
    pub addr: String,
    /// 符号化结果（函数名 + offset）。None = 符号化失败。
    pub symbol: Option<Symbolized>,
    /// 单帧置信度。None = 没尝试符号化（一般是 anonymous frame）。
    pub confidence: Option<SymbolConfidence>,
}

// ─── recent ──────────────────────────────────────────────────────────────────

/// §10 `recent`——复用常驻飞行记录仪的事件聚合。
///
/// **这是 Level 0 唯一不读 /proc 的字段**：它读的是 M4 那个常驻 ring buffer
/// 当前内容里属于此 pid 的最近 N 条。M4 没跑时此字段恒为空——M1 阶段必空。
///
/// 关键（§10「零探针」精确含义）：本字段存在**不**改变「本次调用零新增探针」
/// 的承诺——它只复用飞行记录仪自身的常驻预算（§7.2 低扰动预算），不挂本调用
/// 新探针。如果记录仪没在跑（M1 状态），这里返 [`RecentEvents::RecorderOff`]。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecentEvents {
    /// 飞行记录仪未在跑（M1 默认状态）。
    RecorderOff,
    /// 记录仪运行中，但本 pid 没有最近事件。
    Empty,
    /// 记录仪运行中且本 pid 有最近事件，返回聚合后 N 条。
    Sample { events: Vec<RecorderEvent> },
}

/// §10 `recent` 单条事件——M4 才有内容；M1 单测只造空 enum 不造这个结构。
///
/// shape 留位但先不展开字段，等 M4 落地时定（避免提前定型锁死未来形状）。
/// 用 `#[serde(tag)]` 单元素保留可扩展性。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecorderEvent {
    pub ts: chrono::DateTime<chrono::Utc>,
    /// 事件类型——M4 定；现在只占位。
    #[serde(rename = "type")]
    pub event_type: String,
}

// ─── confidence ─────────────────────────────────────────────────────────────

/// §11 置信度是 first-class output。Level 0 末尾给整体摘要：
/// 「本次快照可信度高低 + 哪些字段低置信 + 原因」。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSummary {
    /// 整体可信度。0.0 = 全部低置信；1.0 = 全部首次命中预定义数据源。
    pub overall: f32,
    /// 低置信字段标记——给 AI deciding 「哪些字段不要太当真」。
    pub low_fields: Vec<LowConfidenceField>,
}

/// §11 一个低置信字段标记。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LowConfidenceField {
    /// 字段路径，如 `state.wchan` / `hotspot.frames[2].symbol`。
    pub path: String,
    /// 实际落到哪一档（含 None = 符号化失败）。
    pub confidence: Option<SymbolConfidence>,
    /// 简短原因（§11 双路交叉验证不通过、kallsyms 没符号 等等）。
    pub reason: String,
}

/// §11 单符号置信度分级。
///
/// 「DWARF 命中 / kallsyms 命中 / 动态符号 / 反汇编恢复，可信度差数量级」——
/// 数量级差就是这一档跨度差。**不标 = 把幻觉当真值喂**（§10 钉死三断言之二）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolConfidence {
    /// DWARF/ORC 完整回溯 + 命中。最高。
    Dwarf,
    /// kallsyms 静态符号表命中。次之。
    Kallsyms,
    /// 动态符号（`.dynsym`）命中——比 kallsyms 弱，常缺内部静态函数。
    Dynsym,
    /// 纯反汇编恢复（启发式、可能错）。最低 nonzero。
    Disasm,
    /// 符号化失败。最差——直接告诉 AI 不能信。
    None,
}

impl SymbolConfidence {
    /// 数值化置信度，用于 overall 聚合（§11）。值越大越可信。
    pub fn score(self) -> f32 {
        match self {
            SymbolConfidence::Dwarf => 1.00,
            SymbolConfidence::Kallsyms => 0.75,
            SymbolConfidence::Dynsym => 0.50,
            SymbolConfidence::Disasm => 0.25,
            SymbolConfidence::None => 0.00,
        }
    }
}

/// §10 / §11 出现在 wchan、StackFrame.symbol 里的「符号化结果」复用结构。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbolized {
    /// `symbol_name + "+0x" + offset` 拼出来的可读串。e.g. `futex_wait_queue_me+0x12`。
    pub name: String,
    /// 若符号化回退了，最终落到哪一档（§11 这里是「它有多可信」的明写出处）。
    pub source: SymbolConfidence,
}

// ─── handles ─────────────────────────────────────────────────────────────────

/// §10 `handles`——不透明游标，按需展开成 Level 1。
///
/// 设计意图（§10）：「什么进 level 0、什么藏 handle 后」正是投影策略。
/// handles 这层让 AI 的 introspect 一次返回是**O(1) 体积**，需要哪部分就
/// 再调 `introspect(pid, view=…, cursor=…, fields=[…], page=…)` 拿对应 Level 1 view。
///
/// M1 阶段所有 handles 都先 None——能给出 cursor 但**不实现展开**，
/// 等到 M3 Level 1 视图上线时才让 cursor 可被消费。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Handles {
    pub threads: Option<Handle>,
    pub maps: Option<Handle>,
    /// stack 的 per-tid 游标——DWARF/ORC 回溯成本只在 view=stack 时付。
    pub stack: Option<Handle>,
    pub fds: Option<Handle>,
    pub env: Option<Handle>,
    pub symbols: Option<Handle>,
}

/// 不透明游标——一个 opaque 字符串（base64 字节数组），AI 当字符串互传，
/// guest-agent 内部 decode 出真实引用。**不把引用直接 serialize** 给 AI：
/// AI 拿不到内部指针，泄露面缩到最小。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handle(pub String);

// ─── cost_hint ───────────────────────────────────────────────────────────────

/// §12 已定形状 = `{token, api_cost?, overhead_est}`。
///
/// §10 钉死的第一断言：**每次返回带 cost_hint**——让 §2.1「编排器 = 分配
/// token/钱预算的调度器」有东西可调度。Level 0 cost_hint 接近零（纯读 /proc，
/// 没回溯没探针），但仍要明写——明写本身比绝对值重要。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostHint {
    /// 本调用预计消耗的 token 数（主要是返回 JSON 自己被吃进上下文）。
    pub token: u32,
    /// 若本调用调了付费外部 API（M2+ 才可能；M1 恒 None）。
    pub api_cost: Option<f32>,
    /// 对目标进程施加的 overhead 估计（纳秒级）。Level 0 ≈ 0；
    /// 挂探针的写能力（M6+）会把这里往上推。
    pub overhead_est_ns: u64,
}

// ════════════════════════════════════════════════════════════════════════════
// Level 1：view 参数 schema（§10）
// ════════════════════════════════════════════════════════════════════════════

/// §10 Level 1 第二形的 `view` 参数。
///
/// `introspect(pid, view=maps|threads|stack|fds, cursor=…, fields=[…], page=…)`
/// 的第一参。每个 view 可投影 (fields=)、可分页。M3 落地。
//
// 提前定义 enum 是为了让跨边界合同早一步锁死——M1 阶段 host-supervisor 还不会
// 收到 Level 1 请求，但 view 列值提前占位，未来 M3 不再改 vsock schema。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level1View {
    Maps,
    Threads,
    Stack,
    Fds,
    /// §10 提到的 cmdline 全长 view——截断后的 identity 可以展开回全 cmdline。
    Cmdline,
    Env,
    Symbols,
}

// ════════════════════════════════════════════════════════════════════════════
// 单测：形状可序列化、circular 不漏字段
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level0_serializes_roundtrip() {
        let l0 = Level0 {
            identity: Identity {
                pid: 42,
                comm: "demo".into(),
                exe: Some("/usr/bin/demo".into()),
                cmdline: Cmdline {
                    short: "./demo --foo".into(),
                    full_len: 11,
                },
                uid: 1000,
                cgroup: Some("/user.slice/...".into()),
            },
            state: ProcState {
                run_state: RunState::D,
                last_cpu: 3,
                nr_threads: 7,
                wchan: Some(Symbolized {
                    name: "futex_wait_queue_me+0x0".into(),
                    source: SymbolConfidence::Kallsyms,
                }),
            },
            resource: Resource {
                rss_bytes: 1_000_000,
                vsz_bytes: 4_000_000,
                nr_fds: 5,
                pct_cpu: 12.5,
                ctxt_switches: CtxtSwitches {
                    voluntary: 100,
                    nonvoluntary: 50,
                },
            },
            mem_shape: MemShape {
                histogram: vec![
                    MapKindBucket {
                        kind: MapKind::Heap,
                        count: 1,
                        total_size: 1_000_000,
                    },
                    MapKindBucket {
                        kind: MapKind::XLib,
                        count: 12,
                        total_size: 8_000_000,
                    },
                ],
                top_n: vec![TopMap {
                    start: "7f0000000000".into(),
                    end: "7f0040000000".into(),
                    size: 4 * 1024 * 1024 * 1024,
                    kind: MapKind::XLib,
                    backing: Some("/usr/lib/libc.so.6".into()),
                }],
            },
            hotspot: Hotspot::Blocked {
                frames: vec![StackFrame {
                    idx: 0,
                    addr: "ffffffff81a2b3c4".into(),
                    symbol: Some(Symbolized {
                        name: "futex_wait_queue_me+0x12".into(),
                        source: SymbolConfidence::Dwarf,
                    }),
                    confidence: Some(SymbolConfidence::Dwarf),
                }],
            },
            recent: RecentEvents::RecorderOff,
            confidence: ConfidenceSummary {
                overall: 0.85,
                low_fields: vec![],
            },
            handles: Handles::default(),
            cost_hint: CostHint {
                token: 500,
                api_cost: None,
                overhead_est_ns: 0,
            },
        };
        let s = serde_json::to_string(&l0).unwrap();
        let back: Level0 = serde_json::from_str(&s).unwrap();
        assert_eq!(back.identity.pid, 42);
        assert_eq!(back.state.run_state, RunState::D);
        assert!(matches!(back.recent, RecentEvents::RecorderOff));
        assert_eq!(back.cost_hint.token, 500);
        // 皇冠明珠体检：完整 maps 没出现在 JSON 里（只有 kind 聚合 + top-N）
        let json_val: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(json_val["mem_shape"]["histogram"].is_array());
        assert!(
            json_val.get("maps_raw").is_none(),
            "完整 maps 不该出现在 Level0"
        );
    }

    #[test]
    fn confidence_score_is_monotone() {
        // §11 分级差数量级——这里只是判单调，绝对值留给合理度评估用
        let dwarf = SymbolConfidence::Dwarf.score();
        let kallsyms = SymbolConfidence::Kallsyms.score();
        let dynsym = SymbolConfidence::Dynsym.score();
        let disasm = SymbolConfidence::Disasm.score();
        let none = SymbolConfidence::None.score();
        assert!(dwarf > kallsyms);
        assert!(kallsyms > dynsym);
        assert!(dynsym > disasm);
        assert!(disasm > none);
    }

    #[test]
    fn run_state_serializes_as_exact_kernel_character() {
        let states = [
            (RunState::R, 'R'),
            (RunState::S, 'S'),
            (RunState::D, 'D'),
            (RunState::Z, 'Z'),
            (RunState::T, 'T'),
            (RunState::TracingStop, 't'),
            (RunState::X, 'X'),
            (RunState::P, 'P'),
            (RunState::I, 'I'),
        ];
        let mut encodings = std::collections::BTreeSet::new();

        for (state, character) in states {
            let serialized = serde_json::to_string(&state).unwrap();
            let wire_value: String = serde_json::from_str(&serialized).unwrap();

            assert_eq!(serialized, format!("\"{character}\""));
            assert_eq!(wire_value.chars().count(), 1);
            assert!(
                encodings.insert(wire_value),
                "known run states must have distinct wire encodings"
            );
            assert_eq!(
                serde_json::from_str::<RunState>(&serialized).unwrap(),
                state
            );
        }

        assert_eq!(encodings.len(), states.len());
    }

    #[test]
    fn unknown_run_state_roundtrips_without_becoming_an_error() {
        let mut encodings = std::collections::BTreeSet::new();

        for character in ['?', 'q'] {
            let state = RunState::Unknown(character);
            let serialized = serde_json::to_string(&state).unwrap();
            let wire_value: String = serde_json::from_str(&serialized).unwrap();

            assert_eq!(wire_value.chars().count(), 1);
            assert!(encodings.insert(wire_value));
            assert_eq!(
                serde_json::from_str::<RunState>(&serialized).unwrap(),
                state
            );
        }

        assert_eq!(encodings.len(), 2);
        assert!(serde_json::from_str::<RunState>("\"\"").is_err());
        assert!(serde_json::from_str::<RunState>("\"??\"").is_err());
    }
}
