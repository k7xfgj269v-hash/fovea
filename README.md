# Fovea

**English** · [中文](README.zh-CN.md)

[![CI](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml/badge.svg)](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml)

**Foveate the kernel.** The name is the retina's *fovea* — the tiny patch of sharpest vision. Your visual field is enormous but bandwidth is scarce, so the eye keeps only the ~2° you are fixating on in high resolution and saccades it to wherever it is needed. That is exactly what this project does to the flood of kernel state: `introspect(pid)` never dumps everything, it projects only *what matters right now* to the AI.

> Turn one Unix box into a **glass box** for AI — humans keep using the shell as usual, while an extra system-interface surface lets an AI fully introspect and operate the kernel.
>
> **Status**: design converged, skeleton up, the first two cuts of M1 have landed. Full design in [`docs/DESIGN.md`](docs/DESIGN.md).

## What it is

A privileged daemon that sits **on top of** Unix (not a new kernel, not a thick runtime framework) and exposes a system interface **designed for tokens, not human eyes**:

- **Full introspection** — see through every process: threads, memory, fds, call stacks, down to runtime functions (transparent *up to the runtime boundary*, not all-seeing).
- **Operate the kernel** — from safe eBPF intervention to controlled, unlimited LKM rewriting.
- **Safety envelope** — let a *hallucinating* operator safely hold ring0. Dangerous capabilities are caged behind an eBPF verifier plus a host-side human-review gate.

The closest existing analogy: a **machine-wide, systematic MCP**.

## Why — the two things that are genuinely new

It is *not* "kernel introspection" (a known hard problem, not AI-specific). What is actually new and actually hard:

1. **Context virtualization / projection.** Kernel state is enormous — process memory in GBs, ftrace in millions of lines, `kcore` is the entire kernel's memory. It does not fit an AI's context window. The hard part is not *capturing* the data, it is deciding **"what should I look at right now"** before feeding it. This is the crown jewel, and it is forced down to a solvable face on [`introspect(pid)`](crates/introspect-schema/src/lib.rs): for a single pid, "what goes into Level 0 vs. what hides behind a handle" is the minimal instance of the projection policy.
2. **How to safely share one real machine.** A human and an AI on the *same real box*, with the AI holding `kcore` plus kernel-write, forces an entire apparatus of trust boundary / arbitration / transparency / audit. The trust boundary lands physically as the **VM boundary = host/guest boundary**.

Full axioms and derivation live in [`docs/DESIGN.md`](docs/DESIGN.md) §14.

## Repository layout

The trust boundary made physical — four crates, clean split, acyclic dependency graph:

```
fovea/
├── Cargo.toml                       # workspace root; deps centralized via workspace.dependencies
├── crates/
│   ├── introspect-schema/           # the cross-vsock contract: Level0/Level1 fields (§10 / §13.4)
│   ├── vsock/                        # host↔guest control channel: Transport trait + MockTransport
│   ├── guest-agent/                 # guest side (untrusted data plane): introspect engine + proc_view + symbolize
│   └── host-supervisor/             # host side (trusted control plane): AuditSink + HumanGate traits
└── docs/
    └── DESIGN.md                    # full design doc (architecture / interfaces / hard problems / build blueprint)
```

Dependency direction (`A → B` = A depends on B, acyclic; `introspect-schema` is the only leaf):

```
vsock            → introspect-schema
guest-agent      → introspect-schema
host-supervisor  → vsock → introspect-schema
```

`guest-agent` and `host-supervisor` never reference each other — the cross-boundary contract is pinned solely by the `introspect-schema` crate, not by crate interdependence.

### Crate status

| Crate | Role | Landed |
|---|---|---|
| **introspect-schema** | cross-boundary contract, zero runtime deps | Level0 all 9 fields (`identity` / `state` / `resource` / `mem_shape` / `hotspot` / `recent` / `confidence` / `handles` / `cost_hint`) at field granularity; §10's three assertions nailed (per-frame confidence, `wchan` in Level0, `cost_hint` shape `{token, api_cost?, overhead_est}`); Level1 `view` enum stubbed ahead of time |
| **vsock** | physical realization of the trust boundary | `Transport` trait + `MockTransport`; `Message` / `Request` / `Response` / `AuditEvent` / `ErrorReport` shapes; §13.6 one-way append-only, §13.8 five-tier side-effect routing (`read` / `dry-runnable-write` / `intervention` / `kernel-write` / `irreversible`) |
| **guest-agent** | untrusted data plane (guest side) | `introspect::engine::introspect` is now real (no longer a stub): `/proc` parsing (stat/status/maps/wchan/fd/stack) → assemble `Level0`; `proc_view`'s 6 pure parsers; `symbolize` trait + `FallbackSymbolizer` (honest `NotFound` off-Linux — **this is what M1 actually uses**) + `BlazeSymbolizer` (Linux-only blazesym **skeleton**, not yet wired into `introspect`, `cfg`-out on Mac so unverified locally); `ProcError` serde hardening + regression tests |
| **host-supervisor** | trusted control plane (host side) | `AuditSink` trait + `InMemoryAuditSink` (unit-tested green); `HumanGate` trait + `GateDecision` + `LkmParamGate` (placeholder `Allow`); traits in place, real values land in M5 |

## Milestones (M0–M9)

Safety scaffold before write capability — see [`docs/DESIGN.md`](docs/DESIGN.md) §13.9.

| Milestone | What it builds | What it proves | Status |
|---|---|---|---|
| **M0** | VM harness: host + guest, vsock, `savevm`/`loadvm`, gdb stub | base runs, rolls back in a snap, can debug the kernel | ⬜ not started |
| **M1** | read-only `introspect(pid)` Level 0: `/proc` + blazesym, zero probes | projection holds (GB maps → a dozen lines) | ✅ shape complete |
| **M2** | MCP front: `introspect` as an MCP tool + self-describing catalog | the capability surface takes shape | ⬜ |
| **M3** | `introspect` Level 1 views + `cost_hint` + confidence | projection / paging / cost become schedulable | ⬜ |
| **M4** | flight recorder: resident ring buffer, ultra-low perturbation | transient events get caught | ⬜ |
| **M5** | **host-side audit sink + arbiter (human-first + teardown) + intervention gate hook** | **the safety scaffold (incl. the pre-emptive gate) — before any write capability** | 🟡 traits in place |
| **M6** | eBPF observation channel: on-demand probes + effect audit | read side complete | ⬜ |
| **M7** | eBPF intervention channel (override / drop) + passively discoverable | first write capability, verifier as the backstop | ⬜ |
| **M8** | fs transactions: dry-run diff + point rollback | fs writes previewable and revertible | ⬜ |
| **M9** | LKM parameterized primitive modules + human gate | the last, most dangerous capability, parameterized | ⬜ |

## Honest status

**What M1 actually landed is the *shape*** — a pure-function parsing layer plus engine assembly, running green in Mac unit tests. The real `/proc` I/O is `cfg`-gated to Linux and only compiles there; blazesym's real kernel-side path (`vmlinux` / `kallsyms` config) is still marked `TODO(M0)`, to be filled in once the VM base exists.

Locally there is **no Rust toolchain**, so everything above was static review, never `cargo check`/`cargo test`. **CI (GitHub Actions, ubuntu) now provides the first real compilation** — including, for the first time, the `#[cfg(target_os = "linux")]` paths (`BlazeSymbolizer`, the real `/proc` I/O) that never compile on Mac. Watch the badge above.

> ⚠️ **CI is red right now — by design.** That first Linux compile surfaced 40 errors, all in the WIP `BlazeSymbolizer` backend: blazesym 0.2.5's `Symbolizer` is `!Send + !Sync` (interior `RefCell`/`Rc`), clashing with our `Symbolizer: Send + Sync` trait; plus a moved API path (`Source`) and the `ctxt_switches` field debt below. The `FallbackSymbolizer` path that M1 actually uses is unaffected. The blazesym backend gets wired in at M0 — the badge stays red until then.

**Known gaps** (M1 debts found in review, to fix before the M0 end-to-end):

- **`resource.ctxt_switches` reads the wrong source** — it reads `/proc/<pid>/stat` fields 40/41, which are `rt_priority`/`policy`, **not** context-switch counts. The real source is the `voluntary_ctxt_switches:` line in `/proc/<pid>/status`. On real Linux this silently returns wrong numbers; the Mac unit test uses an isomorphic fixture (values placed at idx 37/38) that happens to miss it.
- **`build_cmdline` can panic** — `String::truncate(256)` on a non-UTF-8 char boundary panics; `cmdline` is untrusted input and can trigger this with multi-byte characters.
- **`confidence` is only half done** — §11 ① (wchan / top-frame cross-check) is implemented, ② (each frame's symbolization failure into `low_fields`) is not. Under M1's `Fallback` every frame fails to symbolize, yet `overall` reports `1.0` — contradicting axiom 11 ("tell you how uncertain it is").

> The irony: all three are "silent read-side contamination" (§11) — the engine tripped over the very pit it is meant to guard. None block compilation; fix before M0.

## Build & run

Requires the Rust stable toolchain (edition 2021). The pinned toolchain lives in [`rust-toolchain.toml`](rust-toolchain.toml).

```bash
cargo check --all-targets    # compile all 4 crates (incl. bin stubs)
cargo test                   # unit tests (schema + vsock + guest-agent + host-supervisor)
cargo run -p guest-agent     # bin stub — no daemon logic yet
cargo run -p host-supervisor # bin stub — no listener yet
```

> On non-Linux (incl. Mac), `introspect()` `cfg`-gates straight to `NotImplemented` and never touches `/proc`; the pure-function shape is held by `introspect_with_inputs` in unit tests — that is the realization of "`cfg`-gate to Linux, but hold the Level0 assembly shape in Mac unit tests".

## Reading guide

- **Quick alignment** — `docs/DESIGN.md` §1 (positioning), §2 (mental model, the scarce-resource inversion table), §14 (axioms).
- **Getting hands-on** — §10 (`introspect(pid)` primitive + the three nailed assertions), §13 (build blueprint), §13.9 (milestones).
- **Risk-minded** — §8 (trust / arbitration / transparency), §9 (layered rollback), §11 (silent contamination, read and write sides).
- **Where the code meets the doc**:
  - "First cut of the crown jewel" = the `MemShape` section of [`crates/introspect-schema/src/lib.rs`](crates/introspect-schema/src/lib.rs) (GB maps → a dozen-line projection).
  - The two halves of the trust boundary = [`crates/guest-agent/`](crates/guest-agent/) ↔ [`crates/host-supervisor/`](crates/host-supervisor/), over [`crates/vsock/`](crates/vsock/).
  - Axiom 13 "scaffold before write capability", minimal M1 instance = the `AuditSink` trait in [`crates/host-supervisor/src/audit.rs`](crates/host-supervisor/src/audit.rs), present from M1.
  - The three assertions' code home = [`crates/guest-agent/src/introspect.rs`](crates/guest-agent/src/introspect.rs) (every call carries `cost_hint`, `wchan` in Level0, per-frame `SymbolConfidence`).

## Next steps

Following the path left in `docs/DESIGN.md` §15 (**priority 0**: clear the three M1 debts above first, especially `ctxt_switches` — it surfaces silent wrong numbers the moment M0 hits real Linux):

1. **M0 VM base** — QEMU/KVM + virtio-vsock + savevm/loadvm + gdb stub; then the real `Transport` impl replaces `MockTransport`, blazesym's real kernel path (`vmlinux`/`kallsyms`) gets configured in one shot, and `introspect` runs end-to-end inside the guest.
2. **M2 MCP front** — wrap `introspect` into an MCP tool + self-describing catalog (§13.8 side-effect level as a first-class field).
3. **M5 hardening** — append-only file sink + real human gate + pre-emptive intervention hook (the fence is in place *before* M7 reaches in) — the full landing of axiom 13.

> **The iron rule** (§13.9 / axiom 13): build the cage first — including that pre-emptive fence — *before* the AI is allowed to reach in. Never let any write capability predate its container.
