# Fovea

**English** · [中文](README.zh-CN.md)

[![CI](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml/badge.svg)](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml)

**Foveate the kernel.** The name is the retina's *fovea* — the tiny patch of sharpest vision. Your visual field is enormous but bandwidth is scarce, so the eye keeps only the ~2° you are fixating on in high resolution and saccades it to wherever it is needed. That is exactly what this project does to the flood of kernel state: `introspect(pid)` never dumps everything, it projects only *what matters right now* to the AI.

> Turn one Unix box into a **glass box** for AI — humans keep using the shell as usual, while an extra system-interface surface lets an AI fully introspect and operate the kernel.
>
> **Status**: design converged, the executable M0 host harness and the M1 read-side shape have landed. Full design in [`docs/DESIGN.md`](docs/DESIGN.md).

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
| **M0** | VM harness: host + guest, vsock, `savevm`/`loadvm`, gdb stub | executable preflight/launch/QMP/GDB/PT tooling; physical Linux acceptance remains separate | 🟡 harness landed |
| **M1** | read-only `introspect(pid)` Level 0: `/proc` + blazesym, zero probes | projection holds (GB maps → a dozen lines) | ✅ read-side shape complete |
| **M2** | MCP front: `introspect` as an MCP tool + self-describing catalog | the capability surface takes shape | ⬜ |
| **M3** | `introspect` Level 1 views + `cost_hint` + confidence | projection / paging / cost become schedulable | ⬜ |
| **M4** | flight recorder: resident ring buffer, ultra-low perturbation | transient events get caught | ⬜ |
| **M5** | **host-side audit sink + arbiter (human-first + teardown) + intervention gate hook** | **the safety scaffold (incl. the pre-emptive gate) — before any write capability** | 🟡 traits in place |
| **M6** | eBPF observation channel: on-demand probes + effect audit | read side complete | ⬜ |
| **M7** | eBPF intervention channel (override / drop) + passively discoverable | first write capability, verifier as the backstop | ⬜ |
| **M8** | fs transactions: dry-run diff + point rollback | fs writes previewable and revertible | ⬜ |
| **M9** | LKM parameterized primitive modules + human gate | the last, most dangerous capability, parameterized | ⬜ |

## Honest status

**What M1 landed is the *shape*** — a pure-function parsing layer plus engine assembly. The real `/proc` I/O is `cfg`-gated to Linux; the default compatibility entry point still uses the honest `FallbackSymbolizer`, while the Linux-only blazesym backend remains a separately isolated skeleton. The M1 parser contracts now source context-switch counts from `/proc/<pid>/status`, truncate untrusted command lines on UTF-8 boundaries, and lower confidence when frame symbolization fails.

The repository pins Rust stable in [`rust-toolchain.toml`](rust-toolchain.toml). Local `cargo fmt`, all workspace tests, and strict Clippy pass on macOS. GitHub Actions covers both macOS portable tests and the Ubuntu Linux paths, including the `#[cfg(target_os = "linux")]` code that does not compile into the macOS target.

**Current boundaries**:

- The M0 scripts are an executable harness, not physical acceptance. A qualifying Linux x86_64 host with real KVM, explicit guest artifacts, and recorded QMP/GDB/guest-PT evidence is still required; Apple Silicon and CI are not equivalent M0 hardware evidence. See [`docs/M0.md`](docs/M0.md).
- `BlazeSymbolizer` is Linux-only and not wired into the default M1 compatibility path. Its real `vmlinux`/`kallsyms` configuration is still an M0 integration task.
- Write-side semantic contamination remains an open design risk. No eBPF intervention or LKM write capability is exposed by the current implementation.

## Build & run

Requires the Rust stable toolchain (edition 2021). The pinned toolchain lives in [`rust-toolchain.toml`](rust-toolchain.toml).

```bash
cargo check --locked --all-targets --all-features
cargo test --locked --all
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo run -p guest-agent     # bin stub — no daemon logic yet
cargo run -p host-supervisor # bin stub — no listener yet
```

> On non-Linux (incl. Mac), `introspect()` `cfg`-gates straight to `UnsupportedPlatform` and never touches `/proc`; the pure-function shape is held by `introspect_with_inputs` in unit tests — that is the realization of "`cfg`-gate to Linux, but hold the Level0 assembly shape in Mac unit tests".

The M0 contract tests are independent of Cargo and can be run directly:

```bash
scripts/m0/tests/test-check-host.sh
scripts/m0/tests/test-run-vm.sh
python3 scripts/m0/tests/test-qmp-smoke.py
```

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

Following the path left in `docs/DESIGN.md` §15:

1. **M0 physical acceptance** — run the harness on a qualifying Linux x86_64 KVM host, then capture the QMP snapshot, GDB, virtio-vsock, and guest-PT evidence.
2. **M0 integration** — replace `MockTransport` with the real vsock transport and configure the blazesym `vmlinux`/`kallsyms` path inside the guest.
3. **M2 MCP front** — wrap `introspect` into an MCP tool + self-describing catalog (§13.8 side-effect level as a first-class field).
4. **M5 hardening** — append-only file sink + real human gate + pre-emptive intervention hook before any write capability.

> **The iron rule** (§13.9 / axiom 13): build the cage first — including that pre-emptive fence — *before* the AI is allowed to reach in. Never let any write capability predate its container.
