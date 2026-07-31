# Fovea

AI-native system introspection and control infrastructure for Linux.

[![CI](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml/badge.svg)](https://github.com/k7xfgj269v-hash/fovea/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)

Fovea is a privileged service that runs above Linux and exposes a
machine-level interface designed for AI operators. It projects large amounts
of kernel and process state into bounded, structured responses, while keeping
the trusted control plane separate from the guest execution plane.

## Status

- D1 repository licensing and BPF license enforcement: landed.
- M0 executable QEMU/KVM host harness: landed.
- M1 read-only `introspect(pid)` Level 0 with D7 functional acceptance: landed.
- D5 Linux default blazesym worker wiring and wchan/top-frame cross-check:
  landed. Raw Kallsyms is retained only as an explicit, confidence-visible
  fallback.
- Linux fixtures directly capture `R/S/D/Z/T/t/I`; the kernel-only/transient
  `P/X` parser cases remain explicitly byte-derived and do not claim strict
  direct-capture acceptance.
- Fixtures also cover lossy procfs text, degraded maps, cgroup variants,
  confidence scoring, token estimates, and measured snapshot spans.
- CI includes Ubuntu live `/proc` and D5 kernel-symbol acceptance, plus macOS
  portable gates.
- D6 MCP and `/dev/kmsg`, D3 M6a observation probes, and D4 two-tier
  snapshots: pending.
- M0 physical acceptance on a Linux x86_64 KVM host: pending.
- Kernel-write and eBPF intervention capabilities: not exposed.

This project is under active development. The current implementation is a
read-side foundation, not a complete operating system or production daemon.

## Goals

- Project process and kernel state into compact, typed, confidence-aware data.
- Keep the host supervisor and guest agent on opposite sides of a VM boundary.
- Make side effects explicit, auditable, gated, and reversible where possible.
- Add write capabilities only after the safety and audit layers exist.

Fovea is not:

- a replacement kernel;
- a new scheduler, filesystem, or device-driver stack;
- an unrestricted ring-0 interface;
- a claim that all kernel state can be observed without uncertainty.

## Architecture

```text
                        trusted host
                   +---------------------+
AI / MCP ingress ->| host-supervisor     |
                   | audit + gate policy |
                   +----------+----------+
                              |
                         typed vsock
                              |
                   +----------v----------+
                   | guest-agent        |
                   | procfs + projection|
                   | symbolization      |
                   +---------------------+
                        untrusted guest
```

The workspace has four crates:

| Crate | Responsibility |
|---|---|
| `introspect-schema` | Cross-boundary `Level0`/`Level1` data contracts. |
| `vsock` | Typed host/guest messages, transport traits, and protocol validation. |
| `guest-agent` | Linux `/proc` adapters, Level 0 projection, and symbolization ports. |
| `host-supervisor` | Trusted-side audit sink, human gate, and control-plane policy. |

Dependency direction:

```text
vsock            -> introspect-schema
guest-agent      -> introspect-schema
host-supervisor  -> vsock -> introspect-schema
```

The guest agent never imports the host supervisor. The shared schema is the
only cross-boundary contract.

## Repository Layout

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

## Quick Start

Requirements:

- Rust stable, selected by `rust-toolchain.toml`.
- Python 3 for the M0 contract tests and Linux live procfs fixture.
- Linux x86_64, QEMU/KVM, GNU GDB, and explicit guest artifacts for physical
  M0 acceptance.

Build and test the workspace:

```bash
cargo check --locked --all-targets --all-features
cargo test --locked --all
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
```

The macOS test job validates portable code paths. Linux-only `/proc`, QEMU,
KVM, and symbolization paths are validated by the Ubuntu CI job or a real
Linux host.

## M1 Acceptance

The D7 acceptance suite is designed so constant substitutions and silent
fallbacks do not pass. Every fixture records whether it is a direct Linux
capture, an external capture, or a documented derivation; every degradation
must remain visible in `confidence.low_fields`.

`scripts/fixtures/capture-proc-states.c` reproduces direct `R/S/D/Z/T/t/I`
captures. `P` requires a parked kernel thread and `X` is an exit-state race, so
their current parser fixtures are identified as derived instead of being
misrepresented as machine captures.

Run the portable parser and Level 0 contracts:

```bash
cargo test --locked -p guest-agent --test d7_proc_view
cargo test --locked -p guest-agent --test d7_proc_source
cargo test --locked -p guest-agent --test d7_level0
```

On Linux, run the live non-UTF-8 and full numeric `/proc` PID gate:

```bash
cargo test --locked -p guest-agent --test d7_linux_live -- \
  --ignored --nocapture --test-threads=1
```

The live scan allows only normal process disappearance and permission
failures. Parse failures and every other error class fail the gate.

Run the D5 live symbolization gate with nonzero kernel addresses visible:

```bash
sudo sysctl -w kernel.kptr_restrict=0
cargo test --locked -p guest-agent --test d5_symbolization -- \
  --ignored --nocapture --test-threads=1
```

The D5 gate requires two distinct nonzero `/proc/kallsyms` symbols and checks
that blazesym returns the corresponding names. Restricted or zeroed addresses
are a failed prerequisite, not a passing skip.

## M0 Harness

The M0 tooling is an executable harness. It does not download or create
kernel, initrd, disk, or symbol artifacts.

| Tool | Purpose |
|---|---|
| `scripts/m0/check-host.sh` | Validate Linux x86_64, KVM, QEMU, paths, ports, and resources. |
| `scripts/m0/run-vm.sh` | Launch an explicitly supplied QEMU/KVM guest with resource reservations. |
| `scripts/m0/qmp-smoke.py` | Exercise ordered QMP `savevm`/`loadvm` requests. |
| `scripts/m0/gdb-smoke.sh` | Connect to the loopback GDB stub and inspect registers. |
| `scripts/m0/guest-pt-probe.sh` | Probe Intel PT availability inside the guest. |

Run the contract tests:

```bash
scripts/m0/tests/test-check-host.sh
scripts/m0/tests/test-run-vm.sh
python3 scripts/m0/tests/test-qmp-smoke.py
```

For physical acceptance and the complete launch procedure, read
[`docs/M0.md`](docs/M0.md).

QMP and GDB are unauthenticated control interfaces. Keep their sockets and
ports loopback-only, use private mode-700 runtime directories, and do not
reuse a guest disk before collecting required snapshot evidence.

## Documentation

| Document | Contents |
|---|---|
| [`docs/DESIGN.md`](docs/DESIGN.md) | Architecture, trust boundaries, contracts, safety model, and milestones. |
| [`docs/M0.md`](docs/M0.md) | QEMU/KVM harness, prerequisites, acceptance workflow, and cleanup rules. |
| [`README.zh-CN.md`](README.zh-CN.md) | Chinese project overview. |

## Roadmap

1. Complete M0 physical acceptance on a qualifying Linux x86_64 KVM host.
2. Land D6: the host-side MCP front, generated capability documentation, and
   read-only `/dev/kmsg` projection.
3. Land D3 M6a: fixed observation-only eBPF counters with registry and
   owner-scoped flush in the same delivery.
4. Land D4: overlay cold reset plus native QMP snapshot jobs.
5. Replace the mock transport with a real vsock transport and run the guest
   path end to end.
6. Only after the audit and safety layers exist, consider M7 intervention,
   filesystem transactions, and parameterized LKM primitives.

## Current Limitations

- Linux `introspect(pid)` starts the blazesym worker by default. Worker
  initialization, per-address lookup, and shutdown failures fall back or
  degrade explicitly through `confidence.low_fields`; they are not silent.
- D5 debuginfod, build-ID caching, stripped-binary recovery, and JIT symbol
  support remain deferred optimization work.
- D6 MCP and kernel-log projection, D3 M6a probes, and D4 snapshot changes are
  not implemented yet.
- M0 scripts are tooling evidence, not physical KVM acceptance by themselves.
- Apple Silicon and CI are not equivalent to a real Linux x86_64 KVM host.
- Write-side semantic contamination remains an open design risk.

## Contributing

Keep changes scoped to the current milestone and preserve the host/guest
trust boundary. Before submitting a change, run:

```bash
cargo fmt --all --check
cargo test --locked --all
cargo clippy --locked --all-targets --all-features -- -D warnings
```

Changes that affect Linux-only behavior should also be checked with:

```bash
cargo check --locked --all-targets --all-features \
  --target x86_64-unknown-linux-gnu
```

## License

Fovea is licensed under the MIT License. See [`LICENSE`](LICENSE). BPF source
files use the repository's documented dual MIT/GPL declaration required for
Linux helper compatibility.
