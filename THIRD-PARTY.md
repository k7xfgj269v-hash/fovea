# Third-Party Software

Fovea's Rust userspace code is licensed under MIT. The eBPF source directory
is licensed separately as described in `bpf/LICENSE`.

## Dependency Policy

Cargo dependencies remain separate third-party works under their own licenses.
Depending on a crate does not copy its source into Fovea. If third-party source
is copied or adapted into this repository later, this file must identify the
upstream project, source path, revision, license, copyright notice, and affected
Fovea files.

No third-party source is currently recorded as copied into this repository.

## Direct Rust Dependencies

The workspace directly depends on the following external projects. Transitive
dependencies are recorded in `Cargo.lock` and retain their upstream licenses.

| Dependency | Upstream license |
|---|---|
| `async-trait` | MIT OR Apache-2.0 |
| `blazesym` | BSD-3-Clause |
| `chrono` | MIT OR Apache-2.0 |
| `libc` | MIT OR Apache-2.0 |
| `serde` | MIT OR Apache-2.0 |
| `serde_json` | MIT OR Apache-2.0 |
| `thiserror` | MIT OR Apache-2.0 |
| `tokio` | MIT |
| `tokio-vsock` | MIT |
| `tracing` | MIT |
| `tracing-subscriber` | MIT |
| `uuid` | MIT OR Apache-2.0 |

Before copying code from any dependency or reference project, verify its
license at the revision being copied and update this file in the same commit.
