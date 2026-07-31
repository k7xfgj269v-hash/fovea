# Fovea Implementation Progress

Status date: 2026-07-31

This file tracks implementation against
`fovea-execution-decisions-20260729.md`. A decision is marked complete only
for the scope exercised by committed anti-gaming tests. Silent degradation is
not accepted as success.

## Completed

### D1: Licensing

- Repository code is MIT licensed through `LICENSE` and crate metadata.
- BPF sources are required to declare the documented dual MIT/GPL license.
- CI checks repository, crate, dependency, and BPF license declarations.

### D7: M1 Correctness And Acceptance

- Proc state parsing covers the documented Linux states and preserves unknown
  future states as explicit low-confidence data.
- Procfs text uses lossy decoding where Linux permits non-UTF-8 bytes and
  records the affected fields.
- Malformed maps rows degrade per row with exact skipped-row evidence.
- Token cost, overall confidence, raw Kallsyms fallback, snapshot span, fd
  count, cgroup selection, and PID generation checks have reverse assertions.
- Fixtures record capture provenance. Linux CI runs the live non-UTF-8 and
  full numeric `/proc` PID acceptance gate.

### D5: Default Linux Symbolization Wiring

- Linux `introspect(pid)` starts the bounded blazesym worker by default.
- Successful worker results reach Level 0 frames; raw Kallsyms is not the
  constant default.
- Worker initialization and per-address lookup failures retain raw Kallsyms
  with exact error-kind and `fallback=raw_kallsyms` evidence.
- Worker shutdown is explicit and bounded. Shutdown failure is recorded in
  `confidence.low_fields`, lowers confidence, and updates the final token
  estimate.
- Matching wchan/top-frame names do not raise a warning; mismatches do.
- Linux CI requires two distinct nonzero `/proc/kallsyms` addresses and two
  distinct resolved names. Each blazesym result must belong to the full alias
  set reported for its address; restricted or zeroed kallsyms fails the
  prerequisite. A constant symbolizer still cannot pass.

Deferred D5 optimization work includes debuginfod, build-ID keyed caches,
stripped-binary recovery, and JIT symbol sources.

## Pending

### D6: MCP And Kernel Log Projection

- Generate `docs/MCP.md` from the runtime capability catalog.
- Add host-side MCP dispatch with audit-before-send and typed authorization.
- Read kernel logs from `/dev/kmsg` with explicit cursor invalidation and
  degradation evidence.
- Keep kernel logs separate from host audit, guest receipts, and telemetry.

### D3: M6a Observation Probes

- Deliver fixed observation-only kprobe, uprobe, and tracepoint counters.
- Deliver persistent registry, pinned links, list, and owner-scoped flush in
  the same milestone.
- Do not expose M7 intervention or arbitrary BPF input.

### D4: Two-Tier Snapshots

- Add qcow2 overlay cold reset with atomic replacement.
- Replace HMP `savevm`/`loadvm` with native QMP snapshot jobs and terminal job
  verification.

## Verification

Local acceptance completed on 2026-07-31:

- License gate: passed.
- Rust workspace: 149 tests passed, 0 failed.
- Formatting and Clippy with warnings denied: passed.
- `x86_64-unknown-linux-gnu` all-targets/all-features check: passed.
- M0 host checks: 25 passed.
- M0 VM launcher checks: 19 passed.
- M0 QMP contract checks: 10 passed.
- D5 final review: passed. The combined real-worker contract rejected
  constant output, bypassed worker objects, missing shutdown, and
  drop-before-shutdown implementations.

GitHub Linux acceptance completed on 2026-07-31 for commit `1b13467`
(Actions run `30631582370`):

- Full workspace tests, formatting, Clippy, and license gates: passed.
- D7 live `/proc` acceptance: 3 passed, 0 failed.
- `kernel.kptr_restrict=0` was applied and observed by the job.
- D5 live blazesym acceptance: 1 passed, 0 failed. The gate accepted legitimate
  same-address Kallsyms aliases while retaining the distinct-address and
  distinct-name reverse assertions.
- macOS portable tests: passed in the same workflow run.

Local portable gates:

```bash
scripts/ci/check-licenses.sh
cargo test --locked --all
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo check --locked --target x86_64-unknown-linux-gnu \
  --all-targets --all-features
scripts/m0/tests/test-check-host.sh
scripts/m0/tests/test-run-vm.sh
python3 scripts/m0/tests/test-qmp-smoke.py
```

Linux-only CI gates:

```bash
cargo test --locked -p guest-agent --test d7_linux_live -- \
  --ignored --nocapture --test-threads=1
sudo sysctl -w kernel.kptr_restrict=0
cargo test --locked -p guest-agent --test d5_symbolization -- \
  --ignored --nocapture --test-threads=1
```

Forge evidence for the current D5 delivery is retained at:

```text
/tmp/codex-forge-runs/fovea/20260730T144654Z-accf3ddb-complete-execution-decisions
```

## Unverified Assumptions

- No local QEMU/KVM guest acceptance was run on this Apple Silicon machine.
- The D5 live symbolization result is proven on the GitHub Ubuntu runner, not
  on every supported kernel configuration; local verification covers portable
  behavior and the Linux compile target.
- Physical M0 acceptance on a Linux x86_64 KVM host remains pending.
- D5 debuginfod, cache, stripped-binary, and JIT quality assumptions remain
  intentionally unverified because those optimizations are outside this
  delivery.
