#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_root"

fail() {
    printf 'license-check: %s\n' "$*" >&2
    exit 1
}

test -f LICENSE || fail "missing root LICENSE"
test -f bpf/LICENSE || fail "missing bpf/LICENSE"
test -f THIRD-PARTY.md || fail "missing THIRD-PARTY.md"

grep -Fq 'license = "MIT"' Cargo.toml ||
    fail "workspace.package license must be MIT"
if grep -Fq 'license = "MIT OR Apache-2.0"' Cargo.toml; then
    fail "workspace still declares MIT OR Apache-2.0"
fi

for manifest in crates/*/Cargo.toml; do
    grep -Fq 'license.workspace = true' "$manifest" ||
        fail "$manifest must inherit the workspace MIT license"
done

find bpf -type f -name '*.bpf.c' -print | while IFS= read -r source; do
    first_line=$(sed -n '1p' "$source")
    test "$first_line" = '// SPDX-License-Identifier: (MIT OR GPL-2.0-only)' ||
        fail "$source must put the required SPDX declaration on line 1"
    grep -Eq '^[[:space:]]*char LICENSE\[\] SEC\("license"\) = "Dual MIT/GPL";[[:space:]]*$' "$source" ||
        fail "$source is missing the required kernel runtime license"
done

printf 'license-check: ok\n'
