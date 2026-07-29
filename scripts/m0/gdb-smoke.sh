#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: gdb-smoke.sh [OPTIONS]

Connect to the QEMU GDB stub in batch mode and print the guest registers.

Options:
  --host HOST       GDB stub host (default: 127.0.0.1)
  --port PORT       GDB stub TCP port (default: 1234)
  --timeout SECONDS Connection timeout, integer 1..3600 (default: 10)
  --vmlinux PATH    Optional readable vmlinux symbols
  -h, --help        Show this help

Narrow tool override:
  GDB_BIN           Maintained GNU GDB binary (default: gdb)
EOF
}

die() {
    printf 'gdb-smoke: %s\n' "$*" >&2
    exit 1
}

require_uint_range() {
    local label=$1
    local value=$2
    local minimum=$3
    local maximum=$4

    [[ "$value" =~ ^[0-9]+$ ]] ||
        die "$label must be a decimal integer: $value"
    ((${#value} <= 10)) ||
        die "$label is outside $minimum..$maximum: $value"
    local number=$((10#$value))
    ((number >= minimum && number <= maximum)) ||
        die "$label is outside $minimum..$maximum: $value"
}

host=127.0.0.1
port=1234
timeout=10
vmlinux=

while (($# > 0)); do
    case "$1" in
        --host)
            (($# >= 2)) || die "--host requires a value"
            host=$2
            shift 2
            ;;
        --port)
            (($# >= 2)) || die "--port requires a value"
            port=$2
            shift 2
            ;;
        --timeout)
            (($# >= 2)) || die "--timeout requires a value"
            timeout=$2
            shift 2
            ;;
        --vmlinux)
            (($# >= 2)) || die "--vmlinux requires a path"
            vmlinux=$2
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ "$host" =~ ^[A-Za-z0-9._-]+$ ]] ||
    die "host contains unsupported characters: $host"
require_uint_range port "$port" 1 65535
require_uint_range timeout "$timeout" 1 3600

GDB_BIN=${GDB_BIN:-gdb}
if [[ "$GDB_BIN" == */* ]]; then
    [[ -x "$GDB_BIN" ]] || die "GDB_BIN is not executable: $GDB_BIN"
else
    command -v "$GDB_BIN" >/dev/null 2>&1 ||
        die "GDB_BIN was not found in PATH: $GDB_BIN"
fi

gdb_args=(--batch --nx --quiet)
if [[ -n "$vmlinux" ]]; then
    [[ -f "$vmlinux" && -r "$vmlinux" ]] ||
        die "vmlinux must be a readable regular file: $vmlinux"
    gdb_args+=("--se=$vmlinux")
fi
gdb_args+=(
    -ex "set pagination off"
    -ex "set confirm off"
    -ex "set tcp connect-timeout $timeout"
    -ex "target remote $host:$port"
    -ex "info registers"
    -ex detach
)

exec "$GDB_BIN" "${gdb_args[@]}"
