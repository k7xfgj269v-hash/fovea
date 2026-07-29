#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

usage() {
    cat <<'EOF'
Usage: run-vm.sh [OPTIONS]

Launch an explicitly supplied M0 guest with QEMU/KVM. At least --kernel or
--disk is required. This script never downloads or creates guest artifacts.

Boot inputs:
  --kernel PATH      Linux kernel image
  --initrd PATH      Initrd image; requires --kernel
  --disk PATH        Existing guest disk image
  --append TEXT      Append kernel command-line text; repeatable

VM configuration:
  --qmp-socket PATH  QMP Unix socket path (default: /tmp/fovea-m0.qmp.sock)
  --pidfile PATH     QEMU pidfile path (default: /tmp/fovea-m0.pid)
  --gdb-port PORT    Local GDB TCP port (default: 1234)
  --guest-cid CID    vhost-vsock guest CID (default: 3)
  --memory-mib N     Guest memory in MiB (default: 2048)
  --cpus N           Guest virtual CPU count (default: 2)
  --dry-run          Preflight, then print the shell-escaped QEMU command
  -h, --help         Show this help

Narrow test/tool overrides:
  UNAME_BIN, QEMU_BIN, KVM_DEVICE, PYTHON_BIN, FOVEA_LOCK_ROOT
EOF
}

die() {
    printf 'run-vm: %s\n' "$*" >&2
    exit 1
}

require_readable_file() {
    local label=$1
    local path=$2

    [[ -f "$path" && -r "$path" ]] ||
        die "$label must be a readable regular file: $path"
}

canonicalize_path() {
    "$PYTHON_BIN" - "$1" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
}

canonicalize_disk() {
    "$PYTHON_BIN" - "$1" <<'PY'
import os
import stat
import sys

path = sys.argv[1]


def reject(message):
    print(f"run-vm: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    disk_stat = os.lstat(path)
except OSError as exc:
    reject(f"disk cannot be inspected: {path}: {exc}")

if stat.S_ISLNK(disk_stat.st_mode):
    reject(f"disk must not be a symlink: {path}")
if not stat.S_ISREG(disk_stat.st_mode):
    reject(f"disk must be a readable regular file: {path}")
if not os.access(path, os.R_OK):
    reject(f"disk must be a readable regular file: {path}")

canonical = os.path.realpath(path)
try:
    canonical_stat = os.stat(canonical)
except OSError as exc:
    reject(f"canonical disk cannot be inspected: {canonical}: {exc}")

if not stat.S_ISREG(canonical_stat.st_mode):
    reject(f"canonical disk must be a readable regular file: {canonical}")
if not os.access(canonical, os.R_OK):
    reject(f"canonical disk must be a readable regular file: {canonical}")

parent = os.path.dirname(canonical)
try:
    parent_stat = os.lstat(parent)
except OSError as exc:
    reject(f"disk parent directory cannot be inspected: {parent}: {exc}")

if stat.S_ISLNK(parent_stat.st_mode):
    reject(f"disk parent directory is a symlink: {parent}")
if not stat.S_ISDIR(parent_stat.st_mode):
    reject(f"disk parent path is not a directory: {parent}")
if stat.S_IMODE(parent_stat.st_mode) & 0o022:
    reject(f"disk parent directory must not be group/other writable: {parent}")

print(canonical)
print(f"{canonical_stat.st_dev:x}-{canonical_stat.st_ino:x}")
PY
}

ensure_global_lock_root() {
    local root=$1

    if [[ ! -e "$root" && ! -L "$root" ]]; then
        if ! (umask 077 && mkdir -- "$root") 2>/dev/null; then
            [[ -e "$root" || -L "$root" ]] ||
                die "failed to create global launch lock root: $root"
        fi
    fi

    "$PYTHON_BIN" - "$root" <<'PY' || \
        die "global launch lock root security check failed: $root"
import os
import stat
import sys

root = sys.argv[1]


def reject(message):
    print(f"run-vm: global launch lock root {message}: {root}", file=sys.stderr)
    raise SystemExit(1)


try:
    root_stat = os.lstat(root)
except OSError as exc:
    reject(f"cannot be inspected ({exc})")

if stat.S_ISLNK(root_stat.st_mode):
    reject("must not be a symlink")
if not stat.S_ISDIR(root_stat.st_mode):
    reject("must be a directory")
if root_stat.st_uid != os.getuid():
    reject("must be owned by the invoking user")
if stat.S_IMODE(root_stat.st_mode) != 0o700:
    reject("must have mode 700")
PY
}

release_launch_locks() {
    local index
    local lock_path

    index=${#launch_locks[@]}
    while ((index > 0)); do
        index=$((index - 1))
        lock_path=${launch_locks[$index]}
        if ! rmdir -- "$lock_path"; then
            printf 'run-vm: failed to release launch reservation: %s\n' \
                "$lock_path" >&2
        fi
    done
    launch_locks=()
}

cleanup_on_exit() {
    local status=$?

    trap - EXIT TERM INT
    if [[ -n "$qemu_pid" ]]; then
        if kill -0 "$qemu_pid" >/dev/null 2>&1; then
            kill -TERM "$qemu_pid" >/dev/null 2>&1 || true
        fi
        wait "$qemu_pid" >/dev/null 2>&1 || true
        qemu_pid=
    fi
    if ((qemu_stdin_saved)); then
        exec 3<&-
        qemu_stdin_saved=0
    fi
    release_launch_locks
    exit "$status"
}

forward_signal() {
    local signal_name=$1
    local fallback_status=$2
    local child_status=$fallback_status

    trap - TERM INT
    if [[ -n "$qemu_pid" ]]; then
        if kill -0 "$qemu_pid" >/dev/null 2>&1; then
            kill "-$signal_name" "$qemu_pid" >/dev/null 2>&1 || true
        fi
        if wait "$qemu_pid"; then
            child_status=0
        else
            child_status=$?
        fi
        qemu_pid=
    fi
    if ((qemu_stdin_saved)); then
        exec 3<&-
        qemu_stdin_saved=0
    fi
    release_launch_locks
    trap - EXIT
    exit "$child_status"
}

defer_launch_signal() {
    launch_signal=$1
}

acquire_launch_lock() {
    local lock_path=$1
    local diagnostic_path=${2:-$1}

    if (umask 077 && mkdir -- "$lock_path") 2>/dev/null; then
        launch_locks[${#launch_locks[@]}]=$lock_path
        return
    fi
    if [[ -e "$lock_path" || -L "$lock_path" ]]; then
        die "launch resources are already reserved: $diagnostic_path"
    fi
    die "failed to reserve launch resources: $diagnostic_path"
}

kernel=
initrd=
disk=
qmp_socket=/tmp/fovea-m0.qmp.sock
pidfile=/tmp/fovea-m0.pid
gdb_port=1234
guest_cid=3
memory_mib=2048
cpus=2
dry_run=0
append_parts=()
launch_locks=()
qemu_pid=
qemu_stdin_saved=0
launch_signal=

while (($# > 0)); do
    case "$1" in
        --kernel)
            (($# >= 2)) || die "--kernel requires a path"
            kernel=$2
            shift 2
            ;;
        --initrd)
            (($# >= 2)) || die "--initrd requires a path"
            initrd=$2
            shift 2
            ;;
        --disk)
            (($# >= 2)) || die "--disk requires a path"
            disk=$2
            shift 2
            ;;
        --append)
            (($# >= 2)) || die "--append requires text"
            append_parts+=("$2")
            shift 2
            ;;
        --qmp-socket)
            (($# >= 2)) || die "--qmp-socket requires a path"
            qmp_socket=$2
            shift 2
            ;;
        --pidfile)
            (($# >= 2)) || die "--pidfile requires a path"
            pidfile=$2
            shift 2
            ;;
        --gdb-port)
            (($# >= 2)) || die "--gdb-port requires a value"
            gdb_port=$2
            shift 2
            ;;
        --guest-cid)
            (($# >= 2)) || die "--guest-cid requires a value"
            guest_cid=$2
            shift 2
            ;;
        --memory-mib)
            (($# >= 2)) || die "--memory-mib requires a value"
            memory_mib=$2
            shift 2
            ;;
        --cpus)
            (($# >= 2)) || die "--cpus requires a value"
            cpus=$2
            shift 2
            ;;
        --dry-run)
            dry_run=1
            shift
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

[[ -n "$kernel" || -n "$disk" ]] ||
    die "at least one of --kernel or --disk is required"
[[ -z "$initrd" || -n "$kernel" ]] ||
    die "--initrd requires --kernel"
[[ ${#append_parts[@]} -eq 0 || -n "$kernel" ]] ||
    die "--append requires --kernel"
if [[ -n "$kernel" ]]; then
    require_readable_file kernel "$kernel"
fi
if [[ -n "$initrd" ]]; then
    require_readable_file initrd "$initrd"
fi
if [[ -n "$disk" ]]; then
    [[ ! -L "$disk" ]] || die "disk must not be a symlink: $disk"
    require_readable_file disk "$disk"
    [[ "$disk" != *$'\n'* ]] || die "disk path contains a newline"
    [[ "$disk" != *,* ]] || die "disk path cannot contain a comma"
fi

QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}
PYTHON_BIN=${PYTHON_BIN:-python3}

QEMU_BIN="$QEMU_BIN" PYTHON_BIN="$PYTHON_BIN" "$SCRIPT_DIR/check-host.sh" \
    --qmp-socket "$qmp_socket" \
    --pidfile "$pidfile" \
    --gdb-port "$gdb_port" \
    --guest-cid "$guest_cid" \
    --memory-mib "$memory_mib" \
    --cpus "$cpus" >/dev/null

gdb_port=$((10#$gdb_port))
guest_cid=$((10#$guest_cid))

qmp_socket_canonical=$(canonicalize_path "$qmp_socket") ||
    die "failed to canonicalize QMP socket path: $qmp_socket"
pidfile_canonical=$(canonicalize_path "$pidfile") ||
    die "failed to canonicalize pidfile path: $pidfile"
[[ "$qmp_socket_canonical" != *,* ]] ||
    die "QMP socket path cannot contain a comma"

if [[ -n "$disk" ]]; then
    disk_metadata=$(canonicalize_disk "$disk") ||
        die "disk security check failed: $disk"
    [[ "$disk_metadata" == *$'\n'* ]] ||
        die "disk security check did not return canonical identity: $disk"
    disk_canonical=${disk_metadata%%$'\n'*}
    disk_lock_key=${disk_metadata#*$'\n'}
    [[ -n "$disk_canonical" && -n "$disk_lock_key" ]] ||
        die "disk security check returned empty canonical identity: $disk"
    [[ "$disk_canonical" != *$'\n'* && "$disk_lock_key" != *$'\n'* ]] ||
        die "disk security check returned empty canonical identity: $disk"
    [[ "$disk_canonical" != *,* ]] ||
        die "disk path cannot contain a comma"
    disk=$disk_canonical
fi

global_lock_root=${FOVEA_LOCK_ROOT:-/tmp/fovea-m0-launch-$(id -u)}
ensure_global_lock_root "$global_lock_root"
global_lock_root=$(canonicalize_path "$global_lock_root") ||
    die "failed to canonicalize global launch lock root: $global_lock_root"

qemu_argv=(
    "$QEMU_BIN"
    -enable-kvm
    -cpu host
    -machine accel=kvm
    -m "$memory_mib"
    -smp "$cpus"
    -device "vhost-vsock-pci,guest-cid=$guest_cid"
    -qmp "unix:$qmp_socket_canonical,server=on,wait=off"
    -gdb "tcp:127.0.0.1:$gdb_port"
    -pidfile "$pidfile_canonical"
    -no-reboot
    -nographic
)

if [[ -n "$kernel" ]]; then
    qemu_argv+=(-kernel "$kernel")
fi
if [[ -n "$initrd" ]]; then
    qemu_argv+=(-initrd "$initrd")
fi
if ((${#append_parts[@]} > 0)); then
    kernel_append=
    for part in "${append_parts[@]}"; do
        if [[ -n "$kernel_append" ]]; then
            kernel_append+=" "
        fi
        kernel_append+="$part"
    done
    qemu_argv+=(-append "$kernel_append")
fi
if [[ -n "$disk" ]]; then
    qemu_argv+=(-drive "file=$disk,if=virtio")
fi

trap cleanup_on_exit EXIT
trap 'forward_signal TERM 143' TERM
trap 'forward_signal INT 130' INT

acquire_launch_lock \
    "${qmp_socket_canonical}.fovea-launch" \
    "${qmp_socket}.fovea-launch"
acquire_launch_lock \
    "${pidfile_canonical}.fovea-launch" \
    "${pidfile}.fovea-launch"
acquire_launch_lock "${global_lock_root}/gdb-${gdb_port}.fovea-launch"
acquire_launch_lock "${global_lock_root}/cid-${guest_cid}.fovea-launch"
if [[ -n "$disk" ]]; then
    acquire_launch_lock \
        "${global_lock_root}/disk-${disk_lock_key}.fovea-launch"
fi

if ((dry_run)); then
    printf '%q ' "${qemu_argv[@]}"
    printf '\n'
    exit 0
fi

if ! exec 3<&0; then
    die "failed to preserve QEMU stdin"
fi
qemu_stdin_saved=1
trap 'defer_launch_signal TERM' TERM
trap 'defer_launch_signal INT' INT
(
    trap - TERM INT
    exec "${qemu_argv[@]}"
) <&3 &
qemu_pid=$!
exec 3<&-
qemu_stdin_saved=0
trap 'forward_signal TERM 143' TERM
trap 'forward_signal INT 130' INT
if [[ -n "$launch_signal" ]]; then
    pending_signal=$launch_signal
    launch_signal=
    case "$pending_signal" in
        TERM)
            forward_signal TERM 143
            ;;
        INT)
            forward_signal INT 130
            ;;
    esac
fi
if wait "$qemu_pid"; then
    qemu_status=0
else
    qemu_status=$?
fi
qemu_pid=
exit "$qemu_status"
