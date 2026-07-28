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
  UNAME_BIN, QEMU_BIN, KVM_DEVICE, PYTHON_BIN
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
    require_readable_file disk "$disk"
    [[ "$disk" != *,* ]] || die "disk path cannot contain a comma"
fi

"$SCRIPT_DIR/check-host.sh" \
    --qmp-socket "$qmp_socket" \
    --pidfile "$pidfile" \
    --gdb-port "$gdb_port" \
    --guest-cid "$guest_cid" \
    --memory-mib "$memory_mib" \
    --cpus "$cpus" >/dev/null

QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}

qemu_argv=(
    "$QEMU_BIN"
    -enable-kvm
    -cpu host
    -machine accel=kvm
    -m "$memory_mib"
    -smp "$cpus"
    -device "vhost-vsock-pci,guest-cid=$guest_cid"
    -qmp "unix:$qmp_socket,server=on,wait=off"
    -gdb "tcp:127.0.0.1:$gdb_port"
    -pidfile "$pidfile"
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

launch_lock="${qmp_socket}.fovea-launch"
if ! (umask 077 && mkdir -- "$launch_lock") 2>/dev/null; then
    die "launch resources are already reserved: $launch_lock"
fi
release_launch_lock() {
    if ! rmdir -- "$launch_lock"; then
        printf 'run-vm: failed to release launch reservation: %s\n' \
            "$launch_lock" >&2
    fi
}
trap release_launch_lock EXIT

if ((dry_run)); then
    printf '%q ' "${qemu_argv[@]}"
    printf '\n'
    exit 0
fi

"${qemu_argv[@]}"
