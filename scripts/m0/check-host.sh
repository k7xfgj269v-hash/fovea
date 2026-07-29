#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: check-host.sh [OPTIONS]

Validate a Linux x86_64 QEMU/KVM host before launching the M0 guest.

Options:
  --qmp-socket PATH  QMP Unix socket path (default: /tmp/fovea-m0.qmp.sock)
  --pidfile PATH     QEMU pidfile path (default: /tmp/fovea-m0.pid)
  --gdb-port PORT    Local GDB TCP port (default: 1234)
  --guest-cid CID    vhost-vsock guest CID, at least 3 (default: 3)
  --memory-mib N     Guest memory in MiB (default: 2048)
  --cpus N           Guest virtual CPU count (default: 2)
  -h, --help         Show this help

Narrow test/tool overrides:
  UNAME_BIN, QEMU_BIN, KVM_DEVICE, PYTHON_BIN
EOF
}

die() {
    printf 'check-host: %s\n' "$*" >&2
    exit 1
}

require_executable() {
    local label=$1
    local candidate=$2

    [[ -n "$candidate" ]] || die "$label is empty"
    if [[ "$candidate" == */* ]]; then
        [[ -x "$candidate" ]] || die "$label is not executable: $candidate"
    else
        command -v "$candidate" >/dev/null 2>&1 ||
            die "$label was not found in PATH: $candidate"
    fi
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

require_unused_path() {
    local label=$1
    local path=$2
    local parent

    unused_path_canonical=

    [[ -n "$path" ]] || die "$label path is empty"
    [[ "$path" != *$'\n'* ]] || die "$label path contains a newline"
    if [[ -e "$path" || -L "$path" ]]; then
        die "$label path already exists: $path"
    fi

    parent=$(dirname -- "$path")
    [[ -e "$parent" || -L "$parent" ]] ||
        die "$label parent directory does not exist: $parent"
    if ! unused_path_canonical=$("$PYTHON_BIN" - "$label" "$parent" "$path" <<'PY'
import os
import signal
import stat
import sys

label, parent, target = sys.argv[1:4]


def reject(message):
    print(f"check-host: {label} {message}", file=sys.stderr)
    raise SystemExit(1)


def handle_timeout(_signum, _frame):
    reject(f"parent directory check timed out: {parent}")


signal.signal(signal.SIGALRM, handle_timeout)
signal.alarm(5)

try:
    parent_stat = os.lstat(parent)
except OSError as exc:
    reject(f"parent directory cannot be inspected: {parent}: {exc}")

if stat.S_ISLNK(parent_stat.st_mode):
    reject(f"parent directory is a symlink: {parent}")
if not stat.S_ISDIR(parent_stat.st_mode):
    reject(f"parent path is not a directory: {parent}")

try:
    canonical_parent = os.path.realpath(parent)
    canonical_stat = os.lstat(canonical_parent)
except OSError as exc:
    reject(f"canonical parent directory cannot be inspected: {parent}: {exc}")

if stat.S_ISLNK(canonical_stat.st_mode):
    reject(f"canonical parent directory is a symlink: {canonical_parent}")
if not stat.S_ISDIR(canonical_stat.st_mode):
    reject(f"canonical parent path is not a directory: {canonical_parent}")

for checked_path, checked_stat in (
    (parent, parent_stat),
    (canonical_parent, canonical_stat),
):
    if checked_stat.st_uid != os.getuid():
        reject(
            f"parent directory is not owned by the invoking user: "
            f"{checked_path}"
        )
    if stat.S_IMODE(checked_stat.st_mode) != 0o700:
        reject(f"parent directory must have mode 700: {checked_path}")
    if not os.access(checked_path, os.W_OK):
        reject(f"parent directory is not writable: {checked_path}")
    if not os.access(checked_path, os.X_OK):
        reject(
            f"parent directory is not searchable/executable: "
            f"{checked_path}"
        )

try:
    if os.path.lexists(target):
        reject(f"path already exists: {target}")
except OSError as exc:
    reject(f"path cannot be inspected: {target}: {exc}")

target_name = os.path.basename(target)
if not target_name:
    reject(f"path has no target name: {target}")

canonical_target = os.path.realpath(
    os.path.join(canonical_parent, target_name)
)
signal.alarm(0)
print(canonical_target)
PY
    ); then
        die "$label parent directory security check failed: $parent"
    fi
}

qmp_socket=/tmp/fovea-m0.qmp.sock
pidfile=/tmp/fovea-m0.pid
gdb_port=1234
guest_cid=3
memory_mib=2048
cpus=2

while (($# > 0)); do
    case "$1" in
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
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

UNAME_BIN=${UNAME_BIN:-uname}
QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}
KVM_DEVICE=${KVM_DEVICE:-/dev/kvm}
PYTHON_BIN=${PYTHON_BIN:-python3}

require_executable UNAME_BIN "$UNAME_BIN"

host_os=$("$UNAME_BIN" -s) || die "failed to read the host operating system"
[[ "$host_os" == Linux ]] || die "Linux is required; detected: $host_os"

host_arch=$("$UNAME_BIN" -m) || die "failed to read the host architecture"
[[ "$host_arch" == x86_64 ]] ||
    die "x86_64 is required; detected: $host_arch"

require_uint_range gdb-port "$gdb_port" 1 65535
require_uint_range guest-cid "$guest_cid" 3 4294967294
require_uint_range memory-mib "$memory_mib" 1 1048576
require_uint_range cpus "$cpus" 1 4096

[[ -e "$KVM_DEVICE" ]] || die "KVM device is missing: $KVM_DEVICE"
[[ -r "$KVM_DEVICE" && -w "$KVM_DEVICE" ]] ||
    die "KVM device must be readable and writable: $KVM_DEVICE"

require_executable QEMU_BIN "$QEMU_BIN"
require_executable PYTHON_BIN "$PYTHON_BIN"

if ! "$PYTHON_BIN" - "$KVM_DEVICE" <<'PY'
import fcntl
import os
import sys

device = sys.argv[1]
flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
try:
    fd = os.open(device, flags)
except OSError as exc:
    print(f"cannot open KVM device read-write: {exc}", file=sys.stderr)
    raise SystemExit(1)

try:
    try:
        version = fcntl.ioctl(fd, 0xAE00)
    except OSError as exc:
        print(f"KVM_GET_API_VERSION ioctl failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
finally:
    os.close(fd)

if version != 12:
    print(f"KVM API version is {version}; expected 12", file=sys.stderr)
    raise SystemExit(1)
PY
then
    die "KVM API check failed: $KVM_DEVICE"
fi

[[ "$qmp_socket" != "$pidfile" ]] ||
    die "QMP socket and pidfile paths must be different"
[[ "$qmp_socket" != *,* ]] ||
    die "QMP socket path cannot contain a comma"
require_unused_path "QMP socket" "$qmp_socket"
qmp_socket_canonical=$unused_path_canonical
require_unused_path pidfile "$pidfile"
pidfile_canonical=$unused_path_canonical

[[ "$qmp_socket_canonical" != "$pidfile_canonical" ]] ||
    die "QMP socket and pidfile paths resolve to the same canonical path: $qmp_socket_canonical"

if ! "$PYTHON_BIN" - "$gdb_port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", port))
except OSError as exc:
    print(f"GDB port 127.0.0.1:{port} is unavailable: {exc}", file=sys.stderr)
    raise SystemExit(1)
finally:
    sock.close()
PY
then
    die "GDB port is occupied or unavailable: $gdb_port"
fi

printf 'host-ready\n'
