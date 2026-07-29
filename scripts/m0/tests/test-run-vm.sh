#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUN_VM="$SCRIPT_DIR/../run-vm.sh"
PYTHON=$(command -v python3)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fovea-run-vm.XXXXXX")
PIDS=()
WAIT_RELEASE_FILES=()
TERM_RELEASE_FILES=()

cleanup() {
    local pid
    local release
    if ((${#WAIT_RELEASE_FILES[@]} > 0)); then
        for release in "${WAIT_RELEASE_FILES[@]}"; do
            : >"$release"
        done
    fi
    if ((${#TERM_RELEASE_FILES[@]} > 0)); then
        for release in "${TERM_RELEASE_FILES[@]}"; do
            : >"$release"
        done
    fi
    if ((${#PIDS[@]} > 0)); then
        for pid in "${PIDS[@]}"; do
            kill "$pid" >/dev/null 2>&1 || true
        done
        for pid in "${PIDS[@]}"; do
            wait "$pid" >/dev/null 2>&1 || true
        done
    fi
    rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

tests=0
failures=0

fail() {
    printf 'not ok %d - %s\n' "$tests" "$1" >&2
    failures=$((failures + 1))
}

forget_pid() {
    local pid=$1
    local item
    local remaining=()

    for item in "${PIDS[@]}"; do
        if [[ "$item" != "$pid" ]]; then
            remaining[${#remaining[@]}]=$item
        fi
    done
    if ((${#remaining[@]} == 0)); then
        PIDS=()
    else
        PIDS=("${remaining[@]}")
    fi
}

wait_for_file() {
    local path=$1
    local pid=$2
    local attempts=0

    while [[ ! -e "$path" ]] && ((attempts < 300)); do
        if ! kill -0 "$pid" >/dev/null 2>&1; then
            return 1
        fi
        attempts=$((attempts + 1))
        sleep 0.01
    done
    [[ -e "$path" ]]
}

assert_present() {
    local name=$1
    local path=$2

    if [[ ! -d "$path" ]]; then
        fail "$name (missing lock directory: $path)"
        return 1
    fi
    return 0
}

assert_absent() {
    local name=$1
    local path=$2

    if [[ -e "$path" || -L "$path" ]]; then
        fail "$name (lock directory remains: $path)"
        return 1
    fi
    return 0
}

run_failure_case() {
    local name=$1
    local expected_text=$2
    shift 2

    tests=$((tests + 1))
    local stdout_file="$TMP_ROOT/stdout.$tests"
    local stderr_file="$TMP_ROOT/stderr.$tests"
    local status

    if "$@" >"$stdout_file" 2>"$stderr_file"; then
        status=0
    else
        status=$?
    fi

    if ((status == 0)); then
        fail "$name (unexpected success)"
        return
    fi
    if ! grep -F -- "$expected_text" "$stderr_file" >/dev/null 2>&1; then
        fail "$name (missing: $expected_text)"
        sed 's/^/  stderr: /' "$stderr_file" >&2
        return
    fi

    printf 'ok %d - %s\n' "$tests" "$name"
}

FAKE_BIN="$TMP_ROOT/bin"
PYTHON_MODULES="$TMP_ROOT/python-modules"
RUNTIME="$TMP_ROOT/runtime"
PRIVATE_TMPDIR="$TMP_ROOT/tmp"
ALTERNATE_TMPDIR="$TMP_ROOT/alternate-tmp"
GLOBAL_LOCK_ROOT="$TMP_ROOT/global-locks"
ARTIFACTS="$TMP_ROOT/artifacts with spaces"
mkdir -p \
    "$FAKE_BIN" \
    "$PYTHON_MODULES" \
    "$RUNTIME" \
    "$PRIVATE_TMPDIR" \
    "$ALTERNATE_TMPDIR" \
    "$GLOBAL_LOCK_ROOT" \
    "$ARTIFACTS"
chmod 700 \
    "$RUNTIME" \
    "$PRIVATE_TMPDIR" \
    "$ALTERNATE_TMPDIR" \
    "$GLOBAL_LOCK_ROOT" \
    "$ARTIFACTS"

cat >"$FAKE_BIN/uname" <<'EOF'
#!/bin/sh
case "${1-}" in
    -s) printf 'Linux\n' ;;
    -m) printf 'x86_64\n' ;;
    *) exit 2 ;;
esac
EOF

cat >"$FAKE_BIN/qemu-system-x86_64" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$PYTHON_MODULES/fcntl.py" <<'EOF'
def ioctl(_fd, request):
    if request != 0xAE00:
        raise OSError("unexpected ioctl request")
    return 12
EOF

chmod +x "$FAKE_BIN/uname" "$FAKE_BIN/qemu-system-x86_64"
KVM_FILE="$TMP_ROOT/kvm"
: >"$KVM_FILE"

free_port() {
    local port
    while :; do
        port=$("$PYTHON" - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)
        case " ${USED_PORTS:-} " in
            *" $port "*) ;;
            *)
                USED_PORTS="${USED_PORTS:-} $port"
                printf '%s\n' "$port"
                return
                ;;
        esac
    done
}

run_vm_fixture() {
    local fixture_tmpdir=${FIXTURE_TMPDIR:-$PRIVATE_TMPDIR}

    env \
        TMPDIR="$fixture_tmpdir" \
        FOVEA_LOCK_ROOT="$GLOBAL_LOCK_ROOT" \
        PYTHONPATH="$PYTHON_MODULES${PYTHONPATH:+:$PYTHONPATH}" \
        UNAME_BIN="$FAKE_BIN/uname" \
        QEMU_BIN="${QEMU_OVERRIDE:-$FAKE_BIN/qemu-system-x86_64}" \
        KVM_DEVICE="$KVM_FILE" \
        PYTHON_BIN="$PYTHON" \
        FAKE_QEMU_READY="${FAKE_QEMU_READY:-}" \
        FAKE_QEMU_RELEASE="${FAKE_QEMU_RELEASE:-}" \
        FAKE_QEMU_TERM_RECEIVED="${FAKE_QEMU_TERM_RECEIVED:-}" \
        FAKE_QEMU_TERM_RELEASE="${FAKE_QEMU_TERM_RELEASE:-}" \
        FAKE_QEMU_PID_FILE="${FAKE_QEMU_PID_FILE:-}" \
        "$RUN_VM" "$@"
}

KERNEL="$ARTIFACTS/kernel image"
INITRD="$ARTIFACTS/init rd"
DISK="$ARTIFACTS/disk image.qcow2"
: >"$KERNEL"
: >"$INITRD"
: >"$DISK"
DISK_CANONICAL=$("$PYTHON" - "$DISK" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)

run_failure_case \
    "missing kernel and disk are rejected" \
    "at least one of --kernel or --disk is required" \
    "$RUN_VM"
run_failure_case \
    "initrd without kernel is rejected" \
    "--initrd requires --kernel" \
    "$RUN_VM" --initrd "$INITRD" --disk "$DISK"
run_failure_case \
    "append without kernel is rejected" \
    "--append requires --kernel" \
    "$RUN_VM" --append "console=ttyS0" --disk "$DISK"
run_failure_case \
    "missing kernel file is rejected" \
    "kernel must be a readable regular file" \
    "$RUN_VM" --kernel "$TMP_ROOT/missing-kernel"

COMMA_DISK="$ARTIFACTS/disk,image.qcow2"
: >"$COMMA_DISK"
run_failure_case \
    "comma in disk path is rejected" \
    "disk path cannot contain a comma" \
    "$RUN_VM" --disk "$COMMA_DISK"

tests=$((tests + 1))
dry_name="dry-run preserves shell-safe argv and exact VM flags"
PATH_ALIAS_ROOT="$RUNTIME/path-alias"
mkdir "$PATH_ALIAS_ROOT"
mkdir "$PATH_ALIAS_ROOT/real"
chmod 700 "$PATH_ALIAS_ROOT" "$PATH_ALIAS_ROOT/real"
ln -s "$PATH_ALIAS_ROOT/real" "$PATH_ALIAS_ROOT/link"
QMP_PATH="$PATH_ALIAS_ROOT/link/../qmp socket.sock"
PID_PATH="$PATH_ALIAS_ROOT/link/../qemu pid"
QMP_CANONICAL=$("$PYTHON" - "$QMP_PATH" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)
PID_CANONICAL=$("$PYTHON" - "$PID_PATH" <<'PY'
import os
import sys

print(os.path.realpath(sys.argv[1]))
PY
)
GDB_PORT=$(free_port)
if run_vm_fixture \
    --kernel "$KERNEL" \
    --initrd "$INITRD" \
    --disk "$DISK" \
    --append "console=ttyS0" \
    --append "root=/dev/vda rw quiet" \
    --qmp-socket "$QMP_PATH" \
    --pidfile "$PID_PATH" \
    --gdb-port "$GDB_PORT" \
    --guest-cid 9 \
    --memory-mib 3072 \
    --cpus 4 \
    --dry-run \
    >"$TMP_ROOT/dry-run.stdout" 2>"$TMP_ROOT/dry-run.stderr"; then
    expected_argv=(
        "$FAKE_BIN/qemu-system-x86_64"
        -enable-kvm
        -cpu host
        -machine accel=kvm
        -m 3072
        -smp 4
        -device "vhost-vsock-pci,guest-cid=9"
        -qmp "unix:$QMP_CANONICAL,server=on,wait=off"
        -gdb "tcp:127.0.0.1:$GDB_PORT"
        -pidfile "$PID_CANONICAL"
        -no-reboot
        -nographic
        -kernel "$KERNEL"
        -initrd "$INITRD"
        -append "console=ttyS0 root=/dev/vda rw quiet"
        -drive "file=$DISK_CANONICAL,if=virtio"
    )
    expected_output=
    printf -v expected_output '%q ' "${expected_argv[@]}"
    expected_output+=$'\n'

    if printf '%s' "$expected_output" |
        cmp -s - "$TMP_ROOT/dry-run.stdout"; then
        printf 'ok %d - %s\n' "$tests" "$dry_name"
    else
        fail "$dry_name (output mismatch)"
        sed 's/^/  output: /' "$TMP_ROOT/dry-run.stdout" >&2
    fi
else
    fail "$dry_name (dry-run failed)"
    sed 's/^/  stderr: /' "$TMP_ROOT/dry-run.stderr" >&2
fi

STDIN_QEMU="$FAKE_BIN/qemu-stdin"
cat >"$STDIN_QEMU" <<'EOF'
#!/bin/sh
IFS= read -r token || exit 1
[ "$token" = fovea-stdin-test ] || exit 2
EOF
chmod +x "$STDIN_QEMU"

tests=$((tests + 1))
stdin_name="attached QEMU stdin is preserved"
STDIN_QMP="$RUNTIME/stdin.qmp.sock"
STDIN_PIDFILE="$RUNTIME/stdin.pid"
STDIN_PORT=$(free_port)
if printf 'fovea-stdin-test\n' |
    QEMU_OVERRIDE="$STDIN_QEMU" \
    run_vm_fixture \
        --kernel "$KERNEL" \
        --qmp-socket "$STDIN_QMP" \
        --pidfile "$STDIN_PIDFILE" \
        --gdb-port "$STDIN_PORT" \
        --guest-cid 15 \
        >"$TMP_ROOT/stdin.stdout" 2>"$TMP_ROOT/stdin.stderr"; then
    printf 'ok %d - %s\n' "$tests" "$stdin_name"
else
    fail "$stdin_name"
    sed 's/^/  stderr: /' "$TMP_ROOT/stdin.stderr" >&2
fi

WAIT_QEMU="$FAKE_BIN/qemu-wait"
cat >"$WAIT_QEMU" <<'EOF'
#!/bin/sh
: >"$FAKE_QEMU_READY"
while [ ! -e "$FAKE_QEMU_RELEASE" ]; do
    sleep 0.01
done
exit 0
EOF
chmod +x "$WAIT_QEMU"

start_waiting_vm() {
    local qmp_socket=$1
    local pidfile=$2
    local gdb_port=$3
    local guest_cid=$4
    local ready_file=$5
    local release_file=$6
    local stdout_file=$7
    local stderr_file=$8
    local disk=${9-}
    local fixture_tmpdir=${10:-$PRIVATE_TMPDIR}
    local vm_pid
    local -a vm_args

    rm -f -- "$ready_file" "$release_file"
    WAIT_RELEASE_FILES[${#WAIT_RELEASE_FILES[@]}]="$release_file"
    vm_args=(
        --kernel "$KERNEL"
        --qmp-socket "$qmp_socket"
        --pidfile "$pidfile"
        --gdb-port "$gdb_port"
        --guest-cid "$guest_cid"
    )
    if [[ -n "$disk" ]]; then
        vm_args+=(--disk "$disk")
    fi

    (
        exec env \
            TMPDIR="$fixture_tmpdir" \
            FOVEA_LOCK_ROOT="$GLOBAL_LOCK_ROOT" \
            PYTHONPATH="$PYTHON_MODULES${PYTHONPATH:+:$PYTHONPATH}" \
            UNAME_BIN="$FAKE_BIN/uname" \
            QEMU_BIN="$WAIT_QEMU" \
            KVM_DEVICE="$KVM_FILE" \
            PYTHON_BIN="$PYTHON" \
            FAKE_QEMU_READY="$ready_file" \
            FAKE_QEMU_RELEASE="$release_file" \
            "$RUN_VM" "${vm_args[@]}"
    ) >"$stdout_file" 2>"$stderr_file" &
    vm_pid=$!
    PIDS[${#PIDS[@]}]=$vm_pid
    LAST_VM_PID=$vm_pid

    if wait_for_file "$ready_file" "$vm_pid"; then
        return 0
    fi

    : >"$release_file"
    wait "$vm_pid" >/dev/null 2>&1 || true
    forget_pid "$vm_pid"
    return 1
}

run_resource_conflict_case() {
    local name=$1
    local expected_text=$2
    local first_qmp=$3
    local first_pidfile=$4
    local first_port=$5
    local first_cid=$6
    local second_qmp=$7
    local second_pidfile=$8
    local second_port=$9
    local second_cid=${10}
    local first_disk=${11-}
    local second_disk=${12-}
    local label=${13}
    local first_tmpdir=${14:-$PRIVATE_TMPDIR}
    local second_tmpdir=${15:-$PRIVATE_TMPDIR}
    local first_ready="$TMP_ROOT/$label.first.ready"
    local first_release="$TMP_ROOT/$label.first.release"
    local second_ready="$TMP_ROOT/$label.second.ready"
    local second_release="$TMP_ROOT/$label.second.release"
    local first_stdout="$TMP_ROOT/$label.first.stdout"
    local first_stderr="$TMP_ROOT/$label.first.stderr"
    local second_stdout="$TMP_ROOT/$label.second.stdout"
    local second_stderr="$TMP_ROOT/$label.second.stderr"
    local first_pid
    local second_status
    local first_status
    local disk_key
    local lock_root="$GLOBAL_LOCK_ROOT"
    local -a first_locks
    local -a second_args

    tests=$((tests + 1))
    first_locks=(
        "${first_qmp}.fovea-launch"
        "${first_pidfile}.fovea-launch"
        "$lock_root/gdb-${first_port}.fovea-launch"
        "$lock_root/cid-${first_cid}.fovea-launch"
    )
    if [[ -n "$first_disk" ]]; then
        disk_key=$("$PYTHON" - "$first_disk" <<'PY'
import os
import sys

disk_stat = os.stat(sys.argv[1])
print(f"{disk_stat.st_dev:x}-{disk_stat.st_ino:x}")
PY
)
        first_locks[${#first_locks[@]}]="$lock_root/disk-$disk_key.fovea-launch"
    fi

    if ! start_waiting_vm \
        "$first_qmp" "$first_pidfile" "$first_port" "$first_cid" \
        "$first_ready" "$first_release" "$first_stdout" "$first_stderr" \
        "$first_disk" "$first_tmpdir"; then
        fail "$name (first fake QEMU did not stay active)"
        sed 's/^/  stderr: /' "$first_stderr" >&2
        return
    fi
    first_pid=$LAST_VM_PID

    for lock_path in "${first_locks[@]}"; do
        assert_present "$name" "$lock_path" || true
    done

    rm -f -- "$second_ready"
    : >"$second_release"
    WAIT_RELEASE_FILES[${#WAIT_RELEASE_FILES[@]}]="$second_release"
    second_args=(
        --kernel "$KERNEL"
        --qmp-socket "$second_qmp"
        --pidfile "$second_pidfile"
        --gdb-port "$second_port"
        --guest-cid "$second_cid"
    )
    if [[ -n "$second_disk" ]]; then
        second_args+=(--disk "$second_disk")
    fi

    if FIXTURE_TMPDIR="$second_tmpdir" \
        QEMU_OVERRIDE="$WAIT_QEMU" \
        FAKE_QEMU_READY="$second_ready" \
        FAKE_QEMU_RELEASE="$second_release" \
        run_vm_fixture "${second_args[@]}" \
        >"$second_stdout" 2>"$second_stderr"; then
        second_status=0
    else
        second_status=$?
    fi

    if ((second_status == 0)); then
        fail "$name (second launch unexpectedly succeeded)"
    elif ! grep -F -- "$expected_text" "$second_stderr" >/dev/null 2>&1; then
        fail "$name (missing: $expected_text)"
        sed 's/^/  stderr: /' "$second_stderr" >&2
    elif [[ -e "$second_ready" ]]; then
        fail "$name (second fake QEMU was started)"
    else
        printf 'ok %d - %s\n' "$tests" "$name"
    fi

    : >"$first_release"
    if wait "$first_pid"; then
        first_status=0
    else
        first_status=$?
    fi
    forget_pid "$first_pid"
    if ((first_status != 0)); then
        fail "$name (first fake QEMU exited with status $first_status)"
    fi

    for lock_path in "${first_locks[@]}"; do
        assert_absent "$name" "$lock_path" || true
    done
    assert_absent "$name" "${second_qmp}.fovea-launch" || true
    assert_absent "$name" "${second_pidfile}.fovea-launch" || true
}

run_resource_conflict_case \
    "same QMP path is reserved during foreground QEMU" \
    "launch resources are already reserved: $RUNTIME/concurrent.qmp.sock.fovea-launch" \
    "$RUNTIME/concurrent.qmp.sock" \
    "$RUNTIME/concurrent.pid" \
    "$(free_port)" \
    21 \
    "$RUNTIME/concurrent.qmp.sock" \
    "$RUNTIME/concurrent.pid" \
    "$(free_port)" \
    22 \
    "" \
    "" \
    concurrent-qmp

SHARED_PID="$RUNTIME/shared.pid"
run_resource_conflict_case \
    "different QMP paths reject a shared pidfile" \
    "launch resources are already reserved: $SHARED_PID.fovea-launch" \
    "$RUNTIME/pid-first.qmp.sock" \
    "$SHARED_PID" \
    "$(free_port)" \
    31 \
    "$RUNTIME/pid-second.qmp.sock" \
    "$SHARED_PID" \
    "$(free_port)" \
    32 \
    "" \
    "" \
    pidfile-lock

SHARED_PORT=$(free_port)
run_resource_conflict_case \
    "different QMP paths reject a shared GDB port" \
    "gdb-${SHARED_PORT}.fovea-launch" \
    "$RUNTIME/port-first.qmp.sock" \
    "$RUNTIME/port-first.pid" \
    "$SHARED_PORT" \
    41 \
    "$RUNTIME/port-second.qmp.sock" \
    "$RUNTIME/port-second.pid" \
    "$SHARED_PORT" \
    42 \
    "" \
    "" \
    gdb-port-lock

SHARED_CID=51
run_resource_conflict_case \
    "different QMP paths reject a shared guest CID" \
    "cid-${SHARED_CID}.fovea-launch" \
    "$RUNTIME/cid-first.qmp.sock" \
    "$RUNTIME/cid-first.pid" \
    "$(free_port)" \
    "$SHARED_CID" \
    "$RUNTIME/cid-second.qmp.sock" \
    "$RUNTIME/cid-second.pid" \
    "$(free_port)" \
    "$SHARED_CID" \
    "" \
    "" \
    guest-cid-lock

SHARED_CROSS_TMP_PORT=$(free_port)
run_resource_conflict_case \
    "different TMPDIRs reject a shared GDB port" \
    "gdb-${SHARED_CROSS_TMP_PORT}.fovea-launch" \
    "$RUNTIME/cross-tmp-port-first.qmp.sock" \
    "$RUNTIME/cross-tmp-port-first.pid" \
    "$SHARED_CROSS_TMP_PORT" \
    81 \
    "$RUNTIME/cross-tmp-port-second.qmp.sock" \
    "$RUNTIME/cross-tmp-port-second.pid" \
    "$SHARED_CROSS_TMP_PORT" \
    82 \
    "" \
    "" \
    cross-tmp-gdb \
    "$PRIVATE_TMPDIR" \
    "$ALTERNATE_TMPDIR"

SHARED_CROSS_TMP_CID=91
run_resource_conflict_case \
    "different TMPDIRs reject a shared guest CID" \
    "cid-${SHARED_CROSS_TMP_CID}.fovea-launch" \
    "$RUNTIME/cross-tmp-cid-first.qmp.sock" \
    "$RUNTIME/cross-tmp-cid-first.pid" \
    "$(free_port)" \
    "$SHARED_CROSS_TMP_CID" \
    "$RUNTIME/cross-tmp-cid-second.qmp.sock" \
    "$RUNTIME/cross-tmp-cid-second.pid" \
    "$(free_port)" \
    "$SHARED_CROSS_TMP_CID" \
    "" \
    "" \
    cross-tmp-cid \
    "$PRIVATE_TMPDIR" \
    "$ALTERNATE_TMPDIR"

SHARED_CROSS_TMP_DISK="$ARTIFACTS/cross-tmp-disk-hardlink.qcow2"
ln "$DISK" "$SHARED_CROSS_TMP_DISK"
CROSS_TMP_DISK_LOCK_KEY=$("$PYTHON" - "$DISK" <<'PY'
import os
import sys

disk_stat = os.stat(sys.argv[1])
print(f"{disk_stat.st_dev:x}-{disk_stat.st_ino:x}")
PY
)
run_resource_conflict_case \
    "different TMPDIRs reject a shared disk identity" \
    "disk-${CROSS_TMP_DISK_LOCK_KEY}.fovea-launch" \
    "$RUNTIME/cross-tmp-disk-first.qmp.sock" \
    "$RUNTIME/cross-tmp-disk-first.pid" \
    "$(free_port)" \
    101 \
    "$RUNTIME/cross-tmp-disk-second.qmp.sock" \
    "$RUNTIME/cross-tmp-disk-second.pid" \
    "$(free_port)" \
    102 \
    "$DISK" \
    "$SHARED_CROSS_TMP_DISK" \
    cross-tmp-disk \
    "$PRIVATE_TMPDIR" \
    "$ALTERNATE_TMPDIR"

DISK_HARDLINK="$ARTIFACTS/disk-hardlink.qcow2"
ln "$DISK" "$DISK_HARDLINK"
DISK_LOCK_KEY=$("$PYTHON" - "$DISK" <<'PY'
import os
import sys

disk_stat = os.stat(sys.argv[1])
print(f"{disk_stat.st_dev:x}-{disk_stat.st_ino:x}")
PY
)
run_resource_conflict_case \
    "hardlink aliases reject a shared disk identity" \
    "disk-${DISK_LOCK_KEY}.fovea-launch" \
    "$RUNTIME/disk-first.qmp.sock" \
    "$RUNTIME/disk-first.pid" \
    "$(free_port)" \
    61 \
    "$RUNTIME/disk-second.qmp.sock" \
    "$RUNTIME/disk-second.pid" \
    "$(free_port)" \
    62 \
    "$DISK" \
    "$DISK_HARDLINK" \
    disk-identity-lock

SIGNAL_QEMU="$FAKE_BIN/qemu-signal-wait"
cat >"$SIGNAL_QEMU" <<'EOF'
#!/bin/sh
printf '%s\n' "$$" >"$FAKE_QEMU_PID_FILE"
: >"$FAKE_QEMU_READY"

handle_term() {
    : >"$FAKE_QEMU_TERM_RECEIVED"
    while [ ! -e "$FAKE_QEMU_TERM_RELEASE" ]; do
        sleep 0.01
    done
    exit 143
}

trap handle_term TERM INT
while :; do
    sleep 0.01
done
EOF
chmod +x "$SIGNAL_QEMU"

tests=$((tests + 1))
signal_name="TERM is forwarded and locks outlive the child"
SIGNAL_QMP="$RUNTIME/signal.qmp.sock"
SIGNAL_PIDFILE="$RUNTIME/signal.pid"
SIGNAL_PORT=$(free_port)
SIGNAL_CID=71
SIGNAL_READY="$TMP_ROOT/signal.ready"
SIGNAL_TERM_RECEIVED="$TMP_ROOT/signal.term-received"
SIGNAL_TERM_RELEASE="$TMP_ROOT/signal.term-release"
SIGNAL_QEMU_PID_FILE="$TMP_ROOT/signal.qemu-pid"
SIGNAL_STDOUT="$TMP_ROOT/signal.stdout"
SIGNAL_STDERR="$TMP_ROOT/signal.stderr"
SIGNAL_LOCK_ROOT="$GLOBAL_LOCK_ROOT"
SIGNAL_WRAPPER_PID=
SIGNAL_QEMU_PID=
TERM_RELEASE_FILES[${#TERM_RELEASE_FILES[@]}]="$SIGNAL_TERM_RELEASE"
rm -f -- "$SIGNAL_READY" "$SIGNAL_TERM_RECEIVED" "$SIGNAL_QEMU_PID_FILE"
signal_pass=1

(
    exec env \
        TMPDIR="$PRIVATE_TMPDIR" \
        FOVEA_LOCK_ROOT="$GLOBAL_LOCK_ROOT" \
        PYTHONPATH="$PYTHON_MODULES${PYTHONPATH:+:$PYTHONPATH}" \
        UNAME_BIN="$FAKE_BIN/uname" \
        QEMU_BIN="$SIGNAL_QEMU" \
        KVM_DEVICE="$KVM_FILE" \
        PYTHON_BIN="$PYTHON" \
        FAKE_QEMU_READY="$SIGNAL_READY" \
        FAKE_QEMU_TERM_RECEIVED="$SIGNAL_TERM_RECEIVED" \
        FAKE_QEMU_TERM_RELEASE="$SIGNAL_TERM_RELEASE" \
        FAKE_QEMU_PID_FILE="$SIGNAL_QEMU_PID_FILE" \
        "$RUN_VM" \
        --kernel "$KERNEL" \
        --qmp-socket "$SIGNAL_QMP" \
        --pidfile "$SIGNAL_PIDFILE" \
        --gdb-port "$SIGNAL_PORT" \
        --guest-cid "$SIGNAL_CID"
) >"$SIGNAL_STDOUT" 2>"$SIGNAL_STDERR" &
SIGNAL_WRAPPER_PID=$!
PIDS[${#PIDS[@]}]=$SIGNAL_WRAPPER_PID

if ! wait_for_file "$SIGNAL_READY" "$SIGNAL_WRAPPER_PID"; then
    fail "$signal_name (fake QEMU did not become ready)"
    sed 's/^/  stderr: /' "$SIGNAL_STDERR" >&2
    signal_pass=0
else
    SIGNAL_QEMU_PID=$(sed -n '1p' "$SIGNAL_QEMU_PID_FILE")
    kill -TERM "$SIGNAL_WRAPPER_PID"
    if ! wait_for_file "$SIGNAL_TERM_RECEIVED" "$SIGNAL_QEMU_PID"; then
        fail "$signal_name (fake QEMU did not receive TERM)"
        signal_pass=0
    elif ! kill -0 "$SIGNAL_WRAPPER_PID" >/dev/null 2>&1; then
        fail "$signal_name (wrapper exited before child exit)"
        signal_pass=0
    else
        assert_present "$signal_name" "${SIGNAL_QMP}.fovea-launch" || true
        assert_present "$signal_name" "${SIGNAL_PIDFILE}.fovea-launch" || true
        assert_present "$signal_name" "$SIGNAL_LOCK_ROOT/gdb-${SIGNAL_PORT}.fovea-launch" || true
        assert_present "$signal_name" "$SIGNAL_LOCK_ROOT/cid-${SIGNAL_CID}.fovea-launch" || true
    fi

    : >"$SIGNAL_TERM_RELEASE"
    if wait "$SIGNAL_WRAPPER_PID"; then
        SIGNAL_STATUS=0
    else
        SIGNAL_STATUS=$?
    fi
    forget_pid "$SIGNAL_WRAPPER_PID"
    if ((SIGNAL_STATUS != 143)); then
        fail "$signal_name (expected status 143, got $SIGNAL_STATUS)"
        signal_pass=0
    elif [[ -n "$SIGNAL_QEMU_PID" ]] &&
        kill -0 "$SIGNAL_QEMU_PID" >/dev/null 2>&1; then
        fail "$signal_name (fake QEMU process is still alive)"
        signal_pass=0
    elif [[ -d "${SIGNAL_QMP}.fovea-launch" ||
        -d "${SIGNAL_PIDFILE}.fovea-launch" ||
        -d "$SIGNAL_LOCK_ROOT/gdb-${SIGNAL_PORT}.fovea-launch" ||
        -d "$SIGNAL_LOCK_ROOT/cid-${SIGNAL_CID}.fovea-launch" ]]; then
        fail "$signal_name (launch lock remains after child exit)"
        signal_pass=0
    fi
    if ((signal_pass)); then
        printf 'ok %d - %s\n' "$tests" "$signal_name"
    fi
fi

if ((failures > 0)); then
    printf 'FAIL: %d of %d tests failed\n' "$failures" "$tests" >&2
    exit 1
fi

printf 'PASS: %d tests\n' "$tests"
