#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RUN_VM="$SCRIPT_DIR/../run-vm.sh"
PYTHON=$(command -v python3)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fovea-run-vm.XXXXXX")
PIDS=

cleanup() {
    local pid
    if [[ -n "${FAKE_QEMU_RELEASE:-}" ]]; then
        : >"$FAKE_QEMU_RELEASE"
    fi
    for pid in $PIDS; do
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    done
    rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

tests=0
failures=0

fail() {
    printf 'not ok %d - %s\n' "$tests" "$1" >&2
    failures=$((failures + 1))
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
ARTIFACTS="$TMP_ROOT/artifacts with spaces"
mkdir -p "$FAKE_BIN" "$PYTHON_MODULES" "$RUNTIME" "$ARTIFACTS"

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
    "$PYTHON" - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

run_vm_fixture() {
    env \
        PYTHONPATH="$PYTHON_MODULES${PYTHONPATH:+:$PYTHONPATH}" \
        UNAME_BIN="$FAKE_BIN/uname" \
        QEMU_BIN="${QEMU_OVERRIDE:-$FAKE_BIN/qemu-system-x86_64}" \
        KVM_DEVICE="$KVM_FILE" \
        PYTHON_BIN="$PYTHON" \
        FAKE_QEMU_READY="${FAKE_QEMU_READY:-}" \
        FAKE_QEMU_RELEASE="${FAKE_QEMU_RELEASE:-}" \
        "$RUN_VM" "$@"
}

KERNEL="$ARTIFACTS/kernel image"
INITRD="$ARTIFACTS/init rd"
DISK="$ARTIFACTS/disk image.qcow2"
: >"$KERNEL"
: >"$INITRD"
: >"$DISK"

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
QMP_PATH="$RUNTIME/qmp socket.sock"
PID_PATH="$RUNTIME/qemu pid"
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
        -qmp "unix:$QMP_PATH,server=on,wait=off"
        -gdb "tcp:127.0.0.1:$GDB_PORT"
        -pidfile "$PID_PATH"
        -no-reboot
        -nographic
        -kernel "$KERNEL"
        -initrd "$INITRD"
        -append "console=ttyS0 root=/dev/vda rw quiet"
        -drive "file=$DISK,if=virtio"
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

tests=$((tests + 1))
concurrent_name="same QMP path is reserved during foreground QEMU"
CONCURRENT_QMP="$RUNTIME/concurrent.qmp.sock"
CONCURRENT_PID="$RUNTIME/concurrent.pid"
CONCURRENT_PORT=$(free_port)
FAKE_QEMU_READY="$TMP_ROOT/qemu-ready"
FAKE_QEMU_RELEASE="$TMP_ROOT/qemu-release"
QEMU_OVERRIDE="$WAIT_QEMU" \
FAKE_QEMU_READY="$FAKE_QEMU_READY" \
FAKE_QEMU_RELEASE="$FAKE_QEMU_RELEASE" \
run_vm_fixture \
    --kernel "$KERNEL" \
    --qmp-socket "$CONCURRENT_QMP" \
    --pidfile "$CONCURRENT_PID" \
    --gdb-port "$CONCURRENT_PORT" \
    >"$TMP_ROOT/first.stdout" 2>"$TMP_ROOT/first.stderr" &
first_pid=$!
PIDS="$PIDS $first_pid"

attempts=0
while [[ ! -e "$FAKE_QEMU_READY" ]] && ((attempts < 300)); do
    if ! kill -0 "$first_pid" >/dev/null 2>&1; then
        break
    fi
    attempts=$((attempts + 1))
    sleep 0.01
done

if [[ ! -e "$FAKE_QEMU_READY" ]]; then
    fail "$concurrent_name (first fake QEMU did not stay active)"
    sed 's/^/  stderr: /' "$TMP_ROOT/first.stderr" >&2
else
    if QEMU_OVERRIDE="$WAIT_QEMU" \
        FAKE_QEMU_READY="$FAKE_QEMU_READY.second" \
        FAKE_QEMU_RELEASE="$FAKE_QEMU_RELEASE" \
        run_vm_fixture \
            --kernel "$KERNEL" \
            --qmp-socket "$CONCURRENT_QMP" \
            --pidfile "$CONCURRENT_PID" \
            --gdb-port "$CONCURRENT_PORT" \
            >"$TMP_ROOT/second.stdout" 2>"$TMP_ROOT/second.stderr"; then
        fail "$concurrent_name (second launch unexpectedly succeeded)"
    elif ! grep -F \
        "launch resources are already reserved: ${CONCURRENT_QMP}.fovea-launch" \
        "$TMP_ROOT/second.stderr" >/dev/null 2>&1; then
        fail "$concurrent_name (missing launch reservation diagnostic)"
        sed 's/^/  stderr: /' "$TMP_ROOT/second.stderr" >&2
    else
        printf 'ok %d - %s\n' "$tests" "$concurrent_name"
    fi
fi

: >"$FAKE_QEMU_RELEASE"
if ! wait "$first_pid"; then
    fail "$concurrent_name (first fake QEMU exited nonzero)"
fi
if [[ -d "${CONCURRENT_QMP}.fovea-launch" ]]; then
    fail "$concurrent_name (launch reservation was not removed)"
fi

if ((failures > 0)); then
    printf 'FAIL: %d of %d tests failed\n' "$failures" "$tests" >&2
    exit 1
fi

printf 'PASS: %d tests\n' "$tests"
