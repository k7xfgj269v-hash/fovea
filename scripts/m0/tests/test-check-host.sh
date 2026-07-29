#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECK_HOST="$SCRIPT_DIR/../check-host.sh"
PT_PROBE="$SCRIPT_DIR/../guest-pt-probe.sh"
PYTHON=$(command -v python3)
TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/fovea-check-host.XXXXXX")
PIDS=

cleanup() {
    local pid
    for pid in $PIDS; do
        kill "$pid" >/dev/null 2>&1 || true
        wait "$pid" >/dev/null 2>&1 || true
    done
    chmod -R u+rwX "$TMP_ROOT" >/dev/null 2>&1 || true
    rm -rf -- "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

tests=0
failures=0

fail() {
    printf 'not ok %d - %s\n' "$tests" "$1" >&2
    failures=$((failures + 1))
}

run_case() {
    local name=$1
    local expected_status=$2
    local expected_text=$3
    shift 3

    tests=$((tests + 1))
    local stdout_file="$TMP_ROOT/stdout.$tests"
    local stderr_file="$TMP_ROOT/stderr.$tests"
    local status

    if "$@" >"$stdout_file" 2>"$stderr_file"; then
        status=0
    else
        status=$?
    fi

    if [[ "$expected_status" == success ]]; then
        if ((status != 0)); then
            fail "$name (exit $status)"
            sed 's/^/  stderr: /' "$stderr_file" >&2
            return
        fi
    elif ((status == 0)); then
        fail "$name (unexpected success)"
        return
    fi

    if ! grep -F -- "$expected_text" "$stdout_file" "$stderr_file" >/dev/null 2>&1; then
        fail "$name (missing: $expected_text)"
        sed 's/^/  stdout: /' "$stdout_file" >&2
        sed 's/^/  stderr: /' "$stderr_file" >&2
        return
    fi

    printf 'ok %d - %s\n' "$tests" "$name"
}

run_exact_token() {
    local name=$1
    local expected=$2
    shift 2

    tests=$((tests + 1))
    local stdout_file="$TMP_ROOT/stdout.$tests"
    local stderr_file="$TMP_ROOT/stderr.$tests"
    local status
    local line_count

    if "$@" >"$stdout_file" 2>"$stderr_file"; then
        status=0
    else
        status=$?
    fi
    line_count=$(wc -l <"$stdout_file" | tr -d '[:space:]')

    if ((status != 0)) ||
        [[ "$line_count" != 1 ]] ||
        ! grep -Fx -- "$expected" "$stdout_file" >/dev/null 2>&1 ||
        [[ -s "$stderr_file" ]]; then
        fail "$name (expected one '$expected' token and exit zero)"
        sed 's/^/  stdout: /' "$stdout_file" >&2
        sed 's/^/  stderr: /' "$stderr_file" >&2
        return
    fi

    printf 'ok %d - %s\n' "$tests" "$name"
}

FAKE_BIN="$TMP_ROOT/bin"
PYTHON_MODULES="$TMP_ROOT/python-modules"
RUNTIME="$TMP_ROOT/runtime"
mkdir -p "$FAKE_BIN" "$PYTHON_MODULES" "$RUNTIME"
chmod 700 "$RUNTIME"

cat >"$FAKE_BIN/uname" <<'EOF'
#!/bin/sh
case "${1-}" in
    -s) printf '%s\n' "${FAKE_OS:-Linux}" ;;
    -m) printf '%s\n' "${FAKE_ARCH:-x86_64}" ;;
    *) exit 2 ;;
esac
EOF

cat >"$FAKE_BIN/qemu-system-x86_64" <<'EOF'
#!/bin/sh
exit 0
EOF

cat >"$PYTHON_MODULES/fcntl.py" <<'EOF'
import os


def ioctl(_fd, request):
    if request != 0xAE00:
        raise OSError("unexpected ioctl request")
    mode = os.environ.get("FOVEA_KVM_MODE", "success")
    if mode == "ioctl-fail":
        raise OSError("simulated ioctl failure")
    return int(os.environ.get("FOVEA_KVM_API", "12"))
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

run_check() {
    local qmp_path=${QMP_PATH_OVERRIDE:-"$RUNTIME/qmp.sock"}
    local pid_path=${PID_PATH_OVERRIDE:-"$RUNTIME/qemu.pid"}
    local kvm_path=${KVM_OVERRIDE:-"$KVM_FILE"}
    local qemu_path=${QEMU_OVERRIDE:-"$FAKE_BIN/qemu-system-x86_64"}
    local port=${GDB_PORT_OVERRIDE:-$(free_port)}

    env \
        FAKE_OS="${FAKE_OS:-Linux}" \
        FAKE_ARCH="${FAKE_ARCH:-x86_64}" \
        FOVEA_KVM_MODE="${FOVEA_KVM_MODE:-success}" \
        FOVEA_KVM_API="${FOVEA_KVM_API:-12}" \
        PYTHONPATH="$PYTHON_MODULES${PYTHONPATH:+:$PYTHONPATH}" \
        UNAME_BIN="$FAKE_BIN/uname" \
        QEMU_BIN="$qemu_path" \
        KVM_DEVICE="$kvm_path" \
        PYTHON_BIN="$PYTHON" \
        "$CHECK_HOST" \
        --qmp-socket "$qmp_path" \
        --pidfile "$pid_path" \
        --gdb-port "$port" \
        "$@"
}

run_case "success fixture" success "host-ready" run_check
FAKE_OS=Darwin run_case \
    "Darwin is rejected" failure "Linux is required; detected: Darwin" run_check
FAKE_ARCH=aarch64 run_case \
    "aarch64 is rejected" failure "x86_64 is required; detected: aarch64" run_check
KVM_OVERRIDE="$TMP_ROOT/missing-kvm" run_case \
    "missing KVM is rejected" failure "KVM device is missing" run_check

INACCESSIBLE_KVM="$TMP_ROOT/inaccessible-kvm"
: >"$INACCESSIBLE_KVM"
chmod 000 "$INACCESSIBLE_KVM"
KVM_OVERRIDE="$INACCESSIBLE_KVM" run_case \
    "inaccessible KVM is rejected" failure \
    "KVM device must be readable and writable" run_check
chmod 600 "$INACCESSIBLE_KVM"

KVM_DIRECTORY="$TMP_ROOT/kvm-directory"
mkdir "$KVM_DIRECTORY"
KVM_OVERRIDE="$KVM_DIRECTORY" run_case \
    "KVM open failure is rejected" failure "cannot open KVM device read-write" run_check
FOVEA_KVM_MODE=ioctl-fail run_case \
    "failed KVM ioctl is rejected" failure "KVM_GET_API_VERSION ioctl failed" run_check
FOVEA_KVM_API=11 run_case \
    "wrong KVM API is rejected" failure "KVM API version is 11; expected 12" run_check
QEMU_OVERRIDE="$TMP_ROOT/missing-qemu" run_case \
    "missing QEMU is rejected" failure "QEMU_BIN is not executable" run_check

run_case "nonnumeric GDB port is rejected" failure \
    "gdb-port must be a decimal integer" run_check --gdb-port nope
run_case "guest CID below range is rejected" failure \
    "guest-cid is outside 3..4294967294" run_check --guest-cid 2
run_case "zero memory is rejected" failure \
    "memory-mib is outside 1..1048576" run_check --memory-mib 0
run_case "CPU count above range is rejected" failure \
    "cpus is outside 1..4096" run_check --cpus 4097

MODE_755_PARENT="$TMP_ROOT/mode-755-parent"
mkdir "$MODE_755_PARENT"
chmod 755 "$MODE_755_PARENT"
QMP_PATH_OVERRIDE="$MODE_755_PARENT/qmp.sock" run_case \
    "mode 755 QMP parent is rejected" failure \
    "parent directory must have mode 700" run_check

MODE_750_PARENT="$TMP_ROOT/mode-750-parent"
mkdir "$MODE_750_PARENT"
chmod 750 "$MODE_750_PARENT"
QMP_PATH_OVERRIDE="$MODE_750_PARENT/qmp.sock" run_case \
    "mode 750 QMP parent is rejected" failure \
    "parent directory must have mode 700" run_check

INACCESSIBLE_PARENT="$TMP_ROOT/inaccessible-parent"
mkdir "$INACCESSIBLE_PARENT"
chmod 000 "$INACCESSIBLE_PARENT"
QMP_PATH_OVERRIDE="$INACCESSIBLE_PARENT/qmp.sock" run_case \
    "inaccessible QMP parent is rejected" failure \
    "parent directory must have mode 700" run_check
chmod 700 "$INACCESSIBLE_PARENT"

SYMLINK_PARENT="$TMP_ROOT/symlink-parent"
ln -s "$RUNTIME" "$SYMLINK_PARENT"
QMP_PATH_OVERRIDE="$SYMLINK_PARENT/qmp.sock" run_case \
    "QMP parent symlink is rejected" failure \
    "parent directory is a symlink" run_check
rm -f -- "$SYMLINK_PARENT"

NON_DIRECTORY_PARENT="$TMP_ROOT/non-directory-parent"
: >"$NON_DIRECTORY_PARENT"
QMP_PATH_OVERRIDE="$NON_DIRECTORY_PARENT/qmp.sock" run_case \
    "QMP parent non-directory is rejected" failure \
    "parent path is not a directory" run_check
rm -f -- "$NON_DIRECTORY_PARENT"

DUPLICATE_PATH="$RUNTIME/duplicate"
QMP_PATH_OVERRIDE="$DUPLICATE_PATH" PID_PATH_OVERRIDE="$DUPLICATE_PATH" run_case \
    "duplicate QMP and pidfile paths are rejected" failure \
    "QMP socket and pidfile paths must be different" run_check

EXISTING_QMP="$RUNTIME/existing-qmp.sock"
: >"$EXISTING_QMP"
QMP_PATH_OVERRIDE="$EXISTING_QMP" run_case \
    "existing QMP path is rejected" failure "QMP socket path already exists" run_check
rm -f -- "$EXISTING_QMP"

EXISTING_PID="$RUNTIME/existing.pid"
: >"$EXISTING_PID"
PID_PATH_OVERRIDE="$EXISTING_PID" run_case \
    "existing pidfile is rejected" failure "pidfile path already exists" run_check
rm -f -- "$EXISTING_PID"

OCCUPIED_PORT_FILE="$TMP_ROOT/occupied-port"
OCCUPIED_READY="$TMP_ROOT/occupied-ready"
"$PYTHON" - "$OCCUPIED_PORT_FILE" "$OCCUPIED_READY" <<'PY' &
import pathlib
import socket
import sys
import time

port_file = pathlib.Path(sys.argv[1])
ready_file = pathlib.Path(sys.argv[2])
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
sock.listen(1)
port_file.write_text(str(sock.getsockname()[1]), encoding="ascii")
ready_file.touch()
while True:
    time.sleep(1)
PY
listener_pid=$!
PIDS="$PIDS $listener_pid"
while [[ ! -e "$OCCUPIED_READY" ]]; do
    sleep 0.01
done
occupied_port=$(cat "$OCCUPIED_PORT_FILE")
GDB_PORT_OVERRIDE="$occupied_port" run_case \
    "occupied GDB port is rejected" failure \
    "GDB port is occupied or unavailable" run_check
kill "$listener_pid" >/dev/null 2>&1 || true
wait "$listener_pid" >/dev/null 2>&1 || true

PT_ROOT="$TMP_ROOT/guest-root"
PT_COPY="$TMP_ROOT/guest-pt-probe-under-test.sh"
mkdir -p \
    "$PT_ROOT/proc/sys/kernel" \
    "$PT_ROOT/sys/hypervisor" \
    "$PT_ROOT/sys/devices/system/clocksource/clocksource0" \
    "$PT_ROOT/sys/bus/event_source/devices/intel_pt"

"$PYTHON" - "$PT_PROBE" "$PT_COPY" "$PT_ROOT" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
destination = pathlib.Path(sys.argv[2])
root = sys.argv[3]
paths = (
    "/proc/cpuinfo",
    "/proc/sys/kernel/perf_event_paranoid",
    "/sys/hypervisor/type",
    "/sys/devices/system/clocksource/clocksource0/current_clocksource",
    "/sys/devices/system/clocksource/clocksource0/available_clocksource",
    "/sys/bus/event_source/devices/intel_pt/type",
)
for path in paths:
    source = source.replace(path, root + path)
destination.write_text(source, encoding="utf-8")
PY
chmod +x "$PT_COPY"

cat >"$FAKE_BIN/perf" <<'EOF'
#!/bin/sh
exit "${FAKE_PERF_STATUS:-0}"
EOF
chmod +x "$FAKE_BIN/perf"

write_pt_fixture() {
    local flags=$1
    local vendor=$2
    printf 'vendor_id : %s\nflags : %s\n' "$vendor" "$flags" \
        >"$PT_ROOT/proc/cpuinfo"
    printf 'kvm\n' >"$PT_ROOT/sys/hypervisor/type"
    printf 'kvm-clock\n' \
        >"$PT_ROOT/sys/devices/system/clocksource/clocksource0/current_clocksource"
    printf 'kvm-clock tsc\n' \
        >"$PT_ROOT/sys/devices/system/clocksource/clocksource0/available_clocksource"
    printf '9\n' >"$PT_ROOT/sys/bus/event_source/devices/intel_pt/type"
    printf '2\n' >"$PT_ROOT/proc/sys/kernel/perf_event_paranoid"
}

write_pt_fixture "fpu hypervisor intel_pt" GenuineIntel
run_exact_token "guest PT supported state" supported \
    env PATH="$FAKE_BIN:$PATH" UNAME_BIN="$FAKE_BIN/uname" \
    FAKE_OS=Linux FAKE_ARCH=x86_64 FAKE_PERF_STATUS=0 "$PT_COPY"

write_pt_fixture "fpu hypervisor" GenuineIntel
run_exact_token "guest PT unsupported state" unsupported \
    env PATH="$FAKE_BIN:$PATH" UNAME_BIN="$FAKE_BIN/uname" \
    FAKE_OS=Linux FAKE_ARCH=x86_64 FAKE_PERF_STATUS=0 "$PT_COPY"

write_pt_fixture "fpu hypervisor intel_pt" GenuineIntel
rm -f -- "$PT_ROOT/sys/bus/event_source/devices/intel_pt/type"
run_exact_token "exposed Intel PT without event source is misconfigured" misconfigured \
    env PATH="$FAKE_BIN:$PATH" UNAME_BIN="$FAKE_BIN/uname" \
    FAKE_OS=Linux FAKE_ARCH=x86_64 FAKE_PERF_STATUS=0 "$PT_COPY"

if ((failures > 0)); then
    printf 'FAIL: %d of %d tests failed\n' "$failures" "$tests" >&2
    exit 1
fi

printf 'PASS: %d tests\n' "$tests"
