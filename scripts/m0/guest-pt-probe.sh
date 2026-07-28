#!/usr/bin/env bash
set -euo pipefail

finish() {
    printf '%s\n' "$1"
    exit 0
}

[[ $# -eq 0 ]] || finish misconfigured

UNAME_BIN=${UNAME_BIN:-uname}
if [[ "$UNAME_BIN" == */* ]]; then
    [[ -x "$UNAME_BIN" ]] || finish misconfigured
else
    command -v "$UNAME_BIN" >/dev/null 2>&1 || finish misconfigured
fi

host_os=$("$UNAME_BIN" -s 2>/dev/null) || finish misconfigured
[[ "$host_os" == Linux ]] || finish misconfigured
host_arch=$("$UNAME_BIN" -m 2>/dev/null) || finish misconfigured
[[ "$host_arch" == x86_64 ]] || finish unsupported
[[ -r /proc/cpuinfo ]] || finish misconfigured

grep -Eq '^flags[[:space:]]*:.*[[:space:]]hypervisor([[:space:]]|$)' \
    /proc/cpuinfo || finish misconfigured

kvm_observed=0
if [[ -r /sys/hypervisor/type ]] &&
    grep -Eiq '^kvm$' /sys/hypervisor/type; then
    kvm_observed=1
fi
for clocksource in \
    /sys/devices/system/clocksource/clocksource0/current_clocksource \
    /sys/devices/system/clocksource/clocksource0/available_clocksource; do
    if [[ -r "$clocksource" ]] && grep -Eiq '(^|[[:space:]])kvm' "$clocksource"; then
        kvm_observed=1
    fi
done
((kvm_observed == 1)) || finish misconfigured

grep -Eq '^vendor_id[[:space:]]*:[[:space:]]*GenuineIntel$' /proc/cpuinfo ||
    finish unsupported
grep -Eq '^flags[[:space:]]*:.*[[:space:]]intel_pt([[:space:]]|$)' \
    /proc/cpuinfo || finish unsupported

pt_type=/sys/bus/event_source/devices/intel_pt/type
[[ -r "$pt_type" ]] || finish misconfigured
read -r pt_type_value <"$pt_type" || finish misconfigured
[[ "$pt_type_value" =~ ^[0-9]+$ ]] || finish misconfigured

paranoid=/proc/sys/kernel/perf_event_paranoid
[[ -r "$paranoid" ]] || finish misconfigured
read -r paranoid_value <"$paranoid" || finish misconfigured
[[ "$paranoid_value" =~ ^-?[0-9]+$ ]] || finish misconfigured

command -v perf >/dev/null 2>&1 || finish misconfigured
if perf record -q -e intel_pt//u -o /dev/null -- true \
    >/dev/null 2>&1; then
    finish supported
fi

finish misconfigured
