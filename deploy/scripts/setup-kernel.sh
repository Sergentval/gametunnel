#!/bin/sh
# setup-kernel.sh — Load required kernel modules and apply sysctl settings.
# Idempotent: checks current state before making changes. Warnings on failure
# allow the container to continue if modules are already built into the kernel.

set -e

load_module() {
    mod="$1"
    if lsmod 2>/dev/null | grep -q "^${mod} "; then
        echo "setup-kernel: module ${mod} already loaded"
        return 0
    fi
    if modprobe "${mod}" 2>/dev/null; then
        echo "setup-kernel: loaded module ${mod}"
    else
        echo "setup-kernel: WARNING: could not load module ${mod} (may be built-in or unavailable)" >&2
    fi
}

set_sysctl() {
    key="$1"
    val="$2"
    current=$(sysctl -n "${key}" 2>/dev/null || echo "")
    if [ "${current}" = "${val}" ]; then
        echo "setup-kernel: sysctl ${key}=${val} already set"
        return 0
    fi
    if sysctl -w "${key}=${val}" >/dev/null 2>&1; then
        echo "setup-kernel: set ${key}=${val}"
    else
        echo "setup-kernel: WARNING: could not set ${key}=${val}" >&2
    fi
}

# ── Kernel modules ────────────────────────────────────────────────────────────
load_module ip_gre
load_module xt_TPROXY
load_module nf_tproxy_core

# ── sysctl settings ───────────────────────────────────────────────────────────
set_sysctl net.ipv4.ip_forward 1
set_sysctl net.ipv4.conf.all.rp_filter 0
set_sysctl net.ipv4.conf.default.rp_filter 0
set_sysctl net.ipv4.conf.all.accept_local 1
