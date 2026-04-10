#!/bin/bash
#
# kernel-smoke-test.sh -- Validate lorica-kernel-cloud on a Debian VM
#
# Usage:
#   sudo ./kernel-smoke-test.sh --phase install     # Install kernel .deb + reboot
#   sudo ./kernel-smoke-test.sh --phase post-reboot  # Verify kernel after reboot
#   sudo ./kernel-smoke-test.sh --phase docker       # Test Docker on custom kernel
#   sudo ./kernel-smoke-test.sh --phase uninstall    # Remove kernel, verify fallback
#
# Prerequisites:
#   - Debian 13 (trixie) arm64 VM
#   - lorica-base already installed (v0.1)
#   - linux-image-*.deb in /tmp/lorica-kernel/ (copied from host)
#
# Run phases in order, rebooting between install and post-reboot.

set -euo pipefail

PASS=0
FAIL=0
SKIP=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  SKIP: $1"; SKIP=$((SKIP + 1)); }

check() {
    local desc="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

ARCH=$(uname -m)
echo "=== Lorica Kernel Smoke Test ==="
echo "Architecture: $ARCH"
echo "Date: $(date)"
echo ""

case "${1:-}" in
    --phase)
        PHASE="${2:?Usage: $0 --phase <install|post-reboot|docker|uninstall>}"
        ;;
    *)
        echo "Usage: $0 --phase <install|post-reboot|docker|uninstall>"
        exit 1
        ;;
esac

# ===================================================================
# Phase: install
# ===================================================================
if [ "$PHASE" = "install" ]; then
    echo "--- Phase: install ---"
    echo ""

    # Check prerequisites
    echo "[1] Checking prerequisites..."
    check "Running Debian" test -f /etc/debian_version
    check "lorica-base installed" dpkg -l lorica-base

    DEBIAN_VERSION=$(cat /etc/debian_version)
    echo "  Debian version: $DEBIAN_VERSION"
    echo "  Current kernel: $(uname -r)"
    echo ""

    # Find kernel .deb
    echo "[2] Looking for kernel .deb..."
    KERNEL_DEB=$(ls /tmp/lorica-kernel/linux-image-*-lorica-lorica_*_arm64.deb 2>/dev/null | grep -v dbg | head -1)
    if [ -z "$KERNEL_DEB" ]; then
        # Try amd64
        KERNEL_DEB=$(ls /tmp/lorica-kernel/linux-image-*-lorica-lorica_*_amd64.deb 2>/dev/null | grep -v dbg | head -1)
    fi

    if [ -z "$KERNEL_DEB" ]; then
        echo "  FAIL: No kernel .deb found in /tmp/lorica-kernel/"
        echo "  Copy the linux-image-*.deb (not the -dbg one) to /tmp/lorica-kernel/ first."
        exit 1
    fi
    echo "  Found: $KERNEL_DEB"
    echo ""

    # Install
    echo "[3] Installing kernel..."
    apt-get install -y "$KERNEL_DEB"
    check "Kernel package installed" dpkg -l linux-image-*-lorica-lorica

    # Verify GRUB updated
    if command -v update-grub > /dev/null 2>&1; then
        check "GRUB config exists" test -f /boot/grub/grub.cfg
        check "GRUB mentions lorica" grep -q "lorica" /boot/grub/grub.cfg
    else
        skip "GRUB check (update-grub not available)"
    fi

    # Check kernel files installed
    KVER=$(dpkg -L linux-image-*-lorica-lorica 2>/dev/null | grep "vmlinuz" | head -1 | sed 's|.*/vmlinuz-||')
    if [ -n "$KVER" ]; then
        check "vmlinuz installed" test -f "/boot/vmlinuz-${KVER}"
        check "System.map installed" test -f "/boot/System.map-${KVER}"
        check "config installed" test -f "/boot/config-${KVER}"
        echo "  Kernel version: $KVER"
    else
        fail "Could not determine installed kernel version"
    fi

    echo ""
    echo "--- Install phase complete ---"
    echo "  PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
    echo ""
    echo "  Next: set the Lorica kernel as default and reboot."
    echo "  Then run: sudo ./kernel-smoke-test.sh --phase post-reboot"
    echo ""

    if [ $FAIL -gt 0 ]; then exit 1; fi
    exit 0
fi

# ===================================================================
# Phase: post-reboot
# ===================================================================
if [ "$PHASE" = "post-reboot" ]; then
    echo "--- Phase: post-reboot ---"
    echo ""

    KVER=$(uname -r)
    echo "  Running kernel: $KVER"
    echo ""

    # Verify we're on the Lorica kernel
    echo "[1] Kernel identity..."
    check "Kernel is lorica" echo "$KVER" | grep -q "lorica"

    if ! echo "$KVER" | grep -q "lorica"; then
        echo ""
        echo "  WARNING: Not running the Lorica kernel!"
        echo "  You may need to select it in GRUB or set it as default:"
        echo "    grub-set-default 'Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux $KVER'"
        echo "  Then reboot and re-run this phase."
        echo ""
    fi

    # Kernel hardening checks
    echo "[2] Kernel hardening verification..."

    # KASLR
    check "KASLR enabled (RANDOMIZE_BASE)" grep -q "CONFIG_RANDOMIZE_BASE=y" "/boot/config-${KVER}" 2>/dev/null

    # STACKLEAK
    check "STACKLEAK enabled" grep -q "CONFIG_GCC_PLUGIN_STACKLEAK=y" "/boot/config-${KVER}" 2>/dev/null

    # RANDSTRUCT
    check "RANDSTRUCT_FULL enabled" grep -q "CONFIG_RANDSTRUCT_FULL=y" "/boot/config-${KVER}" 2>/dev/null

    # Module signing
    check "MODULE_SIG enabled" grep -q "CONFIG_MODULE_SIG=y" "/boot/config-${KVER}" 2>/dev/null
    check "MODULE_SIG_SHA512" grep -q "CONFIG_MODULE_SIG_SHA512=y" "/boot/config-${KVER}" 2>/dev/null

    # Lockdown
    check "Lockdown INTEGRITY" grep -q "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y" "/boot/config-${KVER}" 2>/dev/null

    # Dangerous features disabled
    check "KEXEC disabled" grep -q "# CONFIG_KEXEC is not set" "/boot/config-${KVER}" 2>/dev/null
    check "HIBERNATION disabled" grep -q "# CONFIG_HIBERNATION is not set" "/boot/config-${KVER}" 2>/dev/null
    check "PROC_KCORE disabled" grep -q "# CONFIG_PROC_KCORE is not set" "/boot/config-${KVER}" 2>/dev/null
    check "DEVMEM disabled" grep -q "# CONFIG_DEVMEM is not set" "/boot/config-${KVER}" 2>/dev/null
    check "USERFAULTFD disabled" grep -q "# CONFIG_USERFAULTFD is not set" "/boot/config-${KVER}" 2>/dev/null

    # Driver stripping
    check "Bluetooth stripped" grep -q "# CONFIG_BT is not set" "/boot/config-${KVER}" 2>/dev/null
    check "Sound stripped" grep -q "# CONFIG_SOUND is not set" "/boot/config-${KVER}" 2>/dev/null

    # Runtime checks
    echo ""
    echo "[3] Runtime verification..."

    # Lockdown mode
    if [ -f /sys/kernel/security/lockdown ]; then
        LOCKDOWN=$(cat /sys/kernel/security/lockdown)
        echo "  Lockdown: $LOCKDOWN"
        check "Lockdown active" echo "$LOCKDOWN" | grep -q "\[integrity\]\|integrity"
    else
        skip "Lockdown file not present"
    fi

    # /proc/kcore should not exist
    check "/proc/kcore absent" test ! -f /proc/kcore

    # /dev/mem should not exist (or be restricted)
    if [ -e /dev/mem ]; then
        fail "/dev/mem exists (CONFIG_DEVMEM should be disabled)"
    else
        pass "/dev/mem absent"
    fi

    # Module signing
    if dmesg 2>/dev/null | grep -q "module verification"; then
        pass "Module verification active (dmesg)"
    else
        skip "Module verification message not found in dmesg"
    fi

    # Sysctl checks (from lorica-base)
    echo ""
    echo "[4] Sysctl verification (lorica-base)..."
    check "kptr_restrict=2" test "$(sysctl -n kernel.kptr_restrict 2>/dev/null)" = "2"
    check "dmesg_restrict=1" test "$(sysctl -n kernel.dmesg_restrict 2>/dev/null)" = "1"
    check "ptrace_scope=2" test "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" = "2"
    check "kexec_load_disabled=1" test "$(sysctl -n kernel.kexec_load_disabled 2>/dev/null)" = "1"
    check "unprivileged_bpf_disabled=1" test "$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null)" = "1"

    # Basic functionality
    echo ""
    echo "[5] Basic functionality..."
    check "Networking works" ping -c 1 -W 5 8.8.8.8
    check "DNS works" getent hosts debian.org
    check "apt works" apt-get update -qq

    echo ""
    echo "--- Post-reboot phase complete ---"
    echo "  PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
    echo ""

    if [ $FAIL -gt 0 ]; then exit 1; fi
    exit 0
fi

# ===================================================================
# Phase: docker
# ===================================================================
if [ "$PHASE" = "docker" ]; then
    echo "--- Phase: docker ---"
    echo ""

    echo "[1] Docker installation..."
    if ! command -v docker > /dev/null 2>&1; then
        echo "  Installing Docker..."
        apt-get update -qq
        apt-get install -y --no-install-recommends docker.io
    fi
    check "Docker installed" command -v docker

    echo ""
    echo "[2] Docker service..."
    systemctl start docker || true
    check "Docker daemon running" docker info

    echo ""
    echo "[3] Container operations..."
    check "Pull image" docker pull --quiet debian:bookworm
    check "Run container" docker run --rm debian:bookworm echo "hello from container"
    check "Container networking" docker run --rm debian:bookworm bash -c "apt-get update -qq > /dev/null 2>&1 && echo ok"

    echo ""
    echo "[4] Key kernel modules for containers..."
    check "overlay module" lsmod | grep -q overlay || modprobe overlay
    check "br_netfilter module" lsmod | grep -q br_netfilter || modprobe br_netfilter
    check "veth exists" ip link add tmp-veth0 type veth peer name tmp-veth1 && ip link del tmp-veth0

    echo ""
    echo "--- Docker phase complete ---"
    echo "  PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
    echo ""

    if [ $FAIL -gt 0 ]; then exit 1; fi
    exit 0
fi

# ===================================================================
# Phase: uninstall
# ===================================================================
if [ "$PHASE" = "uninstall" ]; then
    echo "--- Phase: uninstall ---"
    echo ""

    echo "[1] Removing Lorica kernel..."
    apt-get purge -y linux-image-*-lorica-lorica linux-headers-*-lorica-lorica 2>/dev/null || true
    check "Kernel package removed" ! dpkg -l linux-image-*-lorica-lorica 2>/dev/null

    # Verify GRUB updated
    if command -v update-grub > /dev/null 2>&1; then
        update-grub 2>/dev/null || true
        check "GRUB no longer mentions lorica" ! grep -q "lorica" /boot/grub/grub.cfg 2>/dev/null
    fi

    echo ""
    echo "  Reboot to return to stock Debian kernel."
    echo ""
    echo "--- Uninstall phase complete ---"
    echo "  PASS: $PASS  FAIL: $FAIL  SKIP: $SKIP"
    echo ""

    if [ $FAIL -gt 0 ]; then exit 1; fi
    exit 0
fi
