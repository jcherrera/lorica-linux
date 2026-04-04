#!/usr/bin/env bash
#
# apply-hardening.sh -- Transform a Debian cloud kernel config into a
# Lorica Linux hardened kernel config.
#
# This script takes a stock Debian 13 cloud kernel .config (amd64 or arm64)
# and applies all Lorica hardening changes: KSPP security options, GCC plugin
# enablement, module signing with SHA-512, lockdown enforcement, dangerous
# feature removal, and driver stripping for cloud-only operation.
#
# The script is idempotent: running it twice on the same input produces
# identical output.
#
# Usage:
#   ./apply-hardening.sh <input-config> <output-config>
#
# Example:
#   ./apply-hardening.sh debian-cloud-config-amd64 kernel-config-x86_64
#
# The input file is NOT modified. A copy is made to the output path and
# all changes are applied there.

set -euo pipefail

# ---------------------------------------------------------------------------
# Argument handling
# ---------------------------------------------------------------------------

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <input-config> <output-config>" >&2
    exit 1
fi

INPUT="$1"
OUTPUT="$2"

if [[ ! -f "$INPUT" ]]; then
    echo "Error: input config '$INPUT' not found." >&2
    exit 1
fi

cp -- "$INPUT" "$OUTPUT"

# Clean up .bak files on any exit (normal or error)
trap 'rm -f "${OUTPUT}.bak"' EXIT

# Counters
ENABLED=0
DISABLED=0
ADDED=0

# ---------------------------------------------------------------------------
# Helper functions
#
# Note on string config values: kernel config strings include their quotes,
# e.g., CONFIG_LOCALVERSION="-lorica". Pass the value with quotes:
#   set_config "CONFIG_LOCALVERSION" '"-lorica"'
# ---------------------------------------------------------------------------

# set_config: Set a config option to a value (y, m, n, string, or integer).
# Handles three cases: "# CONFIG_X is not set", "CONFIG_X=<old>", or missing.
set_config() {
    local key="$1"
    local value="$2"

    if grep -q "^# ${key} is not set$" "$OUTPUT"; then
        sed -i.bak "s/^# ${key} is not set$/${key}=${value}/" "$OUTPUT"
        ENABLED=$((ENABLED + 1))
    elif grep -q "^${key}=" "$OUTPUT"; then
        sed -i.bak "s/^${key}=.*$/${key}=${value}/" "$OUTPUT"
        ENABLED=$((ENABLED + 1))
    else
        # Option missing entirely -- append to end of file
        echo "${key}=${value}" >> "$OUTPUT"
        ADDED=$((ADDED + 1))
    fi
}

# disable_config: Disable (unset) a config option.
# Handles: "CONFIG_X=y/m/n/value" -> "# CONFIG_X is not set", or already unset.
disable_config() {
    local key="$1"

    if grep -q "^${key}=" "$OUTPUT"; then
        sed -i.bak "s/^${key}=.*$/# ${key} is not set/" "$OUTPUT"
        DISABLED=$((DISABLED + 1))
    fi
    # Already "not set" or absent -- nothing to do.
}

# remove_config: Remove a config line entirely (for options that should not
# appear at all, e.g., choice-group members being replaced).
remove_config() {
    local key="$1"

    if grep -q "^${key}=" "$OUTPUT" || grep -q "^# ${key} is not set$" "$OUTPUT"; then
        sed -i.bak "/^${key}=/d;/^# ${key} is not set$/d" "$OUTPUT"
    fi
}

echo "=== Lorica Linux Kernel Hardening ==="
echo "Input:  $INPUT"
echo "Output: $OUTPUT"
echo ""

# ===================================================================
# Section 1: Lorica Identity
# ===================================================================

echo "[1/9] Setting Lorica identity..."

set_config "CONFIG_LOCALVERSION" '"-lorica"'

# ===================================================================
# Section 2: Memory Hardening (KSPP)
# ===================================================================

echo "[2/9] Applying memory hardening..."

# -- Already enabled by Debian (set for idempotency) --
set_config "CONFIG_INIT_ON_ALLOC_DEFAULT_ON" "y"
set_config "CONFIG_INIT_STACK_ALL_ZERO" "y"
set_config "CONFIG_HARDENED_USERCOPY" "y"
set_config "CONFIG_FORTIFY_SOURCE" "y"
set_config "CONFIG_STACKPROTECTOR_STRONG" "y"
set_config "CONFIG_SLAB_FREELIST_RANDOM" "y"
set_config "CONFIG_SLAB_FREELIST_HARDENED" "y"
set_config "CONFIG_SHUFFLE_PAGE_ALLOCATOR" "y"
set_config "CONFIG_VMAP_STACK" "y"
set_config "CONFIG_SLAB_BUCKETS" "y"
set_config "CONFIG_LIST_HARDENED" "y"
set_config "CONFIG_BUG_ON_DATA_CORRUPTION" "y"
set_config "CONFIG_SCHED_STACK_END_CHECK" "y"
set_config "CONFIG_KFENCE" "y"

# -- Lorica delta: enable --
set_config "CONFIG_INIT_ON_FREE_DEFAULT_ON" "y"
set_config "CONFIG_PAGE_TABLE_CHECK" "y"
set_config "CONFIG_PAGE_TABLE_CHECK_ENFORCED" "y"
set_config "CONFIG_ZERO_CALL_USED_REGS" "y"
set_config "CONFIG_RANDOM_KMALLOC_CACHES" "y"
set_config "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT" "y"

# Address space layout randomization (already enabled by Debian)
set_config "CONFIG_RANDOMIZE_BASE" "y"
set_config "CONFIG_RANDOMIZE_MEMORY" "y"

# Minimum mmap address (already 65536 on Debian, set for idempotency)
set_config "CONFIG_DEFAULT_MMAP_MIN_ADDR" "65536"

# ===================================================================
# Section 3: GCC Plugins & Struct Randomization
# ===================================================================

echo "[3/9] Enabling GCC plugins and struct randomization..."

# GCC plugin infrastructure
set_config "CONFIG_GCC_PLUGINS" "y"

# STACKLEAK: clear kernel stack on syscall return
set_config "CONFIG_GCC_PLUGIN_STACKLEAK" "y"

# LATENT_ENTROPY: extra entropy from compiler-generated random
set_config "CONFIG_GCC_PLUGIN_LATENT_ENTROPY" "y"

# RANDSTRUCT: randomize struct layout (compiler-agnostic since 6.1)
# Must disable RANDSTRUCT_NONE first (choice group)
remove_config "CONFIG_RANDSTRUCT_NONE"
set_config "CONFIG_RANDSTRUCT_FULL" "y"

# ===================================================================
# Section 4: Module Signing (SHA-512, permissive)
# ===================================================================

echo "[4/9] Configuring module signing (SHA-512)..."

# Module signing enabled (already =y in Debian)
set_config "CONFIG_MODULE_SIG" "y"

# Sign all modules during build
set_config "CONFIG_MODULE_SIG_ALL" "y"

# Switch hash to SHA-512 -- disable all other hash options first
disable_config "CONFIG_MODULE_SIG_SHA1"
disable_config "CONFIG_MODULE_SIG_SHA224"
disable_config "CONFIG_MODULE_SIG_SHA256"
disable_config "CONFIG_MODULE_SIG_SHA384"
disable_config "CONFIG_MODULE_SIG_SHA3_256"
disable_config "CONFIG_MODULE_SIG_SHA3_384"
disable_config "CONFIG_MODULE_SIG_SHA3_512"
set_config "CONFIG_MODULE_SIG_SHA512" "y"
set_config "CONFIG_MODULE_SIG_HASH" '"sha512"'

# ===================================================================
# Section 5: Kernel Lockdown & Access Control
# ===================================================================

echo "[5/9] Enforcing kernel lockdown and access controls..."

# Force integrity lockdown at boot
set_config "CONFIG_SECURITY_LOCKDOWN_LSM" "y"
set_config "CONFIG_SECURITY_LOCKDOWN_LSM_EARLY" "y"
remove_config "CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE"
set_config "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY" "y"
disable_config "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY"

# Yama LSM (already enabled by Debian)
set_config "CONFIG_SECURITY_YAMA" "y"

# Restrict unprivileged BPF (already enabled by Debian)
set_config "CONFIG_BPF_UNPRIV_DEFAULT_OFF" "y"

# Strict /dev/mem (already enabled by Debian)
set_config "CONFIG_STRICT_DEVMEM" "y"
set_config "CONFIG_IO_STRICT_DEVMEM" "y"

# Strict RWX (already enabled by Debian)
set_config "CONFIG_STRICT_KERNEL_RWX" "y"
set_config "CONFIG_STRICT_MODULE_RWX" "y"

# Debug W+X pages (already enabled by Debian)
set_config "CONFIG_DEBUG_WX" "y"

# IOMMU strict DMA (Debian defaults to lazy)
set_config "CONFIG_IOMMU_SUPPORT" "y"
set_config "CONFIG_IOMMU_DEFAULT_DMA_STRICT" "y"
disable_config "CONFIG_IOMMU_DEFAULT_DMA_LAZY"

# Seccomp (already enabled by Debian)
set_config "CONFIG_SECCOMP" "y"
set_config "CONFIG_SECCOMP_FILTER" "y"

# SYN cookies (already enabled by Debian)
set_config "CONFIG_SYN_COOKIES" "y"

# 9P filesystem -- required for virtme-ng CI boot testing.
# virtme-ng mounts the host root via 9P over virtio.
set_config "CONFIG_NET_9P" "y"
set_config "CONFIG_NET_9P_VIRTIO" "y"
set_config "CONFIG_9P_FS" "y"
set_config "CONFIG_9P_FS_POSIX_ACL" "y"

# ===================================================================
# Section 6: Disable Dangerous Features
# ===================================================================

echo "[6/9] Disabling dangerous kernel features..."

# Kexec -- hot-patch vector, enforce at compile time
disable_config "CONFIG_KEXEC"
disable_config "CONFIG_KEXEC_FILE"
disable_config "CONFIG_KEXEC_CORE"
disable_config "CONFIG_KEXEC_SIG"
disable_config "CONFIG_KEXEC_SIG_FORCE"
disable_config "CONFIG_KEXEC_BZIMAGE_VERIFY_SIG"
disable_config "CONFIG_KEXEC_JUMP"

# Hibernation -- not used on servers, exposes memory to disk
disable_config "CONFIG_HIBERNATION"
disable_config "CONFIG_HIBERNATION_SNAPSHOT_DEV"
disable_config "CONFIG_HIBERNATION_COMP_LZO"
disable_config "CONFIG_HIBERNATION_COMP_LZ4"

# /proc/kcore -- exposes kernel memory
disable_config "CONFIG_PROC_KCORE"

# /dev/mem -- raw memory access
disable_config "CONFIG_DEVMEM"

# Line discipline autoload -- attack vector via TTY
disable_config "CONFIG_LDISC_AUTOLOAD"

# userfaultfd -- use-after-free exploit primitive
disable_config "CONFIG_USERFAULTFD"

# binfmt_misc -- arbitrary binary format handler registration
disable_config "CONFIG_BINFMT_MISC"

# DCCP -- rarely used, historical vulnerability source
disable_config "CONFIG_IP_DCCP"
disable_config "CONFIG_IP_DCCP_CCID3"
disable_config "CONFIG_IP_DCCP_TFRC_LIB"

# SCTP -- rarely used on cloud servers, large attack surface
disable_config "CONFIG_IP_SCTP"

# Legacy TIOCSTI -- TTY injection (already disabled by Debian cloud)
disable_config "CONFIG_LEGACY_TIOCSTI"

# COMPAT_BRK -- heap ASLR bypass (already disabled by Debian cloud)
disable_config "CONFIG_COMPAT_BRK"

# ACPI custom method -- arbitrary ACPI write vector
disable_config "CONFIG_ACPI_CUSTOM_METHOD"

# ===================================================================
# Section 7: Driver Stripping (cloud-only kernel)
# ===================================================================

echo "[7/9] Stripping unnecessary drivers..."

# -- Wireless (should already be gone in Debian cloud) --
disable_config "CONFIG_CFG80211"
disable_config "CONFIG_MAC80211"

# -- USB HID / Input devices --
disable_config "CONFIG_USB_HID"
disable_config "CONFIG_HID_GENERIC"
disable_config "CONFIG_INPUT_JOYSTICK"
disable_config "CONFIG_INPUT_TOUCHSCREEN"
disable_config "CONFIG_INPUT_TABLET"

# -- Media / Video / IR --
disable_config "CONFIG_MEDIA_SUPPORT"
disable_config "CONFIG_VIDEO_DEV"
disable_config "CONFIG_RC_CORE"

# -- Legacy buses --
disable_config "CONFIG_PCMCIA"
disable_config "CONFIG_ISA"
disable_config "CONFIG_ISA_BUS"
disable_config "CONFIG_ISA_DMA_API"

# -- Legacy network protocols --
disable_config "CONFIG_DECNET"
disable_config "CONFIG_IPX"
disable_config "CONFIG_APPLETALK"
disable_config "CONFIG_ATALK"
disable_config "CONFIG_ATM"
disable_config "CONFIG_X25"

# -- Legacy / desktop filesystems --
disable_config "CONFIG_NTFS_FS"
disable_config "CONFIG_NTFS3_FS"
disable_config "CONFIG_HFS_FS"
disable_config "CONFIG_HFSPLUS_FS"
disable_config "CONFIG_JFS_FS"
disable_config "CONFIG_REISERFS_FS"
disable_config "CONFIG_UFS_FS"
disable_config "CONFIG_MINIX_FS"

# -- Ham radio / amateur --
disable_config "CONFIG_HAMRADIO"
disable_config "CONFIG_AX25"

# -- Industrial I/O (sensors, ADCs) --
disable_config "CONFIG_IIO"

# -- Parallel port / floppy --
disable_config "CONFIG_PARPORT"
disable_config "CONFIG_FLOPPY"

# -- Framebuffer / VGA console (headless servers) --
disable_config "CONFIG_FB"
disable_config "CONFIG_VGA_CONSOLE"

# ===================================================================
# Section 8: Idempotency Assertions (already disabled by Debian cloud)
# ===================================================================

echo "[8/9] Verifying Debian cloud defaults..."

# These should already be disabled in Debian cloud config.
# Set explicitly for defense-in-depth / idempotency.
disable_config "CONFIG_BT"
disable_config "CONFIG_SOUND"
disable_config "CONFIG_SND"
disable_config "CONFIG_DRM"
disable_config "CONFIG_WLAN"
disable_config "CONFIG_NFC"
disable_config "CONFIG_FIREWIRE"
disable_config "CONFIG_THUNDERBOLT"

# ===================================================================
# Section 9: Cleanup
# ===================================================================

echo "[9/9] Finalizing..."

# ===================================================================
# Summary
# ===================================================================

TOTAL_LINES=$(wc -l < "$OUTPUT")
ENABLED_COUNT=$(grep -c '^CONFIG_.*=y$' "$OUTPUT" || true)
MODULE_COUNT=$(grep -c '^CONFIG_.*=m$' "$OUTPUT" || true)
DISABLED_COUNT=$(grep -c '^# CONFIG_.* is not set$' "$OUTPUT" || true)

echo ""
echo "=== Hardening Complete ==="
echo "Options set/enabled:   $ENABLED"
echo "Options disabled:      $DISABLED"
echo "Options added (new):   $ADDED"
echo ""
echo "Output config stats:"
echo "  Total lines:           $TOTAL_LINES"
echo "  Options enabled (=y):  $ENABLED_COUNT"
echo "  Options as module (=m): $MODULE_COUNT"
echo "  Options disabled:      $DISABLED_COUNT"
echo ""
echo "Output written to: $OUTPUT"
