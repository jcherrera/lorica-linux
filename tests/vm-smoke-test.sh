#!/usr/bin/env bash
# Lorica Linux -- VM Smoke Test
# Run inside a Debian 12 VM to validate the full install/reboot/uninstall lifecycle.
#
# Usage:
#   sudo ./tests/vm-smoke-test.sh --phase pre-reboot
#   # reboot
#   sudo ./tests/vm-smoke-test.sh --phase post-reboot
#   sudo ./tests/vm-smoke-test.sh --phase hardened-post-reboot   # installs + prints reboot
#   # reboot
#   sudo ./tests/vm-smoke-test.sh --phase hardened-post-reboot   # verifies post-reboot
#   sudo ./tests/vm-smoke-test.sh --phase uninstall

set -euo pipefail

# =============================================================================
# Globals
# =============================================================================

PASSES=0
FAILS=0
SKIPS=0
PHASE=""
REPO_ROOT=""
SKIP_BUILD=false
ARCH="$(uname -m)"
IS_X86=false
IS_ARM64=false
GRUB_CFG=""
HARDENED_STATE_FILE="/var/tmp/lorica-hardened-installed"
FAILED_CHECKS=""

# Arch-specific GRUB params: these only affect behavior on x86_64
X86_ONLY_CMDLINE_PARAMS="vsyscall=none"
X86_ONLY_HARDENED_PARAMS="nosmt"

# =============================================================================
# Argument Parsing
# =============================================================================

usage() {
  cat <<EOF
Usage: $(basename "$0") --phase <phase> [--repo-root <path>] [--skip-build]

Phases:
  pre-reboot              Build, install, and validate (before reboot)
  post-reboot             Validate boot parameters and lockdown (after reboot)
  hardened-post-reboot    Install hardened profile or validate after reboot
  uninstall               Purge all packages and verify clean removal

Options:
  --repo-root <path>      Path to lorica-linux repo (default: auto-detect)
  --skip-build            Skip package build in pre-reboot phase
EOF
  exit 1
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --phase)
        [ $# -ge 2 ] || { echo "Error: --phase requires a value"; usage; }
        PHASE="$2"; shift 2 ;;
      --repo-root)
        [ $# -ge 2 ] || { echo "Error: --repo-root requires a value"; usage; }
        REPO_ROOT="$2"; shift 2 ;;
      --skip-build)
        SKIP_BUILD=true; shift ;;
      -h|--help)
        usage ;;
      *)
        echo "Unknown argument: $1"; usage ;;
    esac
  done

  if [ -z "$PHASE" ]; then
    echo "Error: --phase is required"
    usage
  fi

  case "$PHASE" in
    pre-reboot|post-reboot|hardened-post-reboot|uninstall) ;;
    *) echo "Error: unknown phase '$PHASE'"; usage ;;
  esac
}

# =============================================================================
# Setup
# =============================================================================

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (sudo)"
    exit 1
  fi
}

detect_arch() {
  case "$ARCH" in
    x86_64)  IS_X86=true ;;
    aarch64) IS_ARM64=true ;;
    *)       echo "WARNING: Unknown architecture '$ARCH' -- some checks will be skipped" ;;
  esac
}

resolve_repo_root() {
  if [ -z "$REPO_ROOT" ]; then
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    REPO_ROOT="$(cd "$script_dir/.." && pwd)"
  fi

  if [ ! -d "$REPO_ROOT/packages/lorica-base" ]; then
    echo "Error: cannot find packages/lorica-base in repo root: $REPO_ROOT"
    echo "Use --repo-root to specify the correct path"
    exit 1
  fi
}

find_grub_cfg() {
  local candidates=(
    /boot/grub/grub.cfg
    /boot/efi/EFI/debian/grub.cfg
    /boot/grub2/grub.cfg
  )
  for f in "${candidates[@]}"; do
    if [ -f "$f" ]; then
      GRUB_CFG="$f"
      return 0
    fi
  done
  GRUB_CFG=""
  return 1
}

setup_colors() {
  if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BOLD='\033[1m'
    RESET='\033[0m'
  else
    GREEN=''
    RED=''
    YELLOW=''
    BOLD=''
    RESET=''
  fi
}

# =============================================================================
# Output Helpers
# =============================================================================

pass() {
  PASSES=$((PASSES + 1))
  printf "${GREEN}PASS${RESET} %s\n" "$1"
}

fail() {
  FAILS=$((FAILS + 1))
  FAILED_CHECKS="${FAILED_CHECKS}  - $1\n"
  printf "${RED}FAIL${RESET} %s\n" "$1"
}

skip() {
  SKIPS=$((SKIPS + 1))
  printf "${YELLOW}SKIP${RESET} %s (%s)\n" "$1" "${2:-not applicable on $ARCH}"
}

info() {
  printf "${BOLD}----%s %s\n${RESET}" "" "$1"
}

# =============================================================================
# Config Parsers
# =============================================================================

# Extract key=value pairs from a sysctl config file.
# Handles leading whitespace, strips inline comments.
# Preserves spaces in values (e.g. kernel.printk=3 3 3 3).
parse_sysctl_values() {
  local file="$1"
  grep -E '^\s*[a-z].*=' "$file" \
    | sed 's/^[[:space:]]*//' \
    | sed 's/[[:space:]]*#.*//'
}

# Extract boot parameters from a GRUB drop-in config file.
# Joins continuation lines, strips the variable reference, splits on whitespace.
parse_grub_params() {
  local file="$1"
  sed ':a;/\\$/N;s/\\\n//;ta' "$file" \
    | grep 'GRUB_CMDLINE_LINUX=' \
    | sed 's/.*GRUB_CMDLINE_LINUX="//;s/"[[:space:]]*$//' \
    | sed 's/\$GRUB_CMDLINE_LINUX//' \
    | tr -s '[:space:]' '\n' \
    | grep -v '^$'
}

# Extract module names from a modprobe blacklist config.
parse_blacklisted_modules() {
  local file="$1"
  grep '^install ' "$file" | awk '{print $2}'
}

# Normalize whitespace for sysctl value comparison.
# sysctl -n returns tab-separated values (e.g. kernel.printk: "3\t3\t3\t3")
# while config files use spaces (e.g. "3 3 3 3").
normalize_ws() {
  echo "$1" | tr '\t' ' ' | tr -s ' ' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# =============================================================================
# Check Functions
# =============================================================================

check_file_exists() {
  local path="$1" description="$2"
  if [ -f "$path" ]; then
    pass "$description exists: $path"
  else
    fail "$description missing: $path"
  fi
}

check_file_absent() {
  local path="$1" description="$2"
  if [ ! -f "$path" ]; then
    pass "$description removed: $path"
  else
    fail "$description still present: $path"
  fi
}

check_sysctl() {
  local key="$1" expected="$2"
  local actual

  actual="$(sysctl -n "$key" 2>/dev/null)" || {
    # Sysctl may not exist on this kernel version (e.g. sched_child_runs_first
    # removed in 6.12, dev.tty.ldisc_autoload requires 5.1+)
    skip "sysctl $key" "not available on kernel $(uname -r)"
    return
  }

  local actual_norm expected_norm
  actual_norm="$(normalize_ws "$actual")"
  expected_norm="$(normalize_ws "$expected")"

  if [ "$actual_norm" = "$expected_norm" ]; then
    pass "sysctl $key = $expected_norm"
  else
    # Special handling for settings that need kernel modules
    if [ "$key" = "net.core.default_qdisc" ] || [ "$key" = "net.ipv4.tcp_congestion_control" ]; then
      local mod=""
      [ "$key" = "net.core.default_qdisc" ] && mod="sch_fq"
      [ "$key" = "net.ipv4.tcp_congestion_control" ] && mod="tcp_bbr"
      if ! modprobe -n "$mod" 2>/dev/null; then
        skip "sysctl $key = $actual_norm (expected $expected_norm)" "module $mod not available"
        return
      fi
    fi
    fail "sysctl $key = $actual_norm (expected $expected_norm)"
  fi
}

# Check that a sysctl value is NOT the Lorica value (used for uninstall revert checks).
check_sysctl_reverted() {
  local key="$1" lorica_value="$2" debian_default="$3"
  local actual

  actual="$(sysctl -n "$key" 2>/dev/null)" || {
    skip "sysctl $key revert" "not readable"
    return
  }

  local actual_norm lorica_norm
  actual_norm="$(normalize_ws "$actual")"
  lorica_norm="$(normalize_ws "$lorica_value")"

  if [ "$actual_norm" != "$lorica_norm" ]; then
    pass "sysctl $key reverted from $lorica_norm to $actual_norm (Debian default: $debian_default)"
  else
    fail "sysctl $key still $lorica_norm after uninstall (expected Debian default: $debian_default)"
  fi
}

check_grub_param() {
  local param="$1"
  if [ -z "$GRUB_CFG" ]; then
    skip "grub.cfg: $param" "grub.cfg not found"
    return
  fi
  if grep -qF "$param" "$GRUB_CFG"; then
    pass "grub.cfg contains: $param"
  else
    fail "grub.cfg missing: $param"
  fi
}

check_grub_param_absent() {
  local param="$1"
  if [ -z "$GRUB_CFG" ]; then
    skip "grub.cfg absent: $param" "grub.cfg not found"
    return
  fi
  if grep -qF "$param" "$GRUB_CFG"; then
    fail "grub.cfg still contains: $param"
  else
    pass "grub.cfg no longer contains: $param"
  fi
}

check_cmdline_param() {
  local param="$1"

  # Arch-gated params
  if [ "$param" = "vsyscall=none" ] && [ "$IS_X86" = false ]; then
    skip "cmdline: $param" "x86_64-only (no vsyscall on ARM64)"
    return
  fi
  if [ "$param" = "nosmt" ] && [ "$IS_X86" = false ]; then
    skip "cmdline: $param" "x86_64-only (ARM64 has no SMT)"
    return
  fi

  local cmdline
  cmdline="$(cat /proc/cmdline)"
  # Match param as a literal string with word boundaries
  # -w ensures slab_nomerge doesn't match slab_nomerge_foo
  # -F ensures . in page_alloc.shuffle is literal, not regex wildcard
  if echo "$cmdline" | grep -qwF "$param"; then
    pass "cmdline: $param"
  else
    fail "cmdline: $param not found in /proc/cmdline"
  fi
}

check_lockdown() {
  local expected_mode="$1"
  local lockdown_file="/sys/kernel/security/lockdown"

  if [ ! -f "$lockdown_file" ]; then
    fail "lockdown: $lockdown_file does not exist (LSM not loaded?)"
    return
  fi

  local current
  current="$(cat "$lockdown_file")"
  if echo "$current" | grep -q "\[$expected_mode\]"; then
    pass "lockdown: $expected_mode mode active"
  else
    fail "lockdown: expected [$expected_mode], got: $current"
  fi
}

check_audit_rule() {
  local description="$1" pattern="$2"

  if ! command -v auditctl >/dev/null 2>&1; then
    skip "audit: $description" "auditctl not installed"
    return
  fi

  if auditctl -l 2>/dev/null | grep -qF -- "$pattern"; then
    pass "audit: $description"
  else
    fail "audit: $description (pattern '$pattern' not found in auditctl -l)"
  fi
}

check_module_blocked() {
  local mod="$1"
  local output

  # Check if module is built-in (blacklist has no effect on built-in modules)
  if grep -qw "$mod" /lib/modules/"$(uname -r)"/modules.builtin 2>/dev/null; then
    skip "module $mod" "built-in to kernel (blacklist cannot block)"
    return
  fi

  output="$(modprobe -n -v "$mod" 2>&1)" || true

  if echo "$output" | grep -q "install /bin/false"; then
    pass "module $mod: blocked (install /bin/false)"
  elif echo "$output" | grep -q "install /bin/true"; then
    pass "module $mod: blocked (install /bin/true)"
  elif echo "$output" | grep -qE "not found|FATAL"; then
    pass "module $mod: not loadable (not found in kernel)"
  elif [ -z "$output" ]; then
    skip "module $mod" "empty modprobe output (may be built-in or absent)"
  else
    fail "module $mod: not blocked (modprobe -n -v: $output)"
  fi
}

check_io_uring() {
  local iouring_conf="/etc/sysctl.d/91-lorica-io-uring.conf"

  check_file_exists "$iouring_conf" "io_uring sysctl config"

  if [ ! -f "$iouring_conf" ]; then
    return
  fi

  # Mirror the kernel version detection from postinst
  local kver kmajor kminor
  kver="$(uname -r | cut -d. -f1-2)"
  kmajor="$(echo "$kver" | cut -d. -f1)"
  kminor="$(echo "$kver" | cut -d. -f2)"

  if [ "$kmajor" -gt 6 ] || { [ "$kmajor" -eq 6 ] && [ "$kminor" -ge 6 ]; }; then
    if grep -q 'io_uring_disabled=1' "$iouring_conf"; then
      pass "io_uring: kernel >= 6.6, io_uring_disabled=1 present"
    else
      fail "io_uring: kernel >= 6.6 but io_uring_disabled=1 not found in $iouring_conf"
    fi
  elif [ "$kmajor" -gt 5 ] || { [ "$kmajor" -eq 5 ] && [ "$kminor" -ge 13 ]; }; then
    if grep -q 'io_uring_group=-1' "$iouring_conf"; then
      pass "io_uring: kernel >= 5.13 < 6.6, io_uring_group=-1 present"
    else
      fail "io_uring: kernel >= 5.13 but io_uring_group=-1 not found in $iouring_conf"
    fi
  else
    if grep -q 'not available' "$iouring_conf"; then
      pass "io_uring: kernel < 5.13, correctly skipped"
    else
      fail "io_uring: kernel < 5.13 but skip comment not found in $iouring_conf"
    fi
  fi
}

# =============================================================================
# Phase: pre-reboot
# =============================================================================

phase_pre_reboot() {
  # --- A. Baseline snapshot ---
  info "Capturing pre-install baseline..."
  local baseline_dir="/tmp/lorica-baseline"
  mkdir -p "$baseline_dir"
  sysctl -a > "$baseline_dir/sysctl-before.txt" 2>/dev/null || true
  cat /proc/cmdline > "$baseline_dir/cmdline-before.txt" 2>/dev/null || true
  lsmod > "$baseline_dir/lsmod-before.txt" 2>/dev/null || true
  auditctl -l > "$baseline_dir/audit-before.txt" 2>/dev/null || true
  info "Baseline saved to $baseline_dir"
  echo ""

  # --- B. Build ---
  if [ "$SKIP_BUILD" = false ]; then
    info "Building packages..."
    local build_deps_installed=false
    if ! dpkg -l build-essential 2>/dev/null | grep -q '^ii'; then
      info "Installing build dependencies..."
      apt-get update -qq
      apt-get install -y -qq build-essential debhelper devscripts
      build_deps_installed=true
    fi

    # Clean old .deb files to prevent glob matching multiple versions
    rm -f "$REPO_ROOT"/packages/lorica-*.deb "$REPO_ROOT"/packages/lorica-*.changes \
          "$REPO_ROOT"/packages/lorica-*.buildinfo

    local pkg
    for pkg in lorica-keyring lorica-base lorica-hardened-profile lorica-cloud-server; do
      info "Building $pkg..."
      (cd "$REPO_ROOT/packages/$pkg" && dpkg-buildpackage -us -uc -b 2>&1 | tail -1)
    done
    info "Build complete."
    echo ""
  else
    info "Skipping build (--skip-build)"
    echo ""
  fi

  # --- C. Install ---
  info "Installing lorica-keyring + lorica-base + lorica-cloud-server..."
  apt-get install -y \
    "$REPO_ROOT"/packages/lorica-keyring_*.deb \
    "$REPO_ROOT"/packages/lorica-base_*.deb \
    "$REPO_ROOT"/packages/lorica-cloud-server_*.deb
  echo ""

  # --- D. Post-install validation ---
  info "Verifying config file installation..."
  check_file_exists "/usr/lib/sysctl.d/90-lorica-hardening.conf" "sysctl hardening config"
  check_file_exists "/etc/default/grub.d/50-lorica-hardening.cfg" "GRUB hardening config"
  check_file_exists "/etc/modprobe.d/30-lorica-blacklist.conf" "modprobe blacklist"
  check_file_exists "/etc/audit/rules.d/lorica-compliance.rules" "audit rules"
  check_file_exists "/usr/share/doc/lorica-base/cloud-overrides.conf.example" "cloud overrides example"
  echo ""

  info "Verifying io_uring config..."
  check_io_uring
  echo ""

  info "Verifying sysctl values (parsed from 90-lorica-hardening.conf)..."
  local sysctl_src="$REPO_ROOT/packages/lorica-base/usr/lib/sysctl.d/90-lorica-hardening.conf"
  local line key value
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    check_sysctl "$key" "$value"
  done < <(parse_sysctl_values "$sysctl_src")
  echo ""

  info "Verifying GRUB config (parsed from 50-lorica-hardening.cfg)..."
  find_grub_cfg || info "grub.cfg not found -- skipping GRUB checks"
  local grub_src="$REPO_ROOT/packages/lorica-base/etc/default/grub.d/50-lorica-hardening.cfg"
  local param
  while IFS= read -r param; do
    check_grub_param "$param"
  done < <(parse_grub_params "$grub_src")
  echo ""

  info "Verifying module blacklist (spot-check: 6 CVE-motivated modules)..."
  local spot_check_modules=(bluetooth dccp firewire_core usb_storage n_hdlc vivid)
  for mod in "${spot_check_modules[@]}"; do
    check_module_blocked "$mod"
  done
  echo ""

  info "Negative checks: hardened-only settings absent from base..."
  if ! grep -q 'panic_on_warn' /usr/lib/sysctl.d/90-lorica-hardening.conf; then
    pass "panic_on_warn not in base sysctl config"
  else
    fail "panic_on_warn found in base sysctl config (should be hardened-only)"
  fi
  if ! grep -q 'nosmt' /etc/default/grub.d/50-lorica-hardening.cfg; then
    pass "nosmt not in base GRUB config"
  else
    fail "nosmt found in base GRUB config (should be hardened-only)"
  fi
  echo ""

  # --- E. Reboot instruction ---
  info "============================================"
  info "Pre-reboot phase complete."
  info "Reboot the system, then run:"
  info "  sudo $0 --phase post-reboot"
  info "============================================"
}

# =============================================================================
# Phase: post-reboot
# =============================================================================

phase_post_reboot() {
  info "Verifying boot parameters in /proc/cmdline..."
  local grub_src="$REPO_ROOT/packages/lorica-base/etc/default/grub.d/50-lorica-hardening.cfg"
  local param
  while IFS= read -r param; do
    check_cmdline_param "$param"
  done < <(parse_grub_params "$grub_src")
  echo ""

  info "Verifying lockdown mode..."
  check_lockdown "integrity"
  echo ""

  info "Verifying audit rules loaded..."
  check_audit_rule "identity monitoring (-w /etc/passwd)" "-w /etc/passwd"
  check_audit_rule "privileged command (path=/usr/bin/sudo)" "path=/usr/bin/sudo"
  check_audit_rule "time change rules" "time-change"
  check_audit_rule "tmp execution monitoring" "tmp_exec"
  echo ""

  info "Verifying sysctl values persist after reboot (spot-check)..."
  check_sysctl "kernel.kptr_restrict" "2"
  check_sysctl "kernel.yama.ptrace_scope" "2"
  check_sysctl "net.ipv4.tcp_syncookies" "1"
  check_sysctl "kernel.dmesg_restrict" "1"
  check_sysctl "fs.protected_symlinks" "1"
  echo ""

  info "============================================"
  info "Post-reboot phase complete."
  info "To test the hardened profile, run:"
  info "  sudo $0 --phase hardened-post-reboot"
  info "============================================"
}

# =============================================================================
# Phase: hardened-post-reboot (two-stage)
# =============================================================================

phase_hardened_post_reboot() {
  if [ ! -f "$HARDENED_STATE_FILE" ]; then
    # --- Stage 1: Install hardened profile + pre-reboot checks ---
    info "Stage 1: Installing hardened profile..."
    apt-get install -y "$REPO_ROOT"/packages/lorica-hardened-profile_*.deb
    echo ""

    info "Verifying hardened config files installed..."
    check_file_exists "/etc/sysctl.d/92-lorica-hardened.conf" "hardened sysctl config"
    check_file_exists "/etc/default/grub.d/51-lorica-hardened.cfg" "hardened GRUB config"
    echo ""

    info "Verifying hardened sysctl overrides (parsed from 92-lorica-hardened.conf)..."
    local sysctl_src="$REPO_ROOT/packages/lorica-hardened-profile/etc/sysctl.d/92-lorica-hardened.conf"
    local line key value
    while IFS= read -r line; do
      key="${line%%=*}"
      value="${line#*=}"
      check_sysctl "$key" "$value"
    done < <(parse_sysctl_values "$sysctl_src")
    echo ""

    info "Verifying GRUB config has hardened params..."
    find_grub_cfg || info "grub.cfg not found -- skipping GRUB checks"
    local grub_src="$REPO_ROOT/packages/lorica-hardened-profile/etc/default/grub.d/51-lorica-hardened.cfg"
    local param
    while IFS= read -r param; do
      check_grub_param "$param"
    done < <(parse_grub_params "$grub_src")
    echo ""

    # Write state file for stage 2
    touch "$HARDENED_STATE_FILE"

    info "============================================"
    info "Hardened profile installed (stage 1 complete)."
    info "Reboot the system, then re-run:"
    info "  sudo $0 --phase hardened-post-reboot"
    info "============================================"
  else
    # --- Stage 2: Post-reboot verification ---
    info "Stage 2: Verifying hardened profile after reboot..."
    echo ""

    info "Verifying hardened boot params in /proc/cmdline..."
    local grub_src="$REPO_ROOT/packages/lorica-hardened-profile/etc/default/grub.d/51-lorica-hardened.cfg"
    local param
    while IFS= read -r param; do
      check_cmdline_param "$param"
    done < <(parse_grub_params "$grub_src")
    echo ""

    info "Verifying lockdown mode (confidentiality)..."
    check_lockdown "confidentiality"
    echo ""

    info "Verifying hardened sysctl values persist after reboot..."
    local sysctl_src="$REPO_ROOT/packages/lorica-hardened-profile/etc/sysctl.d/92-lorica-hardened.conf"
    local line key value
    while IFS= read -r line; do
      key="${line%%=*}"
      value="${line#*=}"
      check_sysctl "$key" "$value"
    done < <(parse_sysctl_values "$sysctl_src")
    echo ""

    # Clean up state file
    rm -f "$HARDENED_STATE_FILE"

    info "============================================"
    info "Hardened profile fully verified (stage 2 complete)."
    info "To test uninstall, run:"
    info "  sudo $0 --phase uninstall"
    info "============================================"
  fi
}

# =============================================================================
# Phase: uninstall
# =============================================================================

phase_uninstall() {
  # --- Purge hardened profile if installed ---
  if dpkg -l lorica-hardened-profile 2>/dev/null | grep -q '^ii'; then
    info "Purging lorica-hardened-profile..."
    apt-get purge -y lorica-hardened-profile
    echo ""

    info "Verifying hardened config files removed..."
    check_file_absent "/etc/sysctl.d/92-lorica-hardened.conf" "hardened sysctl config"
    check_file_absent "/etc/default/grub.d/51-lorica-hardened.cfg" "hardened GRUB config"
    echo ""
  fi

  # --- Purge base stack ---
  info "Purging lorica-cloud-server, lorica-base, lorica-keyring..."
  apt-get purge -y lorica-cloud-server lorica-base lorica-keyring 2>/dev/null || true
  echo ""

  info "Verifying base config files removed..."
  check_file_absent "/usr/lib/sysctl.d/90-lorica-hardening.conf" "sysctl hardening config"
  check_file_absent "/etc/default/grub.d/50-lorica-hardening.cfg" "GRUB hardening config"
  check_file_absent "/etc/modprobe.d/30-lorica-blacklist.conf" "modprobe blacklist"
  check_file_absent "/etc/audit/rules.d/lorica-compliance.rules" "audit rules"
  check_file_absent "/usr/share/doc/lorica-base/cloud-overrides.conf.example" "cloud overrides example"
  echo ""

  info "Verifying generated io_uring config removed..."
  check_file_absent "/etc/sysctl.d/91-lorica-io-uring.conf" "io_uring sysctl config"
  echo ""

  # Only test revert for values where Debian stock default differs from Lorica
  info "Verifying sysctl values reverted..."
  check_sysctl_reverted "kernel.kptr_restrict"       "2"   "1"
  check_sysctl_reverted "kernel.yama.ptrace_scope"   "2"   "1"
  check_sysctl_reverted "kernel.sysrq"               "0"   "438"
  check_sysctl_reverted "kernel.perf_event_paranoid"  "3"   "2"
  echo ""

  info "Verifying GRUB config cleaned..."
  find_grub_cfg || info "grub.cfg not found -- skipping GRUB revert checks"
  check_grub_param_absent "lockdown=integrity"
  check_grub_param_absent "slab_nomerge"
  check_grub_param_absent "init_on_alloc=1"
  echo ""

  info "Verifying audit rules status after uninstall..."
  if ! command -v auditctl >/dev/null 2>&1; then
    skip "audit rules after uninstall" "auditctl not installed"
  else
    local audit_output
    audit_output="$(auditctl -l 2>/dev/null)" || true
    if echo "$audit_output" | grep -q "identity\|privileged\|time-change"; then
      skip "audit rules still cached in kernel" "reboot required to fully clear loaded audit rules (rules are immutable with -e 2)"
    else
      pass "audit rules cleared after uninstall"
    fi
  fi
  echo ""

  info "============================================"
  info "Uninstall phase complete."
  info "System should be back to stock Debian."
  info "============================================"
}

# =============================================================================
# Summary
# =============================================================================

print_summary() {
  echo ""
  printf "${BOLD}========================================${RESET}\n"
  printf "${BOLD}  RESULTS: %d passed, %d failed, %d skipped${RESET}\n" "$PASSES" "$FAILS" "$SKIPS"
  printf "${BOLD}========================================${RESET}\n"
  if [ "$FAILS" -gt 0 ]; then
    printf "\n${RED}Failed checks:${RESET}\n"
    printf "$FAILED_CHECKS"
    printf "\n${RED}SOME CHECKS FAILED${RESET}\n"
    return 1
  else
    printf "${GREEN}ALL CHECKS PASSED${RESET}\n"
    return 0
  fi
}

# =============================================================================
# Main
# =============================================================================

main() {
  require_root
  parse_args "$@"
  setup_colors
  detect_arch
  resolve_repo_root

  echo ""
  info "Lorica Linux VM Smoke Test"
  info "Phase: $PHASE"
  info "Architecture: $ARCH"
  info "Kernel: $(uname -r)"
  info "Repo root: $REPO_ROOT"
  echo ""

  case "$PHASE" in
    pre-reboot)             phase_pre_reboot ;;
    post-reboot)            phase_post_reboot ;;
    hardened-post-reboot)   phase_hardened_post_reboot ;;
    uninstall)              phase_uninstall ;;
  esac

  local rc=0
  print_summary || rc=$?
  exit "$rc"
}

main "$@"
