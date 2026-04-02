# Lorica Linux -- Hardening Decisions

> Working document for v0.1. Every hardening config that `lorica-base` ships is listed here
> with its source, rationale, and compliance mapping. This becomes the basis for
> CONFIG_RATIONALE.md and the actual config files.
>
> Last updated: 2026-04-02

---

## Methodology

**Sources researched:**
- [Kicksecure security-misc](https://github.com/Kicksecure/security-misc) -- sysctl (`990-security-misc.conf`), GRUB configs (`etc/default/grub.d/`), module blacklists (`etc/modprobe.d/`)
- [KSPP Recommended Settings](https://kspp.github.io/Recommended_Settings) -- kernel self-protection runtime settings
- CIS Debian Linux 12 Benchmark v1.1.0 -- OS-level controls (sections 1, 3, 4, 5)
- PCI-DSS v3.2.1 / v4.0 -- requirements 2.2, 10.x (audit logging)
- SOC 2 Trust Services Criteria -- CC6.x (access controls), CC7.x (monitoring)
- Mozilla OpenSSH Guidelines, cloud-init security docs, Linux audit-userspace PCI-DSS rules

**Decision criteria:**
- Is this relevant to headless cloud servers (not desktops)?
- Does it break common server workloads (Docker, Kubernetes, nginx, PostgreSQL, monitoring agents)?
- What's the security benefit vs. compatibility cost?
- Is it covered by a compliance framework we need to map?

**CNBV note:** Mexico's CNBV (Comisión Nacional Bancaria y de Valores) does not publish
granular technical controls like CIS or PCI-DSS. Collectively, the controls in this document
support CNBV habilitación requirements for information security controls in regulated
financial entities. We do not attempt per-setting CNBV mapping.

**Kicksecure credit:** Many settings in this document are adapted from or informed by
Kicksecure's `security-misc` package. Where a setting originates from Kicksecure, it is
attributed as such. Lorica adapts these for cloud server use cases rather than depending on
the `security-misc` package directly, as ~40% of security-misc targets desktop/physical
hardware irrelevant to cloud VMs.

---

## Two-Profile System

Lorica ships two hardening profiles:

**`lorica-base` (default)** -- Bold, opinionated defaults that justify the distro. Not
stock-Debian-plus-a-little. Every setting is meaningfully harder than Debian's defaults.
Stable enough for production behind load balancers. Containers (Docker, K8s) work.
Monitoring and health checks work. `sudo strace` works.

**`lorica-hardened-profile` (opt-in)** -- Maximum hardening for high-security environments.
Disables hyperthreading, blocks all ICMP, panics on kernel warnings, locks module loading
after boot. Compliance teams can write "we run Lorica hardened profile" in audit docs.
Install via `apt install lorica-hardened-profile` (or drop in the override sysctl/GRUB
configs manually).

Settings marked **HARDENED-ONLY** below are not in `lorica-base` and are activated by the
hardened profile.

---

## Quick Start

**What does `lorica-base` do out of the box?**

Installs drop-in configs that: hide kernel pointers and restrict dmesg, disable kexec and
SysRq, restrict ptrace to privileged users, harden the TCP/IP stack against spoofing and
floods, enable all CPU vulnerability mitigations, zero-fill memory on allocation and free,
disable debugfs, enable kernel lockdown (integrity mode), reboot on kernel oops, blacklist
35+ kernel modules irrelevant to servers (Bluetooth, FireWire, sound, legacy filesystems,
uncommon protocols), and install audit rules mapped to CIS/PCI-DSS for identity changes,
privilege escalation, and system modifications.

**How do I activate the hardened profile?**

```bash
apt install lorica-hardened-profile
# Then reboot to apply boot parameter changes (nosmt, slub_debug, lockdown=confidentiality)
```

Or manually: copy the hardened profile sysctl and GRUB overrides from
`/usr/share/doc/lorica-base/hardened-profile/` into the appropriate drop-in directories.

---

## 1. Sysctl Settings

### 1.1 Kernel Information Leak Prevention

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `kernel.kptr_restrict` | `2` | Hide kernel pointers from all users including root | KSPP, Kicksecure, CIS | INCLUDE | BASE |
| `kernel.dmesg_restrict` | `1` | Restrict kernel log access to CAP_SYSLOG | KSPP, Kicksecure, CIS | INCLUDE | BASE |
| `kernel.perf_event_paranoid` | `3` | Disallow all unprivileged perf events | KSPP, Kicksecure | INCLUDE | BASE |
| `kernel.printk` | `3 3 3 3` | Suppress kernel messages to reduce info leakage | Kicksecure | INCLUDE | BASE |
| `kernel.randomize_va_space` | `2` | Full ASLR (stack, VDSO, mmap, heap) | KSPP, CIS 1.5.1 | INCLUDE | BASE |

**Compliance:** CIS 1.5.1 (ASLR), PCI-DSS 2.2 (system hardening), SOC 2 CC6.1

**Notes:**
- `kptr_restrict=2` hides pointers even from root. Value `1` only hides from unprivileged.
  We use `2` because on a production server, no one should be reading raw kernel addresses.
  **Interaction note:** The hardened profile's `slub_debug=FZ` boot parameter disables
  kernel pointer hashing, which weakens the protection `kptr_restrict` provides. This is
  an accepted tradeoff in the hardened profile (SLUB integrity checking is prioritized
  over pointer obfuscation).
- `perf_event_paranoid=3` is a Debian-carried patch (upstream rejected value 3). Supported
  on Debian's stock kernel.
- `randomize_va_space=2` is already the default on modern kernels but we set it explicitly
  as defense-in-depth.

---

### 1.2 Memory Protection

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `vm.mmap_min_addr` | `65536` | Block low-address mmap (null pointer deref exploits) | KSPP, Kicksecure | INCLUDE | BASE |
| `fs.suid_dumpable` | `0` | Disable core dumps for SUID/SGID processes | KSPP, CIS 1.5.3 | INCLUDE | BASE |
| `kernel.core_pattern` | `\|/bin/false` | Discard all core dumps (pipe to /bin/false) | Best practice | INCLUDE | BASE |

**Compliance:** CIS 1.5.3 (core dumps), PCI-DSS 2.2, SOC 2 CC6.1

**Notes:**
- `suid_dumpable=0` prevents privileged process memory from leaking into core dumps.
  `core_pattern=|/bin/false` is belt-and-suspenders: even if a non-SUID process dumps,
  the core is discarded. Core dumps can contain secrets (database credentials, API keys,
  session tokens).
- `mmap_min_addr=65536` (64KB) prevents mapping the zero page, which is a prerequisite
  for many null pointer dereference exploits.

---

### 1.3 Attack Surface Reduction

| Setting | Value (Base) | Value (Hardened) | Description | Source | Decision | Profile |
|---------|-------------|-----------------|-------------|--------|----------|---------|
| `kernel.kexec_load_disabled` | `1` | `1` | Disable kexec (runtime kernel replacement) | KSPP, Kicksecure | INCLUDE | BASE |
| `kernel.sysrq` | `0` | `0` | Disable SysRq key entirely | Kicksecure, CIS | INCLUDE | BASE |
| `kernel.unprivileged_bpf_disabled` | `1` | `1` | Restrict eBPF to CAP_BPF (root) | KSPP, Kicksecure | INCLUDE | BASE |
| `net.core.bpf_jit_harden` | `2` | `2` | Harden BPF JIT against spray attacks | KSPP, Kicksecure | INCLUDE | BASE |
| `kernel.io_uring_disabled` | `1` | `2` | Restrict io_uring (1=unprivileged disabled, 2=all) | Google prod, KSPP | INCLUDE | BASE |

> **Kernel version note:** `io_uring_disabled` was added in kernel 6.6. On Debian 12
> (kernel 6.1), use `io_uring_group=-1` instead (restricts io_uring to root). The
> actual config file must detect the kernel version and use the appropriate sysctl.
> See open items at end of document.
| `dev.tty.ldisc_autoload` | `0` | `0` | Prevent TTY line discipline autoloading | KSPP | INCLUDE | BASE |
| `vm.unprivileged_userfaultfd` | `0` | `0` | Block unprivileged userfaultfd (UAF exploit primitive) | KSPP | INCLUDE | BASE |

**Compliance:** PCI-DSS 2.2 (disable unnecessary functions), SOC 2 CC6.8

**Notes:**
- `kexec_load_disabled=1` prevents an attacker with root from replacing the running kernel.
  Irreversible until reboot. No legitimate use case on production servers.
- `io_uring_disabled`: io_uring has been a prolific attack surface with multiple CVEs in
  2023-2025. Google disabled it in production. Base restricts to root (`=1`); hardened
  disables entirely (`=2`). High-throughput I/O workloads that depend on io_uring
  (e.g., some database engines) will need to override this.
- `unprivileged_userfaultfd=0` removes a key primitive used in use-after-free exploits
  (attacker-controlled page fault handling). No unprivileged use case on servers.
- `ldisc_autoload=0` requires kernel 5.1+. Prevents exploitation of vulnerable line
  disciplines (n_hdlc has had multiple CVEs).

---

### 1.4 Process Isolation

| Setting | Value (Base) | Value (Hardened) | Description | Source | Decision | Profile |
|---------|-------------|-----------------|-------------|--------|----------|---------|
| `kernel.yama.ptrace_scope` | `2` | `3` | Restrict ptrace (2=CAP_SYS_PTRACE, 3=no attach) | KSPP, Kicksecure | INCLUDE | BASE |
| `kernel.sched_child_runs_first` | `1` | `1` | Run child process before parent after fork() | Kicksecure | INCLUDE | BASE |
| `kernel.panic` | `10` | `10` | Auto-reboot 10s after kernel panic | Best practice | INCLUDE | BASE |

**Compliance:** CIS 1.5.2 (ptrace), PCI-DSS 2.2, SOC 2 CC6.1

**Notes:**
- `ptrace_scope=2`: Requires CAP_SYS_PTRACE for PTRACE_ATTACH. `sudo strace` works;
  unprivileged `strace` does not. KSPP recommends `3` (no attach at all), but that
  breaks too many debugging workflows for a production default. Hardened profile
  escalates to `3`.
- `sched_child_runs_first=1`: After `fork()`, the child process runs before the parent.
  This makes fork-based race condition exploits slightly harder by reducing the window
  where the parent can manipulate shared state before the child executes. Low cost,
  no compatibility impact.
- `panic=10`: If the kernel panics, reboot after 10 seconds rather than hanging
  indefinitely. On cloud servers behind load balancers, a fast reboot is preferable
  to a hung instance. Kicksecure uses `panic=-1` (disabled, delegates to systemd);
  we prefer explicit kernel-level reboot.

---

### 1.5 Crash Behavior

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `kernel.panic_on_warn` | `1` | Panic on kernel warnings (not just oops) | KSPP, Kicksecure | INCLUDE | HARDENED-ONLY |
| `kernel.oops_limit` | `1` | Panic after first kernel oops | KSPP | INCLUDE | HARDENED-ONLY |
| `kernel.warn_limit` | `1` | Panic after first kernel warning | KSPP | INCLUDE | HARDENED-ONLY |

**Compliance:** KSPP full compliance (hardened profile only)

**Notes -- oops=panic (boot param, BASE) vs panic_on_warn (sysctl, HARDENED-ONLY):**

These are distinct and intentionally at different profiles:
- **Kernel oops** = likely memory corruption or a serious bug. Worth rebooting immediately.
  A corrupted kernel on a financial workload is worse than a clean restart. This is why
  `oops=panic` is a BASE boot parameter.
- **Kernel warn** = often informational. A spurious driver warning or a benign race
  condition shouldn't crash a production server. `panic_on_warn=1` is HARDENED-ONLY
  for environments where any kernel anomaly is unacceptable.

---

### 1.6 Network Hardening -- IPv4

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `net.ipv4.tcp_syncookies` | `1` | SYN flood protection | CIS 3.3.8, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.all.rp_filter` | `1` | Strict reverse path filtering (anti-spoofing) | CIS 3.3.7, KSPP, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.default.rp_filter` | `1` | (same, default interface) | CIS 3.3.7 | INCLUDE | BASE |
| `net.ipv4.conf.all.accept_redirects` | `0` | Ignore ICMP redirects (MITM prevention) | CIS 3.3.3, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.default.accept_redirects` | `0` | (same, default interface) | CIS 3.3.3 | INCLUDE | BASE |
| `net.ipv4.conf.all.secure_redirects` | `0` | Ignore even "secure" ICMP redirects | CIS 3.3.4, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.default.secure_redirects` | `0` | (same, default interface) | CIS 3.3.4 | INCLUDE | BASE |
| `net.ipv4.conf.all.send_redirects` | `0` | Don't send ICMP redirects (not a router) | CIS 3.3.2, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.default.send_redirects` | `0` | (same, default interface) | CIS 3.3.2 | INCLUDE | BASE |
| `net.ipv4.conf.all.accept_source_route` | `0` | Disable source-routed packets | CIS 3.3.6, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.default.accept_source_route` | `0` | (same, default interface) | CIS 3.3.6 | INCLUDE | BASE |
| `net.ipv4.conf.all.log_martians` | `1` | Log packets with impossible source addresses | CIS 3.3.5, Kicksecure | INCLUDE | BASE |
| `net.ipv4.conf.default.log_martians` | `1` | (same, default interface) | CIS 3.3.5 | INCLUDE | BASE |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Ignore broadcast ICMP (Smurf attack prevention) | CIS 3.3.x, Kicksecure | INCLUDE | BASE |
| `net.ipv4.icmp_ignore_bogus_error_responses` | `1` | Ignore bogus ICMP error responses | CIS, Kicksecure | INCLUDE | BASE |
| `net.ipv4.tcp_rfc1337` | `1` | TIME-WAIT assassination protection (RFC 1337) | Kicksecure | INCLUDE | BASE |
| `net.ipv4.ip_forward` | `0` | Disable IP forwarding (not a router) | CIS 3.3.1 | INCLUDE | BASE |

**Compliance:** CIS 3.3.1-3.3.8, PCI-DSS 2.2 (network hardening), SOC 2 CC6.6

**Notes:**
- `ip_forward=0`: Docker and Kubernetes require `ip_forward=1` and will set it
  automatically when they start. Our config provides the secure default; container
  runtimes override as needed. This is expected behavior, not a conflict.
- `rp_filter=1` (strict mode) validates that the source address of each incoming packet
  is reachable via the interface it arrived on. Prevents IP spoofing.

---

### 1.7 Network Hardening -- ARP

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| Setting | Value (Base) | Value (Hardened) | Description | Source | Decision | Profile |
|---------|-------------|-----------------|-------------|--------|----------|---------|
| `net.ipv4.conf.all.drop_gratuitous_arp` | `0` | `1` | Drop gratuitous ARP frames | Kicksecure | ADAPT | BASE |
| `net.ipv4.conf.all.arp_filter` | `1` | `1` | Enable ARP filtering (respond only on correct interface) | Kicksecure | INCLUDE | BASE |

**Compliance:** PCI-DSS 2.2, SOC 2 CC6.6

**Notes:**
- **ADAPT rationale for `drop_gratuitous_arp`:** Kicksecure sets `1` (drop). Gratuitous
  ARP is a known cache poisoning vector, but it's also used legitimately by AWS ENI
  failover, keepalived, and cloud provider floating IPs. Since Lorica's primary audience
  is cloud servers on AWS and similar providers, breaking ENI failover on first boot is
  worse than the ARP poisoning risk (which is mitigated at the VPC/network layer on cloud
  platforms). Base keeps `0`; hardened profile sets `1` for environments on trusted
  networks where ARP is a real threat (e.g., bare-metal colocation).

---

### 1.8 Network Hardening -- IPv6

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `net.ipv6.conf.all.accept_redirects` | `0` | Ignore IPv6 ICMP redirects | CIS 3.3.9, Kicksecure | INCLUDE | BASE |
| `net.ipv6.conf.default.accept_redirects` | `0` | (same, default interface) | CIS 3.3.9 | INCLUDE | BASE |
| `net.ipv6.conf.all.accept_source_route` | `0` | Disable IPv6 source routing | CIS 3.3.10, Kicksecure | INCLUDE | BASE |
| `net.ipv6.conf.default.accept_source_route` | `0` | (same, default interface) | CIS 3.3.10 | INCLUDE | BASE |
| `net.ipv6.conf.all.accept_ra` | `0` | Disable IPv6 Router Advertisements | CIS 3.3.11, Kicksecure | ADAPT | BASE |
| `net.ipv6.conf.default.accept_ra` | `0` | (same, default interface) | CIS 3.3.11 | ADAPT | BASE |

**Compliance:** CIS 3.3.9-3.3.11, PCI-DSS 2.2, SOC 2 CC6.6

**Notes:**
- **ADAPT rationale for `accept_ra`:** Router advertisements can be used for MITM and
  DoS attacks. Disabled by default. **Exception:** AWS IPv6-enabled VPCs, GCP dual-stack
  subnets, and Azure IPv6 all use Router Advertisements for address assignment. Disabling
  RA will break IPv6 connectivity on these platforms. The `lorica-base` package should
  ship a commented-out override in `/etc/sysctl.d/99-lorica-cloud-overrides.conf.example`
  with instructions, and the install documentation should prominently note this for IPv6
  users. Override: `net.ipv6.conf.all.accept_ra=1` for the relevant interface.

---

### 1.9 Network Hardening -- ICMP & TCP Options

| Setting | Value (Base) | Value (Hardened) | Description | Source | Decision | Profile |
|---------|-------------|-----------------|-------------|--------|----------|---------|
| `net.ipv4.icmp_echo_ignore_all` | `0` | `1` | Ignore all ICMP echo requests (ping) | Kicksecure | ADAPT | BASE |
| `net.ipv4.tcp_timestamps` | `1` | `1` | Keep TCP timestamps enabled | Kicksecure (disables) | ADAPT | BASE |

**Notes:**
- **ADAPT rationale for `icmp_echo_ignore_all`:** Kicksecure sets this to `1` (ignore all
  pings). For cloud servers, this breaks health checks, monitoring, and basic
  connectivity diagnostics. Base keeps it at `0`. Hardened profile sets `1`.
- **ADAPT rationale for `tcp_timestamps`:** Kicksecure disables TCP timestamps (`=0`) to
  prevent system uptime fingerprinting. **We diverge intentionally.** Modern kernels
  (5.x+) randomize TCP timestamp offsets, making the fingerprinting rationale obsolete.
  Disabling breaks PAWS (Protection Against Wrapped Sequences) and hurts TCP performance
  on lossy or high-latency links. We keep timestamps enabled in both profiles.

---

### 1.10 TCP Performance (Cloud Server Optimization)

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `net.core.default_qdisc` | `fq` | Fair Queue packet scheduler (required for BBR) | Best practice | INCLUDE | BASE |
| `net.ipv4.tcp_congestion_control` | `bbr` | BBR congestion control algorithm | Best practice | INCLUDE | BASE |

**Compliance:** N/A (performance optimization, not security hardening)

**Notes:** Not strictly security, but since Lorica already configures the TCP stack
extensively, shipping modern congestion control signals that Lorica understands server
workloads beyond just locking things down. BBR (Bottleneck Bandwidth and Round-trip
propagation time) provides significantly better throughput on high-latency and lossy
links compared to the default CUBIC. `fq` (Fair Queue) is required as the queueing
discipline for BBR to function correctly. Both are available in Debian's stock kernel.

---

### 1.11 Filesystem Protection

| Setting | Value | Description | Source | Decision | Profile |
|---------|-------|-------------|--------|----------|---------|
| `fs.protected_symlinks` | `1` | Prevent symlink-based TOCTOU attacks | KSPP, CIS, Kicksecure | INCLUDE | BASE |
| `fs.protected_hardlinks` | `1` | Prevent hardlink-based privilege escalation | KSPP, CIS, Kicksecure | INCLUDE | BASE |
| `fs.protected_fifos` | `2` | Restrict FIFO creation in world-writable sticky dirs | KSPP, Kicksecure | INCLUDE | BASE |
| `fs.protected_regular` | `2` | Restrict file creation in world-writable sticky dirs | KSPP, Kicksecure | INCLUDE | BASE |

**Compliance:** CIS 1.5.x, PCI-DSS 2.2, SOC 2 CC6.1

**Notes:**
- `protected_symlinks` and `protected_hardlinks` are default `1` on modern kernels but
  we set explicitly.
- `protected_fifos=2` and `protected_regular=2` (strictest: owner must match directory
  owner) are NOT default. These prevent a class of race condition attacks in /tmp and
  other world-writable directories.

---

### 1.12 Sysctl Settings -- EXCLUDED

These settings were evaluated and intentionally excluded from both profiles.

| Setting | Value | Source | Decision | Rationale |
|---------|-------|--------|----------|-----------|
| `kernel.unprivileged_userns_clone` | `0` | Kicksecure, KSPP | EXCLUDE | Breaks Docker and Kubernetes. Container workloads require unprivileged user namespaces. |
| `user.max_user_namespaces` | `0` | Kicksecure, KSPP | EXCLUDE | Same as above. Disabling user namespaces prevents container runtimes from functioning. |
| `kernel.modules_disabled` | `1` | KSPP | EXCLUDE (base) | Prevents all module loading after boot. Breaks cloud agents, DKMS, and any driver loaded post-init. Available in hardened profile via post-boot init script (v0.2). |
| `net.ipv6.conf.all.use_tempaddr` | `2` | Kicksecure | EXCLUDE | IPv6 privacy extensions. Rotates IPv6 addresses to prevent tracking. Irrelevant for servers with static addressing. Desktop/privacy feature. |
| `net.ipv4.conf.all.arp_ignore` | `2` | Kicksecure | EXCLUDE | Responds to ARP only if target IP is local to receiving interface. Can break multi-homed servers and some cloud networking configurations. Risk outweighs benefit for most setups. |

---

## 2. Boot Parameters

### 2.1 CPU Vulnerability Mitigations

| Parameter | Value | Description | Source | Decision | Profile |
|-----------|-------|-------------|--------|----------|---------|
| `mitigations` | `auto` | Enable all CPU mitigations appropriate to hardware | KSPP, Kicksecure | INCLUDE | BASE |

**Compliance:** PCI-DSS 2.2, SOC 2 CC6.1

**Notes:**
- `mitigations=auto` is the kernel default and enables Spectre v1/v2, Meltdown, L1TF,
  MDS, TAA, MMIO stale data, and Retbleed mitigations automatically based on hardware.
- Kicksecure additionally sets individual params (`spectre_v1=on`, `spectre_v2=on`,
  `l1tf=flush,nosmt`, `mds=full,nosmt`, etc.) for maximum strictness. These are redundant
  with `mitigations=auto` in most cases and add command-line clutter. We use the master
  switch. The hardened profile adds `nosmt` separately for SMT-specific mitigations.

---

### 2.2 Memory Hardening

| Parameter | Value | Description | Source | Decision | Profile |
|-----------|-------|-------------|--------|----------|---------|
| `init_on_alloc` | `1` | Zero-fill memory at allocation time | KSPP, Kicksecure | INCLUDE | BASE |
| `init_on_free` | `1` | Zero-fill memory at free time | KSPP, Kicksecure | INCLUDE | BASE |
| `slab_nomerge` | (flag) | Prevent slab cache merging (heap isolation) | KSPP, Kicksecure | INCLUDE | BASE |
| `page_alloc.shuffle` | `1` | Randomize page allocator freelists | KSPP, Kicksecure | INCLUDE | BASE |
| `pti` | `on` | Force Page Table Isolation (Meltdown mitigation) | KSPP, Kicksecure | INCLUDE | BASE |
| `randomize_kstack_offset` | `on` | Randomize kernel stack offset per syscall | KSPP | INCLUDE | BASE |

**Compliance:** PCI-DSS 2.2, SOC 2 CC6.1

**Notes:**
- `init_on_alloc=1` + `init_on_free=1`: Prevents information leaks and use-after-free
  exploitation via uninitialized memory. ~1-3% performance overhead on allocation-heavy
  workloads. Acceptable tradeoff for security.
- `slab_nomerge`: Prevents heap overflow in one slab cache from corrupting a different
  object type. Increases memory usage slightly.
- `pti=on`: Forces PTI even on CPUs that claim to be safe. Defense-in-depth.

---

### 2.3 Kernel Security

| Parameter | Value (Base) | Value (Hardened) | Description | Source | Decision | Profile |
|-----------|-------------|-----------------|-------------|--------|----------|---------|
| `vsyscall` | `none` | `none` | Disable vsyscall page (legacy, exploitable) | KSPP, Kicksecure | INCLUDE | BASE |
| `debugfs` | `off` | `off` | Disable debugfs entirely | KSPP, Kicksecure | INCLUDE | BASE |
| `lockdown` | `integrity` | `confidentiality` | Kernel lockdown mode | KSPP, Kicksecure | INCLUDE | BASE |
| `oops` | `panic` | `panic` | Reboot on kernel oops | KSPP, Kicksecure | INCLUDE | BASE |
| `panic` | `10` | `10` | Auto-reboot 10s after panic | Best practice | INCLUDE | BASE |
| `quiet` | (flag) | (flag) | Suppress boot messages | Kicksecure | INCLUDE | BASE |
| `loglevel` | `0` | `0` | Minimum kernel log level at boot | Kicksecure | INCLUDE | BASE |

**Compliance:** PCI-DSS 2.2, SOC 2 CC6.1, CC6.8

**Notes:**
- `lockdown=integrity` (base): Prevents unsigned module loading and direct hardware
  access from userspace. `confidentiality` (hardened) additionally blocks reading kernel
  memory, which prevents some legitimate monitoring and debugging tools from working.
- `oops=panic` (base): A kernel oops indicates likely memory corruption. On a financial
  workload behind load balancers, a clean restart is safer than continuing with a
  potentially corrupted kernel. Combined with `panic=10`, the server reboots automatically.
- `vsyscall=none`: The vsyscall page is a fixed-address mapping that defeats ASLR. No
  modern software needs it (glibc switched to vDSO in 2012).

---

### 2.4 Boot Parameters -- HARDENED-ONLY

| Parameter | Value | Description | Source | Decision | Profile |
|-----------|-------|-------------|--------|----------|---------|
| `nosmt` | (flag) | Disable Simultaneous Multi-Threading (hyperthreading) | KSPP, Kicksecure | INCLUDE | HARDENED-ONLY |
| `slub_debug` | `FZ` | SLUB sanity checks (F) + red zoning (Z) | Kicksecure | INCLUDE | HARDENED-ONLY |
| `lockdown` | `confidentiality` | Maximum kernel lockdown (replaces `integrity`) | KSPP | INCLUDE | HARDENED-ONLY |

**Notes:**
- `nosmt`: Disabling SMT prevents Spectre-class cross-thread attacks but effectively
  halves your vCPU count (~20-30% throughput loss). Most cloud hypervisors already
  mitigate at the host level. Enable this for multi-tenant workloads or environments
  processing highly sensitive data where side-channel risk is in the threat model.
- `slub_debug=FZ`: Enables SLUB allocator integrity checks and red zoning (buffer
  overflow detection). Has measurable performance overhead and disables kernel pointer
  hashing (makes kptr_restrict less effective). Only for environments where detection of
  memory corruption outweighs performance.

---

### 2.5 Boot Parameters -- EXCLUDED

| Parameter | Source | Decision | Rationale |
|-----------|--------|----------|-----------|
| `module.sig_enforce=1` | KSPP, Kicksecure | EXCLUDE | Not feasible on stock Debian kernel. Debian's kernel modules are signed, but third-party modules (DKMS, cloud agents) are not. Deferred to v0.2 with custom kernel. **v0.2 note:** When Lorica ships a custom kernel, this becomes one of the highest-value additions -- it prevents loading unsigned (potentially malicious) kernel modules entirely. The custom kernel's signing key would be the gatekeeper. |
| `spectre_v1=on`, `spectre_v2=on`, `l1tf=flush,nosmt`, `mds=full,nosmt`, etc. | Kicksecure | EXCLUDE | Redundant with `mitigations=auto`. Adding individual params provides no additional protection beyond the master switch, adds boot command-line clutter, and makes maintenance harder when new mitigations are added. |
| `efi=disable_early_pci_dma` | Kicksecure | EXCLUDE | Protects against DMA attacks via PCI devices during early boot. Cloud VMs don't have physical PCI devices exposed to untrusted DMA. |

---

## 3. Module Blacklist

All modules below are disabled via `install <module> /bin/false` in
`/etc/modprobe.d/30-lorica-blacklist.conf`. This prevents the module from loading even if
hardware requests it. All are in the BASE profile unless noted.

### 3.1 Bluetooth

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `bluetooth` | Bluetooth protocol stack | Kicksecure, CIS | CIS 1.1.x, PCI-DSS 2.2.2 |
| `btusb` | Bluetooth USB driver | Kicksecure | PCI-DSS 2.2.2 |
| `btrtl` | Realtek Bluetooth firmware | Kicksecure | PCI-DSS 2.2.2 |
| `btintel` | Intel Bluetooth firmware | Kicksecure | PCI-DSS 2.2.2 |
| `btbcm` | Broadcom Bluetooth firmware | Kicksecure | PCI-DSS 2.2.2 |
| `btmtk` | MediaTek Bluetooth firmware | Kicksecure | PCI-DSS 2.2.2 |

**Rationale:** No cloud server needs Bluetooth. Blocking the protocol stack (`bluetooth`)
and all vendor drivers eliminates the entire attack surface.

---

### 3.2 FireWire (IEEE 1394)

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `firewire_core` | FireWire bus driver (core) | Kicksecure, CIS | CIS 1.1.x, PCI-DSS 2.2.2 |
| `firewire_ohci` | FireWire OHCI host controller | Kicksecure | PCI-DSS 2.2.2 |
| `firewire_sbp2` | FireWire storage (SBP-2) | Kicksecure | PCI-DSS 2.2.2 |
| `firewire_net` | FireWire networking (IPv4 over 1394) | Kicksecure | PCI-DSS 2.2.2 |

**Rationale:** FireWire provides direct memory access (DMA) to the host. Even on VMs
without FireWire hardware, loading the driver creates kernel attack surface. Classic
physical DMA attack vector.

---

### 3.3 Thunderbolt + DMA

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `thunderbolt` | Thunderbolt bus driver | Kicksecure | PCI-DSS 2.2.2 |
| `apple_gmux` | Apple graphics MUX (Mac-specific) | Best practice | PCI-DSS 2.2.2 |

**Rationale:** Thunderbolt, like FireWire, provides DMA access. No cloud VM exposes
Thunderbolt. `apple_gmux` is Mac-specific display switching hardware, entirely irrelevant
on servers.

---

### 3.4 Sound

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `soundcore` | Linux sound subsystem core | Kicksecure | PCI-DSS 2.2.2 |
| `snd` | ALSA sound core | Kicksecure | PCI-DSS 2.2.2 |
| `snd_pcm` | ALSA PCM (audio playback/capture) | Kicksecure | PCI-DSS 2.2.2 |

**Rationale:** Blocking the core sound modules prevents all sound drivers from loading.
No server workload requires audio.

---

### 3.5 Legacy / Uncommon Filesystems

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `cramfs` | Compressed ROM filesystem | CIS 1.1.x, Kicksecure | CIS 1.1.x, PCI-DSS 2.2.2 |
| `freevxfs` | Veritas VxFS filesystem | CIS 1.1.x, Kicksecure | CIS 1.1.x, PCI-DSS 2.2.2 |
| `jffs2` | Journaling Flash File System v2 | CIS 1.1.x, Kicksecure | CIS 1.1.x, PCI-DSS 2.2.2 |
| `hfs` | Apple HFS filesystem | CIS 1.1.x, Kicksecure | CIS 1.1.x, PCI-DSS 2.2.2 |
| `hfsplus` | Apple HFS+ filesystem | CIS 1.1.x, Kicksecure | CIS 1.1.x, PCI-DSS 2.2.2 |
| `udf` | Universal Disk Format (optical media) | CIS 1.1.x, Kicksecure | CIS 1.1.x, PCI-DSS 2.2.2 |

**Rationale:** CIS benchmark explicitly requires disabling uncommon filesystems to reduce
kernel attack surface. No server workload uses these. Each filesystem module represents
parseable untrusted data paths in the kernel.

---

### 3.6 USB Storage

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `usb_storage` | USB mass storage driver | Kicksecure, CIS | PCI-DSS 2.2.2 |
| `uas` | USB Attached SCSI (fast USB storage) | Kicksecure | PCI-DSS 2.2.2 |

**Rationale:** Cloud VMs don't have USB ports. Blocking prevents any USB storage device
from being recognized if somehow passed through to a VM.

---

### 3.7 Video / Webcam

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `uvcvideo` | USB Video Class (webcams) | Kicksecure | PCI-DSS 2.2.2 |

**Rationale:** No server needs a webcam driver.

---

### 3.8 Intel Management Engine

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `mei` | Intel Management Engine Interface (core) | Kicksecure | PCI-DSS 2.2.2 |
| `mei_me` | Intel ME device driver | Kicksecure | PCI-DSS 2.2.2 |

**Rationale:** The Intel ME is a separate processor with full system access that runs
independently of the OS. The kernel driver provides a communication channel to it. On
cloud VMs, the ME is managed by the hypervisor; the guest kernel driver is unnecessary
attack surface.

---

### 3.9 Uncommon Network Protocols

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `dccp` | Datagram Congestion Control Protocol | CIS, Kicksecure | CIS 3.2.x, PCI-DSS 2.2.2 |
| `sctp` | Stream Control Transmission Protocol | CIS, Kicksecure | CIS 3.2.x, PCI-DSS 2.2.2 |
| `rds` | Reliable Datagram Sockets (Oracle) | CIS, Kicksecure | CIS 3.2.x, PCI-DSS 2.2.2 |
| `tipc` | Transparent Inter-Process Communication | CIS, Kicksecure | CIS 3.2.x, PCI-DSS 2.2.2 |
| `appletalk` | AppleTalk protocol (legacy) | Kicksecure | PCI-DSS 2.2.2 |
| `ipx` | Novell IPX protocol (legacy) | Kicksecure | PCI-DSS 2.2.2 |
| `can` | Controller Area Network (automotive/industrial) | Kicksecure | PCI-DSS 2.2.2 |
| `p8023` | 802.3 raw frame protocol (legacy) | Kicksecure | PCI-DSS 2.2.2 |
| `n_hdlc` | HDLC line discipline (multiple CVEs) | Best practice | PCI-DSS 2.2.2 |

**Rationale:** CIS benchmark explicitly requires disabling uncommon network protocols.
These represent kernel attack surface with no use case on cloud servers. DCCP, SCTP, and
RDS have had multiple kernel vulnerabilities. `n_hdlc` is included because it has been a
recurring CVE source (TTY line discipline exploits).

---

### 3.10 Miscellaneous Hardware

| Module | Description | Source | Compliance |
|--------|-------------|--------|------------|
| `pcspkr` | PC speaker (beep) | Best practice | PCI-DSS 2.2.2 |
| `vivid` | Virtual Video Test Driver (kernel test module) | Best practice | PCI-DSS 2.2.2 |
| `efi_pstore` | EFI variable storage for crash logs | Best practice | PCI-DSS 2.2.2 |

**Rationale:** `pcspkr` is noise on a headless server. `vivid` is a kernel test driver
(virtual video device) that has been repeatedly used for privilege escalation:
CVE-2019-18683, and again in 2023 as a local priv-esc vector. It should never be loaded
on production systems. `efi_pstore` writes crash data to EFI variables, which is
unnecessary on cloud VMs where serial console and CloudWatch/journald capture crash
information.

---

### 3.11 Module Blacklist -- EXCLUDED (Not Blacklisted)

These modules were considered but intentionally NOT blacklisted.

| Module | Source | Decision | Rationale |
|--------|--------|----------|-----------|
| `nouveau`, `radeon`, `amdgpu` | Kicksecure | EXCLUDE | GPU drivers. Needed for ML/GPU compute workloads (CUDA, ROCm). If not using GPUs, users can optionally blacklist. |
| `evdev` | Kicksecure | EXCLUDE | Event device input. Some cloud VMs use evdev for virtual console input. Low risk, not worth potential breakage. |
| `pcieport` | Kicksecure | EXCLUDE | PCI Express port services. Required by cloud VMs for NVMe, network adapters, and passthrough devices. |
| `cfg80211`, `mac80211` | Kicksecure | EXCLUDE | WiFi protocol stack. Already absent on cloud VMs (no WiFi hardware). Blacklisting is unnecessary and could confuse users debugging network issues. |
| `nf_conntrack` | Kicksecure | EXCLUDE | Connection tracking. Required for NAT, Docker networking, iptables stateful rules. Cannot be disabled on servers running containers. |

---

## 4. Audit Rules

All audit rules are in the BASE profile. Audit is observe-only with zero risk of breaking
workloads. These rules are written to `/etc/audit/rules.d/lorica-compliance.rules`.

**Architecture note:** All syscall-based rules (those using `-S`) include both `b64` and
`b32` variants. A 64-bit kernel can still execute 32-bit syscalls via `int 0x80`, and an
attacker could use 32-bit syscall numbers to bypass 64-bit-only audit rules. File-watch
rules (`-w`) do not need arch specifiers. This is a CIS benchmark requirement.

### 4.1 Identity and Access Changes

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-w /etc/passwd -p wa -k identity` | User account changes | CIS, PCI-DSS | 4.1.4 | 10.2.5 |
| `-w /etc/group -p wa -k identity` | Group membership changes | CIS, PCI-DSS | 4.1.4 | 10.2.5 |
| `-w /etc/shadow -p wa -k identity` | Password hash changes | CIS, PCI-DSS | 4.1.4 | 10.2.5 |
| `-w /etc/gshadow -p wa -k identity` | Group password changes | CIS | 4.1.4 | 10.2.5 |
| `-w /etc/security/opasswd -p wa -k identity` | Password history file | CIS | 4.1.4 | 10.2.5 |

**Compliance:** CIS 4.1.4, PCI-DSS 10.2.5 (identity changes), SOC 2 CC6.1

---

### 4.2 Privilege Escalation

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-w /etc/sudoers -p wa -k scope` | Sudoers file changes | CIS, PCI-DSS | 4.1.5 | 10.2.2 |
| `-w /etc/sudoers.d -p wa -k scope` | Sudoers drop-in directory | CIS | 4.1.5 | 10.2.2 |

**Compliance:** CIS 4.1.5, PCI-DSS 10.2.2 (privilege changes), SOC 2 CC6.1

---

### 4.3 Privileged Command Execution

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Password changes | CIS, PCI-DSS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Sudo usage | CIS, PCI-DSS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | User switching | CIS, PCI-DSS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Shell changes | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Group changes | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | User modification | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/sbin/groupmod -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Group modification | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | User creation | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/sbin/userdel -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | User deletion | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/sbin/groupadd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Group creation | CIS | 4.1.11 | 10.2.2 |
| `-a always,exit -F path=/usr/sbin/groupdel -F perm=x -F auid>=1000 -F auid!=-1 -k privileged` | Group deletion | CIS | 4.1.11 | 10.2.2 |

**Compliance:** CIS 4.1.11, PCI-DSS 10.2.2, SOC 2 CC7.1

**Notes:** `auid>=1000` filters to human users (not system accounts). `auid!=-1`
excludes processes without a login UID (daemons, cron jobs started at boot). Modern
`auditd` supports `-1` directly; the legacy equivalent is the unsigned form `4294967295`.

---

### 4.4 Login and Session Events

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-w /var/log/faillog -p wa -k logins` | Failed login attempts | CIS, PCI-DSS | 4.1.7 | 10.2.4 |
| `-w /var/log/lastlog -p wa -k logins` | Last login records | CIS, PCI-DSS | 4.1.7 | 10.2.4 |
| `-w /var/run/utmp -p wa -k session` | Active sessions | CIS | 4.1.7 | 10.2.1 |
| `-w /var/log/wtmp -p wa -k logins` | Historical logins | CIS | 4.1.7 | 10.2.1 |
| `-w /var/log/btmp -p wa -k logins` | Bad login attempts | CIS | 4.1.7 | 10.2.4 |

**Compliance:** CIS 4.1.7, PCI-DSS 10.2.1/10.2.4, SOC 2 CC7.1

---

### 4.5 Time Changes

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change` | System time adjustment (64-bit) | CIS, PCI-DSS | 4.1.3 | 10.4 |
| `-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change` | System time adjustment (32-bit) | CIS, PCI-DSS | 4.1.3 | 10.4 |
| `-a always,exit -F arch=b64 -S clock_settime -k time-change` | Clock setting (64-bit) | CIS | 4.1.3 | 10.4 |
| `-a always,exit -F arch=b32 -S clock_settime -k time-change` | Clock setting (32-bit) | CIS | 4.1.3 | 10.4 |
| `-w /etc/localtime -p wa -k time-change` | Timezone changes | CIS | 4.1.3 | 10.4 |

**Compliance:** CIS 4.1.3, PCI-DSS 10.4 (time synchronization), SOC 2 CC7.1

**Notes:** Time manipulation can be used to corrupt log integrity and evade detection.
PCI-DSS requires monitoring all time changes.

---

### 4.6 Network Configuration Changes

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-w /etc/hosts -p wa -k network_modifications` | Host resolution changes | CIS | 4.1.6 | 10.2.7 |
| `-w /etc/hostname -p wa -k network_modifications` | Hostname changes | CIS | 4.1.6 | 10.2.7 |
| `-w /etc/network -p wa -k network_modifications` | Network configuration | CIS | 4.1.6 | 10.2.7 |
| `-w /etc/issue -p wa -k system-locale` | System identification banner | CIS | 4.1.6 | 10.2.7 |
| `-w /etc/issue.net -p wa -k system-locale` | Remote login banner | CIS | 4.1.6 | 10.2.7 |

**Compliance:** CIS 4.1.6, PCI-DSS 10.2.7, SOC 2 CC7.1

---

### 4.7 Kernel Module Loading

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -F auid!=-1 -k modules` | Module load/unload syscalls (64-bit) | CIS, PCI-DSS | 4.1.16 | 10.2.7 |
| `-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -F auid!=-1 -k modules` | Module load/unload syscalls (32-bit) | CIS, PCI-DSS | 4.1.16 | 10.2.7 |
| `-w /sbin/modprobe -p x -k modules` | modprobe execution | CIS | 4.1.16 | 10.2.7 |
| `-w /etc/modprobe.d -p wa -k modprobe` | Module config changes | CIS | 4.1.16 | 10.2.7 |

**Compliance:** CIS 4.1.16, PCI-DSS 10.2.7, SOC 2 CC7.1

---

### 4.8 Mount Operations

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F arch=b64 -S mount -S umount2 -F auid!=-1 -k mount` | Filesystem mount/unmount (64-bit) | CIS, PCI-DSS | 4.1.12 | 10.2.7 |
| `-a always,exit -F arch=b32 -S mount -S umount2 -F auid!=-1 -k mount` | Filesystem mount/unmount (32-bit) | CIS, PCI-DSS | 4.1.12 | 10.2.7 |

**Compliance:** CIS 4.1.12, PCI-DSS 10.2.7, SOC 2 CC7.1

---

### 4.9 File Permission Changes

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod` | Permission changes (64-bit) | CIS, PCI-DSS | 4.1.9 | 10.2.7 |
| `-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=-1 -k perm_mod` | Permission changes (32-bit) | CIS, PCI-DSS | 4.1.9 | 10.2.7 |
| `-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod` | Ownership changes (64-bit) | CIS, PCI-DSS | 4.1.9 | 10.2.7 |
| `-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=-1 -k perm_mod` | Ownership changes (32-bit) | CIS, PCI-DSS | 4.1.9 | 10.2.7 |
| `-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod` | Extended attribute changes (64-bit) | CIS | 4.1.9 | 10.2.7 |
| `-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=-1 -k perm_mod` | Extended attribute changes (32-bit) | CIS | 4.1.9 | 10.2.7 |

**Compliance:** CIS 4.1.9, PCI-DSS 10.2.7, SOC 2 CC7.1

---

### 4.10 File Deletion by Users

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete` | File deletion/rename (64-bit) | CIS, PCI-DSS | 4.1.13 | 10.2.7 |
| `-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=-1 -k delete` | File deletion/rename (32-bit) | CIS, PCI-DSS | 4.1.13 | 10.2.7 |

**Compliance:** CIS 4.1.13, PCI-DSS 10.2.7, SOC 2 CC7.1

---

### 4.11 Execution from World-Writable Directories

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-a always,exit -F arch=b64 -S execve -F dir=/tmp -k tmp_exec` | Binary execution from /tmp (64-bit) | Lorica | -- | 10.2.7 |
| `-a always,exit -F arch=b32 -S execve -F dir=/tmp -k tmp_exec` | Binary execution from /tmp (32-bit) | Lorica | -- | 10.2.7 |
| `-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k tmp_exec` | Binary execution from /var/tmp (64-bit) | Lorica | -- | 10.2.7 |
| `-a always,exit -F arch=b32 -S execve -F dir=/var/tmp -k tmp_exec` | Binary execution from /var/tmp (32-bit) | Lorica | -- | 10.2.7 |

**Compliance:** PCI-DSS 10.2.7, SOC 2 CC7.1

**Notes:** This is a Lorica-original addition not required by CIS. Dropping a binary into
`/tmp` or `/var/tmp` and executing it is one of the most common attacker patterns after
initial compromise. Monitoring `execve` from world-writable directories provides early
detection of post-exploitation activity. Particularly relevant for the fintech threat model
where attackers attempt to establish persistence after web application compromise.

---

### 4.12 Scheduled Tasks and SSH

| Rule | What it monitors | Source | CIS # | PCI-DSS |
|------|-----------------|--------|-------|---------|
| `-w /etc/cron.allow -p wa -k cron` | Cron access control | CIS | 4.1.15 | 10.2.7 |
| `-w /etc/cron.deny -p wa -k cron` | Cron deny list | CIS | 4.1.15 | 10.2.7 |
| `-w /etc/cron.d -p wa -k cron` | Cron job directory | CIS | 4.1.15 | 10.2.7 |
| `-w /etc/crontab -p wa -k cron` | System crontab | CIS | 4.1.15 | 10.2.7 |
| `-w /etc/at.allow -p wa -k cron` | At access control | CIS | 4.1.15 | 10.2.7 |
| `-w /etc/at.deny -p wa -k cron` | At deny list | CIS | 4.1.15 | 10.2.7 |
| `-w /etc/ssh/sshd_config -p wa -k sshd` | SSH daemon config changes | Best practice | -- | 10.2.7 |

**Compliance:** CIS 4.1.15, PCI-DSS 10.2.7, SOC 2 CC7.1

---

### 4.13 Audit Configuration Immutability

| Rule | What it does | Source | CIS # | PCI-DSS |
|------|-------------|--------|-------|---------|
| `-e 2` | Make audit rules immutable (require reboot to change) | CIS, PCI-DSS | 4.1.17 | 10.5 |

**Compliance:** CIS 4.1.17, PCI-DSS 10.5 (secure audit trails), SOC 2 CC7.1

**Notes:** This MUST be the last rule in the file. Once applied, audit rules cannot be
modified until reboot. This prevents an attacker who gains root from disabling audit
logging to cover their tracks.

---

## 5. Summary

### Settings Count

| Category | BASE | HARDENED-ONLY | EXCLUDED | Total Evaluated |
|----------|------|---------------|----------|-----------------|
| Sysctl | 41 | 3 | 5 | 49 |
| Boot parameters | 14 | 3 | 3+ | 20 |
| Module blacklist | 38 | 0 | 5 | 43 |
| Audit rules | 16 rule groups | 0 | 0 | 16 |
| **Total** | **~109** | **6** | **13** | **~128** |

### Compliance Coverage

| Framework | Coverage |
|-----------|----------|
| CIS Debian Linux 12 | Sections 1.1.x (filesystems), 1.5.x (process hardening), 3.3.x (network params), 4.1.x (audit rules) |
| PCI-DSS v3.2.1/v4.0 | 2.2 (system hardening), 2.2.2 (unnecessary services), 10.2.x (audit events), 10.4 (time sync), 10.5 (audit integrity) |
| SOC 2 | CC6.1 (access controls), CC6.6 (system boundaries), CC6.8 (software controls), CC7.1 (monitoring) |
| CNBV | Collectively supports habilitación requirements for information security controls |

### Key Divergences from Kicksecure

| Setting | Kicksecure | Lorica Base | Why |
|---------|-----------|-------------|-----|
| `icmp_echo_ignore_all` | `1` (block all ping) | `0` (allow ping) | Cloud health checks, monitoring, and diagnostics require ICMP |
| `tcp_timestamps` | `0` (disabled) | `1` (enabled) | Modern kernels randomize offsets; disabling breaks PAWS and TCP performance |
| `drop_gratuitous_arp` | `1` (drop) | `0` (allow) | AWS ENI failover, keepalived, and floating IPs rely on gratuitous ARP |
| `unprivileged_userns_clone` | `0` (disabled) | not set (allowed) | Docker and Kubernetes require unprivileged user namespaces |
| `panic_on_warn` | `1` (panic) | not set in base | Spurious warnings shouldn't crash production servers |
| `lockdown` | `confidentiality` | `integrity` (base) | Confidentiality mode blocks legitimate monitoring/debugging tools |
| `ip_forward` | `0` | `0` (Docker overrides) | Same setting; Docker/K8s will override at runtime as needed |
| `io_uring_disabled` | not set | `1` (base) / `2` (hardened) | Lorica addition: io_uring is a prolific CVE source |
| `core_pattern` | not set | `\|/bin/false` | Lorica addition: belt-and-suspenders core dump prevention |
| `default_qdisc` + `tcp_congestion_control` | not set | `fq` + `bbr` | Lorica addition: modern congestion control for cloud servers |
| `/tmp` execve audit | not set | monitored | Lorica addition: detect attacker binary drops in world-writable dirs |

### Open Items for Step 3

- [ ] **HARD REQUIREMENT:** Validate `io_uring_disabled` sysctl on target kernel. If Debian 12 (kernel 6.1), must use `io_uring_group=-1` instead. The sysctl config or postinst script must detect kernel version and apply the correct knob. A silently failing sysctl that leaves io_uring enabled is a false sense of security.
- [ ] Verify `dev.tty.ldisc_autoload` is available on target kernel (requires 5.1+)
- [ ] Test `lockdown=integrity` on stock Debian kernel -- confirm it doesn't break cloud agents
- [ ] Determine exact privileged binary paths on Debian 13 (Trixie) for audit rules
- [ ] Test `oops=panic` on Debian stock kernel -- confirm clean reboot behavior
