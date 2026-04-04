# Lorica Linux -- Configuration Rationale

> For sysadmins and auditors. Every setting shipped by `lorica-base` and
> `lorica-hardened-profile` is listed here with its value, purpose, rationale,
> breakage risk, and compliance mapping.
>
> Authoritative source of design decisions: `docs/hardening-decisions.md`
>
> Generated from shipped config files, cross-referenced against hardening-decisions.md.
> Last updated: 2026-04-02

---

## Profiles

Lorica ships two hardening profiles:

- **lorica-base** (default) -- Bold, opinionated defaults for production cloud servers.
  Docker/K8s work. Monitoring works. `sudo strace` works. Installed via
  `apt install lorica-cloud-server`.

- **lorica-hardened-profile** (opt-in) -- Maximum hardening. Disables hyperthreading,
  blocks all ICMP, panics on kernel warnings, upgrades kernel lockdown to
  `confidentiality`. Install via `apt install lorica-hardened-profile`, then reboot.

Override any setting by placing a file in `/etc/sysctl.d/99-*.conf` (takes priority
over `/usr/lib/sysctl.d/`). GRUB overrides go in `/etc/default/grub.d/` with a higher
number prefix.

---

## 1. Sysctl Hardening

**Config file:** `/usr/lib/sysctl.d/90-lorica-hardening.conf` (lorica-base)
**Hardened overrides:** `/etc/sysctl.d/92-lorica-hardened.conf` (lorica-hardened-profile)

### 1.1 Kernel Information Leak Prevention

**Compliance:** CIS 1.5.1, PCI-DSS 2.2, SOC 2 CC6.1

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `kernel.kptr_restrict` | `2` | Hides kernel pointers from all users, including root | On a production server, no one should read raw kernel addresses. Value `1` only hides from unprivileged users; `2` hides from everyone. | Setting to `0` exposes kernel ASLR layout, making exploits trivial to target. Setting to `1` still leaks to root. | KSPP, Kicksecure, CIS |
| `kernel.dmesg_restrict` | `1` | Restricts kernel log access to processes with `CAP_SYSLOG` | Kernel logs can reveal addresses, hardware details, and loaded modules useful to attackers. | Setting to `0` lets any user read dmesg, leaking kernel internals. | KSPP, Kicksecure, CIS |
| `kernel.perf_event_paranoid` | `3` | Disallows all unprivileged perf events | Perf can leak kernel addresses and timing information. Value `3` is Debian-specific (upstream rejected it); supported on Debian's stock kernel. | Setting to `2` allows unprivileged CPU-level profiling. Setting to `0`/`1` allows userspace profiling that can leak kernel state. | KSPP, Kicksecure |
| `kernel.printk` | `3 3 3 3` | Suppresses kernel messages on console | Reduces information leakage via console output. All four values (current, default, minimum, boot-time-default) set to `3` (errors only). | Raising values increases verbosity, potentially exposing sensitive kernel details on serial consoles or cloud console logs. | Kicksecure |
| `kernel.randomize_va_space` | `2` | Enables full ASLR: stack, VDSO, mmap, and heap | Already default on modern kernels; set explicitly as defense-in-depth so nothing can accidentally lower it. | Setting to `0` disables ASLR entirely. Setting to `1` randomizes only stack and mmap. | KSPP, CIS 1.5.1 |

### 1.2 Memory Protection

**Compliance:** CIS 1.5.3, PCI-DSS 2.2, SOC 2 CC6.1

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `vm.mmap_min_addr` | `65536` | Blocks low-address mmap (first 64 KB) | Prevents null pointer dereference exploits, which require mapping the zero page. 64 KB is the standard minimum. | Lowering allows mapping addresses near zero, enabling a class of kernel exploits. | KSPP, Kicksecure |
| `fs.suid_dumpable` | `0` | Disables core dumps for SUID/SGID processes | Prevents privileged process memory (which may contain credentials) from being written to disk. | Setting to `1` or `2` allows core dumps of privileged processes, potentially exposing secrets. | KSPP, CIS 1.5.3 |
| `kernel.core_pattern` | `\|/bin/false` | Pipes all core dumps to `/bin/false` (discards them) | Belt-and-suspenders with `suid_dumpable=0`. Even non-SUID processes can hold secrets (API keys, session tokens, database credentials). | Changing to a file path enables core dump collection. Useful for debugging but a secret-exposure risk in production. | Lorica |

### 1.3 Attack Surface Reduction

**Compliance:** PCI-DSS 2.2, SOC 2 CC6.8

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `kernel.kexec_load_disabled` | `1` | Disables kexec (runtime kernel replacement) | An attacker with root could use kexec to replace the running kernel, bypassing all protections. Irreversible until reboot. No legitimate use on production servers. | Setting to `0` allows runtime kernel replacement. Only useful for live-patching workflows (which should use kpatch instead). | KSPP, Kicksecure |
| `kernel.sysrq` | `0` | Disables the SysRq key entirely | SysRq can force reboots, kill processes, and sync disks -- useful for physical debugging, dangerous on cloud servers where console access exists. | Setting to non-zero enables various SysRq functions (1=all, or bitmask for specific functions). | Kicksecure, CIS |
| `kernel.unprivileged_bpf_disabled` | `1` | Restricts eBPF to `CAP_BPF` (root) | eBPF has been a recurring kernel exploit vector. Unprivileged eBPF is unnecessary on servers. | Setting to `0` allows unprivileged users to load eBPF programs, increasing attack surface. | KSPP, Kicksecure |
| `net.core.bpf_jit_harden` | `2` | Hardens BPF JIT against spray attacks | Constant blinding for both privileged and unprivileged JIT. Prevents using JIT-compiled BPF as a code-reuse gadget. | Setting to `0` disables JIT hardening. Setting to `1` only hardens unprivileged JIT. | KSPP, Kicksecure |
| `dev.tty.ldisc_autoload` | `0` | Prevents TTY line discipline autoloading | Requires kernel 5.1+. Vulnerable line disciplines like `n_hdlc` have had multiple CVEs. Disabling autoload prevents exploitation without explicit `root` action. | Setting to `1` allows any process to trigger loading of any line discipline module. | KSPP |
| `vm.unprivileged_userfaultfd` | `0` | Blocks unprivileged userfaultfd | `userfaultfd` provides attacker-controlled page fault handling, a key primitive in use-after-free exploits. No unprivileged use case on servers. | Setting to `1` allows unprivileged users to use userfaultfd, enabling a class of kernel exploits. | KSPP |

**Note on io_uring:** io_uring restriction is handled by the `postinst` script because
the sysctl name depends on kernel version. On kernel 6.6+, `kernel.io_uring_disabled=1`
(base) or `=2` (hardened). On kernel 6.1 (Debian 12), `io_uring_group=-1` restricts
io_uring to root. The generated config is written to `/etc/sysctl.d/91-lorica-io-uring.conf`.
io_uring has been a prolific CVE source (2023-2025); Google disabled it in production.

### 1.4 Process Isolation

**Compliance:** CIS 1.5.2, PCI-DSS 2.2, SOC 2 CC6.1

| Setting | Value (Base) | Value (Hardened) | What it does | Why this value | What breaks if you change it | Source |
|---------|-------------|-----------------|-------------|----------------|------------------------------|--------|
| `kernel.yama.ptrace_scope` | `2` | `3` | Restricts ptrace. `2`=requires `CAP_SYS_PTRACE`; `3`=no attach at all | Base: `sudo strace` works but unprivileged `strace` does not. KSPP recommends `3` but that breaks too many debugging workflows for a default. Hardened: maximum lockdown. | Base `2`: unprivileged debuggers (strace, gdb) won't work without sudo. Hardened `3`: even `sudo strace -p <pid>` won't work -- only strace on child processes via `sudo strace <command>`. | KSPP, Kicksecure |
| `kernel.sched_child_runs_first` | — | — | **Removed.** EEVDF scheduler (kernel 6.12+, Debian 13) dropped this sysctl. Previously set to `1` (Kicksecure default) to run child before parent after `fork()`. | N/A — sysctl no longer exists on modern kernels. | N/A | Kicksecure |
| `kernel.panic` | `10` | `10` | Auto-reboot 10 seconds after kernel panic | On cloud servers behind load balancers, a fast reboot is better than a hung instance. Kicksecure uses `-1` (delegate to systemd); we prefer explicit kernel-level reboot. | Setting to `0` disables auto-reboot (server hangs on panic). Higher values delay recovery. | Best practice |

### 1.6 Network Hardening -- IPv4

**Compliance:** CIS 3.3.1-3.3.8, PCI-DSS 2.2, SOC 2 CC6.6

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `net.ipv4.tcp_syncookies` | `1` | Enables SYN flood protection | Under SYN flood, the kernel uses cryptographic cookies instead of allocating connection state, preventing resource exhaustion. | Setting to `0` removes SYN flood protection. No reason to disable. | CIS 3.3.8, Kicksecure |
| `net.ipv4.conf.all.rp_filter` | `1` | Strict reverse path filtering (anti-spoofing) | Validates that each incoming packet's source address is reachable via the interface it arrived on. Prevents IP spoofing. | Setting to `0` disables anti-spoofing. Setting to `2` (loose mode) allows asymmetric routing but weakens spoofing protection. | CIS 3.3.7, KSPP, Kicksecure |
| `net.ipv4.conf.default.rp_filter` | `1` | Same as above, for newly created interfaces | Ensures new interfaces inherit the setting. | Same as above. | CIS 3.3.7 |
| `net.ipv4.conf.all.accept_redirects` | `0` | Ignores ICMP redirect messages | ICMP redirects can be used for MITM attacks by rerouting traffic through an attacker's host. Servers should use static routes. | Setting to `1` allows remote hosts to alter the server's routing table. | CIS 3.3.3, Kicksecure |
| `net.ipv4.conf.default.accept_redirects` | `0` | Same for new interfaces | Ensures new interfaces inherit the setting. | Same as above. | CIS 3.3.3 |
| `net.ipv4.conf.all.secure_redirects` | `0` | Ignores "secure" ICMP redirects (from default gateway) | Even redirects from the default gateway can be spoofed. There is no secure ICMP redirect on an untrusted network. | Setting to `1` trusts redirects from the default gateway, which may be spoofed. | CIS 3.3.4, Kicksecure |
| `net.ipv4.conf.default.secure_redirects` | `0` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.4 |
| `net.ipv4.conf.all.send_redirects` | `0` | Prevents sending ICMP redirects | A server is not a router and should not send redirects. | Setting to `1` is only valid for routers; on a server, it leaks network topology. | CIS 3.3.2, Kicksecure |
| `net.ipv4.conf.default.send_redirects` | `0` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.2 |
| `net.ipv4.conf.all.accept_source_route` | `0` | Disables source-routed packets | Source routing allows the sender to dictate the packet's path, bypassing network security controls. | Setting to `1` allows attackers to route packets through specific paths to bypass firewalls. | CIS 3.3.6, Kicksecure |
| `net.ipv4.conf.default.accept_source_route` | `0` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.6 |
| `net.ipv4.conf.all.log_martians` | `1` | Logs packets with impossible source addresses | Martian packets indicate spoofing attempts or misconfiguration. Logging enables detection. | Setting to `0` silently drops impossible packets without logging, hindering forensics. | CIS 3.3.5, Kicksecure |
| `net.ipv4.conf.default.log_martians` | `1` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.5 |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | Ignores ICMP echo requests sent to broadcast addresses | Prevents Smurf amplification attacks where the server is used to flood a victim. | Setting to `0` allows the server to participate in Smurf attacks. | CIS, Kicksecure |
| `net.ipv4.icmp_ignore_bogus_error_responses` | `1` | Ignores bogus ICMP error responses | Prevents log flooding from malformed ICMP errors. | Setting to `0` allows log pollution from crafted ICMP packets. | CIS, Kicksecure |
| `net.ipv4.tcp_rfc1337` | `1` | Enables TIME-WAIT assassination protection (RFC 1337) | Prevents RST packets from prematurely closing TIME-WAIT sockets, which can cause connection hijacking. | Setting to `0` allows TIME-WAIT assassination. No compatibility cost to enabling. | Kicksecure |
| `net.ipv4.ip_forward` | `0` | Disables IP forwarding | A server is not a router. Docker and Kubernetes override this to `1` at runtime automatically; this provides the secure default. | Setting to `1` allows the server to route packets between interfaces. Container runtimes set this as needed. | CIS 3.3.1 |

### 1.7 Network Hardening -- ARP

**Compliance:** PCI-DSS 2.2, SOC 2 CC6.6

| Setting | Value (Base) | Value (Hardened) | What it does | Why this value | What breaks if you change it | Source |
|---------|-------------|-----------------|-------------|----------------|------------------------------|--------|
| `net.ipv4.conf.all.drop_gratuitous_arp` | `0` | `1` | Controls whether gratuitous ARP frames are dropped | Base allows gratuitous ARP because AWS ENI failover, keepalived, and floating IPs depend on it. Cloud VPCs mitigate ARP poisoning at the network layer. Hardened drops it for bare-metal or trusted-network environments where ARP poisoning is a real threat. | Base: setting to `1` breaks AWS ENI failover, keepalived, and any floating IP mechanism. Hardened: setting to `0` allows ARP cache poisoning on networks without VPC-level protection. | Kicksecure |
| `net.ipv4.conf.all.arp_filter` | `1` | `1` | ARP filtering -- responds only on the correct interface | Prevents ARP responses from leaking across interfaces on multi-homed servers. | Setting to `0` allows a host to respond to ARP requests on any interface, regardless of which interface owns the IP. | Kicksecure |

### 1.8 Network Hardening -- IPv6

**Compliance:** CIS 3.3.9-3.3.11, PCI-DSS 2.2, SOC 2 CC6.6

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `net.ipv6.conf.all.accept_redirects` | `0` | Ignores IPv6 ICMP redirects | Same rationale as IPv4 redirects: MITM prevention. | Setting to `1` allows remote hosts to alter IPv6 routing. | CIS 3.3.9, Kicksecure |
| `net.ipv6.conf.default.accept_redirects` | `0` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.9 |
| `net.ipv6.conf.all.accept_source_route` | `0` | Disables IPv6 source routing | Prevents sender-dictated packet paths. | Setting to `1` allows source routing, bypassing network controls. | CIS 3.3.10, Kicksecure |
| `net.ipv6.conf.default.accept_source_route` | `0` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.10 |
| `net.ipv6.conf.all.accept_ra` | `0` | Disables IPv6 Router Advertisements | Router advertisements can be used for MITM and DoS. Disabled by default. **Exception:** cloud IPv6 VPCs use RA for address assignment -- see Cloud Overrides section. | Setting to `1` is required for AWS/GCP/Azure IPv6 VPCs. Without it, SLAAC-based IPv6 addresses won't be assigned. See section 7. | CIS 3.3.11, Kicksecure |
| `net.ipv6.conf.default.accept_ra` | `0` | Same for new interfaces | Same rationale. | Same as above. | CIS 3.3.11 |

### 1.9 ICMP and TCP Options

| Setting | Value (Base) | Value (Hardened) | What it does | Why this value | What breaks if you change it | Source |
|---------|-------------|-----------------|-------------|----------------|------------------------------|--------|
| `net.ipv4.icmp_echo_ignore_all` | `0` | `1` | Controls whether the server responds to ping | Base allows ping because cloud health checks, monitoring (Nagios, Datadog, Prometheus blackbox exporter), and basic connectivity diagnostics depend on ICMP echo. Hardened blocks it to reduce fingerprinting surface. | Base: setting to `1` breaks cloud load balancer health checks and ping-based monitoring. Hardened: setting to `0` allows network fingerprinting via ping. | Kicksecure |
| `net.ipv4.tcp_timestamps` | `1` | `1` | Keeps TCP timestamps enabled | Kicksecure disables timestamps to prevent uptime fingerprinting. **We diverge intentionally.** Modern kernels (5.x+) randomize TCP timestamp offsets, making fingerprinting obsolete. Disabling breaks PAWS (Protection Against Wrapped Sequences) and hurts TCP performance on lossy/high-latency links. Enabled in both profiles. | Setting to `0` breaks PAWS, degrades TCP performance on lossy links, and can cause connection failures under high sequence number wrap rates. | Kicksecure (adapted) |

### 1.10 TCP Performance

**Compliance:** N/A (performance optimization)

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `net.core.default_qdisc` | `fq` | Sets Fair Queue as the default packet scheduler | Required for BBR congestion control to function correctly. | Changing breaks BBR. The default `pfifo_fast` works with CUBIC but not BBR. | Best practice |
| `net.ipv4.tcp_congestion_control` | `bbr` | Enables BBR congestion control | BBR (Bottleneck Bandwidth and Round-trip propagation time) provides significantly better throughput on high-latency and lossy links compared to CUBIC. Available in Debian's stock kernel. | Changing to `cubic` (default) loses BBR's advantages on cloud networks. Not a security concern. | Best practice |

### 1.11 Filesystem Protection

**Compliance:** CIS 1.5.x, PCI-DSS 2.2, SOC 2 CC6.1

| Setting | Value | What it does | Why this value | What breaks if you change it | Source |
|---------|-------|-------------|----------------|------------------------------|--------|
| `fs.protected_symlinks` | `1` | Prevents symlink-based TOCTOU attacks | Restricts following symlinks in world-writable sticky directories (like `/tmp`) unless the follower owns the symlink. Prevents a class of time-of-check-to-time-of-use attacks. Default on modern kernels; set explicitly. | Setting to `0` allows symlink TOCTOU attacks in `/tmp`. | KSPP, CIS, Kicksecure |
| `fs.protected_hardlinks` | `1` | Prevents hardlink-based privilege escalation | Restricts creating hardlinks to files the user doesn't own. Prevents using hardlinks to gain access to privileged files. Default on modern kernels; set explicitly. | Setting to `0` allows hardlink-based privilege escalation. | KSPP, CIS, Kicksecure |
| `fs.protected_fifos` | `2` | Restricts FIFO creation in world-writable sticky directories | Value `2` (strictest): FIFO owner must match directory owner. Prevents race condition attacks via named pipes in `/tmp`. NOT a kernel default. | Setting to `0` allows unrestricted FIFO creation. Setting to `1` is less strict (only checks group). | KSPP, Kicksecure |
| `fs.protected_regular` | `2` | Restricts regular file creation in world-writable sticky directories | Value `2` (strictest): file owner must match directory owner. Same class of race condition prevention as `protected_fifos`. NOT a kernel default. | Setting to `0` allows unrestricted file creation. Setting to `1` is less strict. | KSPP, Kicksecure |

### 1.5 Crash Behavior (HARDENED-ONLY)

These settings are NOT in lorica-base. They are activated by `lorica-hardened-profile`.

**Compliance:** KSPP full compliance

| Setting | Value | What it does | Why HARDENED-ONLY | What breaks if you enable it | Source |
|---------|-------|-------------|-------------------|------------------------------|--------|
| `kernel.panic_on_warn` | `1` | Panics (reboots) on kernel warnings, not just oops | Kernel warnings are often informational -- a spurious driver warning or benign race condition. Panicking on warnings in production causes unnecessary reboots. Appropriate for high-security environments where any kernel anomaly is unacceptable. | Server reboots on any kernel warning, including benign ones. Expect increased reboot frequency on some hardware/driver combinations. | KSPP, Kicksecure |
| `kernel.oops_limit` | `1` | Panics after the first kernel oops | In base, `oops=panic` (boot param) already reboots on oops. This sysctl provides an additional safety net for the hardened profile. | Same as `oops=panic` -- reboots on first oops. | KSPP |
| `kernel.warn_limit` | `1` | Panics after the first kernel warning | Companion to `panic_on_warn`. Ensures even a single warning triggers a reboot in the hardened profile. | Same breakage as `panic_on_warn`. | KSPP |

---

## 2. GRUB Boot Parameters

**Config file:** `/etc/default/grub.d/50-lorica-hardening.cfg` (lorica-base)
**Hardened overrides:** `/etc/default/grub.d/51-lorica-hardened.cfg` (lorica-hardened-profile)

After modifying, run `sudo update-grub && reboot`.

### 2.1 BASE Parameters

| Parameter | Value | What it does | Why this value | What breaks if you change it | Source | Compliance |
|-----------|-------|-------------|----------------|------------------------------|--------|------------|
| `mitigations` | `auto` | Enables all CPU vulnerability mitigations appropriate to hardware | Master switch for Spectre, Meltdown, L1TF, MDS, TAA, Retbleed, etc. Kicksecure sets individual params (`spectre_v2=on`, etc.) but these are redundant with `auto` and add clutter. | Setting to `off` disables all CPU mitigations. ~5-30% performance gain but exposes the system to hardware vulnerabilities. | KSPP, Kicksecure | PCI-DSS 2.2, SOC 2 CC6.1 |
| `oops=panic` | -- | Reboots the kernel on any oops (likely memory corruption) | On a financial workload behind a load balancer, a clean restart is safer than continuing with a potentially corrupted kernel. Combined with `panic=10` for automatic reboot. | Removing allows the kernel to continue after an oops, risking data corruption. | KSPP, Kicksecure | PCI-DSS 2.2 |
| `panic` | `10` | Auto-reboot 10 seconds after kernel panic | Gives enough time for panic output to reach serial console / CloudWatch, then reboots. | Setting to `0` causes the server to hang indefinitely on panic. Higher values delay recovery. | Best practice | -- |
| `init_on_alloc` | `1` | Zero-fills memory at allocation time | Prevents information leaks and use-after-free exploitation via uninitialized memory. ~1-3% performance overhead on allocation-heavy workloads. | Setting to `0` removes the overhead but allows uninitialized memory reads. | KSPP, Kicksecure | PCI-DSS 2.2, SOC 2 CC6.1 |
| `init_on_free` | `1` | Zero-fills memory at free time | Same as `init_on_alloc` but at deallocation. Together they ensure memory is clean on both sides of its lifecycle. ~1-3% additional overhead. | Setting to `0` leaves freed memory intact, enabling use-after-free data leaks. | KSPP, Kicksecure | PCI-DSS 2.2, SOC 2 CC6.1 |
| `slab_nomerge` | (flag) | Prevents slab cache merging (heap isolation) | Without this, the kernel merges slab caches with similar object sizes for efficiency. Merging allows a heap overflow in one cache to corrupt objects of a different type. Increases memory usage slightly. | Removing allows slab merging, making cross-cache heap exploits easier. | KSPP, Kicksecure | PCI-DSS 2.2 |
| `page_alloc.shuffle` | `1` | Randomizes page allocator freelists | Makes heap layout less predictable, increasing the difficulty of heap spray attacks. | Setting to `0` returns to deterministic page allocation order. | KSPP, Kicksecure | PCI-DSS 2.2 |
| `pti` | `on` | Forces Page Table Isolation (Meltdown mitigation) | Forces PTI even on CPUs that claim to be safe. Defense-in-depth against undisclosed Meltdown variants. | Setting to `off` disables PTI, removing Meltdown protection. Setting to `auto` trusts CPU's self-reported immunity. | KSPP, Kicksecure | PCI-DSS 2.2, SOC 2 CC6.1 |
| `vsyscall` | `none` | Disables the vsyscall page | The vsyscall page is a fixed-address mapping that defeats ASLR. No modern software needs it (glibc switched to vDSO in 2012). | Setting to `emulate` provides backward compatibility for very old binaries. `xonly` is a middle ground. Ancient glibc (pre-2.15) may break with `none`. | KSPP, Kicksecure | PCI-DSS 2.2 |
| `debugfs` | `off` | Disables debugfs entirely | debugfs exposes kernel internal state and is a recurring source of information leaks. No production use case. | Setting to `on` exposes `/sys/kernel/debug/`. Useful for kernel development only. | KSPP, Kicksecure | PCI-DSS 2.2, SOC 2 CC6.8 |
| `lockdown` | `integrity` | Enables kernel lockdown in integrity mode | Prevents unsigned module loading and direct hardware access from userspace. Does not block reading kernel memory (confidentiality mode does). Chosen for base because confidentiality mode breaks some monitoring and debugging tools. | Removing disables lockdown entirely. Setting to `confidentiality` additionally blocks reading kernel memory (see hardened profile). | KSPP, Kicksecure | PCI-DSS 2.2, SOC 2 CC6.1 |
| `randomize_kstack_offset` | `on` | Randomizes kernel stack offset per syscall | Prevents stack-based attacks that depend on predicting kernel stack layout. | Setting to `off` returns to deterministic kernel stack offsets. | KSPP | PCI-DSS 2.2 |
| `quiet loglevel=0` | -- | Suppresses boot messages | Reduces information leakage via boot console. Combined with `kernel.printk=3 3 3 3` (sysctl) for runtime suppression. | Removing increases boot verbosity. Useful for debugging but exposes kernel details on shared consoles. | Kicksecure | -- |

### 2.2 HARDENED-ONLY Parameters

These supplement the base parameters. The kernel uses the last value for duplicate params, so `lockdown=confidentiality` overrides base's `lockdown=integrity`.

| Parameter | Value | What it does | Why HARDENED-ONLY | What breaks if you enable it | Source |
|-----------|-------|-------------|-------------------|------------------------------|--------|
| `nosmt` | (flag) | Disables Simultaneous Multi-Threading (hyperthreading) | Prevents Spectre-class cross-thread attacks. Effectively halves vCPU count with ~20-30% throughput loss. Most cloud hypervisors already mitigate at the host level. Enable for multi-tenant workloads processing highly sensitive data where side-channel risk is in the threat model. | Halves vCPU count. ~20-30% throughput reduction on CPU-bound workloads. | KSPP, Kicksecure |
| `slub_debug` | `FZ` | Enables SLUB allocator integrity checks (F) and red zoning (Z) | Detects heap buffer overflows and use-after-free at the allocator level. Measurable performance overhead. **Interaction:** disables kernel pointer hashing, which weakens `kptr_restrict` protection. Accepted tradeoff -- SLUB integrity checking is prioritized over pointer obfuscation in the hardened profile. | Performance overhead on allocation-heavy workloads. Disables kernel pointer hashing. | Kicksecure |
| `lockdown` | `confidentiality` | Maximum kernel lockdown (replaces `integrity` from base) | Additionally blocks reading kernel memory via `/dev/mem`, `/dev/kmem`, and kprobes. Prevents tools like `bpftrace`, some `perf` modes, and `/proc/kcore` from working. | Breaks `bpftrace`, some `perf` profiling modes, `/proc/kcore` access, and any tool that reads kernel memory. | KSPP |

---

## 3. Kernel Module Blacklist

**Config file:** `/etc/modprobe.d/30-lorica-blacklist.conf` (lorica-base)

All modules are disabled via `install <module> /bin/false`, which prevents loading even if hardware requests it. All are in the BASE profile.

### 3.1 Bluetooth

**Modules:** `bluetooth`, `btusb`, `btrtl`, `btintel`, `btbcm`, `btmtk`

**Rationale:** No cloud server needs Bluetooth. Blocking the protocol stack (`bluetooth`) and all vendor drivers eliminates the entire attack surface.

**What breaks:** Bluetooth devices won't be recognized. Irrelevant on cloud VMs.

**Compliance:** CIS 1.1.x, PCI-DSS 2.2.2

### 3.2 FireWire (IEEE 1394)

**Modules:** `firewire_core`, `firewire_ohci`, `firewire_sbp2`, `firewire_net`

**Rationale:** FireWire provides direct memory access (DMA) to the host. Even on VMs without FireWire hardware, loading the driver creates kernel attack surface. Classic physical DMA attack vector.

**What breaks:** FireWire devices won't work. Irrelevant on cloud VMs.

**Compliance:** CIS 1.1.x, PCI-DSS 2.2.2

### 3.3 Thunderbolt and DMA

**Modules:** `thunderbolt`, `apple_gmux`

**Rationale:** Thunderbolt, like FireWire, provides DMA access. No cloud VM exposes Thunderbolt. `apple_gmux` is Mac-specific display switching hardware, entirely irrelevant on servers.

**What breaks:** Thunderbolt devices won't be recognized. Irrelevant on cloud VMs.

**Compliance:** PCI-DSS 2.2.2

### 3.4 Sound

**Modules:** `soundcore`, `snd`, `snd_pcm`

**Rationale:** Blocking the core sound modules prevents all sound drivers from loading. No server workload requires audio.

**What breaks:** Audio won't work. Irrelevant on headless servers.

**Compliance:** PCI-DSS 2.2.2

### 3.5 Legacy / Uncommon Filesystems

**Modules:** `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`

**Rationale:** CIS benchmark explicitly requires disabling uncommon filesystems. Each filesystem module represents parseable untrusted data paths in the kernel. No server workload uses these.

**What breaks:** Cannot mount these filesystem types. Use `ext4`, `xfs`, or `btrfs` instead.

**Compliance:** CIS 1.1.x, PCI-DSS 2.2.2

### 3.6 USB Storage

**Modules:** `usb_storage`, `uas`

**Rationale:** Cloud VMs don't have USB ports. Blocking prevents USB storage devices from being recognized if somehow passed through to a VM.

**What breaks:** USB drives won't be mounted. Irrelevant on cloud VMs.

**Compliance:** PCI-DSS 2.2.2

### 3.7 Video / Webcam

**Modules:** `uvcvideo`

**Rationale:** No server needs a webcam driver.

**What breaks:** USB webcams won't work. Irrelevant on headless servers.

**Compliance:** PCI-DSS 2.2.2

### 3.8 Intel Management Engine

**Modules:** `mei`, `mei_me`

**Rationale:** The Intel ME is a separate processor with full system access running independently of the OS. The kernel driver provides a communication channel to it. On cloud VMs, the ME is managed by the hypervisor; the guest kernel driver is unnecessary attack surface.

**What breaks:** Intel AMT remote management via the guest OS. Cloud VMs use hypervisor-level management instead.

**Compliance:** PCI-DSS 2.2.2

### 3.9 Uncommon Network Protocols

**Modules:** `dccp`, `sctp`, `rds`, `tipc`, `appletalk`, `ipx`, `can`, `p8023`, `n_hdlc`

**Rationale:** CIS benchmark explicitly requires disabling uncommon network protocols. DCCP, SCTP, and RDS have had multiple kernel vulnerabilities. `n_hdlc` is a recurring CVE source (TTY line discipline exploits). No cloud server workload uses any of these.

**What breaks:** Applications using DCCP, SCTP, RDS, TIPC, AppleTalk, IPX, CAN bus, 802.3 raw frames, or HDLC won't work. If you need SCTP (some telecom workloads), remove that specific line from the blacklist.

**Compliance:** CIS 3.2.x, PCI-DSS 2.2.2

### 3.10 Miscellaneous Hardware

**Modules:** `pcspkr`, `vivid`, `efi_pstore`

**Rationale:**
- `pcspkr` -- PC speaker beep. Noise on a headless server.
- `vivid` -- Virtual Video Test Driver. A kernel test module repeatedly used for privilege escalation (CVE-2019-18683 and again in 2023). Should never be loaded on production systems.
- `efi_pstore` -- Writes crash data to EFI variables. Unnecessary on cloud VMs where serial console and journald capture crash information.

**What breaks:** PC speaker beeps, the `vivid` test device, and EFI-based crash logging. None are relevant to cloud servers.

**Compliance:** PCI-DSS 2.2.2

---

## 4. Audit Rules

**Config file:** `/etc/audit/rules.d/lorica-compliance.rules` (lorica-base)

Audit rules are observe-only with zero risk of breaking workloads. All are in the BASE
profile.

**Architecture note:** All syscall rules include both `b64` and `b32` variants. A 64-bit
kernel can execute 32-bit syscalls via `int 0x80`, and an attacker could use 32-bit
syscall numbers to bypass 64-bit-only audit rules. This is a CIS benchmark requirement.

**Filter note:** `auid>=1000` restricts to human users (UID 1000+, not system accounts).
`auid!=-1` excludes processes without a login UID (daemons, cron jobs started at boot).

### Global Settings

| Setting | Value | Purpose |
|---------|-------|---------|
| `-b 8192` | Buffer size 8192 | Large enough for busy servers without excessive memory usage |
| `-f 1` | Failure mode: syslog | On buffer overflow, log to syslog rather than panicking. Avoids DoS via audit flooding. |

### 4.1 Identity and Access Changes

**Rules:** Watch `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, `/etc/security/opasswd` for writes and attribute changes.

**Why:** Detects unauthorized user/group creation, password changes, and membership modifications. Any change to these files outside of expected provisioning is a red flag.

**Compliance:** CIS 4.1.4, PCI-DSS 10.2.5, SOC 2 CC6.1

### 4.2 Privilege Escalation

**Rules:** Watch `/etc/sudoers` and `/etc/sudoers.d` for writes and attribute changes.

**Why:** Modifying sudoers is a primary post-exploitation persistence technique. Detects privilege escalation attempts.

**Compliance:** CIS 4.1.5, PCI-DSS 10.2.2, SOC 2 CC6.1

### 4.3 Privileged Command Execution

**Rules:** Monitor execution of `passwd`, `sudo`, `su`, `chsh`, `newgrp`, `usermod`, `groupmod`, `useradd`, `userdel`, `groupadd`, `groupdel` by human users (auid >= 1000).

**Why:** Tracks who used privileged commands and when. Essential for incident investigation and compliance auditing.

**Compliance:** CIS 4.1.11, PCI-DSS 10.2.2, SOC 2 CC7.1

### 4.4 Login and Session Events

**Rules:** Watch `/var/log/faillog`, `/var/log/lastlog`, `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp` for writes and attribute changes.

**Why:** Detects login tracking manipulation. An attacker modifying these files is attempting to hide their access.

**Compliance:** CIS 4.1.7, PCI-DSS 10.2.1/10.2.4, SOC 2 CC7.1

### 4.5 Time Changes

**Rules:** Monitor `adjtimex`, `settimeofday`, `stime` (32-bit), `clock_settime` syscalls and watch `/etc/localtime` for changes.

**Why:** Time manipulation corrupts log integrity and evades detection. PCI-DSS explicitly requires monitoring all time changes.

**Compliance:** CIS 4.1.3, PCI-DSS 10.4, SOC 2 CC7.1

### 4.6 Network Configuration Changes

**Rules:** Watch `/etc/hosts`, `/etc/hostname`, `/etc/network`, `/etc/issue`, `/etc/issue.net` for writes and attribute changes.

**Why:** Detects DNS hijacking (hosts file), hostname changes that could affect log correlation, and network reconfiguration. Issue file changes may indicate defacement or information disclosure.

**Compliance:** CIS 4.1.6, PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.7 Kernel Module Loading

**Rules:** Monitor `init_module`, `finit_module`, `delete_module` syscalls (b64 + b32), watch `/sbin/modprobe` execution, and watch `/etc/modprobe.d` for changes.

**Why:** Kernel module loading is a primary rootkit installation vector. Any module load/unload outside of expected boot-time initialization should be investigated.

**Compliance:** CIS 4.1.16, PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.8 Mount Operations

**Rules:** Monitor `mount` and `umount2` syscalls (b64 + b32).

**Why:** Unexpected mount operations can indicate data exfiltration, backdoor filesystem mounting, or privilege escalation via mount namespace manipulation.

**Compliance:** CIS 4.1.12, PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.9 File Permission Changes

**Rules:** Monitor `chmod`, `fchmod`, `fchmodat`, `chown`, `fchown`, `fchownat`, `lchown`, `setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr` syscalls by human users (b64 + b32).

**Why:** Permission and ownership changes can be used to weaken file access controls, enable privilege escalation, or make files world-readable for exfiltration.

**Compliance:** CIS 4.1.9, PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.10 File Deletion by Users

**Rules:** Monitor `unlink`, `unlinkat`, `rename`, `renameat` syscalls by human users (b64 + b32).

**Why:** Tracks file deletion and renaming. Useful for detecting evidence destruction, log tampering, and unauthorized data removal.

**Compliance:** CIS 4.1.13, PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.11 Execution from World-Writable Directories (Lorica original)

**Rules:** Monitor `execve` syscalls with `dir=/tmp` and `dir=/var/tmp` (b64 + b32).

**Why:** Dropping a binary into `/tmp` or `/var/tmp` and executing it is one of the most common attacker patterns after initial compromise. This is a Lorica-original addition not required by CIS, designed for the fintech threat model where attackers establish persistence after web application compromise.

**Compliance:** PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.12 Scheduled Tasks and SSH

**Rules:** Watch `/etc/cron.allow`, `/etc/cron.deny`, `/etc/cron.d`, `/etc/crontab`, `/etc/at.allow`, `/etc/at.deny` for changes, and `/etc/ssh/sshd_config` for changes.

**Why:** Cron and at modifications are persistence mechanisms. SSH config changes can weaken authentication or open backdoors.

**Compliance:** CIS 4.1.15, PCI-DSS 10.2.7, SOC 2 CC7.1

### 4.13 Audit Configuration Immutability

**Rule:** `-e 2` (MUST be the last rule in the file)

**Why:** Makes audit rules immutable until reboot. Once applied, an attacker who gains root cannot disable audit logging to cover their tracks. This is a critical tamper-resistance control.

**Compliance:** CIS 4.1.17, PCI-DSS 10.5, SOC 2 CC7.1

---

## 5. Profile Divergences: lorica-base vs lorica-hardened-profile

Every setting where the hardened profile overrides the base profile:

| Setting | Base Value | Hardened Value | Why they differ |
|---------|-----------|---------------|-----------------|
| `kernel.yama.ptrace_scope` | `2` (CAP_SYS_PTRACE required) | `3` (no attach at all) | Base preserves `sudo strace` for debugging. Hardened eliminates all ptrace attach. |
| `net.ipv4.conf.all.drop_gratuitous_arp` | `0` (allow) | `1` (drop) | Base preserves AWS ENI failover and floating IPs. Hardened drops gratuitous ARP for environments where ARP poisoning is a real threat (bare-metal, colocation). |
| `net.ipv4.icmp_echo_ignore_all` | `0` (allow ping) | `1` (block ping) | Base preserves cloud health checks and monitoring. Hardened eliminates ICMP fingerprinting surface. |
| `kernel.panic_on_warn` | not set (don't panic on warnings) | `1` (panic on warnings) | Kernel warnings are often informational. Base tolerates them; hardened treats any kernel anomaly as unacceptable. |
| `kernel.oops_limit` | not set | `1` (panic after first oops) | Additional safety net alongside `oops=panic` boot parameter. |
| `kernel.warn_limit` | not set | `1` (panic after first warning) | Companion to `panic_on_warn`. |
| `lockdown` (boot param) | `integrity` | `confidentiality` | Integrity prevents unsigned modules and direct hardware access. Confidentiality additionally blocks reading kernel memory, breaking some monitoring/debugging tools. |
| `nosmt` (boot param) | not set | enabled | Disables hyperthreading to prevent Spectre-class cross-thread attacks. ~20-30% throughput loss. |
| `slub_debug` (boot param) | not set | `FZ` | Enables SLUB allocator integrity checks. Measurable performance overhead. Disables kernel pointer hashing (weakens kptr_restrict). |

---

## 6. Key Divergences from Kicksecure

Settings where Lorica intentionally differs from Kicksecure's `security-misc`:

| Setting | Kicksecure | Lorica Base | Rationale |
|---------|-----------|-------------|-----------|
| `icmp_echo_ignore_all` | `1` (block) | `0` (allow) | Cloud health checks and monitoring require ICMP echo |
| `tcp_timestamps` | `0` (disabled) | `1` (enabled) | Modern kernels randomize offsets; disabling breaks PAWS and TCP performance |
| `drop_gratuitous_arp` | `1` (drop) | `0` (allow) | AWS ENI failover, keepalived, and floating IPs depend on gratuitous ARP |
| `unprivileged_userns_clone` | `0` (disabled) | not set | Docker and Kubernetes require unprivileged user namespaces |
| `panic_on_warn` | `1` (panic) | not set in base | Spurious warnings shouldn't crash production servers |
| `lockdown` | `confidentiality` | `integrity` (base) | Confidentiality mode blocks legitimate monitoring/debugging tools |
| `io_uring_disabled` | not set | `1` (base) / `2` (hardened) | Lorica addition: io_uring is a prolific CVE source |
| `core_pattern` | not set | `\|/bin/false` | Lorica addition: belt-and-suspenders core dump prevention |
| `default_qdisc` + `tcp_congestion_control` | not set | `fq` + `bbr` | Lorica addition: modern congestion control for cloud servers |
| `/tmp` execve audit | not set | monitored | Lorica addition: detect attacker binary drops in world-writable directories |

---

## 7. Cloud Overrides

**Example file:** `/usr/share/doc/lorica-base/cloud-overrides.conf.example`

Some lorica-base defaults need to be adjusted for specific cloud environments. Copy the
settings you need to `/etc/sysctl.d/99-lorica-cloud-overrides.conf` and run
`sudo sysctl --system`. Files in `/etc/sysctl.d/` override `/usr/lib/sysctl.d/` by design.

### IPv6 Router Advertisements

```
net.ipv6.conf.all.accept_ra=1
net.ipv6.conf.default.accept_ra=1
```

**When needed:** AWS IPv6-enabled VPCs, GCP dual-stack subnets, Azure IPv6. These
platforms use Router Advertisements (SLAAC) for IPv6 address assignment. Without this
override, IPv6 addresses won't be assigned.

**Provider notes:**
- **AWS:** Required for any VPC with IPv6 CIDR blocks. Without RA, EC2 instances won't
  receive their IPv6 address via DHCPv6/SLAAC.
- **GCP:** Required for dual-stack subnets. GCP uses RA for IPv6 address configuration.
- **Azure:** Required for IPv6-enabled virtual networks. Azure uses RA for address assignment.

**Security tradeoff:** Router advertisements can be used for MITM and DoS attacks on
untrusted networks. On cloud VPCs, the RA source is the hypervisor's virtual router --
trusted infrastructure.

### Gratuitous ARP

```
net.ipv4.conf.all.drop_gratuitous_arp=0
```

**When needed:** Only if running `lorica-hardened-profile` with AWS Elastic IPs, floating
IPs, keepalived, or any high-availability failover mechanism that uses gratuitous ARP.

lorica-base already allows gratuitous ARP (`drop_gratuitous_arp=0`). This override is
only needed to revert the hardened profile's `drop_gratuitous_arp=1`.

**Provider notes:**
- **AWS:** ENI failover sends gratuitous ARP to update ARP caches when an IP moves between
  instances. Dropping these breaks failover.
- **Any HA setup using keepalived/VRRP:** Virtual IP migration relies on gratuitous ARP.

### ICMP Echo (Ping)

```
net.ipv4.icmp_echo_ignore_all=0
```

**When needed:** Only if running `lorica-hardened-profile` but requiring ping-based health
checks or monitoring.

lorica-base already allows ping (`icmp_echo_ignore_all=0`). This override reverts the
hardened profile's block.

**Provider notes:**
- **AWS ELB/ALB:** Can use HTTP health checks instead of ICMP. If using ICMP health checks,
  this override is required.
- **Monitoring (Nagios, Datadog, Prometheus blackbox exporter):** Ping checks require ICMP echo.
  Switch to TCP/HTTP checks if running the hardened profile without this override.

### IP Forwarding (Docker / Kubernetes)

```
net.ipv4.ip_forward=1
```

**When needed:** Normally not needed as an override. Docker and Kubernetes set
`ip_forward=1` automatically at runtime. If your container runtime isn't overriding this,
check its configuration rather than setting it manually.

lorica-base sets `ip_forward=0` as the secure default. Container runtimes override at
startup. This is expected behavior, not a conflict.

---

## 6. Kernel Hardening Config (lorica-kernel-cloud)

**Package:** `lorica-kernel-cloud` (opt-in, installed separately)
**Source:** kernel.org 6.12 LTS, starting from Debian 13 cloud config
**Config generation:** `packages/lorica-kernel-cloud/apply-hardening.sh`
**Full decision log:** `docs/hardening-decisions.md` Section 6

### Approach: Strip Down, Not Build Up

The kernel config starts from Debian 13's `cloud-amd64` / `cloud-arm64` config and strips
down, rather than building up from `defconfig`. This is intentional:

- Debian's cloud config already includes the right cloud hypervisor drivers (Virtio, ENA, GVE, Hyper-V)
- Starting from a known-bootable config avoids boot failures from missing drivers
- The delta between Debian's config and ours is visible and auditable
- When rebasing to a new kernel version, download new Debian config, re-run `apply-hardening.sh`

### GCC Plugins: Why GCC, Not Clang

We build with GCC + security plugins for v0.2:

| Feature | GCC | Clang |
|---------|-----|-------|
| STACKLEAK (clear stack on syscall return) | Yes (plugin) | No equivalent |
| LATENT_ENTROPY (extra boot entropy) | Yes (plugin) | No equivalent |
| RANDSTRUCT (struct randomization) | Yes (compiler-agnostic since 6.1) | Yes |
| kCFI (Control-Flow Integrity) | No | Yes |
| Shadow Call Stack (arm64) | No | Yes |
| Debian toolchain match | Yes | No (adds build complexity) |

GCC gives us STACKLEAK and LATENT_ENTROPY, which Clang cannot provide. Clang gives kCFI and
Shadow Call Stack, which are primarily valuable on arm64/Graviton. KSPP recommends GCC+plugins
for x86_64 and Clang for arm64. We follow the x86_64 recommendation for v0.2 and will evaluate
Clang for v0.3 when arm64 is the priority.

### Module Signing: Two-Tier

- **BASE:** All in-tree modules signed with SHA-512. Unsigned modules are logged but not blocked.
  This is permissive because all cloud-relevant modules (ENA, NVMe, Virtio, overlay, br_netfilter)
  are in-tree and signed automatically. The only things that would be unsigned are NVIDIA,
  VirtualBox, or ZFS-DKMS -- none typical for cloud servers.

- **HARDENED:** `module.sig_enforce=1` boot parameter blocks unsigned modules entirely.
  `kernel.modules_disabled=1` sysctl locks module loading after boot.

Signing key is ephemeral per build (standard for distribution kernels).

### Driver Stripping: What and Why

The custom kernel removes entire subsystems at compile time. This goes beyond the module
blacklist in `lorica-base` -- blacklisted modules still exist in the kernel image and could
theoretically be loaded if the blacklist is bypassed. Compile-time removal means the code
doesn't exist at all.

**Removed:** Bluetooth, WiFi, sound, GPU, USB HID, joystick, touchscreen, webcam, FireWire,
Thunderbolt, PCMCIA, ISA, NFC, IR, amateur radio, industrial I/O, parallel port, floppy,
all physical NIC drivers, legacy protocols (IPX, Appletalk, DECnet, ATM, X.25), legacy
filesystems (NTFS, HFS, JFS, ReiserFS).

**Kept:** Everything needed for cloud VMs and containers -- Virtio, ENA, GVE, Hyper-V, NVMe,
SCSI, dm-crypt, ext4, XFS, Btrfs, overlayfs, netfilter/nftables, container networking,
WireGuard, cgroups v2, namespaces, seccomp, eBPF (hardened), AppArmor, SELinux, audit.

### Dangerous Features: Compile-Time vs Sysctl

Several features are disabled both via sysctl (v0.1) and at compile time (v0.2). Compile-time
removal is stronger because it cannot be bypassed even with `CAP_SYS_ADMIN`:

| Feature | v0.1 (sysctl) | v0.2 (compile-time) |
|---------|---------------|---------------------|
| kexec | `kexec_load_disabled=1` | `CONFIG_KEXEC=n` |
| userfaultfd | `unprivileged_userfaultfd=0` | `CONFIG_USERFAULTFD=n` |
| ldisc autoload | `ldisc_autoload=0` | `CONFIG_LDISC_AUTOLOAD=n` |
| DCCP, SCTP | modprobe blacklist | `CONFIG_IP_DCCP=n`, `CONFIG_IP_SCTP=n` |
| /dev/mem | N/A (exists on stock kernel) | `CONFIG_DEVMEM=n` |
| /proc/kcore | N/A (exists on stock kernel) | `CONFIG_PROC_KCORE=n` |
| hibernation | N/A | `CONFIG_HIBERNATION=n` |
| binfmt_misc | N/A | `CONFIG_BINFMT_MISC=n` |

### Performance Impact

| Feature | Overhead | Notes |
|---------|----------|-------|
| STACKLEAK | ~1% | Clears kernel stack on every syscall return |
| init_on_alloc | <1% | Zero-fill heap allocations |
| init_on_free | 3-5% | Zero-fill freed memory (first knob to disable if needed) |
| ZERO_CALL_USED_REGS | ~1% | Clears CPU registers on function return |
| RANDSTRUCT | ~0% | Compile-time only, no runtime cost |
| SLAB_FREELIST_HARDENED | ~0% | Negligible metadata validation overhead |
| **Total BASE** | **~5-7%** | Acceptable for security workloads |
| nosmt (HARDENED) | Halves vCPUs | Only in hardened profile |
| slub_debug (HARDENED) | ~5-10% | Only in hardened profile |
