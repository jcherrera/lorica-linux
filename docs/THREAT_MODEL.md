# Lorica Linux Threat Model

> This document describes what Lorica v0.1 protects against, what it does not, and what changes in v0.2. It reflects the actual shipped state: OS-level hardening on Debian's stock kernel.

## Target Environment

Lorica targets **headless cloud servers** running regulated or security-sensitive workloads (fintech, healthcare, SaaS, government). The assumed environment:

- No physical access (cloud VM or remote bare-metal)
- No desktop, GUI, or local users sitting at a terminal
- Network-facing services (web servers, databases, APIs)
- Potentially running containers (Docker, Kubernetes)
- Managed by SSH or cloud agent (SSM, cloud-init)

## Attacker Model

Lorica hardens against two attacker profiles:

1. **Remote attacker with network access.** Scanning, probing, exploiting network-facing services. Lorica reduces the attack surface (disabled modules, blocked protocols, hardened network stack) and ensures audit logging captures suspicious activity.

2. **Attacker with unprivileged shell access.** Has gained a foothold (e.g., via a web application vulnerability) and is attempting to escalate privileges, exfiltrate data, or persist. Lorica restricts kernel information leaks, limits debugging capabilities, hardens memory protections, and logs privilege-relevant syscalls.

## What v0.1 Protects Against

### Kernel Information Leaks

| Mitigation | Config | What it prevents |
|------------|--------|------------------|
| Hide kernel pointers | `kptr_restrict=2` | Blocks `/proc/kallsyms` address leaks used to defeat KASLR |
| Restrict dmesg | `dmesg_restrict=1` | Prevents unprivileged users from reading kernel ring buffer |
| Disable debugfs | `debugfs=off` (boot param) | Removes `/sys/kernel/debug` entirely |
| Restrict perf | `perf_event_paranoid=3` | Blocks unprivileged access to CPU performance counters (side-channel vector) |
| Disable kexec | `kexec_load_disabled=1` | Prevents loading a new kernel at runtime (rootkit vector) |

### Memory Protections

| Mitigation | Config | What it prevents |
|------------|--------|------------------|
| Zero-fill allocations | `init_on_alloc=1` (boot param) | Prevents use-after-free info leaks from heap |
| Zero-fill freed memory | `init_on_free=1` (boot param) | Prevents data recovery from freed memory |
| Disable slab merging | `slab_nomerge` (boot param) | Makes slab overflow exploitation harder |
| Randomize page allocator | `page_alloc.shuffle=1` (boot param) | Adds entropy to physical page layout |
| Stack randomization | `randomize_kstack_offset=on` (boot param) | Randomizes kernel stack offset per syscall |
| CPU mitigations | `mitigations=auto,nosmt` (hardened) | Enables all Spectre/Meltdown/MDS mitigations |
| Disable core dumps | `fs.suid_dumpable=0`, `core_pattern=\|/bin/false` | Prevents credential/memory leaks via core dumps |
| Restrict ptrace | `ptrace_scope=2` (base), `3` (hardened) | Blocks unprivileged process inspection |

### Network Hardening

| Mitigation | Config | What it prevents |
|------------|--------|------------------|
| SYN flood protection | `tcp_syncookies=1` | Mitigates SYN flood denial of service |
| Strict reverse path filtering | `rp_filter=1` | Drops packets with spoofed source addresses |
| Block ICMP redirects | `accept_redirects=0` | Prevents MITM via ICMP redirect injection |
| Block source routing | `accept_source_route=0` | Prevents attacker-controlled packet routing |
| Log impossible addresses | `log_martians=1` | Logs packets from bogus source IPs |
| Harden BPF JIT | `bpf_jit_harden=2` | Mitigates JIT spray attacks |
| Disable unprivileged BPF | `unprivileged_bpf_disabled=1` | Blocks unprivileged eBPF programs (exploit vector) |

### Attack Surface Reduction

| Mitigation | Config | What it prevents |
|------------|--------|------------------|
| 38 kernel modules disabled | `modprobe.d/30-lorica-blacklist.conf` | Blocks Bluetooth, FireWire, Thunderbolt, USB storage, sound, uncommon filesystems, legacy network protocols |
| io_uring disabled | `io_uring_disabled=1` (via postinst) | Blocks a prolific source of kernel CVEs |
| Kernel lockdown (integrity) | `lockdown=integrity` (boot param) | Prevents unsigned code from running in kernel space |
| Disable magic SysRq | `sysrq=0` | Blocks keyboard-based kernel manipulation |

### Audit and Compliance

| Mitigation | Config | What it provides |
|------------|--------|------------------|
| Identity change monitoring | Watch rules on `/etc/passwd`, `/etc/shadow`, etc. | Detects unauthorized user/group modifications |
| Privilege escalation monitoring | Watch + syscall rules for sudo, su, setuid | Detects privilege escalation attempts |
| Kernel module load monitoring | Syscall rules for `init_module`, `finit_module` | Detects runtime kernel module loading |
| Network config monitoring | Syscall rules for `sethostname`, `setdomainname` | Detects network configuration tampering |
| `/tmp` execution monitoring | Execve monitoring in `/tmp`, `/var/tmp` | Detects attacker binary drops in world-writable directories |
| Immutable audit rules | `-e 2` as final rule | Prevents attackers from disabling audit logging without reboot |

### Hardened Profile (lorica-hardened-profile)

For maximum-security environments, the hardened profile adds:

| Mitigation | Config | Tradeoff |
|------------|--------|----------|
| Disable hyperthreading | `nosmt` (boot param) | Halves vCPU count; eliminates Spectre-class cross-thread attacks |
| Panic on kernel warnings | `panic_on_warn=1` | Crashes on warnings; eliminates continued execution after anomaly |
| Block all ICMP echo | `icmp_echo_ignore_all=1` | Breaks ping-based monitoring; blocks ICMP reconnaissance |
| Drop gratuitous ARP | `drop_gratuitous_arp=1` | Breaks some failover mechanisms; blocks ARP spoofing |
| Full kernel lockdown | `lockdown=confidentiality` | Blocks debugging tools; prevents any kernel data extraction |
| Disable ptrace entirely | `ptrace_scope=3` | Breaks all debuggers; maximum process isolation |
| SLUB integrity checks | `slub_debug=FZP` (boot param) | Performance overhead; validates slab allocator integrity |
| Fully disable io_uring | `io_uring_disabled=2` | Blocks io_uring even for root |

## What v0.1 Does NOT Protect Against

### Out of Scope

These are real threats that Lorica does not address. Use complementary tools:

| Threat | Why it's out of scope | What to use instead |
|--------|----------------------|---------------------|
| Application vulnerabilities (SQLi, XSS, RCE) | OS hardening cannot fix application code | WAFs, SAST/DAST, secure coding practices |
| Container runtime attacks | Lorica hardens the host, not container isolation | Falco, Seccomp profiles, AppArmor per-container policies |
| Full disk encryption | Infrastructure-layer concern | LUKS, cloud provider encryption (EBS, PD) |
| Network segmentation | Infrastructure-layer concern | VPCs, security groups, firewalls |
| Identity and access management | Application/infrastructure layer | IAM, SSO, MFA |
| Supply chain attacks on application dependencies | Application-layer concern | Dependency scanning, SBOMs, pinned versions |
| DDoS beyond SYN floods | Requires network-level mitigation | Cloud provider DDoS protection, CDNs |
| Insider threats with root access | Root can bypass all OS hardening | Separation of duties, audit logging (Lorica helps detect, not prevent) |

### Limitations of v0.1 (Addressed in v0.2)

v0.1 ships on Debian's **stock kernel**. This means several kernel-level hardening measures are not yet available:

| Limitation | Why it matters | v0.2 plan |
|------------|---------------|-----------|
| No signed kernel modules | Attackers with root can load arbitrary modules | Custom kernel with `MODULE_SIG_FORCE=y` |
| No struct layout randomization | Kernel exploits can rely on known struct offsets | Custom kernel with `GCC_PLUGIN_RANDSTRUCT=y` |
| No stack leak prevention | Kernel stack may leak data between syscalls | Custom kernel with `GCC_PLUGIN_STACKLEAK=y` |
| No Control-Flow Integrity | Kernel ROP/JOP attacks not mitigated at compile level | Evaluate Clang CFI in custom kernel |
| Stock kernel attack surface | Debian's kernel includes many drivers Lorica doesn't need | Stripped cloud-only kernel config |

## Assumptions

1. **The server runs Debian 12 or 13.** Lorica is tested on Bookworm and Trixie. Other Debian derivatives (Ubuntu) may work but are not validated.
2. **Physical access is not a threat.** Lorica does not harden against evil maid attacks, cold boot attacks, or hardware implants.
3. **The base Debian installation is not compromised.** Lorica hardens a clean system. It cannot remediate an already-compromised host.
4. **SSH is the primary remote access method.** Lorica does not ship SSH hardening configs (this is environment-specific), but its audit rules monitor authentication events.
5. **The administrator reviews audit logs.** Lorica generates audit events but does not include alerting or log aggregation. Use a SIEM or log shipper alongside.
