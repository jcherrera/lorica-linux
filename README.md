# Lorica Linux

**Security-hardened Debian for servers.**

Lorica is an opinionated, security-hardened layer on top of Debian Stable. It targets headless servers running regulated or security-sensitive workloads: fintech, healthcare, SaaS, government.

It is **not** a fork. It is a thin collection of hardening configurations, meta-packages, and curated defaults. Install it on any existing Debian system with `apt install lorica-cloud-server`.

## What You Get

- Hardened OS defaults: sysctl, boot parameters, kernel module restrictions
- Audit rules mapped to compliance frameworks (CIS, PCI-DSS, SOC 2, CNBV)
- Minimal attack surface: unnecessary daemons removed, services locked down
- Documented rationale for every security decision
- Clean install/uninstall: Lorica uses drop-in configs, never modifies Debian-owned files

## What This Is Not

- Not a desktop OS
- Not a privacy/anonymity tool (see [Kicksecure](https://www.kicksecure.com/) for that)
- Not a fork of Debian (we inherit 99% of Debian as-is)
- Not a replacement for application-layer security

## Install

```bash
# Add Lorica signing key and repository
curl -fsSL https://lorica-linux.github.io/repo/lorica-keyring.asc | sudo tee /usr/share/keyrings/lorica.asc
echo "deb [signed-by=/usr/share/keyrings/lorica.asc] https://lorica-linux.github.io/repo stable main" \
  | sudo tee /etc/apt/sources.list.d/lorica.list

# Install
sudo apt update
sudo apt install lorica-cloud-server

# Reboot to apply boot parameter hardening
sudo reboot
```

## Uninstall

```bash
sudo apt remove lorica-cloud-server lorica-base lorica-keyring
sudo reboot
```

Lorica uses drop-in configuration files (`/usr/lib/sysctl.d/`, `/etc/default/grub.d/`, `/etc/modprobe.d/`). Removing the packages removes the configs. Your system returns to stock Debian behavior.

## What's Included

### Sysctl Hardening

Memory protections, network hardening, kernel pointer restrictions, and more. Every setting is documented with its rationale and compliance mapping.

### Boot Parameter Hardening

CPU vulnerability mitigations, IOMMU enforcement, kernel hardening flags, applied via GRUB drop-in config.

### Kernel Module Blacklist

Disables kernel modules irrelevant to servers: Bluetooth, FireWire, Thunderbolt, USB HID, uncommon filesystems, legacy protocols.

### Audit Rules

Pre-configured audit rules for compliance: privileged command execution, file permission changes, user/group modifications, kernel module loading, network configuration changes. Mapped to CIS and PCI-DSS controls.

### Service Lockdown

Unnecessary packages removed (exim4, cups, avahi-daemon, rpcbind). Security tooling pre-installed (AppArmor, auditd, fail2ban, UFW, unattended-upgrades).

## Documentation

- [CONFIG_RATIONALE.md](docs/CONFIG_RATIONALE.md) -- Every hardening config explained
- [COMPLIANCE_MAP.md](docs/COMPLIANCE_MAP.md) -- Mapping to CIS, PCI-DSS, SOC 2, CNBV
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) -- What's in scope and what's not
- [INSTALL.md](docs/INSTALL.md) -- Detailed installation guide

## Roadmap

**v0.1 (current):** OS-level hardening on Debian's stock kernel. Sysctl, boot params, audit rules, module blacklist, compliance docs.

**v0.2:** Custom hardened kernel built from kernel.org LTS with full KSPP hardening. ARM64 support. AWS AMI.

**v0.3:** Compliance automation (CIS auto-validation, PCI-DSS evidence generation).

## Acknowledgments

Lorica's sysctl and boot parameter hardening is informed by [Kicksecure's security-misc](https://github.com/Kicksecure/security-misc), adapted for cloud/server workloads. We also reference the [KSPP recommended settings](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings) and [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks).

## Security

If you find a security vulnerability, please open a [GitHub Security Advisory](https://github.com/lorica-linux/lorica-linux/security/advisories/new) on this repository. Do not open a public issue for security vulnerabilities.

## License

GPLv2. See [LICENSE](LICENSE).
