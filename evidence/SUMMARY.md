# Scan evidence summary (reference build, 2026-10-05)

OpenSCAP, SCAP Security Guide 0.1.82, profile `xccdf_org.ssgproject.content_profile_hipaa`, RHEL 10.2.

| Scan | Pass | Fail | Not applicable | Not checked |
|---|---|---|---|---|
| Baseline (fresh AMI + updates) | 36 | 121 | 4 | 2 |
| After hardening | 153 | 4 | 4 | 2 |

Remaining failures and their documented exceptions: `partition_for_var_log_audit`, `ensure_gpgcheck_repo_metadata`, `grub2_password`, `grub2_admin_username` (see `docs/COMPLIANCE.md` section 8).

The full HTML reports are kept with the server records, not in this repository, because they list the host's complete configuration.
