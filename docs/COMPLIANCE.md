# HIPAA Security Rule compliance pack: single-server WordPress on AWS EC2

Status: build complete; owner actions remain in section 9. Last updated 2026-10-06.

This document is the written record the HIPAA Security Rule (45 CFR 164.308 to 164.316) asks a covered entity or business associate to keep. It describes the system, the risk analysis, each safeguard and where the evidence for it lives. GDPR equivalents are listed beside each control for EU use (health data is a "special category" under Art. 9).

HIPAA does not certify servers. What exists at the end of this build is: a Business Associate Agreement with the hosting provider, the technical safeguards below, and this documentation. The organisation that owns the data remains the compliant party; this server is one component.

## 1. System description

| Item | Value |
|---|---|
| Platform | AWS EC2, single instance, Red Hat Enterprise Linux 10 |
| Instance | t3.small, 20 GB gp3 root volume, encrypted (AWS managed KMS key) |
| Public address | one Elastic IP, one DNS A record (not proxied) |
| Application | WordPress on nginx 1.26 + PHP-FPM 8.3 + MariaDB 10.11 (localhost only) |
| Data classes | website content and admin accounts; patient data only if a form on the site stores it locally |
| Network exposure | TCP 22 (admin IP only), 80 (redirect), 443 |

Where the site uses a third-party HIPAA form provider that stores entries on its own platform, the server itself never holds patient data and most of the handling obligations sit with that provider under its own BAA.

## 2. Risk analysis (164.308(a)(1)(ii)(A))

| # | Risk | Likelihood | Impact | Treatment |
|---|---|---|---|---|
| R1 | Unauthorised SSH access | Low | High | Key-only auth, root login refused, SSH open to one admin IP, fail2ban, named accounts, audit of all logins |
| R2 | Data read from a lost or copied disk/snapshot | Low | High | Root volume and all snapshots encrypted; EBS encryption by default on |
| R3 | Data read in transit | Low | High | TLS 1.2/1.3 only on 443, HTTP redirects, HSTS; backups to S3 over TLS with a TLS-only bucket policy |
| R4 | Compromise through an unpatched package | Medium | High | Daily automatic security updates; kernel updates applied with reboot during maintenance |
| R5 | WordPress compromise (plugins, admin brute force) | Medium | High | File editing disabled, xmlrpc blocked, PHP in uploads blocked, SELinux enforcing, minor core auto-updates, admin password policy and 2FA plugin (see 9) |
| R6 | Loss of data (deletion, corruption, region failure) | Low | High | Nightly dump + files to versioned S3, AWS Backup daily snapshot (14 d), weekly automated restore test |
| R7 | Undetected tampering or unauthorised activity | Medium | Medium | Immutable auditd rules (HIPAA profile), AIDE daily, CloudTrail on the account, audit/auth/system logs shipped to CloudWatch Logs |
| R8 | Loss of the single administrator's access | Low | Medium | Two admin accounts with the same key; EC2 Serial Console and SSM available through the instance role |
| R9 | AWS account takeover | Low | High | Root MFA on, no root keys, IAM user for automation to be MFA-protected and its key deleted after the build |

Review this table at least yearly and after any significant change (164.308(a)(8)).

## 3. Control mapping

Legend: TS = Technical Safeguard 164.312, AS = Administrative 164.308, PS = Physical 164.310. GDPR column gives the nearest article.

| Control | HIPAA | GDPR | Implementation | Evidence |
|---|---|---|---|---|
| Hosting provider agreement | 164.308(b), 164.314(a) | Art. 28 | AWS BAA accepted in AWS Artifact; only HIPAA-eligible services used (EC2, EBS, S3, CloudTrail, AWS Backup, CloudWatch, KMS, IAM) | Artifact agreement status |
| Unique user identification | TS (a)(2)(i) | Art. 32 | One Linux account per person (`ec2-user` for automation, named admin account); no shared logins; root SSH refused | `sshd -T`, `/etc/passwd` |
| Emergency access | TS (a)(2)(ii) | Art. 32 | Second admin account, EC2 Serial Console, AWS Systems Manager via instance role | IAM instance profile |
| Automatic logoff | TS (a)(2)(iii) | Art. 32 | SSH idle timeout 15 min (`ClientAliveInterval 300` x 3), shell `TMOUT=900` | `01-hipaa-extra.conf`, `/etc/profile.d/tmout.sh` |
| Encryption at rest | TS (a)(2)(iv) | Art. 32(1)(a) | EBS volume + snapshots encrypted (KMS); S3 buckets SSE-S3 default; AWS Backup vault encrypted | EC2 console "Encrypted" column, bucket encryption config |
| Encryption in transit | TS (e)(1), (e)(2)(ii) | Art. 32(1)(a) | TLS 1.2/1.3 only, modern ciphers, HSTS 1 year, HTTP 301 to HTTPS; S3 bucket policies deny non-TLS | `openssl s_client`, bucket policy |
| Audit controls | TS (b) | Art. 30, 32 | auditd with the SCAP HIPAA rule set (privileged commands, identity files, DAC changes, module loads, time changes, logins), rules immutable until reboot (`-e 2`), `audit=1` on kernel command line | `auditctl -s`, `/etc/audit/rules.d/` |
| Integrity | TS (c)(1) | Art. 32(1)(b) | AIDE database initialised after hardening, daily check 03:30; SELinux enforcing; package signature checks enforced for repo and local packages | `aide-check.timer`, `/etc/dnf/dnf.conf` |
| Person/entity authentication | TS (d) | Art. 32 | SSH public key only, password auth off, `MaxAuthTries 3`, fail2ban (5 failures / 10 min, 1 h ban) | `sshd -T`, `fail2ban-client status sshd` |
| Access control (network) | TS (a)(1) | Art. 32 | Security group: 22 from admin IP only, 80/443 public; host firewall (firewalld) allows ssh/http/https only; MariaDB bound to 127.0.0.1 | SG rules, `firewall-cmd --list-services`, `ss -tlnp` |
| Security management / patching | AS (a)(1) | Art. 32(1)(d) | `dnf-automatic` installs security updates daily; full patch + reboot at build | `dnf-automatic.timer`, `dnf needs-restarting` |
| Malicious software protection | AS (a)(5)(ii)(B) | Art. 32 | SELinux enforcing, AIDE, signed packages only, WordPress file editing disabled, PHP execution blocked in uploads | nginx site config, `wp-config.php` |
| Log-in monitoring | AS (a)(5)(ii)(C) | Art. 32 | `/var/log/secure`, auditd login events, fail2ban | logs |
| Data backup plan | AS (a)(7)(ii)(A) | Art. 32(1)(c) | Nightly 02:00 UTC: MariaDB dump + wp-content + wp-config, SHA-256 manifest, to private versioned S3 (35-day expiry); AWS Backup daily EBS snapshot, 14-day retention | `/var/log/hipaa-backup.log`, S3 listing, Backup vault |
| Disaster recovery / testing | AS (a)(7)(ii)(B), (D) | Art. 32(1)(c),(d) | Weekly automated restore of the newest dump into a scratch database with table-count comparison and checksum verification; first run passed 2026-10-06 (12/12 tables) | `/var/log/hipaa-backup.log` |
| Evaluation | AS (a)(8) | Art. 32(1)(d) | OpenSCAP scan against the SCAP Security Guide HIPAA profile before and after hardening: 36 pass / 121 fail to 153 pass / 4 fail | `evidence/baseline-report.html`, `evidence/post-report.html` |
| Account-level audit trail | AS (a)(1)(ii)(D) | Art. 30 | CloudTrail multi-region trail, log file validation on, to a private versioned bucket | CloudTrail console |
| Physical safeguards | PS | Art. 32 | Inherited from AWS data centres under the BAA and AWS SOC/ISO reports | AWS Artifact |
| Login warning banner | AS (a)(5) | - | `/etc/issue` shown at SSH login | `sshd -T | grep banner` |
| Documentation retention | 164.316(b)(2) | Art. 5(2), 30 | This pack and the evidence folder kept 6 years; CloudWatch log groups `/hipaa-server/{audit,secure,messages,backup}` set to 2192-day retention | repository history |

## 4. Access list

| Account | Type | Purpose | Auth |
|---|---|---|---|
| `ec2-user` | Linux, sudo | Automation and build scripts | SSH key |
| named admin (`ammar`) | Linux, sudo | Day-to-day administration | SSH key (same key at build; rotate to a personal key) |
| `wp` | MariaDB, localhost only | WordPress database user | password in `wp-config.php` (640 root:apache) |
| WordPress admin | Application | Site administration | password, 2FA plugin to add |
| IAM user for automation | AWS | Build scripts only | access key; delete after build, MFA required while it exists |
| AWS root | AWS | Billing, BAA acceptance only | MFA on, no access keys |

Review quarterly. Remove accounts the same day a person leaves (164.308(a)(3)(ii)(C)).

## 5. Change and maintenance procedure

1. Snapshot (or confirm last night's AWS Backup) before any change.
2. Back up the config file being edited (`cp file file.bak-YYYYMMDD`).
3. Apply the change with the matching script in `server/`, never by hand where a script exists.
4. Validate (`sshd -t`, `nginx -t`) before reloading a service.
5. Re-run the OpenSCAP HIPAA scan after any OS-level change and keep the report in `evidence/`.
6. Record the change in the server log.

## 6. Incident and breach response (164.308(a)(6), 164.400 to 414; GDPR Art. 33, 34)

1. Contain: restrict the security group to the admin IP only, stop the instance if active compromise is suspected (the encrypted volume and snapshots keep the evidence).
2. Preserve: snapshot the volume before any cleanup; export CloudTrail, auditd and nginx logs for the period.
3. Assess: what data was on the server, whether it was accessed, how many individuals.
4. Notify: HIPAA requires notice to affected individuals without unreasonable delay and within 60 days, to HHS (within 60 days if 500+ individuals, otherwise annually), and to the media if 500+ in one state. GDPR requires notice to the supervisory authority within 72 hours and to individuals without undue delay when the risk is high.
5. Recover: rebuild from the hardening scripts on a fresh instance, restore the last clean backup, rotate every credential (SSH keys, DB password, WordPress salts and passwords, IAM keys).
6. Record: keep the incident report with this pack for 6 years.

## 7. Backup and restore evidence

First backup and restore test, 2026-10-06 04:30 UTC: dump 21 KB, wp-content 12.7 MB, SHA-256 manifest uploaded; restore into scratch database verified checksum and 12 of 12 tables. Ongoing results append to `/var/log/hipaa-backup.log`.

Recovery point objective: 24 hours (nightly dump) or the last AWS Backup snapshot. Recovery time objective: about 1 hour on a fresh instance using the scripts in `server/`.

## 8. Documented exceptions

| Scan rule | Reason | Compensating control |
|---|---|---|
| `partition_for_var_log_audit` | Single-volume cloud image; separate audit partition would require a second EBS volume | Audit log on encrypted volume, `space_left_action` configured by the profile, shipped to CloudWatch Logs in near real time |
| `ensure_gpgcheck_repo_metadata` | Red Hat Update Infrastructure on AWS does not sign repository metadata | Package signatures (`gpgcheck=1`, `localpkg_gpgcheck=1`) are verified for every package |
| `grub2_password`, `grub2_admin_username` | No console access to the boot loader exists for a cloud instance except through AWS (IAM-controlled) | IAM/MFA controls on the AWS account; EC2 Serial Console disabled by default |
| `rsyslog_remote_loghost` | Remediation set a placeholder host that does not exist; removed | CloudWatch agent ships audit, secure, messages and backup logs off-server with 6-year retention |
| CloudWatch agent package signature | RHEL 10's crypto policy rejects Amazon's signing key, so rpm cannot verify the package | Signature verified with GnuPG against the fingerprint AWS publishes (9376 16F3 450B 7D80 6CBD 9725 D581 6730 3B78 9C72), SHA-256 of the installed rpm recorded in the server log, then installed with `--nogpgcheck` for that one package only; `localpkg_gpgcheck=1` stays on |

## 9. Open items

- Accept the AWS BAA in AWS Artifact (account owner).
- MFA on the automation IAM user, then delete its access key when the build is signed off.
- Delete the pre-encryption rollback snapshot and old unencrypted volume once the server is accepted.
- WordPress: change the initial admin password, add a 2FA plugin, set a strong password policy.
- Rotate the named admin account to a personal SSH key (it currently shares the build key).
- Yearly review date: 2027-10-06.
