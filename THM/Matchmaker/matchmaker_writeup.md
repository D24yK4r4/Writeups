# Matchmaker CTF Writeup

## Challenge Description

Matchmaker is a playful, hash-powered experience that pairs you with your ideal dog by comparing **MD5** fingerprints. Upload a photo, let the hash chemistry do its thing, and watch the site reveal whether your vibe already matches one of our curated pups.

**Target:** `http://10.81.167.129`

## Reconnaissance

### Port Scan
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14
80/tcp open  http    nginx
```

### Directory Enumeration
```bash
gobuster dir -u http://10.81.167.129 -w wordlist.txt
```

Results:
```
/static               (Status: 301)
/upload               (Status: 405)
```

### Discovered Endpoints
- Upload endpoint: `/upload`
- Static files: `/static/uploads/`
- View endpoint: `/view/<uuid>`
- Example image: `http://10.81.167.129/static/uploads/00795a8b-fb58-47c0-91be-af068ddc71b4.jpg`

## Analysis

The challenge description heavily emphasizes **MD5 fingerprints**, which is a major hint. MD5 is known to be vulnerable to collision attacks where two different files can produce the same hash.

### Initial Hypothesis

First, I checked the existing dog image on the server:

```bash
wget http://10.81.167.129/static/uploads/00795a8b-fb58-47c0-91be-af068ddc71b4.jpg
md5sum 00795a8b-fb58-47c0-91be-af068ddc71b4.jpg
```

Result:
```
a15ec1ecaef0eac2d8a9be79d1d51296  00795a8b-fb58-47c0-91be-af068ddc71b4.jpg
```

### Testing Re-upload

I attempted to re-upload the same dog image to see if it would trigger a match:

```bash
curl -F "file=@00795a8b-fb58-47c0-91be-af068ddc71b4.jpg" http://10.81.167.129/upload
```

Response:
```
Your photo already lives here
We already received that exact snapshot, so there is no need to upload it again.
```

The server detects duplicate uploads based on hash, so we need a different approach.

## Exploitation: MD5 Collision Attack

The key insight is that we need to upload **two different files with the same MD5 hash** to demonstrate the MD5 collision vulnerability.

### Solution Script

```python
#!/usr/bin/env python3
import requests
import hashlib

TARGET = "http://10.81.167.129"

# Known MD5 collision pair (Marc Stevens, 2012)
FILE1 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)

FILE2 = bytes.fromhex(
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)

# Verify collision
hash1 = hashlib.md5(FILE1).hexdigest()
hash2 = hashlib.md5(FILE2).hexdigest()
print(f"File1 MD5: {hash1}")
print(f"File2 MD5: {hash2}")
print(f"Collision: {hash1 == hash2}")

# Upload both files
files1 = {'file': ('image1.jpg', FILE1, 'image/jpeg')}
r1 = requests.post(f"{TARGET}/upload", files=files1)
print(f"Upload 1: {r1.status_code}")

files2 = {'file': ('image2.jpg', FILE2, 'image/jpeg')}
r2 = requests.post(f"{TARGET}/upload", files=files2)
print(f"Upload 2: {r2.status_code}")

# Check for flag
if 'THM{' in r2.text or 'flag' in r2.text.lower():
    print("\nFLAG FOUND!")
    print(r2.text)
```

### Execution

```bash
python3 test_collision.py
```

Output:
```
Hash1: 79054025255fb1a26e4bc422aef54eb4
Hash2: 79054025255fb1a26e4bc422aef54eb4
Collision verified: True
```

After uploading the second file (which has the same MD5 hash as the first but different content), the server detects the collision and returns the match page.

## Flag

```
THM{hash_puppies_4_all}
```

## Key Takeaways

1. **MD5 is broken**: This challenge demonstrates why MD5 should not be used for security-critical applications
2. **Collision attacks are practical**: Pre-computed collision pairs exist and can be used in real attacks
3. **The hint was in plain sight**: The challenge description explicitly mentioned "MD5 fingerprints" - always pay attention to these details
4. **Not about matching the server's dog image**: The challenge was about demonstrating MD5 collision by uploading two different files with identical hashes

## References

- [MD5 Collision Examples](https://www.mscs.dal.ca/~selinger/md5collision/)
- Marc Stevens' MD5 collision research (2012)
