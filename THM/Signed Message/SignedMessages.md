# LoveNote CTF Challenge - Write-up

## Challenge Overview

LoveNote is a messaging platform that claims to use "industry-standard RSA-2048 digital signatures" to ensure message authenticity. The goal is to forge an admin signature and prove the cryptographic system is broken.

**Challenge URL:** `http://10.82.180.19:5000`

---

## Vulnerability Discovery

### Initial Reconnaissance

After registering an account, I received RSA keys that were suspiciously small (512-bit, not 2048-bit as advertised). However, without access to the admin's public key, factorization wasn't immediately viable.

The breakthrough came from examining the application logs, which revealed:

```
[2026-02-06 14:23:15] Development mode: ENABLED
[2026-02-06 14:23:15] Using deterministic key generation
[2026-02-06 14:23:15] Seed pattern: {username}_lovenote_2026_valentine
```

### The Critical Flaw: Deterministic Key Generation

The platform generates RSA keys **deterministically** based on username:

- **Seed formula:** `{username}_lovenote_2026_valentine`
- **Prime p:** `nextprime(SHA256(seed))`
- **Prime q:** `nextprime(SHA256(seed + "pki"))`

This means anyone can reconstruct any user's private key from their username alone!

---

## Exploitation

### Step 1: Install Dependencies

```bash
pip3 install pycryptodome sympy
```

### Step 2: Create Exploit Script

Save the following as `forge_admin_sig.py`:

```python
import hashlib
from sympy import nextprime
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

TARGET_USER = "admin"
TARGET_MESSAGE = "Welcome to LoveNote! Send encrypted love messages this Valentine's Day. Your communications are secured with industry-standard RSA-2048 digital signatures."


def generate_admin_key():
    seed_str = f"{TARGET_USER}_lovenote_2026_valentine"
    seed_bytes = seed_str.encode('utf-8')

    sha256_p = hashlib.sha256(seed_bytes).hexdigest()
    p = nextprime(int(sha256_p, 16))

    sha256_q = hashlib.sha256(seed_bytes + b"pki").hexdigest()
    q = nextprime(int(sha256_q, 16))

    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    return RSA.construct((n, e, d))


def forge_signature(key, message):
    h = SHA256.new(message.encode('utf-8'))
    modBits = key.size_in_bits()
    emLen = (modBits - 1 + 7) // 8
    maxSalt = emLen - h.digest_size - 2

    signer = pss.new(key, salt_bytes=maxSalt)
    signature = signer.sign(h)
    return signature.hex()


if __name__ == '__main__':
    admin_key = generate_admin_key()
    signature = forge_signature(admin_key, TARGET_MESSAGE)
    print(signature)
```

### Step 3: Execute the Exploit

```bash
python3 forge_admin_sig.py
```

**Output:**
```
015907d562908f066ddf7146d5552c084af83f4d77167fafbdca29633e70cdf34d611ea2ec1ab9d7babd886be48074b4af7913647dedd18f296e858a732695a6
```

### Step 4: Verify on Platform

Navigate to the signature verification page and submit:

- **User:** `admin`
- **Message:** `Welcome to LoveNote! Send encrypted love messages this Valentine's Day. Your communications are secured with industry-standard RSA-2048 digital signatures.`
- **Signature:** `015907d562908f066ddf7146d5552c084af83f4d77167fafbdca29633e70cdf34d611ea2ec1ab9d7babd886be48074b4af7913647dedd18f296e858a732695a6`

**Result:**
```
✓ Signature Valid
You successfully forged an admin signature!
```

---

## Flag

```
THM{REDACTED}
```

---

## Technical Details

### How the Attack Works

1. **Seed Generation:** The deterministic seed is created from the target username
2. **Prime Derivation:** Two primes (p and q) are derived from hashed versions of the seed
3. **Key Reconstruction:** The RSA private key is rebuilt using standard RSA math (n = p×q, d = e⁻¹ mod φ(n))
4. **Signature Forging:** With the admin's private key, we can sign any message using PSS+SHA256
5. **Verification Bypass:** The forged signature passes validation because it's mathematically valid

### Why This is Catastrophic

- **Complete Identity Theft:** Any user can impersonate any other user
- **No Trust Anchors:** The entire PKI foundation is compromised
- **Scalable Attack:** Forging signatures for any username takes seconds
- **Undetectable:** Forged signatures are cryptographically indistinguishable from legitimate ones

---

## Lessons Learned

1. **Never use deterministic/predictable entropy** for cryptographic key generation
2. RSA keys must be generated from **cryptographically secure random sources** (e.g., `/dev/urandom`, `os.urandom()`)
3. Username-based seeding creates a trivial forgery attack
4. Even strong cryptographic primitives (RSA, PSS, SHA-256) are worthless with weak key generation
5. **Development mode settings should never leak into production**

---

## Remediation

To fix this vulnerability:

1. Use `Crypto.Random` or `secrets` module for key generation
2. Remove all deterministic seeding mechanisms
3. Regenerate all user keypairs with proper entropy
4. Implement key rotation policies
5. Disable development mode in production
6. Add monitoring for suspicious signature verification patterns

---

**Date:** February 15, 2026  
**Difficulty:** Medium  
**Category:** Cryptography
