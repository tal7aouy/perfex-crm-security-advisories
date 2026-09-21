# VULN-02 — Predictable Password-Reset / Set-Password Tokens (Account Takeover)

| | |
|---|---|
| **Researcher** | tal7aouy |
| **Severity** | High (CVSS 3.1: 8.1 — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **CWE** | CWE-330 / CWE-338: Use of Insufficiently Random Values |
| **Authentication** | None |
| **Component** | `application/helpers/general_helper.php` |
| **Affected line** | 803 (`app_generate_hash`) |

---

## 1. Summary

All password-reset and staff "set password" tokens are produced by a non-cryptographic generator built from `rand()`, `uniqid()`, `microtime()` and `time()`. These sources are predictable, so an attacker can guess a valid token and set a new password on any account —
**including administrators** — without any credentials.

## 2. Root cause

```php
// application/helpers/general_helper.php:803
function app_generate_hash()
{
    return md5(rand() . microtime() . time() . uniqid());
}
```

- `rand()` — not a CSPRNG; small, predictable state.
- `uniqid()` — derived from the current microtime; no real entropy.
- `microtime()` / `time()` — attacker-observable via the HTTP `Date` header.

This value is stored as `new_pass_key` and consumed by:

| Flow | Validator | Window |
|---|---|---|
| Contact password reset | `Authentication_model::reset_password` (`:271`) | 1 hour |
| Staff password reset | (`:325`) | 1 hour |
| **Staff "set password" invite** | `can_set_password()` | **48 hours** |

The staff invite route (`admin/authentication/set_password/1/<staffid>/<key>`) is publicly reachable and honours the 48-hour window — the most attacker-friendly target.

## 3. Exploitation

1. **Trigger** a reset or invite for the target account (or wait for a pending staff invite).
2. **Anchor time:** read the server clock from the HTTP `Date` response header to constrain `time()` / `microtime()`.
3. **Brute-force** the small residual PRNG space offline (md5 over the constrained inputs).
4. **Submit** candidate keys:
   - Contact: `POST authentication/reset_password/0/<userid>/<key>` with `password`/`passwordr`
   - Staff/admin: `POST admin/authentication/set_password/1/<staffid>/<key>`
5. On the correct key, the new password is set → **full account takeover**.

### Why it is realistic
The generator's inputs are almost entirely time-based and observable; only the `rand()`/`uniqid()` residue must be searched, and the validity window (up to 48h) gives ample time.

## 4. Impact

Account takeover of any user, including administrators — leading to full application compromise.

## 5. Remediation

Use a cryptographically secure generator. See `patch.diff`.

```php
function app_generate_hash()
{
    return bin2hex(random_bytes(32)); // CSPRNG, 256-bit
}
```

Also convert the `create_autologin()` key to `bin2hex(random_bytes(16))` (`Authentication_model.php:153`) — same weak-PRNG class.

## 6. References

- CWE-338: https://cwe.mitre.org/data/definitions/338.html
- PHP `random_bytes`: https://www.php.net/manual/en/function.random-bytes.php

— tal7aouy
