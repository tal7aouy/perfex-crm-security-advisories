# VULN-05 — Unauthenticated Path Traversal / Arbitrary File Read (`Download::preview_*`)

| | |
|---|---|
| **Researcher** | tal7aouy |
| **Severity** | High (CVSS 3.1: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N) |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory |
| **Authentication** | None |
| **Component** | `application/controllers/Download.php:14-92` (`preview_video`, `preview_image`) |

---

## 1. Summary

The `preview_image` and `preview_video` actions build a filesystem path directly from the `path` request parameter with no traversal filtering, then stream the file to the client. `Download` extends `App_Controller`, which does not enforce login, so this is an
**unauthenticated arbitrary file read** (constrained to image/video file extensions).

## 2. Root cause

```php
// application/controllers/Download.php
public function preview_image() {
    $path = FCPATH . $this->input->get('path');   // attacker-controlled; NO sanitization
    ...
    $file = fopen($path, 'rb');
    while (!feof($file)) { echo fread($file, 1024); }
}
```

- No `../` filtering and no `realpath()` confinement.
- The only restriction is an extension allowlist (`jpg/jpeg/png/bmp/gif/tif` for images; `mp4/m4v/webm/ogv/...` for video), which limits *which* files stream but not *where* they come from.
- The `FCPATH.` prefix prevents `php://` / `http://` stream-wrapper abuse (no SSRF), but does not stop directory traversal.

## 3. Exploitation

```
GET /download/preview_image?path=../../../../../../home/other-tenant/uploads/private.png
GET /download/preview_video?path=../../../../../../var/backups/media-dump.mp4
```

No authentication, cookie, or token required. The response body is the raw file.

### Notes on reach
- Any file readable by the web server user, whose name ends in an allowed extension, can be exfiltrated — cross-tenant uploads, media/backups saved with image/video extensions, etc.
- Files without an allowed extension (e.g. `config.php`, `/etc/passwd`) fall back to a placeholder image and are **not** disclosed by this specific bug.

## 4. Impact

Unauthenticated disclosure of image/video-extension files anywhere on the host filesystem (information disclosure; cross-tenant data theft in shared hosting).

## 5. Remediation

Canonicalize the path and confine it to the intended media root. See `patch.diff`.

```php
$base = realpath(FCPATH . 'uploads');
$real = realpath(FCPATH . $this->input->get('path'));
if ($real === false || strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) {
    show_404();
}
$path = $real;
```

Apply to both `preview_image()` and `preview_video()`.

## 6. References
- CWE-22: https://cwe.mitre.org/data/definitions/22.html

— tal7aouy
