# Version History

## v3.3.0 - 2026-05-25

### Added
- **Test Callback Button**: "Test Callback" in Build Tracking tab fires a real `vapt_force_ping` AJAX call, bypasses throttle, and shows a full diagnostic panel (URL, mode, build ID, HTTP status, SSL, raw response). Throttle cleared on success.
- **`.buildincl` Allowlist**: Explicit allowlist file controls exactly which files go into client builds. Replaces the fragile blocklist. Edit `.buildincl` to adjust without code changes.
- **Duplicate Build Filename Prompt**: Modal asks Overwrite vs Save as New when a same-named build already exists in `releases/builds/`.
- **Build Generation Loading Overlay**: Full-screen spinner overlay during client zip generation.

### Fixed
- **Heartbeat silent failure**: `blocking => false` in `maybe_trigger_callback()` dropped requests on single-server local setups. Changed to `blocking => true` with response parsing and remote command processing.
- **False "Build Generation Failed" toast**: Stale message copy shown on success. Now accurate.
- **`handle_force_ping` HMAC**: Missing `ksort` before signing caused master-side signature rejection. Fixed.
- **`handle_force_ping` SSL**: `sslverify` was hardcoded `false`. Now conditional on `tracking_mode`.
- **Critical parse error / site crash**: Orphaned `'payload' => $payload` / `] );` fragment after `handle_force_ping` replacement caused PHP parse error. Removed.
- **Dirty client builds**: Blocklist missed ZIPs, markdown docs, test files. Replaced with `.buildincl` allowlist.

### Changed
- `vaptNotify.confirm()` extended with `onCancel`, `confirmLabel`, `cancelLabel` parameters.

### Infrastructure
- Version bumped to `3.3.0` in:
  - Plugin header `Version:` in `vapt-security.php`
  - `VAPT_VERSION` constant
  - `package.json`

---

## v3.2.1 - 2026-05-23

### Added
- **HMAC Payload Protection**: Client-to-Master ping payloads now include an HMAC signature (`sig` field) generated using `hash_hmac('sha256', json_encode($payload), 'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2')`. Master server verifies signature with `hash_equals()` before processing data, preventing tampered payloads.

### Changed
- **Non-blocking Ping**: Changed `wp_remote_post` in `maybe_trigger_callback()` from `blocking: true` to `blocking: false` to prevent page load delays on client sites (up to 15 seconds per page load).

### Fixed
- **Email Notifications**: `send_license_notification_email()` now sends to `tanmalik786@gmail.com` instead of `get_option('admin_email')` for all license event emails (extension, expiry warnings).
- **Authoritative First Activation**: `maybe_trigger_callback()` now checks if `first_activation` is already stored in the Master's `vapt_build_tracking` for this build_id. If set, it uses the Master's value instead of the local `vapt_initial_install_time`, preventing re-installation from resetting the urgency sequence.
- **Custom Term Date Parsing**: `handle_push_remote_command()` now correctly handles date strings (e.g., `2025-12-31`) when processing custom term extensions, parsing them correctly via `strtotime()`.

### Security
- HMAC verification in `handle_build_callback()` prevents processing of payloads with invalid signatures.
- Uses `hash_equals()` for timing-attack safe signature comparison.

### Infrastructure
- Version consistency: All version references updated to `3.2.1`:
  - Plugin header `Version:` in `vapt-security.php`
  - `VAPT_VERSION` constant (already was `3.2.1`)
  - `package.json` `version` field

---

## v3.2.0 - [Previous Version]

[Previous version details would go here]