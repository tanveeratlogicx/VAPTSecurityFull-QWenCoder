# Version History

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