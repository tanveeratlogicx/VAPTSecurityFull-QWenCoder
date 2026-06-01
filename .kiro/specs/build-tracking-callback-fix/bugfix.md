# Bugfix Requirements Document

## Introduction

The Build Tracking & Callback System is completely non-functional: client sites never send a ping to the master server (`https://vaptsecure.net/vapts`), so the Build Tracking tab on the Domain Admin page always shows no data.

Two bugs are responsible for the core failure. The primary blocker is that all existing locked-config files were generated before the tracking fields (`build_id`, `integrity_url`, `tracking_mode`) were added to the schema, so `maybe_trigger_callback()` exits immediately on every client site. The secondary bug is a non-deterministic HMAC signature: even after locked-config files are regenerated, the client and master compute `json_encode()` over arrays whose key order may differ, causing `hash_equals()` to reject every callback with "Invalid signature".

A third bug (Bug C) affects the local/testing tracking mode: the `tracking_mode = 'testing'` option in the locked-config generator is misleadingly labelled and broken for local-as-master scenarios. The stored value `'testing'` is not self-explanatory, the dropdown label implies a hardcoded domain rather than the current generator site, and `wp_remote_post` uses `sslverify => true` by default, causing callbacks from locally-hosted client sites to a local master to fail silently on HTTP or self-signed-cert environments.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a client site loads and `maybe_trigger_callback()` reads a locked-config file that was generated before the tracking fields existed THEN the system logs "VAPT Tracking Error: Locked config file is missing build_id." and returns without sending any HTTP request to the master server.

1.2 WHEN the locked-config generator (`handle_generate_locked_config()`) creates a new locked-config file THEN the system omits `build_id`, `integrity_url`, and `tracking_mode` from the generated JSON payload, so every newly generated config also lacks the required tracking fields.

1.3 WHEN a client site sends a callback POST request and the master server reconstructs the payload for HMAC verification by reading `$_POST` THEN the system computes `json_encode($_POST)` without sorting keys, producing a key order that may differ from the order used by the client when it signed the payload, causing `hash_equals()` to fail and the master to reject the request with "Invalid signature".

1.4 WHEN a client site signs the outgoing callback payload by calling `json_encode($payload)` before appending `sig` THEN the system does not sort the payload keys before encoding, so the resulting HMAC input is dependent on PHP's internal array insertion order, which is not guaranteed to match the order in which `$_POST` keys arrive at the master.

1.5 WHEN the locked-config generator UI presents the local tracking mode option THEN the system stores the value `'testing'` in the generated config file and displays the label "Testing (vaptsecure.local)", which is misleading because: (a) the stored value `'testing'` is not self-explanatory when reading a config file, (b) the label implies a hardcoded domain rather than the current generator site's own `admin-ajax.php` endpoint, and (c) `maybe_trigger_callback()` calls `wp_remote_post` with `sslverify => true` by default, causing callbacks from locally-hosted client sites to a local master to fail silently when the master is running on HTTP or a self-signed certificate.

### Expected Behavior (Correct)

2.1 WHEN a client site loads and `maybe_trigger_callback()` reads a locked-config file that contains a valid `build_id` THEN the system SHALL proceed past the `build_id` guard and send an HTTP POST callback to the master server.

2.2 WHEN the locked-config generator creates a new locked-config file THEN the system SHALL include `build_id` (a unique identifier for the build), `integrity_url` (the master callback endpoint), and `tracking_mode` in the generated JSON payload so that every newly generated config contains the required tracking fields.

2.3 WHEN the master server reconstructs the payload for HMAC verification THEN the system SHALL call `ksort()` on the payload array before calling `json_encode()`, ensuring the key order is deterministic and matches the client's signing order.

2.4 WHEN a client site signs the outgoing callback payload THEN the system SHALL call `ksort()` on the payload array before calling `json_encode()`, ensuring the HMAC input is identical to what the master will compute during verification.

2.5 WHEN the locked-config generator UI presents the local tracking mode option THEN the system SHALL store the value `'local'` (renamed from `'testing'`) in the generated config file and display the label "This Install (local master)" to make it clear the callback URL points to the current generator site's own `admin-ajax.php` endpoint. The dropdown SHALL continue to auto-select this option when `is_local_environment()` returns true. WHEN `tracking_mode === 'local'`, the `wp_remote_post` call in `maybe_trigger_callback()` SHALL include `'sslverify' => false` so callbacks from locally-hosted client sites to a local master succeed regardless of SSL certificate validity. The `integrity_url` resolution logic SHALL remain unchanged: `admin_url('admin-ajax.php')` of the generator site is still the correct URL for local mode.

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a client site sends a callback with a correctly signed payload (after both sides apply `ksort()`) THEN the system SHALL CONTINUE TO verify the HMAC signature successfully and record the tracking data in `vapt_build_tracking`.

3.2 WHEN the master server receives a callback with a tampered or missing signature THEN the system SHALL CONTINUE TO reject the request with "Invalid signature" and not update tracking data.

3.3 WHEN `maybe_trigger_callback()` is called within the throttle window (12 hours on production, 60 seconds on local) THEN the system SHALL CONTINUE TO skip the ping and not send a duplicate request.

3.4 WHEN a build is activated for the first time on a client site THEN the system SHALL CONTINUE TO trigger `notify_superadmin_first_activation()` and send a notification email to `tanmalik786@gmail.com`.

3.5 WHEN the master server processes a callback for a build that has pending commands THEN the system SHALL CONTINUE TO return those commands in the JSON response and clear them from `vapt_pending_commands`.

3.6 WHEN a locked-config file is loaded and its domain pattern does not match the current site's domain THEN the system SHALL CONTINUE TO reject the config and not activate the locked configuration.

3.7 WHEN `wp_remote_post` is called for the callback THEN the system SHALL CONTINUE TO use `blocking => false` so the HTTP request does not block page load on the client site.

3.8 WHEN a config file containing the legacy value `tracking_mode = 'testing'` is read at runtime by `maybe_trigger_callback()` THEN the system SHALL CONTINUE TO function correctly, because `maybe_trigger_callback()` uses `integrity_url` directly and does not branch on `tracking_mode` at runtime. No migration of existing config files is required for the Bug C rename.

3.9 WHEN `tracking_mode === 'production'` THEN the system SHALL CONTINUE TO use the production `integrity_url` and SHALL CONTINUE TO call `wp_remote_post` with default SSL verification (`sslverify => true`), completely unaffected by the Bug C changes.

3.10 WHEN `tracking_mode === 'custom'` THEN the system SHALL CONTINUE TO use the user-supplied `integrity_url` and SHALL CONTINUE TO call `wp_remote_post` with default SSL verification (`sslverify => true`), completely unaffected by the Bug C changes.
