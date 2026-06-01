# Implementation Plan

## Overview

Fix three independent bugs that together make the Build Tracking & Callback System completely non-functional:

- **Bug A** — Legacy locked-config files lack `build_id`, `integrity_url`, and `tracking_mode`, causing `maybe_trigger_callback()` to exit immediately without sending any HTTP ping.
- **Bug B** — Non-deterministic HMAC: client and master call `json_encode()` on unsorted arrays, so `hash_equals()` fails with "Invalid signature" even for legitimate callbacks.
- **Bug C** — `tracking_mode = 'testing'` is misleading and broken for local-as-master: rename to `'local'`, update the dropdown label to "This Install (local master)", and add `sslverify => false` when `tracking_mode === 'local'`.

The workflow follows the exploratory bugfix methodology: write exploration and preservation tests against unfixed code first, then apply the fix, then verify all tests pass.

## Task Dependency Graph

```json
{
  "waves": [
    { "wave": 1, "tasks": ["1"] },
    { "wave": 2, "tasks": ["2"] },
    { "wave": 3, "tasks": ["3.1", "3.2", "3.3", "3.4", "3.5", "3.6"] },
    { "wave": 4, "tasks": ["3.7"] },
    { "wave": 5, "tasks": ["3.8"] },
    { "wave": 6, "tasks": ["4"] }
  ]
}
```

## Tasks

- [x] 1. Write bug condition exploration tests (BEFORE implementing any fix)
  - **Property 1: Bug Condition** - Missing build_id Early Exit & HMAC Key-Order Mismatch
  - **CRITICAL**: These tests MUST FAIL (Bug A test) or surface the defect (Bug B test) on unfixed code — failure/mismatch confirms the bugs exist
  - **DO NOT attempt to fix the tests or the code when they fail**
  - **NOTE**: These tests encode the expected behavior — they will validate the fix when they pass after implementation
  - **GOAL**: Surface counterexamples that demonstrate all three bugs exist on the unfixed code
  - **Scoped PBT Approach**: For Bug A, scope to the concrete failing case: a config array where `build_id` is absent/empty. For Bug B, scope to payload arrays with the same key-value pairs but different insertion orders.
  - **Bug A test** — inject a config array without `build_id` into `maybe_trigger_callback()`:
    - Assert `wp_remote_post` is NEVER called (guard fires and function returns early)
    - Confirm the error log contains "VAPT Tracking Error: Locked config file is missing build_id."
    - Run on UNFIXED code — test PASSES (confirms the guard fires, i.e., the bug exists)
  - **Bug B test** — build a standard 8-key payload, compute client HMAC without `ksort`, then simulate `$_POST` with keys in a different order and compute master HMAC without `ksort`:
    - Assert the two HMAC digests DIFFER (non-determinism confirmed)
    - Also assert a full round-trip (sign → POST → verify, unfixed) returns `hash_equals() === false`
    - Run on UNFIXED code — test PASSES (confirms the signature mismatch exists)
  - **Bug C test** — call `handle_generate_locked_config()` with local mode and inspect output:
    - Assert output JSON contains `tracking_mode: "testing"` (the defective value, confirming Bug C exists)
    - Assert `wp_remote_post` args for a config with `tracking_mode = 'testing'` include `sslverify => true` (the defective default)
    - Run on UNFIXED code — test PASSES (confirms the misleading value and broken SSL setting exist)
  - Document all counterexamples found (e.g., "HMAC differs for payload with keys reordered: sha256(A)=abc… vs sha256(B)=xyz…")
  - Mark task complete when all exploration tests are written, run, and failures/defects are documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Throttle, Tamper Rejection, First Activation, Pending Commands, Non-Blocking HTTP, SSL Defaults
  - **IMPORTANT**: Follow observation-first methodology — run each test against UNFIXED code first to record baseline behavior
  - **Observe on UNFIXED code (non-buggy inputs — cases where `isBugCondition` returns false):**
    - Observe: calling `maybe_trigger_callback()` twice within the throttle window → `wp_remote_post` called at most once
    - Observe: sending a callback with a corrupted `sig` → master returns `{"success":false,"data":{"message":"Invalid signature"}}` and does NOT update `vapt_build_tracking`
    - Observe: sending a callback for a new `build_id` → `notify_superadmin_first_activation()` called exactly once
    - Observe: pre-populating `vapt_pending_commands` for a `build_id`, then sending a valid callback → commands returned in response and entry cleared
    - Observe: inspecting `wp_remote_post` call args → `blocking => false` is always present
    - Observe: `maybe_trigger_callback()` with `tracking_mode = 'production'` → `sslverify` is `true` (or absent, defaulting to true)
    - Observe: `maybe_trigger_callback()` with `tracking_mode = 'custom'` → `sslverify` is `true`
    - Observe: `maybe_trigger_callback()` with legacy `tracking_mode = 'testing'` → `sslverify` is `true`
  - **Write property-based tests capturing observed behavior patterns from Preservation Requirements:**
    - For all inputs where `isBugCondition` returns false (valid `build_id` present, keys already in same order), assert `original_function(input) == fixed_function(input)`
    - Property: for any tampered `sig` value, `handle_build_callback()` always returns "Invalid signature" and never writes to `vapt_build_tracking`
    - Property: for any non-`'local'` tracking mode (`'production'`, `'custom'`, `'testing'`, absent), `wp_remote_post` is always called with `sslverify => true`
  - Run all preservation tests on UNFIXED code
  - **EXPECTED OUTCOME**: All preservation tests PASS (confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10_

- [x] 3. Fix for missing build_id guard, non-deterministic HMAC, and broken local tracking mode

  - [x] 3.1 Add `ksort` before client-side HMAC signing in `maybe_trigger_callback()`
    - In `vapt-security.php`, locate the line (approx. line 2912):
      `$payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), $salt );`
    - Insert `ksort( $payload );` immediately before that line
    - `sig` is appended after the sort so it is excluded from the canonical string — matching master behavior
    - _Bug_Condition: isBugCondition_B(client_payload, post_array) where json_encode(client_payload) != json_encode(post_array) due to key-order mismatch_
    - _Expected_Behavior: hash_hmac('sha256', json_encode(ksorted_payload_without_sig), salt) is identical on client and master for any key insertion order_
    - _Preservation: blocking => false unchanged; throttle logic unchanged; domain-lock unchanged_
    - _Requirements: 2.4, 3.7_

  - [x] 3.2 Add `ksort` before master-side HMAC verification in `handle_build_callback()`
    - In `vapt-security.php`, locate the block (approx. line 2792):
      `$payload_for_sig = $_POST; unset( $payload_for_sig['sig'] ); $expected_sig = hash_hmac(...)`
    - Insert `ksort( $payload_for_sig );` after the `unset` and before `hash_hmac`
    - After unsetting `sig`, remaining keys are sorted to the same canonical order the client produced
    - _Bug_Condition: isBugCondition_B — $_POST key order differs from client payload insertion order_
    - _Expected_Behavior: hash_equals($expected_sig, $received_sig) returns true for any legitimate callback_
    - _Preservation: tampered/missing sig still rejected; pending-command dispatch unchanged; first-activation unchanged_
    - _Requirements: 2.3, 3.1, 3.2, 3.4, 3.5_

  - [x] 3.3 Rename `'testing'` to `'local'` in both generator functions (Bug C — 3a)
    - In `vapt-security.php`, in `handle_generate_locked_config()`, change:
      `if ( $tracking_mode === 'testing' ) {` → `if ( $tracking_mode === 'local' ) {`
    - In `vapt-security.php`, in `handle_generate_client_build()`, apply the same rename
    - `integrity_url` resolution logic (`admin_url('admin-ajax.php')`) is unchanged
    - _Bug_Condition: isBugCondition_C — tracking_mode stored as 'testing' is opaque and misleading_
    - _Expected_Behavior: generated config contains tracking_mode: "local" (self-explanatory value)_
    - _Preservation: integrity_url resolution unchanged; production and custom modes unaffected_
    - _Requirements: 2.5, 3.8, 3.9, 3.10_

  - [x] 3.4 Update dropdown option value and label in `templates/admin-domain-control.php` (Bug C — 3b)
    - Change: `<option value="testing" ...>Testing (vaptsecure.local)</option>`
    - To:     `<option value="local" ...>This Install (local master)</option>`
    - The `selected()` condition using `is_local_environment()` stays exactly the same
    - _Bug_Condition: isBugCondition_C — label implies hardcoded domain, value is opaque_
    - _Expected_Behavior: dropdown stores 'local', label reads "This Install (local master)"_
    - _Preservation: auto-select logic for is_local_environment() unchanged_
    - _Requirements: 2.5_

  - [x] 3.5 Add `sslverify` conditional to `wp_remote_post` in `maybe_trigger_callback()` (Bug C — 3c)
    - In `vapt-security.php`, locate the `wp_remote_post` call (approx. line 2915) and add to its args array:
      `'sslverify' => ( $config['tracking_mode'] ?? 'production' ) !== 'local',`
    - `sslverify` is `true` for `'production'`, `'custom'`, absent (null-coalesces to `'production'`), and legacy `'testing'` (since `'testing' !== 'local'` is `true`)
    - `sslverify` is `false` only for `'local'` mode — safe because local mode is development-only
    - _Bug_Condition: isBugCondition_C — sslverify => true (default) causes silent failure on HTTP/self-signed-cert local master_
    - _Expected_Behavior: wp_remote_post called with sslverify => false when tracking_mode === 'local'_
    - _Preservation: sslverify => true for production, custom, testing (legacy), and absent modes; blocking => false unchanged_
    - _Requirements: 2.5, 3.8, 3.9, 3.10_

  - [x] 3.6 Regenerate the four legacy locked-config files via the Domain Admin UI
    - Deploy the fixed `vapt-security.php` to the master server first (changes 3.1–3.5 must be live)
    - For each of the four legacy files that lack `build_id`, open Domain Admin → Build Management:
      - `releases/configurations/vapt-wptest-locked-config.php`
      - `releases/configurations/vapt-locked-config.php`
      - `releases/configurations/vapt-vaptsecure-locked-config.php`
      - `releases/configurations/vapt-hermasnet.com-locked-config.php`
    - Use "Generate Config File" (or "Generate Client Build") for the same domain pattern
    - Confirm each new file contains `build_id`, `integrity_url`, and `tracking_mode`
    - Distribute each new config to the corresponding client site, replacing the old file
    - _Bug_Condition: isBugCondition_A — config array where empty($config['build_id']) is true_
    - _Expected_Behavior: maybe_trigger_callback() proceeds past build_id guard and calls wp_remote_post_
    - _Preservation: domain_pattern, license, white_label data preserved; domain-lock enforcement unchanged_
    - _Requirements: 2.1, 2.2_

  - [x] 3.7 Verify bug condition exploration test now passes (after fix)
    - **Property 1: Expected Behavior** - Missing build_id Guard Bypassed & HMAC Symmetry Achieved
    - **IMPORTANT**: Re-run the SAME tests from task 1 — do NOT write new tests
    - The tests from task 1 encode the expected behavior; passing them confirms the fix is correct
    - Re-run Bug A test: `maybe_trigger_callback()` with a config that HAS `build_id` → assert `wp_remote_post` IS called
    - Re-run Bug B test: full round-trip (sign fixed → POST → verify fixed) with reordered `$_POST` → assert `hash_equals() === true`
    - Re-run Bug C test: `handle_generate_locked_config()` with local mode → assert `tracking_mode: "local"` in output; `maybe_trigger_callback()` with `tracking_mode = 'local'` → assert `sslverify => false`
    - **EXPECTED OUTCOME**: All exploration tests PASS (confirms all three bugs are fixed)
    - _Requirements: 2.1, 2.3, 2.4, 2.5_

  - [x] 3.8 Verify preservation tests still pass (after fix)
    - **Property 2: Preservation** - No Regressions in Throttle, Tamper Rejection, First Activation, Pending Commands, Non-Blocking HTTP, SSL Defaults
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run all preservation property tests from step 2 against the fixed code
    - **EXPECTED OUTCOME**: All preservation tests PASS (confirms no regressions introduced)
    - Confirm: throttle window still prevents duplicate pings
    - Confirm: tampered/missing `sig` still rejected with "Invalid signature"
    - Confirm: first-activation notification still fires for new `build_id`
    - Confirm: pending commands still returned and cleared
    - Confirm: `blocking => false` still present in all `wp_remote_post` calls
    - Confirm: `sslverify => true` for `'production'`, `'custom'`, `'testing'` (legacy), and absent modes
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10_

- [x] 4. Checkpoint — Ensure all tests pass
  - Run the full test suite (unit tests + property-based tests)
  - Confirm all exploration tests from task 1 now PASS (bugs fixed)
  - Confirm all preservation tests from task 2 still PASS (no regressions)
  - Perform integration verification: place a regenerated locked-config (with `build_id`) on a client site, trigger a page load, and confirm the Build Tracking tab on the master shows data within the throttle window (≤ 60 s on local, ≤ 12 h on production)
  - Verify that a client site with a valid config does not send duplicate pings within the throttle window across multiple page loads
  - Verify that switching from a legacy config (no `build_id`) to a regenerated config causes the first successful ping to appear in the tracking table
  - Ask the user if any questions arise before closing the spec

## Notes

- Tasks 1 and 2 MUST be completed before any code changes are made. The exploration and preservation tests serve as the specification for correctness.
- The four legacy config files (task 3.6) require a manual UI step on the deployed master server — they cannot be regenerated programmatically without the original `build_id` values.
- The `ksort` fix (tasks 3.1 and 3.2) is a two-line change but resolves a non-deterministic failure that would affect every single callback in every environment.
- Existing configs storing `tracking_mode = 'testing'` require no migration: `'testing' !== 'local'` evaluates to `true`, so `sslverify` remains `true` for those files — identical to current behavior (Requirement 3.8).
- Property-based testing is strongly recommended for the HMAC symmetry property (Property 2 in design) because it exercises all 8! = 40,320 permutations of the 8 payload keys automatically.
