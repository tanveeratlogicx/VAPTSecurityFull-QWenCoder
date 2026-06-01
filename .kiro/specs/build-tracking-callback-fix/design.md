# Build Tracking Callback Fix — Bugfix Design

## Overview

The Build Tracking & Callback System is completely non-functional because two independent bugs
prevent any client site from ever sending a ping to the master server
(`https://vaptsecure.net/vapts`).

**Bug A — Missing tracking fields in locked-config files.**  
All locked-config files generated before the tracking schema was extended omit `build_id`,
`integrity_url`, and `tracking_mode`. The `maybe_trigger_callback()` function guards on
`empty($config['build_id'])` and returns immediately, so no HTTP request is ever sent.
Additionally, the generator (`handle_generate_locked_config()`) was also missing these fields
in its output payload, meaning even freshly generated configs would be broken — however,
inspection of the current source confirms the generator already writes all three fields
correctly. The fix therefore focuses on regenerating the four existing legacy config files
that were produced before the schema was complete.

**Bug B — Non-deterministic HMAC signature.**  
The client signs the payload with `hash_hmac('sha256', json_encode($payload), $salt)` and
the master reconstructs the signature from `json_encode($_POST)`. PHP does not guarantee that
`$_POST` key order matches the order in which the client built `$payload`, so `hash_equals()`
fails with "Invalid signature" even for legitimate callbacks. The fix is to call `ksort()` on
both arrays before `json_encode()`, making the canonical string deterministic on both sides.

The fix is minimal and surgical: two one-line `ksort()` insertions in `vapt-security.php` plus
a one-time regeneration of the four legacy locked-config files.

**Bug C — Misleading and broken `tracking_mode = 'testing'` for local-as-master scenarios.**  
The locked-config generator stores the value `'testing'` for the local tracking mode, but this
string is not self-explanatory when reading a config file. The dropdown label "Testing
(vaptsecure.local)" implies a hardcoded domain rather than the current generator site's own
`admin-ajax.php` endpoint. Additionally, `maybe_trigger_callback()` calls `wp_remote_post`
with `sslverify => true` by default, causing callbacks from locally-hosted client sites to a
local master to fail silently when the master is running on HTTP or a self-signed certificate.
The fix has three parts: (3a) rename the stored value from `'testing'` to `'local'` in both
generator functions; (3b) update the dropdown label to "This Install (local master)"; and
(3c) pass `sslverify => false` in `wp_remote_post` when `tracking_mode === 'local'`. Existing
configs storing `'testing'` require no migration — the `sslverify` expression evaluates
`'testing' !== 'local'` as `true`, preserving the current behaviour for those files.

---

## Glossary

- **Bug_Condition (C)**: The set of inputs that trigger defective behaviour — either a
  locked-config array that lacks `build_id` (Bug A), or a payload array whose key order
  differs between client and master (Bug B).
- **Property (P)**: The desired correct behaviour for inputs in C — the callback is sent and
  the signature verifies successfully.
- **Preservation**: All behaviours that must remain unchanged by the fix — throttling, tamper
  rejection, first-activation notification, pending-command dispatch, domain-lock enforcement,
  and non-blocking HTTP.
- **`maybe_trigger_callback()`**: Client-side function in `vapt-security.php` that reads the
  locked config, builds the payload, signs it, and fires `wp_remote_post`.
- **`handle_build_callback()`**: Master-side AJAX handler in `vapt-security.php` that receives
  the POST, reconstructs the HMAC, and records tracking data.
- **`handle_generate_locked_config()`**: Master-side AJAX handler that writes a new
  `vapt-{domain}-locked-config.php` file to `releases/configurations/`.
- **`$salt`**: The shared HMAC secret `'VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2'` hard-coded in
  both signing and verification paths.
- **Legacy config**: A locked-config file generated before `build_id`, `integrity_url`, and
  `tracking_mode` were added to the payload schema (the four files currently in
  `releases/configurations/` that lack these keys).
- **`'local'` tracking mode**: The renamed value (previously `'testing'`) stored in a
  locked-config file to indicate that the callback `integrity_url` points to the generator
  site's own `admin-ajax.php` endpoint (i.e., a local-as-master setup). When this mode is
  active, `wp_remote_post` uses `sslverify => false` to accommodate HTTP or self-signed-cert
  local environments. The `integrity_url` resolution logic — `admin_url('admin-ajax.php')` of
  the generator site — is unchanged.

---

## Bug Details

### Bug Condition

**Bug A** manifests when `maybe_trigger_callback()` decodes a locked-config file whose JSON
payload does not contain a `build_id` key. The function exits at the guard on line ~2886
without sending any HTTP request.

**Bug B** manifests when the client and master compute `json_encode()` over the same logical
payload but with different key insertion orders, producing different canonical strings and
therefore different HMAC digests.

**Bug C** manifests when the locked-config generator stores `tracking_mode = 'testing'` and
the client site later calls `maybe_trigger_callback()` in a local-as-master environment. The
misleading label and stored value make the option confusing, and the default `sslverify => true`
in `wp_remote_post` causes the callback to fail silently when the local master is running on
HTTP or a self-signed certificate.

**Formal Specification:**

```
FUNCTION isBugCondition(input)
  INPUT: input — either a locked-config array OR a (client_payload, post_array) pair
  OUTPUT: boolean

  // Bug A: missing build_id
  IF input IS locked_config_array THEN
    RETURN empty(input['build_id'])

  // Bug B: key-order mismatch
  IF input IS (client_payload, post_array) THEN
    client_canonical := json_encode(client_payload)          // no ksort
    server_canonical := json_encode(post_array)              // no ksort
    RETURN client_canonical != server_canonical
      AND  same_key_value_pairs(client_payload, post_array)

  // Bug C: local mode with sslverify => true (default) causes silent failure
  IF input IS (tracking_mode, environment) THEN
    RETURN tracking_mode IN ['testing', 'local']
      AND  is_local_environment()
      AND  sslverify IS true   // default — fails on HTTP or self-signed cert

END FUNCTION
```

### Examples

**Bug A — legacy config missing build_id:**
- Config JSON: `{"domain_pattern":"wptest","white_label":{...},"generated_at":1779276458}`
- `maybe_trigger_callback()` reads this, finds `$config['build_id']` empty, logs
  `"VAPT Tracking Error: Locked config file is missing build_id."`, and returns.
- No HTTP POST is ever sent to `https://vaptsecure.net/vapts`.

**Bug A — legacy config missing integrity_url:**
- Even if `build_id` were somehow present, `$config['integrity_url']` would be empty and the
  function would fall back to the `VAPT_INTEGRITY_URL` constant — this is acceptable fallback
  behaviour, but the primary blocker is the missing `build_id`.

**Bug B — key-order mismatch:**
- Client builds payload in insertion order:
  `{"action":"vapt_build_callback","build_id":"B250420-a1b2","domain":"hermasnet.com",...}`
- `$_POST` arrives at master with keys in a different order (e.g. alphabetical or HTTP
  transmission order):
  `{"action":"vapt_build_callback","build_id":"B250420-a1b2","domain":"hermasnet.com",...}`
  — same values, different key sequence → different `json_encode()` output → different HMAC →
  `hash_equals()` returns `false` → master responds `{"success":false,"data":{"message":"Invalid signature"}}`.

**Bug B — edge case (keys already in same order):**
- If PHP happens to preserve insertion order through the HTTP layer (possible in some
  environments), the signature may verify correctly by accident. This is non-deterministic and
  cannot be relied upon.

**Bug C — misleading label and stored value:**
- The Domain Admin dropdown shows "Testing (vaptsecure.local)" with stored value `'testing'`.
  A developer reading a config file sees `tracking_mode: "testing"` with no indication it
  means "local master". Expected: stored value `'local'`, label "This Install (local master)".

**Bug C — silent SSL failure in local mode:**
- A client site on `http://vaptsecure.local` has a regenerated config with
  `tracking_mode: "testing"` (or `"local"`) and `integrity_url` pointing to
  `http://vaptsecure.local/wp-admin/admin-ajax.php`. `wp_remote_post` is called with default
  `sslverify => true`. cURL rejects the connection because the local master uses HTTP or a
  self-signed certificate. The callback silently fails; no error is logged at the PHP level
  because `blocking => false`. Expected: `sslverify => false` when `tracking_mode === 'local'`.

---

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Throttle window logic (12 h production / 60 s local) in `maybe_trigger_callback()` must
  continue to prevent duplicate pings within the window (Requirement 3.3).
- `handle_build_callback()` must continue to reject payloads with a tampered or absent `sig`
  field with "Invalid signature" (Requirement 3.2).
- First-activation detection must continue to call `notify_superadmin_first_activation()` and
  send email to `tanmalik786@gmail.com` (Requirement 3.4).
- Pending-command dispatch must continue to return commands from `vapt_pending_commands` and
  clear them after delivery (Requirement 3.5).
- Domain-lock enforcement must continue to reject configs whose `domain_pattern` does not
  match the current site's host (Requirement 3.6).
- `wp_remote_post` must continue to be called with `blocking => false` so the callback does
  not block page load (Requirement 3.7).
- Existing configs storing `tracking_mode = 'testing'` must continue to function correctly at
  runtime — `maybe_trigger_callback()` uses `integrity_url` directly, and the `sslverify`
  expression `'testing' !== 'local'` evaluates to `true`, preserving current behaviour for
  those files (Requirement 3.8).
- When `tracking_mode === 'production'`, `wp_remote_post` must continue to use default SSL
  verification (`sslverify => true`) (Requirement 3.9).
- When `tracking_mode === 'custom'`, `wp_remote_post` must continue to use default SSL
  verification (`sslverify => true`) (Requirement 3.10).

**Scope:**
All inputs that do NOT involve a missing `build_id` or a key-order mismatch are completely
unaffected by this fix. This includes:
- Mouse/keyboard interactions with the admin UI.
- All other AJAX handlers.
- License validation, OTP, rate-limiting, and hardening features.
- The locked-config integrity check (`$vapt_locked_config_sig` file-level signature) — this
  is a separate HMAC over the raw JSON string and is not affected by `ksort`.
- Callbacks using `tracking_mode === 'production'` or `tracking_mode === 'custom'` — these
  are completely unaffected by the Bug C changes and continue to use `sslverify => true`.
- Existing locked-config files storing `tracking_mode = 'testing'` — no migration is needed
  because `maybe_trigger_callback()` does not branch on `tracking_mode` at runtime.

---

## Hypothesized Root Cause

1. **Schema added after config files were generated (Bug A — primary blocker).**  
   The `build_id`, `integrity_url`, and `tracking_mode` fields were added to
   `handle_generate_locked_config()` at some point after the four existing config files in
   `releases/configurations/` were written. Those files were never regenerated, so every
   client site that received one of them will always hit the `empty($config['build_id'])` guard.

2. **`json_encode` called on unsorted array on the client side (Bug B — secondary).**  
   In `maybe_trigger_callback()`, the payload array is built with explicit key insertion order
   and then passed directly to `json_encode()` without sorting. The resulting canonical string
   is therefore tied to PHP's internal array insertion order at the time of the call.

3. **`json_encode` called on `$_POST` without sorting on the master side (Bug B — secondary).**  
   In `handle_build_callback()`, the verification reconstructs the canonical string from
   `$_POST` (after unsetting `sig`). HTTP POST key order is determined by the HTTP client
   library (`wp_remote_post` / cURL) and is not guaranteed to match the order in which the
   PHP array was built on the client. Even a single key arriving in a different position
   produces a completely different HMAC.

4. **No canonical serialisation contract was defined.**  
   The original implementation assumed `json_encode` would produce the same output on both
   sides, which is only true if key order is identical — an assumption that does not hold
   across HTTP boundaries.

5. **`tracking_mode = 'testing'` is an opaque, misleading value (Bug C).**  
   The stored string `'testing'` gives no indication that it means "use the generator site's
   own `admin-ajax.php` as the callback endpoint". The dropdown label "Testing
   (vaptsecure.local)" compounds the confusion by implying a hardcoded domain. The rename to
   `'local'` with label "This Install (local master)" makes the intent self-evident.

6. **`wp_remote_post` defaults to `sslverify => true` for all modes (Bug C).**  
   Local development environments commonly run on HTTP or with self-signed certificates.
   Because `blocking => false` suppresses cURL errors at the PHP level, the SSL failure is
   completely silent — the developer sees no error and no tracking data, with no obvious
   diagnostic path. Passing `sslverify => false` only when `tracking_mode === 'local'` is the
   minimal targeted fix; all other modes retain the secure default.

---

## Correctness Properties

Property 1: Bug Condition A — Locked Config with build_id Proceeds to Send Callback

_For any_ locked-config array where `build_id` is a non-empty string (i.e., `isBugCondition`
for Bug A returns `false`), the fixed `maybe_trigger_callback()` function SHALL proceed past
the `build_id` guard and invoke `wp_remote_post` with the master callback URL, provided the
throttle window has elapsed.

**Validates: Requirements 2.1**

Property 2: Bug Condition B — HMAC Signing/Verification Symmetry

_For any_ payload array containing the fields `action`, `build_id`, `domain`,
`license_type`, `license_expiry`, `license_status`, `version`, and `initial_install` with
arbitrary key insertion order, the fixed client signing step and the fixed master verification
step SHALL produce identical HMAC digests — i.e., `hash_hmac('sha256', json_encode(ksorted_payload), $salt)` is equal on both sides regardless of the order in which keys were
inserted into the array.

**Validates: Requirements 2.3, 2.4**

Property 3: Preservation — Tampered Signature Still Rejected

_For any_ payload where the `sig` field does not match the HMAC of the ksort-canonicalised
payload, the fixed `handle_build_callback()` SHALL continue to return `{"success":false,"data":{"message":"Invalid signature"}}` and SHALL NOT update `vapt_build_tracking`.

**Validates: Requirements 3.1, 3.2**

Property 4: Preservation — Non-Callback Behaviours Unchanged

_For any_ input that does not involve the `build_id` guard or the HMAC signing/verification
path (throttle checks, domain-lock enforcement, first-activation notification, pending-command
dispatch, `blocking => false`), the fixed code SHALL produce exactly the same behaviour as the
original code.

**Validates: Requirements 3.3, 3.4, 3.5, 3.6, 3.7**

Property 5: Bug Condition C — Local Mode Uses Correct Label, Value, and SSL Setting

_For any_ locked-config generated with the local tracking mode option selected, the fixed
generator SHALL store `tracking_mode = 'local'` (not `'testing'`) and the dropdown SHALL
display "This Install (local master)". Additionally, _for any_ runtime callback where
`$config['tracking_mode'] === 'local'`, the fixed `maybe_trigger_callback()` SHALL call
`wp_remote_post` with `'sslverify' => false`, enabling callbacks to succeed on HTTP or
self-signed-cert local masters. For all other tracking modes (`'production'`, `'custom'`, or
the legacy `'testing'`), `sslverify` SHALL remain `true`, preserving the secure default.

**Validates: Requirements 2.5, 3.8, 3.9, 3.10**

---

## Fix Implementation

### Changes Required

#### File: `vapt-security.php`

**Change 1 — Client-side HMAC signing (`maybe_trigger_callback`)**

Add `ksort($payload)` immediately before the `json_encode($payload)` call that computes `sig`.

Current code (approx. line 2912):
```php
$payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), $salt );
```

Fixed code:
```php
ksort( $payload );
$payload['sig'] = hash_hmac( 'sha256', json_encode( $payload ), $salt );
```

Rationale: `ksort` sorts the array in-place by key in ascending ASCII order. Because `sig` is
appended after the sort, it is not included in the canonical string — matching the master's
behaviour of unsetting `sig` before verifying.

**Change 2 — Master-side HMAC verification (`handle_build_callback`)**

Add `ksort($payload_for_sig)` immediately before the `json_encode($payload_for_sig)` call
that computes `$expected_sig`.

Current code (approx. line 2792):
```php
$payload_for_sig = $_POST;
unset( $payload_for_sig['sig'] );
$expected_sig = hash_hmac( 'sha256', json_encode( $payload_for_sig ), $salt );
```

Fixed code:
```php
$payload_for_sig = $_POST;
unset( $payload_for_sig['sig'] );
ksort( $payload_for_sig );
$expected_sig = hash_hmac( 'sha256', json_encode( $payload_for_sig ), $salt );
```

Rationale: After unsetting `sig`, the remaining keys are sorted to the same canonical order
that the client produced. The HMAC inputs are now byte-for-byte identical.

#### Migration: Regenerate Legacy Locked-Config Files

The four existing config files in `releases/configurations/` that lack `build_id` must be
regenerated via the Domain Admin UI. There is no automated migration path because:

1. The original `build_id` values are unknown (they were never stored).
2. The `domain_pattern`, `license`, and `white_label` data are preserved in the existing
   files and can be re-entered or copied from the build history.

**Recommended procedure:**

1. Deploy the fixed `vapt-security.php` to the master server.
2. For each legacy config file, open the Domain Admin → Build Management page.
3. Use "Generate Config File" (or "Generate Client Build") to produce a new config for the
   same domain pattern. The generator will assign a fresh `build_id` and include
   `integrity_url` and `tracking_mode`.
4. Distribute the new config file to the corresponding client site, replacing the old one.
5. Verify the Build Tracking tab shows data within the next throttle window (≤ 60 s on local,
   ≤ 12 h on production).

**Affected files (confirmed by inspection — all lack `build_id`):**
- `releases/configurations/vapt-wptest-locked-config.php`
- `releases/configurations/vapt-locked-config.php`
- `releases/configurations/vapt-vaptsecure-locked-config.php`
- `releases/configurations/vapt-hermasnet.com-locked-config.php`

**Note on `handle_generate_locked_config()` (Bug 1.2):**  
Inspection of the current source confirms the generator already writes `build_id`,
`integrity_url`, and `tracking_mode` into the payload. Bug 1.2 as described in the
requirements was present at some earlier point but has since been corrected in the generator
code. No code change is needed in the generator; only the legacy files need regeneration.

---

#### File: `vapt-security.php` — Bug C Changes

**Change 3a — Rename `'testing'` to `'local'` in generator functions**

In both `handle_generate_locked_config()` and `handle_generate_client_build()`, update the
condition that resolves `integrity_url` for the local mode.

Current code (in both functions):
```php
if ( $tracking_mode === 'testing' ) {
    $integrity_url = admin_url( 'admin-ajax.php' );
```

Fixed code (in both functions):
```php
if ( $tracking_mode === 'local' ) {
    $integrity_url = admin_url( 'admin-ajax.php' );
```

Rationale: The `integrity_url` resolution logic is unchanged — `admin_url('admin-ajax.php')`
of the generator site is still the correct URL for local mode. Only the mode string changes
from the opaque `'testing'` to the self-explanatory `'local'`.

**Change 3b — Update dropdown label in `templates/admin-domain-control.php`**

Current code:
```html
<option value="testing" ...>Testing (vaptsecure.local)</option>
```

Fixed code:
```html
<option value="local" ...>This Install (local master)</option>
```

Rationale: The `selected()` condition using `is_local_environment()` stays exactly the same.
The new label makes it clear the callback URL points to the current generator site's own
`admin-ajax.php` endpoint, not a hardcoded domain.

**Change 3c — Add `sslverify => false` for local mode in `maybe_trigger_callback()`**

Current code (approx. line 2915):
```php
$response = wp_remote_post( $integrity_url, [
    'method'    => 'POST',
    'blocking'  => false,
    'body'      => $payload,
    'timeout'   => 15,
] );
```

Fixed code:
```php
$response = wp_remote_post( $integrity_url, [
    'method'    => 'POST',
    'blocking'  => false,
    'body'      => $payload,
    'timeout'   => 15,
    'sslverify' => ( $config['tracking_mode'] ?? 'production' ) !== 'local',
] );
```

Rationale: `sslverify` is `true` for `'production'` and `'custom'` modes (secure default),
and `false` only for `'local'` mode where the master may be running on HTTP or a self-signed
certificate. This is safe because local mode is only used in development environments.

**Backward compatibility:** Existing configs storing `tracking_mode = 'testing'` are safe.
The expression `'testing' !== 'local'` evaluates to `true`, so those configs continue to use
`sslverify => true` — identical to the current behaviour. No migration is needed.

---

## Testing Strategy

### Validation Approach

Testing follows a two-phase approach:

1. **Exploratory / Bug Condition Checking** — run tests against the *unfixed* code to confirm
   the bugs reproduce as described and to validate the root cause analysis.
2. **Fix Checking + Preservation Checking** — run the same tests against the *fixed* code to
   confirm the bugs are resolved and no regressions are introduced.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate both bugs on unfixed code. Confirm or
refute the root cause analysis.

**Test Plan**: Write unit tests that directly exercise `maybe_trigger_callback()` with a
legacy config (no `build_id`) and that exercise the HMAC path with a shuffled payload. Run
on unfixed code to observe failures.

**Test Cases:**

1. **Legacy Config Early Exit (Bug A)**: Inject a config array without `build_id` into
   `maybe_trigger_callback()` and assert that `wp_remote_post` is never called.
   *(Will pass on unfixed code — confirms the guard fires.)*

2. **HMAC Mismatch on Key Reorder (Bug B)**: Build a payload array, compute the client HMAC
   without `ksort`, then simulate `$_POST` with keys in a different order and compute the
   master HMAC without `ksort`. Assert the two HMACs differ.
   *(Will pass on unfixed code — confirms the non-determinism.)*

3. **Round-Trip Failure (Bug B end-to-end)**: Call the full signing path (unfixed) and feed
   the result to the full verification path (unfixed) with a reordered `$_POST`. Assert
   `hash_equals` returns `false`.
   *(Will pass on unfixed code — confirms end-to-end failure.)*

**Expected Counterexamples:**
- `wp_remote_post` is never invoked when `build_id` is absent.
- HMAC digests differ when key order differs between client and master.

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed functions
produce the expected correct behaviour.

**Pseudocode:**
```
FOR ALL config WHERE isBugCondition_A(config) IS false   // build_id present
  result := maybe_trigger_callback_fixed(config)
  ASSERT wp_remote_post WAS called
  ASSERT payload['sig'] == hash_hmac('sha256', json_encode(ksorted_payload_without_sig), salt)
END FOR

FOR ALL (client_payload, post_array) WHERE same_key_value_pairs(client_payload, post_array)
  client_sig := sign_fixed(client_payload)
  server_sig := verify_fixed(post_array)
  ASSERT client_sig == server_sig
  ASSERT hash_equals(server_sig, client_sig) IS true
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed
functions produce the same result as the original functions.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT original_function(input) == fixed_function(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for the HMAC symmetry property
because it generates many random key orderings automatically, catching edge cases that manual
unit tests would miss. For the remaining preservation requirements, targeted unit tests are
sufficient.

**Test Cases:**

1. **Throttle Preservation**: Call `maybe_trigger_callback()` twice within the throttle
   window; assert `wp_remote_post` is called at most once.
2. **Tamper Rejection Preservation**: Send a callback with a corrupted `sig`; assert master
   returns "Invalid signature" and does not update `vapt_build_tracking`.
3. **First Activation Preservation**: Send a callback for a new `build_id`; assert
   `notify_superadmin_first_activation()` is called exactly once.
4. **Pending Commands Preservation**: Pre-populate `vapt_pending_commands` for a `build_id`;
   send a valid callback; assert commands are returned and the entry is cleared.
5. **Non-Blocking HTTP Preservation**: Inspect the `wp_remote_post` arguments; assert
   `blocking => false`.

### Unit Tests

- Test `maybe_trigger_callback()` with a config that has `build_id` → assert `wp_remote_post`
  is called.
- Test `maybe_trigger_callback()` with a config missing `build_id` → assert `wp_remote_post`
  is NOT called and error is logged.
- Test `handle_build_callback()` with a correctly signed, ksort-canonicalised payload →
  assert `wp_send_json_success` is called and tracking data is written.
- Test `handle_build_callback()` with a tampered `sig` → assert "Invalid signature" response.
- Test `handle_build_callback()` with a missing `sig` → assert "Invalid signature" response.
- Test `handle_generate_locked_config()` → assert output JSON contains `build_id`,
  `integrity_url`, and `tracking_mode`.

**Bug C unit tests:**
- Test `handle_generate_locked_config()` with local mode selected → assert output JSON
  contains `tracking_mode: "local"` (not `"testing"`).
- Test `handle_generate_client_build()` with local mode selected → assert output JSON
  contains `tracking_mode: "local"` (not `"testing"`).
- Test `maybe_trigger_callback()` with `$config['tracking_mode'] = 'local'` → assert
  `wp_remote_post` is called with `sslverify => false`.
- Test `maybe_trigger_callback()` with `$config['tracking_mode'] = 'production'` → assert
  `wp_remote_post` is called with `sslverify => true` (or key absent, defaulting to true).
- Test `maybe_trigger_callback()` with `$config['tracking_mode'] = 'custom'` → assert
  `wp_remote_post` is called with `sslverify => true`.
- Test `maybe_trigger_callback()` with legacy `$config['tracking_mode'] = 'testing'` → assert
  `wp_remote_post` is called with `sslverify => true` (backward compatibility).
- Test `maybe_trigger_callback()` with `$config['tracking_mode']` absent (null coalesce
  defaults to `'production'`) → assert `wp_remote_post` is called with `sslverify => true`.

### Property-Based Tests

- **HMAC Symmetry (Property 2)**: Generate random permutations of the standard payload key
  set. For each permutation, compute the client HMAC (ksort + json_encode) and the master
  HMAC (ksort + json_encode on the same values). Assert they are always equal. This property
  should hold for all 8! = 40,320 permutations of the 8 payload keys.

- **Canonical String Stability**: For any payload array, assert that
  `json_encode(ksorted_array)` produces the same string regardless of the order in which keys
  were inserted. Generate 1,000+ random insertion orders and assert string equality.

- **Tamper Detection Preservation (Property 3)**: Generate random payloads and random
  corruptions of the `sig` field. Assert that `handle_build_callback()` always rejects
  corrupted signatures, never accepting them.

### Integration Tests

- Deploy fixed plugin to local environment; place a regenerated locked-config (with `build_id`)
  on a client site; trigger a page load; assert the Build Tracking tab on the master shows
  data within 60 seconds.
- Verify that switching from a legacy config (no `build_id`) to a regenerated config causes
  the first successful ping to appear in the tracking table.
- Verify that a client site with a valid config does not send duplicate pings within the
  throttle window across multiple page loads.
