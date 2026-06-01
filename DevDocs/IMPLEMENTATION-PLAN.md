# Build Tracking — Gap Analysis & Implementation Plan

**Plugin:** VAPTSecurityFull-QWenCoder  
**Date:** 2026-05-25  
**Analyst:** Cascade AI

---

## How to Use This Document

1. Read the **Gap Analysis** section to understand what the current codebase is missing or doing incorrectly.
2. Review the **Proposed Implementation Plan** to see the recommended fix order.
3. Each phase is designed to be implemented independently — you can stop after any phase and the system will still function.

---

## Gap Analysis

### Critical Gaps

#### 1. `ensure_release_dirs()` Migration Silently Breaks Client Sites

**What it does:** On `plugins_loaded`, `ensure_release_dirs()` migrates any `vapt-*-locked-config.php` files from the **plugin root** into `releases/configurations/`.

**Why it breaks:**
- `enforce_domain_lock()`, `has_locked_config()`, and `get_locked_config_data()` all search **only the plugin root** for locked config files.
- On a client site, the first page load migrates the config file out of the root.
- On the next page load, the plugin cannot find the config file in the root and `init()` returns early — **the plugin self-destructs**.

**Where in code:**
- Migration logic: `vapt-security.php` — `ensure_release_dirs()` (around line 1380–1440)
- Config lookup: `enforce_domain_lock()`, `has_locked_config()`, `get_locked_config_data()` (around line 2509–2600)

**Status:** Not mentioned anywhere in `BUILD-TRACKING-PLAN.md`.

---

#### 2. Per-Row "Test Callback" Button Is Claimed but Does Not Exist

**What the plan claims:**
> "Per-row test button on every zip build in the Build History table (🔵 network icon)"

**Reality:**
- The button is **nowhere in the codebase**.
- Not in the initial Build History table template (`admin-domain-control.php`).
- Not in the AJAX-refreshed table output (`handle_get_history_table()` in `vapt-security.php`).
- Not in any JavaScript.
- The only test callback UI elements that exist are:
  - The **master diagnostic notice** (`#vapt-diag-ping-btn`) which tests the master's own callback URL, not a specific build.
  - The **client diagnostic notice** (`#vapt-callback-diag`) which appears on client sites when `callback_test` is enabled.

**Status:** Plan claims this is implemented; it is not.

---

#### 3. `handle_get_history_table()` Missing Tracking Attributes on Edit Button

**What happens:**
- In the **initial PHP-rendered** Build History table (`admin-domain-control.php` lines ~856–858), the `.vapt-edit-build` button has:
  - `data-tracking-mode`
  - `data-custom-url`
- In the **AJAX-refreshed** table (`handle_get_history_table()` in `vapt-security.php` lines ~2453–2467), these two attributes are **omitted**.

**Impact:** After clicking "Refresh" or any action that triggers a table reload, the Edit/Reuse button loses the tracking mode and custom URL values. When you click Edit, the form doesn't restore those fields correctly.

**Status:** Not mentioned in the plan.

---

### Medium Gaps

#### 4. Version Inconsistency (SVP Framework Violation)

| Source | Version |
|--------|---------|
| `vapt-security.php` plugin header | `3.3.0` |
| `package.json` | `3.3.0` |
| `README.txt` Stable tag | **`3.2.0`** |

The WordPress.org plugin repository (and the SVP framework) requires the `Stable tag` in `README.txt` to match the actual plugin version. Currently it is one minor version behind.

**Status:** Not mentioned in the plan.

---

#### 5. `VAPT_VERSION` Constant Is Not White-Labeled in ZIP Builds

**What happens:**
- `setup_constants()` hardcodes: `define( 'VAPT_VERSION', '3.3.0' );`
- When a client build is generated with a white-label version (e.g., `1.0.1`), the ZIP file contents are correctly updated:
  - Plugin header comment gets `Version: 1.0.1`
  - `README.txt` gets `Stable tag: 1.0.1`
- **But the runtime constant `VAPT_VERSION` remains `3.3.0`**.

**Impact:**
- Client heartbeat callbacks send `version => 3.3.0` instead of the white-label version.
- The Build Tracking tab shows the wrong version for custom-branded builds.

**Status:** Not mentioned in the plan.

---

#### 6. Build Tracking Tab UI Doesn't Refresh After Remote Actions

**What happens:**
- Pushing `EXTEND_LICENSE` or `SUSPEND` from the Remote Management Modal shows a success toast.
- However, the Build Tracking table retains stale data (old expiry date, old status) until the user manually reloads the page.

**Status:** Not mentioned in the plan.

---

### Plan Claims vs Reality

| Plan Claim | Reality |
|---|---|
| "Per-row test button on every zip build" | **Missing entirely** |
| "Test Callback button on Older Builds — Fixed" | PHP fallback in `handle_force_ping()` exists, but **no UI button exists** to trigger it on older builds |
| "Three Legacy Config Files Still Not Regenerated" | Correct — confirmed `vapt-locked-config.php`, `vapt-vaptsecure-locked-config.php`, `vapt-hermasnet.com-locked-config.php` all missing `build_id`, `integrity_url`, `tracking_mode` |

---

## Proposed Implementation Plan

### Phase 1: Fix Critical Breaking Bug

**Goal:** Prevent client sites from self-destructing after the first page load.

**Tasks:**
1. **Update config file discovery functions** (`enforce_domain_lock()`, `has_locked_config()`, `get_locked_config_data()`) to search **both**:
   - Plugin root (for backward compatibility with legacy installs)
   - `releases/configurations/` (for new installs after migration)
   - Always pick the **newest file by modification time**.
2. **Harden `ensure_release_dirs()`** so it:
   - Only migrates files that haven't already been migrated.
   - Adds a flag/check so it doesn't race-condition with `enforce_domain_lock()`.
   - Skips migration if running on a client site (non-master) where the plugin is already locked to a domain.

**Rationale:** Without this fix, any client build installed on a live site will stop working after one page load. This is a production blocker.

---

### Phase 2: Add Missing UI & Fix Data Consistency

**Goal:** Implement the per-row Test Callback button and restore missing Edit/Reuse attributes.

**Tasks:**
3. **Add per-row "Test Callback" button** to:
   - Initial Build History table template (`templates/admin-domain-control.php`)
   - AJAX-refreshed table output (`handle_get_history_table()` in `vapt-security.php`)
   - Button should:
     - Only appear for `zip` type builds.
     - Use the 🔵 `dashicons-networking` icon.
     - Pass `build_id`, `integrity_url`, and `tracking_mode` to the `vapt_force_ping` AJAX handler.
     - Include the inline result row (green/yellow/red with HTTP status, URL, SSL state, raw response) just like the master diagnostic notice.
4. **Fix `handle_get_history_table()`** to include `data-tracking-mode` and `data-custom-url` on the `.vapt-edit-build` button, matching the initial template.

**Rationale:** The plan explicitly documents this feature. It is essential for verifying that deployed client builds can reach the master.

---

### Phase 3: Version & Polish

**Goal:** Align version numbers and improve white-label accuracy.

**Tasks:**
5. **Bump `README.txt` Stable tag** from `3.2.0` → `3.3.0`.
6. **(Optional but recommended)** White-label the `VAPT_VERSION` constant in ZIP builds:
   - During `handle_generate_client_zip()`, after white-labeling the plugin header, also perform a string replacement inside `vapt-security.php` content so that `define( 'VAPT_VERSION', '3.3.0' )` becomes `define( 'VAPT_VERSION', '{$wl_version}' )`.
   - This ensures client callbacks report the correct build version.

**Rationale:** Version consistency is required for the SVP framework and for accurate build tracking.

---

### Phase 4: Legacy Config Cleanup

**Goal:** Remove stale configuration files that cannot participate in the tracking system.

**Tasks:**
7. **Delete or archive** the 3 legacy config files from `releases/configurations/`:
   - `vapt-locked-config.php`
   - `vapt-vaptsecure-locked-config.php`
   - `vapt-hermasnet.com-locked-config.php`
   - **Before deleting**, confirm each domain has a newer, properly-generated config with `build_id`, `integrity_url`, and `tracking_mode`.
   - Or regenerate them via Build Generator → Generate Config File with correct domain/white-label settings (as the plan suggests).

**Rationale:** These configs lack tracking metadata and will never send heartbeats. They clutter the configurations directory and confuse diagnostics.

---

### Optional Enhancement: Real-Time Tracking Tab Refresh

**Goal:** Improve UX when managing builds remotely.

**Tasks:**
8. After a successful `vapt_push_remote_command` AJAX call, trigger a partial refresh of the Build Tracking tab table (or at least update the specific row's expiry date / status badge via JavaScript) without requiring a full page reload.

**Rationale:** Not critical, but significantly improves the admin UX when extending licenses or suspending builds.

---

## Decision Checklist

Use this checklist before starting implementation:

- [ ] **Phase 1** — Do you want to fix the client site self-destruction bug first? (Strongly recommended)
- [ ] **Phase 2** — Do you want the per-row Test Callback button implemented?
- [ ] **Phase 3** — Do you want version alignment and white-label constant fixes?
- [ ] **Phase 4** — Should I regenerate or delete the 3 legacy config files?
- [ ] **Optional** — Should I add real-time tracking tab refresh after remote actions?

---

## Files That Will Be Modified

| File | Phases | Nature of Change |
|------|--------|------------------|
| `vapt-security.php` | 1, 2, 3, 4 | PHP logic for config discovery, table rendering, ZIP generation |
| `templates/admin-domain-control.php` | 2, Optional | HTML/JS for per-row button, modal refresh |
| `README.txt` | 3 | Version bump |
| `releases/configurations/*` | 4 | Legacy file cleanup |
