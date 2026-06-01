# Build Tracking & Callback System — Status Plan

**Plugin:** VAPTSecurityFull-QWenCoder  
**Current Version:** 3.3.0  
**Date:** 2026-05-25

---

## What We Have Achieved

### Core Infrastructure
- **Domain-locked config system** — generator produces `vapt-{domain}-locked-config.php` with `build_id`, `integrity_url`, `tracking_mode`, HMAC signature, license, and white-label metadata baked in.
- **Build Generator UI** — Build Generator tab with two actions: Generate Config File (server-side only) and Generate Client Build (zip).
- **`.buildincl` allowlist** — explicit file allowlist controls exactly what goes into client zips. No more accidental inclusion of dev docs, test files, or zip archives.
- **Build History table** — tracks every generated build with ID, domain, type, version, license, dates, and actions (download, edit/reuse, export, suspend/resume, purge).
- **Releases directory structure** — `releases/builds/` for zips, `releases/configurations/` for config files, `releases/logs/` for exported records.

### Callback / Heartbeat System
- **Client-side heartbeat** (`maybe_trigger_callback`) — fires on every page load, throttled to 60 s (local) or 12 h (production). Sends `build_id`, domain, license state, version, and initial install time to the master.
- **HMAC signing** — payload is `ksort`-ed before signing with `hash_hmac('sha256', json_encode($payload), $salt)`. Master verifies with `hash_equals()` before processing.
- **Master-side receiver** (`handle_build_callback`) — records `last_seen`, domain, IP, license, version, and history per `build_id`. Returns pending remote commands.
- **Remote commands** — master can push `EXTEND_LICENSE`, `SUSPEND` commands to client on next heartbeat.
- **First activation notification** — email sent to superadmin on first ping from a new build.
- **Blocking HTTP** — changed from `blocking: false` (silent failure on single-server local) to `blocking: true` with response parsing.

### Test Callback Button
- **Per-row test button** on every zip build in the Build History table (🔵 network icon).
- Fires `vapt_force_ping` AJAX with `build_id`, `integrity_url`, `tracking_mode` from the history record.
- Falls back to `VAPT_INTEGRITY_URL` (production) when `integrity_url` is empty (older builds).
- Inline result row expands below the build row: ✓ green / ⚠ yellow / ✗ red with HTTP status, URL, SSL state, and raw response body.
- On success, throttle is cleared so the next natural heartbeat fires immediately.

### Build Generation UX
- **Loading overlay** — full-screen spinner during zip generation.
- **Duplicate filename prompt** — modal asks Overwrite vs Save as New (timestamp-suffixed) when a same-named build exists.
- **Accurate success/error messages** — no more false "Build Generation Failed" toasts.

---

## What Is Still Outstanding / Being Worked On

### 1. Callback Not Reaching Master (Priority)
**Status:** Partially fixed — `blocking: true` applied, HMAC signing corrected.  
**Remaining:** Need to verify end-to-end on the actual client site (wptest) after deploying the regenerated config. The `vapt-vapttest-wptest-v1.0.1.zip` build uses `tracking_mode: local` pointing to `http://vaptsecure.local/wp-admin/admin-ajax.php`. Once installed on the wptest site, the Test Callback button on the master should confirm the round-trip works.

**To verify:**
1. Install `vapt-vapttest-wptest-v1.0.1.zip` on the wptest client site
2. Click Test Callback on the master against that build — expect ✓ green
3. Check Build Tracking tab — expect wptest to appear as ONLINE

### 2. Three Legacy Config Files Still Not Regenerated
**Status:** Outstanding (Task 3.6 from execution report).  
`vapt-locked-config.php`, `vapt-vaptsecure-locked-config.php`, `vapt-hermasnet.com-locked-config.php` are all missing `build_id`, `integrity_url`, `tracking_mode`. Those client sites will never send a heartbeat until their configs are regenerated.

**To do:** Regenerate each via Build Generator → Generate Config File with correct domain/white-label settings.

### 3. Test Callback Button on Older Builds
**Status:** Fixed in this session.  
Older builds (pre-3.3.0) had empty `integrity_url` in history. PHP handler now falls back to `VAPT_INTEGRITY_URL` when `integrity_url` is empty, so the button works on all zip builds.

### 4. Build Tracking Tab — Live Data
**Status:** UI exists, data depends on heartbeats arriving.  
Once callbacks are confirmed working (item 1 above), the tracking table will populate with real ONLINE/OFFLINE status, last seen times, and license info per build.

### 5. Remote Command Delivery Verification
**Status:** Code exists, untested end-to-end.  
The `EXTEND_LICENSE` and `SUSPEND` commands are queued on the master and returned on the next heartbeat. Need a live round-trip to confirm the client processes them correctly.

---

## Architecture Summary

```
Master Site (vaptsecure.local)
│
├── Build Generator Tab
│   ├── Generate Config File  →  releases/configurations/vapt-{domain}-locked-config.php
│   └── Generate Client Build →  releases/builds/vapt-{slug}-{domain}-{version}.zip
│                                 └── contains: vapt-security.php (white-labelled)
│                                              + vapt-{domain}-locked-config.php
│                                              + includes/, assets/, templates/, vendor/
│
├── Build History Table
│   └── Per-row: Download | Edit | Export | Test Callback | Suspend | Purge
│
└── Build Tracking Tab
    └── Per build_id: domain, IP, status, last seen, license, version

Client Site (e.g. wptest)
│
└── vapt-security.php (white-labelled)
    └── on every page load → maybe_trigger_callback()
        ├── throttle check (60s local / 12h production)
        ├── read locked config → build_id, integrity_url, tracking_mode
        ├── build + sign payload (ksort + HMAC)
        └── wp_remote_post(integrity_url) → master's handle_build_callback()
            └── master records last_seen, returns pending commands
```

---

## Version History of This Work

| Version | Key Changes |
|---------|-------------|
| 3.2.1 | HMAC signing added, non-blocking ping (later reverted) |
| 3.3.0 | Blocking ping, `.buildincl`, Test Callback button, duplicate prompt, loading overlay, parse error fix |
