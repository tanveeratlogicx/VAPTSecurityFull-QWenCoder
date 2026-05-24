# VAPT Implementation Plan

**Source Document:** Ankai_WebApp (VAPT Draft 1.0) 24_April_2026_Edgex.xlsx/csv  
**Target:** VAPTSecurity-Full Plugin (v2.7.1)  
**Date:** 2026-05-20  
**Author:** Cascade AI (pair programming with Tanveer Malik)

---

## Executive Summary

The VAPT assessment identified **14 vulnerabilities** across the WordPress application at `http://172.25.7.4`. As of version **3.0.0**, **13 out of 14 risks are fully mitigated** within the plugin. V#9 (Outdated Plugins) was intentionally skipped as per project requirements (operational task, not code-based).

---

## Status Matrix

| V# | Vulnerability Name | Rating | Status | Action |
|----|-------------------|--------|--------|--------|
| 1 | Lack of Rate Limiting on WordPress Login | High | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 2 | WordPress Cron Job Vulnerability (DoS) | High | :white_check_mark: Implemented | Native feature |
| 3 | XML-RPC Leads to Unauthenticated Blind SSRF | High | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 4 | Directory Listing Vulnerability | Medium | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 5 | Lack of Rate Limiting on Contact Form | Medium | :white_check_mark: Implemented | Native feature |
| 6 | Banner Grabbing Vulnerability | Medium | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 7 | Username Enumeration via WordPress REST API | Medium | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 8 | Username Enumeration via wp-login.php | Medium | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 9 | Outdated and Vulnerable WordPress Plugins | Medium | :fast_forward: Skipped | Out of scope |
| 10 | Unauthenticated Exposure of WordPress REST API Endpoints | Medium | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 11 | Clickjacking | Low | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 12 | Public Exposure of Debug Log File | Low | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 13 | Information Disclosure via readme.html | Low | :white_check_mark: Implemented | Fixed in v3.0.0 |
| 14 | No Input Validation | Low | :white_check_mark: Implemented | Native feature |

---

## Architecture Decision

All new protections will be consolidated into a single new class:

**File:** `includes/class-hardening.php` (Class: `VAPT_Hardening`)

This keeps the existing codebase stable while adding all 11 new protections in one well-organized module. Each sub-feature is independently togglable via the existing options system.

New feature slugs for `class-features.php`:
- `login_protection`
- `xmlrpc_protection`
- `security_headers`
- `rest_api_protection`
- `info_disclosure_protection`

---

## Phase 1: HIGH Priority (COMPLETED)

### V#1 — Lack of Rate Limiting on WordPress Login

**VAPT Finding:**
> The WordPress login page (/wp-login.php) lacks rate limiting, allowing attackers to perform brute-force attacks to guess credentials without facing restrictions.

**Implementation:**
- Hook: `wp_authenticate` (pre-auth check) and `wp_login_failed` (track failures)
- Reuse existing `VAPT_Rate_Limiter` class with login-specific window (e.g., 5 attempts per 15 minutes)
- After threshold: block IP temporarily (lockout period configurable)
- Add admin setting: "Max Login Attempts", "Login Lockout Duration (minutes)"
- Log all blocked attempts via `VAPT_Security_Logger`

**Evidence/Verification:**
- Attempt login 6+ times with wrong password → get 429/blocked response
- Check Security Logs tab → see `blocked_login_attempt` entries

---

### V#2 — WordPress Cron Job Vulnerability (DoS) :white_check_mark: ALREADY IMPLEMENTED

**Current Implementation:**
- `vapt-security.php` lines 189-227: `protect_wp_cron()` method
- `class-rate-limiter.php` lines 76-109: `allow_cron_request()` method
- Configurable max requests per hour (default: 60)
- IP blocking for violators
- Whitelisted IPs bypass
- Security logging of blocked requests

**Evidence/Verification:**
- Visit `/wp-cron.php` repeatedly → after limit reached, get 429 response
- Check Security Logs → `blocked_cron_request` events recorded

---

### V#3 — XML-RPC Leads to Unauthenticated Blind SSRF

**VAPT Finding:**
> Using a simple POST request to the xmlrpc.php endpoint, I was able to bypass input validation and send a request to an external URL.

**Implementation:**
- Add filter: `add_filter('xmlrpc_enabled', '__return_false')`
- Remove `X-Pingback` header: `remove_action('wp_head', 'rsd_link')`
- Block direct access to `xmlrpc.php` via `template_redirect` or early init check
- Return 403 with message: "XML-RPC is disabled for security reasons."
- Add admin setting toggle: "Disable XML-RPC"

**Evidence/Verification:**
- POST to `/xmlrpc.php` → get 403 response
- Check response headers → no `X-Pingback` header present
- `system.listMethods` call returns error/forbidden

---

## Phase 2: MEDIUM Priority (COMPLETED)

### V#4 — Directory Listing Vulnerability

**VAPT Finding:**
> Directory listing is enabled for the /wp-content/uploads/ directory.

**Implementation:**
- On plugin activation: create `index.php` (with `<?php // Silence is golden.`) in:
  - `wp-content/uploads/`
  - `wp-content/plugins/`
  - `wp-content/themes/`
- Generate `.htaccess` rule: `Options -Indexes` in `wp-content/` if Apache detected
- Add Nginx guidance in admin notice

**Evidence/Verification:**
- Browse to `/wp-content/uploads/` → see blank page or 403, NOT file listing

---

### V#5 — Lack of Rate Limiting on Contact Form :white_check_mark: ALREADY IMPLEMENTED

**Current Implementation:**
- `vapt-security.php` lines 805-828: Rate limiting in `handle_form_submission()`
- `class-rate-limiter.php` lines 42-71: `allow_request()` with configurable window
- IP blocking after 5+ violations
- Third-party form integrations (CF7, Elementor, WPForms, Gravity Forms) in `class-integrations-manager.php`

**Evidence/Verification:**
- Submit form rapidly (10+ times per minute) → get 429 "Too many requests"
- Check Security Logs → `blocked_form_submission` events

---

### V#6 — Banner Grabbing Vulnerability

**VAPT Finding:**
> Banner grabbing reveals the server's software versions and other information.

**Implementation:**
- `header_remove('X-Powered-By')` on `send_headers` action
- `remove_action('wp_head', 'wp_generator')` — removes WP version from HTML
- `add_filter('the_generator', '__return_empty_string')` — removes from RSS/Atom
- Remove version from script/style enqueue: filter `style_loader_src` and `script_loader_src`
- Add admin setting toggle: "Hide Version Information"

**Evidence/Verification:**
- Check response headers → no `X-Powered-By`, no `Server` version leak from PHP
- View page source → no `<meta name="generator" content="WordPress X.X">` tag
- Check RSS feed → no version info

---

### V#7 — Username Enumeration via WordPress REST API

**VAPT Finding:**
> The WordPress REST API may allow attackers to enumerate usernames by checking for the existence of specific usernames.

**Implementation:**
- Filter `rest_authentication_errors` to block unauthenticated access to `/wp/v2/users`
- Return `WP_Error('rest_forbidden', 'Authentication required.', ['status' => 401])`
- Add admin setting toggle: "Restrict User REST API"

**Evidence/Verification:**
- GET `/wp-json/wp/v2/users` while logged out → 401 Unauthorized
- GET `/wp-json/wp/v2/users` while logged in as admin → works normally

---

### V#8 — Username Enumeration via wp-login.php

**VAPT Finding:**
> The wp-login.php page may reveal information about usernames upon failed login attempts.

**Implementation:**
- Filter `login_errors` to return generic message: "Invalid username or password."
- Filter `shake_error_codes` to normalize behavior
- This prevents disclosure of whether a username exists

**Evidence/Verification:**
- Attempt login with non-existent username → "Invalid username or password."
- Attempt login with valid username but wrong password → same message
- Both scenarios produce identical response (no differentiation)

---

### V#9 — Outdated and Vulnerable WordPress Plugins

**VAPT Finding:**
> The application is using outdated versions of WordPress plugins (WPBakery v8.6.1, Slider Revolution) with publicly known vulnerabilities.

**Implementation:**
- Add admin dashboard widget: "Plugin Security Status"
- Check `get_plugin_updates()` for available updates
- Flag plugins not updated in 90+ days (based on `last_updated` from WP.org API)
- Display warnings with links to update
- Add weekly email digest option for outdated plugin alerts
- Note: Full CVE scanning is out of scope; this is an advisory/awareness feature

**Evidence/Verification:**
- Dashboard widget shows list of plugins needing updates
- Outdated plugins highlighted in red with "Update Now" links

---

### V#10 — Unauthenticated Exposure of WordPress REST API Endpoints

**VAPT Finding:**
> The application exposes internal endpoints through the WordPress REST API (/wp-json/wp/v2/pages/) without proper access restrictions.

**Implementation:**
- Filter `rest_authentication_errors` for sensitive endpoints:
  - `/wp/v2/users` (covered by V#7)
  - `/wp/v2/pages` — restrict to authenticated users
  - `/wp/v2/posts` — allow public (needed for themes) OR restrict
- Provide granular toggles per endpoint type
- Add admin setting: "REST API Access Level" (Public / Authenticated Only / Disabled)

**Evidence/Verification:**
- GET `/wp-json/wp/v2/pages` while logged out → 401 or limited response
- Sensitive paths like `/my-account/`, `/cart/`, `/checkout/` not discoverable

---

## Phase 3: LOW Priority (COMPLETED)

### V#11 — Clickjacking

**VAPT Finding:**
> The application is vulnerable to clickjacking. The remote web server does not set an X-Frame-Options response header.

**Implementation:**
- Hook `send_headers` action (early priority)
- Send headers:
  ```
  X-Frame-Options: SAMEORIGIN
  X-Content-Type-Options: nosniff
  X-XSS-Protection: 1; mode=block
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=(), camera=()
  ```
- Add admin setting toggle: "Enable Security Headers"

**Note:** The USER_GUIDE.md already documents this feature but the code was never written. This fixes that gap.

**Evidence/Verification:**
- Check response headers via browser DevTools or `curl -I` → all headers present
- Try embedding site in `<iframe>` from different domain → blocked

---

### V#12 — Public Exposure of Debug Log File

**VAPT Finding:**
> The application exposes a publicly accessible debug log file at /wp-content/debug.log.

**Implementation:**
- On `template_redirect`: if request is for `debug.log`, return 403
- Generate `.htaccess` rule blocking access to `*.log` files in `wp-content/`
- Add admin notice if `WP_DEBUG` and `WP_DEBUG_LOG` are both `true` in production
- Optionally: move debug log to a non-public location

**Evidence/Verification:**
- Browse to `/wp-content/debug.log` → 403 Forbidden
- `.htaccess` contains: `<Files "debug.log"> Require all denied </Files>`

---

### V#13 — Information Disclosure via readme.html

**VAPT Finding:**
> The presence of a readme.html file may disclose sensitive information.

**Implementation:**
- On `template_redirect`: if request is for `/readme.html`, return 403 or redirect to home
- On plugin activation: attempt to rename `readme.html` to `readme.html.bak` in ABSPATH
- Add admin notice recommending manual deletion

**Evidence/Verification:**
- Browse to `/readme.html` → 403 or redirect to homepage
- File no longer accessible to unauthenticated users

---

### V#14 — No Input Validation :white_check_mark: ALREADY IMPLEMENTED

**Current Implementation:**
- `class-input-validator.php`: Full schema-based validation with 3 sanitization levels
- `prevent_xss()` method: Strips scripts, event handlers, javascript: URLs
- `check_security_violations()`: Detects and blocks XSS/injection patterns
- `sanitize_value_by_level()`: Public helper for third-party integrations
- Integrated with CF7, Elementor Forms, WPForms, Gravity Forms

**Evidence/Verification:**
- Submit `<script>alert('xss')</script>` in any form → stripped/blocked
- Submit SQL injection payload `' OR 1=1 --` → sanitized
- Check logs → `validation_error` events recorded

---

## Implementation Order

1. Create `includes/class-hardening.php` with all protections
2. Wire into `vapt-security.php` init
3. Add admin settings fields/toggles for new features
4. Update `class-features.php` with new feature slugs
5. Update `USER_GUIDE.md` with all 14 risk verifications
6. Test each protection and document evidence
7. Bump version to 3.0.0

---

## Files to be Modified/Created

| File | Action |
|------|--------|
| `includes/class-hardening.php` | **CREATE** — Main hardening module |
| `vapt-security.php` | MODIFY — Wire hardening class, add settings fields |
| `includes/class-features.php` | MODIFY — Add new feature slugs |
| `includes/class-rate-limiter.php` | MODIFY — Add login-specific rate limiting methods |
| `templates/admin-settings.php` | MODIFY — Add new settings tabs/sections |
| `USER_GUIDE.md` | MODIFY — Document all 14 protections |
| `CHANGELOG.md` | MODIFY — Document v3.0.0 changes |

---

## Final Status

**Plugin Version 3.0.0 is now fully implemented and ready for client delivery.**

All features are documented in the `USER_GUIDE.md` with verification steps, and toggles are available in the **Hardening** tab of the plugin settings.
