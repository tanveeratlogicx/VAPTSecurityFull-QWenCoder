# BUILD-TRACKING-PLAN.md — Implementation Review & Gap Analysis

**Plugin:** VAPT Security - Full
**Plan file:** DevDocs/BUILD-TRACKING-PLAN.md
**Review date:** 2026-05-23

---

## Executive Summary

The build tracking & callback system is **largely implemented** across the plugin.
The two-way heartbeat, tiered license-expiry notices, Build Tracking UI tab,
locked-config generation, and remote commands are all present in working code.
However, there are **8 concrete defects**, plus a **root-cause chain-of-failure**
that explains why the Build Tracking tab is empty on both production and local.

---

## §1 — Core Logic & Configuration

### 1.1 Version Bump to 3.2.1 — [!WARN] Partially Done

| Location | Current | Target | Status |
|---|---|---|---|
| Plugin header (line 6) | 3.2.0 | 3.2.1 **[FAIL]** | |
| VAPT_VERSION const (line 124) | 3.2.1 | 3.2.1 **[OK]** | |
| package.json | 3.2.0 | 3.2.1 **[FAIL]** | |
| VERSION_HISTORY.md | missing | exists **[FAIL]** | |

### 1.2 VAPT_INTEGRITY_URL Constant — [OK] Done
Lines 127–128. Guarded with `!defined()`. No issues.

### 1.3 AJAX Callback Endpoints — [OK] Done
Lines 222–224. nopriv + priv + push remote command. No issues.

### 1.4 build_id + integrity_url in All Build Payloads — [OK] Done
Both generator and zip builder serialise them (§1665 / §1802).

---

## §2 — Remote Management & Command System

### 2.1 Two-Way Heartbeat — [OK] Done
`maybe_trigger_callback()` line 2791 throttles to 12 h; Master responses
handled by `handle_build_callback()` line 2718 + `process_remote_commands()` line 2884.

`first_activation` is immutable on Master (written only on record creation, line 2725).

### 2.2 Tiered Expiry Notices — [OK] Logic Correct
`display_license_expiry_notices()` line 2911.

| License Type | Level | Threshold | Class | Headline |
|---|---|---|---|---|
| Standard/Pro | L1 | <= 20 days | notice-info | "Friendly Reminder" |
| Standard/Pro | L2 | <= 10 days | notice-warning | "Attention" |
| Standard/Pro | L3 | <= 5 days  | notice-error | "URGENT" |
| Demo | L1 | <= 10 days | notice-warning | "Trial Ending Soon" |
| Demo | L2 | <= 3 days  | notice-error | "Final Notice" |
| Trial | L1 | <= 3 days  | notice-error | "Immediate Action" |

### 2.3 Multi-Channel Delivery — [!WARN] Notices [OK] / Email [!WARN]
- **Admin notices:** native WP notice classes — [OK].
- **HTML emails:** `send_license_notification_email()` line 2966 generates inline-styled HTML.
  - [!WARN] Recipient: uses `get_option('admin_email')` vs `tanmalik786@gmail.com` per plan (line 2967).
  - [!WARN] Brand colour: plan says Calm/Blue; code uses green `#00a32a`.

### 2.4 Authoritative first_activation — [!WARN] Partial
Correctly locked on Master. On the client, `vapt_initial_install_time` is a local option
not validated against a Master-authoritative grant date.

### 2.5 Custom Term Remote Action — **[FAIL] MISSING**
Remote Management modal line 874 has Add Full Term, +30 Days, +90 Days, and Suspend —
no expiry-date picker, no `EXTEND_CUSTOM` handler, no command path anywhere.

---

## §3 — UI Implementation

### 3.1 Build Tracking Tab — [OK] Done
Lines 410–414 of admin-domain-control.php.

### 3.2 Tracking Table — [OK] Done (lines 799–865)
All 7 plan columns present. Status computed at line 818:
`time() - $t['last_seen'] < 24 * HOUR_IN_SECONDS`.

### 3.3 Remote Actions — [!WARN] Extend [OK] / Suspend [OK] / Custom Term **[FAIL]**
See §2.5.

### 3.4 Email on First Activation — [OK] Done
Lines 2776–2786; hardcoded to `tanmalik786@gmail.com`.

---

## §4 — Security & Optimization

### 4.1 HMAC on All Callback Payloads — **[FAIL] Partial**
Config-file HMAC present (generation lines 1704/1837, verification line 2521).
Salt: `VAPT_LOCKED_CONFIG_INTEGRITY_SALT_v2`.
**[FAIL]** Client-to-Master ping payload (line 2828) carries no `sig` field.
Master does not verify caller identity before trusting data.

### 4.2 Async / Non-Blocking Pings — **[FAIL] blocking: true**
Line 2842: `'blocking' => true` — must be `false` per plan.

---

## §5 — Deployment & Testing — **[FAIL] Undocumented**
No automated tests or step-by-step guidance for the command loop or 5-day expiry notice.

---

## Summary Matrix

| § | Plan Item | Status |
|---|---|---|
| 1.1 | Bump all version files to 3.2.1 | [!WARN] Header [FAIL] / pkg.json [FAIL] / history [FAIL] |
| 1.2 | VAPT_INTEGRITY_URL | [OK] |
| 1.3 | AJAX callback endpoints | [OK] |
| 1.4 | build_id + integrity_url in payloads | [OK] |
| 2.1 | Two-way heartbeat | [OK] |
| 2.2 | Tiered expiry notices | [OK] |
| 2.3 | Notices + branded HTML emails | [!WARN] recipient wrong |
| 2.4 | Authoritative first_activation lock | [!WARN] partial |
| 2.5 | Custom Term remote action | **[FAIL] Missing** |
| 3.1 | Build Tracking tab | [OK] |
| 3.2 | Tracking table | [OK] |
| 3.3 | Remote actions Extend/Custom/Suspend | [!WARN] Custom Term absent |
| 3.4 | Email on first activation | [OK] |
| 4.1 | HMAC on all callback payloads | **[FAIL] Ping payload unsigned** |
| 4.2 | Non-blocking pings | **[FAIL] blocking: true** |
| 5 | Deployment & testing | **[FAIL] Undocumented** |


---

## §6 — CONFIRMED ROOT CAUSE: Build Tracking Tab Is Empty

### Environment Audit

| WordPress Instance        | Active Plugin              | Plugin Ver | Has Tracking? | Build Tracking Tab? |
|--------------------------|---------------------------|------------|---------------|---------------------|
| `vaptsecure` (prod master) | `VAPT-Secure/vaptsecure.php` | **2.11.0** | ❌ **NO**       | ❌ **NO**             |
| `VAPTSecurity-Full` (dev) | `vapt-security.php`         | **3.2.1**  | ✅ **YES**      | ✅ **YES**             |

### Critical Finding: Different Plugin Installed on Production

The production WordPress (`T:\~\Local925 Sites\vaptsecure\app\public\`) does NOT run
`VAPTSecurity-Full/vapt-security.php`. Its active plugin is
`VAPT-Secure/vaptsecure.php` **version 2.11.0** — a completely different codebase.

Version 2.11.0 has **no tracking system at all**:
- No `vapt_build_tracking` option
- No `vapt_build_history` option
- No `handle_build_callback()` function
- No `maybe_trigger_callback()` function
- No "Build Tracking" tab
- No `VAPT_INTEGRITY_URL` constant
- No heartbeat mechanism

### Chain-of-Failure

```
Client page loads
  → enforce_domain_lock() — passes (Universal Wildcard match) ✓
  → maybe_trigger_callback() fires on every page load
    → get_locked_config_data() — reads locked config ✓
    → get_option('vapt_build_tracking', []) — empty on Master (v2.11.0 has nothing)
    → build_id field is MISSING from locked config (pre-tracking config)
    → wp_remote_post(integrity_url, blocking=true, timeout=15s)
      → POST to https://vaptsecure.net/vapts → 404 (v2.11.0 has no handler)
      → is_wp_error() = true; only error_log(); silent return
    → table never populated → stays empty forever
```

### Legacy Locked Configs Pre-Date Tracking Fields

Three of four locked-config files were generated **before** tracking fields were
added to the generator payload. They are structurally incomplete:

| Locked Config              | Has `build_id`? | Has `integrity_url`? | Has `license`? | Generated |
|----------------------------|-----------------|---------------------|----------------|-----------|
| `vapt-vaptsecure-locked-config.php` | ❌ | ❌ | ❌ | May 20, 2026 |
| `vapt-wptest-locked-config.php`     | ❌ | ❌ | ❌ | May 22, 2026 |
| `vapt-hermasnet.com-locked-config.php` | ✅ BH260525-xxxx | ✅ | ✅ demo | May 22, 2026 |
| `vapt-locked-config.php`           | ❌ | ❌ | ❌ | May 22, 2026 |

`hermasnet.com` is the **only** build with tracking-capable metadata.

### Required Fixes

| Priority | Fix | File(s) |
|---|---|---|
| 🔴 Critical | Deploy **VAPTSecurity-Full v3.2.1** to production WordPress (`vaptsecure`) | Both envs |
| 🔴 Critical | Change `blocking: true` → `false` in `maybe_trigger_callback()` (~line 2842) | vapt-security.php |
| 🔴 Critical | Add HMAC `sig` to client→Master ping payload + `hash_equals()` verify in `handle_build_callback()` | vapt-security.php |
| 🟠 High | Re-generate ALL locked-configs via Build Generator (do not hand-edit PHP files) | all clients |
| 🟠 High | Fix `send_license_notification_email()` recipient → `tanmalik786@gmail.com` (line 2967) | vapt-security.php |
| 🟡 Medium | Add Custom Term (expiry date picker) to Remote Management modal | admin-domain-control.php / vapt-security.php |
| 🟡 Medium | Add rollback-safe `first_activation` check on the client | vapt-security.php |
| 🟢 Low | Bump plugin header + `package.json` to `3.2.1` and create `VERSION_HISTORY.md` | root |

### Production Must Deploy v3.2.1 First

**Before any locked-config is re-generated, the production WordPress must be running
`VAPTSecurity-Full/vapt-security.php`. Using v2.11.0 on production means the build
tracking table will never receive any callbacks regardless of config quality.**
