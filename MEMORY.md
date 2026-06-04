# MEMORY — VAPTSecurityFull-QWenCoder

## Repo
- Path: `VAPTSecurityFull-QWenCoder/`
- Type: WordPress plugin
- Primary entrypoint: `vapt-security.php`

## Observed Version
- `vapt-security.php` header: **3.4.4**
- `package.json` version: **3.4.4**

## High-level Architecture (from `ARCHITECTURE.md`)
- Layer 1: WP-Cron Protection (DoS targeting `wp-cron.php`)
- Layer 2: General Rate Limiting (IP-based, 429 responses)
- Layer 3: Input Validation (schema-based sanitization; optional strictness)
- Layer 4: Security Logging (event logging + retention/cleanup)

## Domain-Locked Config / Build System
- AJAX endpoints generate:
  - Locked config PHP in `releases/configurations/`
  - Client ZIP builds via `.buildincl` allowlist
- Master/Client check-in:
  - Client sends payload to master via `vapt_build_callback`
  - Master verifies integrity/signature (HMAC) and returns commands

## Key Files Already Read
- `package.json`
- `vapt-security.php`
- `VERSION_HISTORY.md`
- `ARCHITECTURE.md`

## Notes / Constraints
- Search tooling may fail due to missing ripgrep (`rg`) binary.
  - Use targeted `list_files` + `read_file` instead of global regex search.

## Persistent Requirements (Product)
- Installation and Activation timestamps must be tied to the unique Build ID on the client site (not just domain).
- Expiry must be computed from Activation time (client activation), not from build generation time.
- Dates shown in the Master UI must respect WordPress Settings (timezone + date_format + time_format), avoid browser locale formatting.

