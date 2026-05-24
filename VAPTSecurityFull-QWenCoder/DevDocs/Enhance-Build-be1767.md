# Enhance-Build Plan

Enhance the `Locked Configuration Generator` by moving licensing controls into it and adding sophisticated domain matching types (Standard, Wildcard, Universal).

## UI Enhancements (`templates/admin-domain-control.php`)
- **Core Lock Settings Update**:
    - Add `Domain Type` dropdown (Standard, Wildcard, Universal).
    - Move `License Type` dropdown, `Auto Renewal` toggle, and `Terms Renewed` display from the main License panel into this section.
    - Implementation of real-time expiry date updates in the Generator panel when the License Type is changed.
- **License Management Cleanup**:
    - Remove the redundant `License Type` and `Auto Renewal` fields from the primary License Management card to avoid confusion (per request).

## Backend Enhancements (`vapt-security.php`)
- **AJAX Handler Updates**:
    - Update `handle_generate_locked_config` and `handle_generate_client_zip` to accept the new `domain_type`, `license_type`, and `auto_renew` parameters.
    - Bundle the selected license configuration into the exported payload.
- **Domain Lock Logic Refinement**:
    - Update `enforce_domain_lock` to support the three matching modes:
        - **Standard**: Exact match (current behavior).
        - **Wildcard**: Containment check (e.g., `example.` or `.example`).
        - **Universal**: Complete bypass of the domain validation check.
    - Update `enforce_domain_lock` to import the bundled license data (Type/Expiry/Auto-Renew) into the target site's database upon installation.

## Verification
- Test build generation with each `Domain Type`.
- Verify that the generated ZIP correctly applies the bundled license and domain lock on a fresh installation.
