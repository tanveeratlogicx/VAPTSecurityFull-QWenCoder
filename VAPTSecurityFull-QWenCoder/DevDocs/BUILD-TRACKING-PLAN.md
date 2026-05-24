# VAPT Build Tracking & Callback System Implementation Plan

This plan implements a discreet "Phone Home" tracking system that monitors build activations, license status, and versioning across client domains, sending data back to `https://vaptsecure.net/vapts` and displaying it in a new **Build Tracking** tab on your Domain Admin page.

## 1. Core Logic & Configuration (`vapt-security.php`)
- **Version Update**: Bump `VAPT_VERSION` to `3.2.1`.
- **Discreet Callback Constant**: Define `VAPT_INTEGRITY_URL` defaulting to `https://vaptsecure.net/vapts`.
- **AJAX Endpoint**: Implement `wp_ajax_nopriv_vapt_build_callback` to receive tracking data AND return remote commands (like license extensions).
- **Build Generation Update**: Injects `build_id` and `VAPT_INTEGRITY_URL` into all payloads.

## 2. Remote Management & Command System
- **Two-Way Heartbeat**:
    - **Client Site**: Sends status (Build ID, Domain, IP, Activation Date, Expiry).
    - **Master Server**: Returns "pending commands" (Extensions, Renewals, Suspensions).
- **Tiered Expiry Notification System (Urgency Sequence)**:
    - Implement a rule-based engine to trigger different levels of notices based on `License Type` and `Days Remaining`:
        - **Standard/Pro (30-365 days)**: 
            - *Level 1 (20 days out)*: "Friendly Reminder" (Blue/Info) - Suggests early renewal.
            - *Level 2 (10 days out)*: "Attention Required" (Yellow/Warning) - Mentions upcoming protection loss.
            - *Level 3 (5 days out)*: "Urgent Action Required" (Red/Error) - Strong urgency, direct link to renew.
        - **Demo (15 days)**: 
            - *Level 1 (10 days out)*: "Trial Ending Soon" (Yellow/Warning).
            - *Level 2 (3 days out)*: "Final Notice" (Red/Error).
        - **Trial (7 days)**: 
            - *Single Alert (3 days out)*: "Immediate Action Required" (Red/Error).
- **Multi-Channel Delivery**:
    - **Admin Notices**: Styled with standard WordPress notice classes (`notice-info`, `notice-warning`, `notice-error`) but enhanced with custom CSS for maximum visibility.
    - **HTML Emails**: Professional, branded emails matching the urgency level (Level 1: Calm/Blue, Level 3: Urgent/Red).
- **Authoritative Tracking**: 
    - Master server locks `initial_activation` date to prevent resetting the urgency sequence via re-installation.

## 3. UI Implementation (`templates/admin-domain-control.php`)
- **New Tab**: Add "Build Tracking" to the Domain Admin navigation.
- **Tracking Table**: 
    - Create a professional table showing Build ID, Domain, Status (Online/Offline), Initial Install, Initial Activation, Last Heartbeat, License Info, and Version.
    - **Remote Actions**: Add a "Manage" button/dropdown for each build with options to:
        - **Extend License**: Adds another full term to the current expiry (e.g., +30 days for Standard, +365 for Pro) based on the build's license type.
        - **Custom Term**: Manually set a specific expiry date or add a specific number of days for special cases.
        - **Suspend Build**: Remote kill-switch to deactivate the plugin on the client site immediately.
- **Notifications**: Master sends email to `tanmalik786@gmail.com` on first-time activation of any build.

## 4. Security & Optimization
- **Payload Protection**: Use `hash_hmac` with the existing integrity salt for all callback data.
- **Async Processing**: Ensure client-side pings are non-blocking.

## 5. Deployment & Testing
- Test the remote command loop (Master pushes update -> Client pulls and applies).
- Verify the 5-day expiry notice appears correctly on client sites.
