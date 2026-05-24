# VAPT Security - Superadmin Owner's Guide

This guide is for the Superadmin (tanmalik786) to manage and validate the security features of the VAPT Security plugin before delivery to clients.

---

## 1. Accessing the Interface
The security interface is located at:
**VAPT Security > Settings** in your WordPress sidebar.

The plugin provides a tabbed interface for managing different security domains:
- **General**: License management and homepage testing.
- **Hardening**: (NEW) 11 VAPT-specific security controls.
- **Rate Limiter**: Form submission throttling.
- **Input Validation**: XSS and SQLi prevention.
- **WP-Cron Protection**: DoS protection for cron jobs.
- **Security Logging**: Audit trail of all blocked attacks.
- **Statistics**: (UPDATED) Real-time monitoring of blocked IPs and login failures.

---

## 2. Managing Hardening Features (VAPT Report)
Navigate to the **Hardening** tab. This is where you resolve the majority of the VAPT report findings.

### Feature Toggles
You can manually toggle the following 11 protections:
1.  **Login Rate Limiting**: Set `Max Login Attempts` and `Lockout Duration`.
2.  **Disable XML-RPC**: Blocks `xmlrpc.php` and removes pingback headers.
3.  **Restrict REST API**: Implements a whitelist-only approach for public users.
4.  **Security Headers**: Sends `X-Frame-Options` (Clickjacking fix), etc.
5.  **Information Disclosure**: Hides WP version, blocks `debug.log` and `readme.html`.
6.  **Directory Listing**: Prevents browsing file folders (via `.htaccess` and silencer files).

### Server-Level Configuration
The Hardening tab also displays:
- **.htaccess Preview**: Rules automatically added to your server.
- **Nginx Snippet**: Copy-pasteable rules for Nginx environments.

---

## 3. Monitoring & Verification
Before delivering to a client, use the **Statistics** tab to verify the plugin is active and catching threats.

### How to Validate Login Protection (V#1)
1. Open an Incognito window.
2. Go to `/wp-login.php` and fail a login 5 times.
3. On the 6th attempt, you will see the "Too many attempts" message.
4. **Interface Check:** Go to the **Statistics** tab in your admin dashboard. You will see your IP listed under "Login Request Statistics" with 6 failed attempts.

### How to Validate REST API Whitelist (V#7 & V#10)
1. While logged out, visit `/wp-json/wp/v2/users`.
2. You should receive a `rest_forbidden` (401) error.
3. **Interface Check:** If you need to allow a specific plugin (like WooCommerce), add `wc/v3` to the **Whitelisted REST Namespaces** textarea on the Hardening tab.

---

## 4. Security Audit Logs
Navigate to the **Security Logging** tab to see exactly what the plugin has blocked.
- Each entry shows the **IP**, **Event Type** (e.g., `login_failed`, `blocked_cron_request`), and **Timestamp**.
- You can filter these logs to prove the security effectiveness to your clients.

---

## 5. Domain Control (Superadmin Only)
If you are logged in as `tanmalik786`, you have access to the **Domain Control** menu.
- **Domain Locking**: Lock the plugin to a specific client domain.
- **Generate Locked Config**: This creates a `vapt-locked-config.php` file.
- **Client Zip**: Generates a clean plugin ZIP for the client that includes your pre-configured hardening settings.

---

## 6. Pre-Delivery Checklist
Before sending the plugin to a client:
1. [ ] **Hardening Tab**: Ensure all 11 toggles are ON.
2. [ ] **General Tab**: Verify the License is active.
3. [ ] **Statistics Tab**: Click "Reset Data" for all IPs to clear your testing history.
4. [ ] **Domain Control**: Generate the Locked Config for the client's production domain.
5. [ ] **Zip Generator**: Generate the client-specific ZIP for delivery.

---
*Owner's Guide - VAPT Security v3.0.0*
