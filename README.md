# VAPT Security Plugin (Full Edition)

[![Version](https://img.shields.io/badge/version-3.2.1-blue.svg)](https://github.com/tanveeratlogicx/vapt-security-full)
[![WordPress](https://img.shields.io/badge/WordPress-6.3+-blue.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-8.0+-blue.svg)](https://php.net/)
[![License](https://img.shields.io/badge/license-GPL--3.0+-blue.svg)](LICENSE)

## Overview

**VAPT Security** is a comprehensive WordPress security plugin initially developed for **Gargash Equipment Solutions** to address critical VAPT (Vulnerability Assessment and Penetration Testing) findings. The plugin has evolved into a full-featured security solution with advanced protection mechanisms, license management, and white-label build capabilities.

> **Originally created to address specific VAPT vulnerabilities, now enhanced with enterprise-grade features including domain locking, OTP authentication, license management, and remote build tracking.**

---

## 🛡️ Core Security Features (VAPT Compliance)

### 1. **WP-Cron DoS Protection**
- Rate limiting on `wp-cron.php` access with configurable hourly limits
- Automatic IP blocking for abusive patterns
- Integration with proxy/Cloudflare IP detection
- Option to disable WP-Cron and use system-level cron jobs

### 2. **Advanced Rate Limiting**
- Configurable request limits per IP address per minute
- Separate tracking for regular requests and cron requests
- Violation counter with progressive blocking
- Automatic cleanup of old request data
- Persistent violator handling with permanent blocks

### 3. **Multi-Level Input Validation**
- Schema-based validation approach
- Three sanitization levels: Basic, Standard, Strict
- XSS prevention with comprehensive filtering
- Email, URL, and custom regex pattern validation
- Length restrictions and format enforcement

### 4. **Security Logging & Monitoring**
- Detailed event logging with timestamps
- Statistical dashboard with IP analysis
- Event categories: form submissions, blocked requests, validation errors, CAPTCHA failures
- Automatic log rotation and size management

---

## 🔐 Advanced Security Hardening (v3.0+)

### Implemented VAPT Security Controls:

| ID | Control | Status | Description |
|----|---------|--------|-------------|
| V#1 | Login Rate Limiting | ✅ | Brute-force protection on wp-login.php with configurable lockout |
| V#2 | Input Validation | ✅ | Multi-level sanitization (Basic/Standard/Strict) |
| V#3 | XML-RPC Protection | ✅ | Full disabling and blocking of xmlrpc.php |
| V#4 | Directory Listing | ✅ | index.php silencer files + .htaccess Options -Indexes |
| V#5 | File Upload Security | ✅ | Restricted file types and upload validation |
| V#6 | Banner Grabbing | ✅ | Hide WordPress version, remove generator tags |
| V#7 | REST API Whitelisting | ✅ | Strict unauthenticated access control |
| V#8 | Username Enumeration | ✅ | Generic login error messages |
| V#9 | Information Disclosure | ✅ | Block debug.log, readme.html access |
| V#10 | REST API Protection | ✅ | WooCommerce-safe whitelist support |
| V#11 | Security Headers | ✅ | X-Frame-Options, X-Content-Type-Options, etc. |
| V#12 | Debug Log Protection | ✅ | Block access to debug.log files |
| V#13 | readme.html Protection | ✅ | Block access to readme.html |
| V#14 | Form Rate Limiting | ✅ | Throttle form submissions per IP |

### Additional Hardening Features:
- **Security Headers**: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Content-Security-Policy
- **Server-Level Protection**: Automatic .htaccess rule generation for Apache/Nginx
- **Information Disclosure Prevention**: Hiding WordPress version, blocking sensitive files
- **Login Statistics**: Real-time tracking of failed login attempts per IP

---

## 🏢 Enterprise Features (v2.0+)

### Domain Control & Superadmin Management
- **OTP Authentication**: 120-second validity OTP for Superadmin access
- **Domain Locking**: Generate locked configuration files bound to specific domains
- **White-Label Builds**: Custom plugin name, author, and description for client deliveries
- **Build Generator**: Create domain-specific plugin packages with unique IDs (e.g., B240521-XXXX)

### License Management System
Five license types with varying validity periods:
- **Standard**: 30 days (auto-renewable)
- **Pro**: 365 days (auto-renewable)
- **Developer**: Unlimited (no expiry)
- **Trial**: 7 days (testing purposes)
- **Demo**: 15 days (demonstrations)

Features:
- Real-time expiry date calculation in admin UI
- Auto-renewal capability
- License type switching with immediate effect
- Automatic update suppression for white-labeled installations

### Build History & Tracking (v3.1+)
- **Build Export/Import**: Export build logs to JSON (single) or ZIP (multiple/all)
- **Dynamic History Refresh**: AJAX-based table refresh after imports or status changes
- **Build Management**: Suspend/Resume and Delete controls in history table
- **Unique Build IDs**: Traceability with format B240521-XXXX
- **Direct Config Downloads**: Download previously generated configuration files
- **Enhanced History Data**: Domain Type, License Expiry columns

### White-Label Packaging (v3.1.3+)
- Dynamic README.txt and USER_GUIDE.md customization
- Sensitive data stripping from delivery builds
- SSL bypass for local development environments
- Robust environment detection for loopback/internal requests

---

## 📊 Build Tracking & Remote Management (v3.2+)

### Phone Home Callback System
- **Two-Way Heartbeat**: Client sites send status, master server returns commands
- **Discreet Tracking**: Monitors build activations, license status, versioning
- **Remote Commands**: License extensions, renewals, suspensions from master server

### Tiered Expiry Notification System
Rule-based urgency notifications based on license type and days remaining:

| License Type | Level 1 | Level 2 | Level 3 |
|--------------|---------|---------|---------|
| Standard/Pro (30-365 days) | 20 days out (Blue/Info) | 10 days out (Yellow/Warning) | 5 days out (Red/Error) |
| Demo (15 days) | 10 days out (Yellow) | 3 days out (Red) | - |
| Trial (7 days) | 3 days out (Red/Error) | - | - |

### Multi-Channel Delivery
- **Admin Notices**: Styled WordPress notices with custom CSS
- **HTML Emails**: Professional branded emails matching urgency level
- **Authoritative Tracking**: Master server locks initial activation date

---

## 📁 Project Structure

```
vapt-security-full/
├── vapt-security.php           # Main plugin file (v3.2.1)
├── includes/
│   ├── class-rate-limiter.php  # Core rate limiting engine
│   ├── class-input-validator.php # Multi-level validation
│   ├── class-hardening.php     # 11+ security hardening controls
│   ├── class-license.php       # License management (5 types)
│   ├── class-otp.php           # OTP authentication
│   ├── class-features.php      # Feature enable/disable flags
│   ├── class-security-logger.php # Event logging system
│   ├── class-captcha-handler.php # CAPTCHA integration
│   ├── class-integrations-manager.php # Third-party integrations
│   └── class-encryption.php    # HMAC signatures & encryption
├── templates/
│   ├── admin-settings.php      # Main settings dashboard
│   ├── admin-domain-control.php # Superadmin domain management
│   ├── admin-otp-settings.php  # OTP configuration
│   └── form-template.php       # Test form template
├── assets/
│   ├── css/admin.css           # Admin interface styling
│   └── js/vapt-security.js     # AJAX & UI interactions
├── releases/
│   ├── builds/                 # Generated build artifacts
│   ├── configurations/         # Domain-locked config files
│   └── logs/                   # Build operation logs
├── tests/                      # Verification & test scripts
├── bin/                        # Version bump scripts (Win/Linux)
└── docs/                       # Documentation files
```

---

## ⚙️ Configuration

### Configuration File Support
The plugin supports a `vapt-config.php` configuration file for advanced customization:

```php
// Feature Enable/Disable
define('VAPT_FEATURE_WP_CRON_PROTECTION', true);
define('VAPT_FEATURE_RATE_LIMITING', true);
define('VAPT_FEATURE_INPUT_VALIDATION', true);
define('VAPT_FEATURE_SECURITY_LOGGING', true);
define('VAPT_FEATURE_SECURITY_HEADERS', true);
define('VAPT_FEATURE_XMLRPC_PROTECTION', true);
define('VAPT_FEATURE_LOGIN_PROTECTION', true);

// Whitelisted IPs
define('VAPT_WHITELISTED_IPS', ['127.0.0.1', '::1']);

// Debug Mode
define('VAPT_DEBUG_MODE', false);
```

Copy `vapt-config-sample.php` to your WordPress root directory and customize as needed.

---

## 🧪 Testing

### Built-in Test Tools
- `test-vapt-features.php` - Comprehensive feature verification script
- `tests/verification_auth.php` - Authentication flow testing
- `tests/test-rate-limiter.php` - Rate limiting unit tests
- `tests/test-plugin-structure.php` - Plugin structure validation

### Test URLs
Access these endpoints to verify protection:
- **WP-Cron**: `/wp-cron.php` (rate limit test)
- **Form Submission**: `/wp-admin/admin-ajax.php?action=vapt_form_submit`
- **XML-RPC**: `/xmlrpc.php` (should be blocked)
- **Debug Log**: `/wp-content/debug.log` (should be blocked)

---

## 📦 Installation

### Requirements
- WordPress 6.3 or higher
- PHP 8.0 or higher
- MySQL 5.5.5 or higher

### Steps
1. Upload the plugin to `/wp-content/plugins/vapt-security-full/`
2. Activate through the 'Plugins' menu in WordPress
3. Navigate to **VAPT Security** in the admin menu
4. Configure settings according to your security requirements
5. (Optional) Add `vapt-config.php` to WordPress root for advanced customization

### For Client Deployments
Use the **Domain Control** panel (Superadmin only) to:
1. Generate domain-locked configuration files
2. Select license type and duration
3. Create white-labeled build packages
4. Download client-ready ZIP files

---

## 🔄 Recent Enhancements (v3.1 - v3.2)

### Version 3.2.1 (Current)
- **Build History Export/Import**: Full JSON/ZIP export with import capability
- **Dynamic History Refresh**: AJAX-based real-time table updates
- **Improved Build Management**: Suspend/Resume/Delete actions in history
- **Master Admin Access**: Relaxed authorization for site administrators
- **Dedicated Releases Storage**: Reorganized `releases/` directory structure

### Version 3.1.x Series
- **Build Editing**: Quick reload of build settings into generator
- **Enhanced History Data**: Domain Type and License Expiry columns
- **Unique Build IDs**: B240521-XXXX format for traceability
- **Direct Config Downloads**: Download historical configuration files
- **Domain Matching Types**: Standard, Wildcard, Universal match modes
- **Integrated Licensing**: License selection in build generator
- **Auto-Import License**: Automatic license installation on client sites
- **Real-time Expiry Preview**: Calculated expiry date display
- **White-Label Packaging**: Dynamic README.txt and USER_GUIDE.md
- **Local Dev SSL Bypass**: Development environment support
- **Sensitive Data Stripping**: Internal references removed from builds

### Version 3.0.0 (Major Release)
- **11 New Security Controls**: Complete VAPT compliance
- **Login Rate Limiting**: Brute-force protection
- **REST API Whitelisting**: WooCommerce-compatible
- **XML-RPC Full Blocking**: SSRF and brute-force prevention
- **Security Headers Implementation**: Clickjacking and MIME-type protection
- **Server-Level Hardening**: .htaccess and Nginx snippets
- **Hardening Dashboard**: Granular control interface
- **Login Statistics**: Failed attempt tracking

---

## 📚 Documentation

- **[FEATURES.md](FEATURES.md)** - Detailed feature descriptions and testing guides
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and data flow diagrams
- **[CHANGELOG.md](CHANGELOG.md)** - Complete version history
- **[USER_GUIDE.md](USER_GUIDE.md)** - End-user documentation
- **[SUPERADMIN_GUIDE.md](SUPERADMIN_GUIDE.md)** - Superadmin operations guide
- **[DevDocs/](DevDocs/)** - Development documentation and build plans

---

## 🚀 Roadmap

### Planned Features
- [ ] reCAPTCHA and hCaptcha integration
- [ ] Enhanced REST API endpoint protection
- [ ] Real-time monitoring dashboard
- [ ] Security log export functionality
- [ ] Customizable block duration settings
- [ ] Two-factor authentication integration
- [ ] File integrity monitoring
- [ ] Malware scanning capabilities
- [ ] Redis/Memcached integration for high-traffic sites
- [ ] Multilingual admin interface support

---

## 🔒 Security Considerations

This plugin implements defense-in-depth security:
- Multiple protection layers (rate limiting, validation, hardening)
- Secure defaults with conservative settings
- Comprehensive event logging and auditing
- Regular security updates and vulnerability patches

**Important**: Always test in a staging environment before deploying to production.

---

## 📄 License

This plugin is licensed under the **GPL-3.0+** License. See the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Tanveer Malik**
- GitHub: [@tanveeratlogicx](https://github.com/tanveeratlogicx)
- Plugin URI: [https://github.com/tanveeratlogicx/vapt-security-full](https://github.com/tanveeratlogicx/vapt-security-full)

---

## 🙏 Acknowledgments

- Originally developed for **Gargash Equipment Solutions** ([https://gargashequipmentsolutions.com](https://gargashequipmentsolutions.com))
- Enhanced with QWen-Coder AI assistance ([https://coder.qwen.ai](https://coder.qwen.ai))

---

*Last Updated: May 2026 | Version: 3.2.1*

