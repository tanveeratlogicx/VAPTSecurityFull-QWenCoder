# Changelog

All notable changes to the VAPT Security plugin will be documented in this file.

## [3.3.0] - 2026-05-25

### Added
- **Test Callback Button**: New "Test Callback" button in the Build Tracking tab fires a real ping to the master server on demand and displays a full diagnostic panel — target URL, tracking mode, build ID, HTTP status, SSL verify state, and raw response body. Colour-coded result (green/yellow/red). On success, throttle is cleared so the next natural heartbeat fires immediately.
- **`.buildincl` Allowlist**: Replaced the fragile blocklist approach for client build packaging with an explicit allowlist file (`.buildincl`). Only `vapt-security.php`, `uninstall.php`, `README.txt`, `USER_GUIDE.md`, `assets/`, `includes/`, `templates/`, and `vendor/autoload.php` + `vendor/composer/` are included. Edit `.buildincl` to add or remove files without touching code.
- **Duplicate Build Filename Prompt**: If a build with the same filename already exists in `releases/builds/`, a modal now asks whether to **Overwrite** or **Save as New** (timestamp-suffixed) before writing.
- **Build Generation Loading Overlay**: Full-screen dimmed overlay with spinner appears while the client zip is being generated, preventing double-clicks and giving clear visual feedback.

### Fixed
- **Heartbeat Not Reaching Master**: `maybe_trigger_callback()` was using `blocking => false`, which silently drops requests on single-server local setups where the originating PHP process holds the only available slot. Changed to `blocking => true` with proper response parsing and remote command processing.
- **"Build Generation Failed" Toast on Success**: Stale error message copy was shown even when the build succeeded. Message now accurately reflects the outcome.
- **`handle_force_ping` HMAC Mismatch**: Force ping was signing the payload without `ksort`, causing signature verification failures on the master. Fixed to match `maybe_trigger_callback()` signing order.
- **`handle_force_ping` SSL**: `sslverify` was hardcoded `false`. Now driven by `tracking_mode` (same as the natural heartbeat).
- **Parse Error / Critical Site Crash**: Orphaned code fragment (`'payload' => $payload` / `] );`) left behind from a partial replacement of `handle_force_ping` caused a PHP parse error that took the entire site down. Removed.
- **Dirty Files in Client Build**: Previous blocklist approach was missing many dev/doc files, causing ZIPs, markdown docs, and test files to appear in client builds. Replaced with `.buildincl` allowlist.

### Changed
- `vaptNotify.confirm()` now accepts optional `onCancel`, `confirmLabel`, and `cancelLabel` parameters for flexible modal dialogs.

## [3.2.1] - 2026-05-22
### Changed
- **PHP Version Requirement**: Raised minimum PHP version from 7.2.24 to 8.3+ for WordPress 7.x compatibility
- **WordPress Version Requirement**: Raised minimum WordPress version from 5.0 to 6.3+ for WordPress 7.x compatibility

## [3.2.0] - 2026-05-22
### Added
- **Build History Export/Import**: Full support for exporting build logs to JSON (single) or ZIP (multiple/all) and importing them to other sites.
- **Dynamic History Refresh**: Added AJAX-based history table refresh for a seamless experience after imports or status changes.
- **Improved Build Management**: Added 'Suspend/Resume' and 'Delete' controls directly in the build history table.
- **Master Admin Access**: Relaxed authorization checks to allow any site administrator to manage builds on both local and remote environments.
- **Dedicated Releases Storage**: Reorganized build artifacts into a structured `releases/` directory.

### Fixed
- **Single-Record Import**: Fixed a critical bug that prevented importing single JSON record objects.
- **Version Alignment**: Corrected the version display in the admin header to be closer to the title.

## [3.1.6] - 2026-05-21
### Added
- **Build Editing**: New 'Edit' action in Build History to quickly reload settings into the generator.
- **Enhanced History Data**: Added 'Domain Type' and 'License Expiry' columns to the history table for better overview.
- **Improved Logging**: Build logs now capture full white-label metadata and precise expiry timestamps.

## [3.1.5] - 2026-05-21
### Added
- **Build History & Logs**: New section in the Build Generator tab to track and manage generated builds.
- **Unique Build IDs**: Each generated build now receives a unique ID (e.g., B240521-XXXX) for better traceability.
- **Direct Config Downloads**: Build history now allows downloading previously generated configuration PHP files directly from the server.
- **Visual Enhancements**: Added Dashicons to Build Generator headers and improved column organization.

### Fixed
- **UI Compactness**: Enforced stricter layout constraints in the Generator grid to eliminate wasted whitespace on large screens.
- **Alignment**: Standardized label widths and input spacing for a more professional, uniform look.

## [3.1.4] - 2026-05-21

### Added
- **Domain Matching Types**: Added 'Standard', 'Wildcard' (containment), and 'Universal' (bypass) match modes to the Generator.
- **Integrated Licensing**: Moved license selection and auto-renewal controls directly into the build generator.
- **Auto-Import License**: Generated builds now automatically install the selected license type and expiry on the client site.
- **Real-time Expiry Feedback**: The generator now displays the calculated expiry date immediately upon selecting a license type.

### Changed
- Refactored Domain Admin UI to streamline the build generation process.
- Updated core enforcement logic to support sophisticated domain pattern matching.

## [3.1.3] - 2026-05-20

### Added
- **Local Dev Nuclear Bypass**: Added SSL bypass for WordPress.org requests in local environments.
- **Robust Environment Detection**: Improved loopback and internal request detection.
- **Dynamic White-Label Packaging**: Build engine now white-labels README.txt and USER_GUIDE.md on-the-fly.
- **Sensitive Data Stripping**: Automatic removal of internal management references from delivery builds.

### Changed
- Extended OTP session duration for local development.
- Updated build exclusion list with technical documentation and dev files.

## [3.1.2] - 2026-05-20

### Added
- **White-Labeling Support**: Full customization of plugin name, author, and description for client builds.
- **Enhanced Build Generator**: Support for white-label metadata and dynamic configuration filenames.
- **Update Suppression**: Automated disabling of plugin updates for white-labeled installations.

### Changed
- **Improved Domain Lock**: Added local environment bypass and support for multiple domain-specific lock files.
- **Enhanced User Guide**: Updated documentation with white-labeled build instructions.
- Synchronized version across package.json and vapt-security.php.

## [3.1.1] - 2026-05-20

### Fixed
- Internal version synchronization and consistency fixes.

## [3.1.0] - 2026-05-20

### Added
- **Trial License Type**: New 7-day validity license for testing purposes.
- **Demo Build License Type**: New 15-day validity license for demonstrations.
- **Enhanced Expiry Preview**: Admin UI now shows real-time expiry date calculation when switching license types.

### Changed
- Minor version bump to v3.1.0.

## [3.0.0] - 2026-05-20

### Added
- **Major Security Hardening Module**: Implemented 11 new security controls based on VAPT report.
- **Login Rate Limiting**: Protection against brute-force attacks on wp-login.php with configurable lockout.
- **REST API Whitelisting**: Strict unauthenticated access control with WooCommerce-safe whitelist support.
- **XML-RPC Protection**: Full disabling and blocking of xmlrpc.php to prevent SSRF and brute-force.
- **Security Headers**: Implementation of X-Frame-Options, X-Content-Type-Options, and more.
- **Server-Level Hardening**: Automatic .htaccess rule generation for Apache and Nginx configuration snippets.
- **Information Disclosure Prevention**: Hiding WordPress version, blocking debug.log and readme.html access.
- **Directory Listing Protection**: index.php silencer files and .htaccess Options -Indexes enforcement.
- **Hardening Dashboard**: New admin settings tab for granular control of all hardening features.
- **Login Statistics**: Real-time tracking of failed login attempts per IP.

### Changed
- **Major Version Bump**: Updated to v3.0.0 reflecting the significant security enhancements.
- **Enhanced Rate Limiter**: Core limiter now supports login-specific tracking and lockout windows.
- **Updated User Guide**: Comprehensive verification steps added for all 14 VAPT risks.

## [2.7.1] - 2025-12-19

### Changed
- Increased Superadmin OTP timer from 60 seconds to 120 seconds in Domain Control access.

## [2.5.0] - 2025-12-18

### Added
- **Client Zip Generator**: Generates clean, domain-specific plugin zip files for client delivery.
- **Dynamic Documentation**: `USER_GUIDE.md` automatically updates with the client's actual domain upon installation.
- **Integrity Verification**: Added HMAC signatures to locked configuration files to prevent tampering.
- **Smart Filenames**: Zip files are automatically named based on the target domain (e.g., `vapt-security-client.zip`).

### Changed
- Consolidates Domain Admin access into a single, Superadmin-only submenu.
- Excluded development files and internal guides from client builds.

## [2.1.0] - 2025-12-18
 
### Added
- Domain Locked Configuration Generator for Superadmin
- Submenu "Domain Control" (conditionally visible only to Superadmin)
- Automatic importing of locked configuration files on activation/init

## [2.0.0] - 2025-12-18

### Added
- Domain Control features for superadmin
- OTP Authentication integration
- License management system

### Changed
- Removed legacy "Qoder" references
- Updated repository URLs to tanveeratlogicx/VAPTSecurity
- **Major Release**: Plugin version updated to 2.0.0

## [1.0.5] - 2025-12-15

### Fixed
- Configuration system now properly hides disabled features in admin interface
- Conditional rendering of admin tabs based on feature flags
- Menu positioning now correctly appears as top-level menu above Appearance
- Fixed configuration file loading path to use plugin directory instead of WordPress root
- Added descriptive text below checkbox fields to explain feature effects

### Added
- Test URLs displayed conditionally for each feature section
- General settings section now includes homepage URL for testing
- Clickable test URLs with target="_blank" for easy testing
- Helpful notes and warnings for each test URL
- More descriptive test URLs for form-related features
- Separate configuration flag (VAPT_SHOW_TEST_URLS) to control test URL visibility
- Updated sample configuration file with new flag documentation

## [1.0.4] - 2025-12-15

### Added
- Comprehensive changelog documentation
- Sample configuration file (vapt-config-sample.php)
- Test script for feature verification (test-vapt-features.php)
- Enhanced documentation files

## [1.0.3] - 2025-12-15

### Added
- Configuration file support (`vapt-config.php`) for advanced customization
- Sample configuration file (`vapt-config-sample.php`) for easy setup
- Comprehensive FEATURES.md documentation with detailed feature explanations
- Test script (`test-vapt-features.php`) for easy feature testing
- Feature enable/disable controls through configuration
- IP whitelisting capability to prevent blocking trusted sources
- Customizable user messages and debug mode support
- Detailed testing methodologies and instructions

### Changed
- Enhanced plugin initialization with configuration file loading
- Improved feature descriptions in admin interface
- Added test URL information in settings
- Updated README.txt with configuration and testing instructions
- Enhanced security features with whitelisted IPs support

## [1.0.2] - 2025-12-15

### Added
- Modern horizontal tab interface for admin settings
- Enhanced CSS styling for better user experience
- Improved responsive design for mobile devices
- Tab persistence using localStorage to remember last active tab

### Changed
- Redesigned admin interface with cleaner, more modern look
- Updated statistics tables with better styling
- Improved form layout and spacing
- Enhanced visual hierarchy in settings panels

## [1.0.1] - 2025-12-15

### Changed
- Renamed main plugin file to `vapt-security.php`
- Updated plugin URI to reflect correct repository name
- Removed duplicate plugin folder
- Cleaned up file structure to maintain single source of truth

### Fixed
- Resolved file duplication issues
- Corrected plugin naming inconsistencies
- Streamlined directory structure

## [1.0.0] - 2025-12-15

### Added
- Initial release of VAPT Security plugin
- WP-Cron DoS protection with rate limiting and IP blocking
- Advanced input validation with multiple sanitization levels
- Rate limiting functionality with violation tracking
- Security logging and monitoring features
- Comprehensive admin interface with tabbed settings
- Support for Cloudflare and proxy IP detection
- Scheduled cleanup of old data
- Detailed documentation and architecture diagrams

### Features
- **WP-Cron Protection**: Implements rate limiting specifically for wp-cron.php access with configurable limits and automatic IP blocking
- **Input Validation**: Provides multi-level sanitization (Basic, Standard, Strict) with comprehensive XSS prevention
- **Rate Limiting**: Configurable request limits per IP address with separate tracking for regular and cron requests
- **Security Logging**: Detailed logging of security events with statistical dashboard and IP analysis
- **Performance Optimization**: Efficient data storage with scheduled cleanup and minimal overhead

### Security
- Protection against DoS attacks via wp-cron.php
- Strict server-side input validation and sanitization
- Rate limiting on form submissions to prevent abuse
- Automatic IP blocking for repeated violations
- Comprehensive XSS prevention techniques
- Secure handling of proxy and Cloudflare IPs

### Performance
- Efficient data structures for quick lookups
- Hourly cleanup of temporary data
- Daily optimization of stored data
- Automatic removal of expired blocks
- Minimal impact on normal site operations

### Compatibility
- WordPress 6.3+ compatibility
- PHP 8.3+ support (Updated for WordPress 7.x)
- MySQL 5.5.5+ compatibility
- Works with popular caching plugins
- Supports multisite installations
- Compatible with CDN and proxy services

## [Unreleased]

### Planned Improvements
- Integration with reCAPTCHA and hCaptcha services
- REST API endpoint protection
- Enhanced dashboard with real-time monitoring
- Export functionality for security logs
- Whitelist functionality for trusted IPs
- Customizable block duration settings
- Enhanced statistics and reporting features
- Multilingual support for admin interface

### Security Enhancements
- Two-factor authentication integration
- Brute force protection for login attempts
- File integrity monitoring
- Malware scanning capabilities
- Enhanced firewall rules
- Advanced threat detection algorithms

### Performance Improvements
- Redis/Memcached integration for high-traffic sites
- Database indexing optimizations
- Asynchronous logging for better performance
- Caching strategies for frequently accessed data
- Lazy loading for admin dashboard components

## Roadmap

### Version 1.1.0 (Planned)
- reCAPTCHA integration
- REST API protection
- Enhanced dashboard
- Export functionality

### Version 1.2.0 (Planned)
- Two-factor authentication
- Brute force protection
- File integrity monitoring

### Version 1.3.0 (Planned)
- Malware scanning
- Advanced threat detection
- Redis/Memcached support

## Release Process

1. Update version number in main plugin file
2. Update CHANGELOG.md with release notes
3. Tag release in Git repository
4. Package plugin for distribution
5. Update documentation if needed
6. Announce release to users

## Deprecated Features

None at this time.

## Known Issues

None at this time.