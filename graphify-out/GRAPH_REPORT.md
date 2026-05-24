# Graph Report - VAPTSecurity-Full  (2026-05-24)

## Corpus Check
- 57 files · ~48,171 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 640 nodes · 770 edges · 65 communities (54 shown, 11 thin omitted)
- Extraction: 87% EXTRACTED · 13% INFERRED · 0% AMBIGUOUS · INFERRED: 97 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `015b1b54`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]

## God Nodes (most connected - your core abstractions)
1. `VAPT_Security` - 69 edges
2. `Changelog` - 25 edges
3. `sanitize_text_field()` - 21 edges
4. `VAPT_Hardening` - 18 edges
5. `esc_html_e()` - 18 edges
6. `VAPT_Rate_Limiter` - 16 edges
7. `is_wp_error()` - 13 edges
8. `VAPT_License` - 13 edges
9. `VAPT_Security_Logger` - 12 edges
10. `VAPT Security Plugin Documentation` - 12 edges

## Surprising Connections (you probably didn't know these)
- None detected - all connections are within the same source files.

## Communities (65 total, 11 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.05
Nodes (7): VAPT_Encryption, VAPT_License, VAPT_OTP, esc_html_e(), set_transient(), sanitize_text_field(), VAPT_Security

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (9): VAPT_Features, VAPT_Hardening, VAPT_Integrations_Manager, VAPT_Cron, wp_die(), add_action(), add_filter(), is_wp_error() (+1 more)

### Community 2 - "Community 2"
Cohesion: 0.05
Nodes (41): 1. WP-Cron DoS Protection, 2. Advanced Input Validation, 3. Rate Limiting & Throttling, 4. Security Logging & Monitoring, API Reference, Architecture, Best Practices, code:php (VAPT_Security::instance()) (+33 more)

### Community 3 - "Community 3"
Cohesion: 0.05
Nodes (36): 1. WP-Cron Testing, 2. Form Submission Testing, 3. Rate Limit Testing Script, code:php (// test-rate-limit.php), code:php (<?php), Configuration File, Configuration File Loading, Configuration Options (+28 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (32): 1. Defense in Depth, 1. Efficient Data Structures, 1. WP-Cron Protection Layer, 2. Rate Limiting Layer, 2. Scheduled Maintenance, 2. Secure Defaults, 3. Input Validation Layer, 3. Minimal Overhead (+24 more)

### Community 5 - "Community 5"
Cohesion: 0.06
Nodes (30): 1.1 Version Bump to 3.2.1 — [!WARN] Partially Done, 1.2 VAPT_INTEGRITY_URL Constant — [OK] Done, 1.3 AJAX Callback Endpoints — [OK] Done, 1.4 build_id + integrity_url in All Build Payloads — [OK] Done, §1 — Core Logic & Configuration, 2.1 Two-Way Heartbeat — [OK] Done, 2.2 Tiered Expiry Notices — [OK] Logic Correct, 2.3 Multi-Channel Delivery — [!WARN] Notices [OK] / Email [!WARN] (+22 more)

### Community 6 - "Community 6"
Cohesion: 0.08
Nodes (25): Architecture Decision, code:block1 (X-Frame-Options: SAMEORIGIN), Executive Summary, Files to be Modified/Created, Final Status, Implementation Order, Phase 1: HIGH Priority (COMPLETED), Phase 2: MEDIUM Priority (COMPLETED) (+17 more)

### Community 7 - "Community 7"
Cohesion: 0.1
Nodes (8): VAPT_Input_Validator, Elementor_Ajax_Handler, sanitize_textarea_field(), WP_Error, wp_strip_all_tags(), WPCF7_Validation, WPForms, WPForms_Process

### Community 8 - "Community 8"
Cohesion: 0.09
Nodes (22): 1.1 Deploy v3.2.1 to Production, 1.2 Fix Blocking Ping Issue, 1.3 Add HMAC Payload Protection, 2.1 Re-generate Locked Configs, 2.2 Fix Email Notifications, 2.3 Add Custom Term Remote Action, 2.4 Add Authoritative Tracking on Client, 3.1 Create Deployment Testing Documentation (+14 more)

### Community 10 - "Community 10"
Cohesion: 0.11
Nodes (17): Automated Scripts, Best Practices, Branching Strategy, code:bash (# For Windows), code:php (* Version:     X.Y.Z), code:block3 (Stable tag: X.Y.Z), code:bash (git add vapt-security.php README.txt CHANGELOG.md), code:bash (git tag -a "vX.Y.Z" -m "Version X.Y.Z") (+9 more)

### Community 12 - "Community 12"
Cohesion: 0.12
Nodes (16): 1. Update License Constants and Logic (`includes/class-license.php`), 2. Update License Management UI (`templates/admin-domain-control.php`), 3. Version and Changelog Updates, 4. Update Configuration Sample (`vapt-config-sample.php`), code:php (<option value="trial" <?php selected( $license_type, 'trial'), code:php ('trial' => date_i18n( get_option( 'date_format' ), time() + ), Current State Analysis, Dependencies (+8 more)

### Community 13 - "Community 13"
Cohesion: 0.13
Nodes (14): [1.0.4] - 2025-12-15, [2.1.0] - 2025-12-18, [2.7.1] - 2025-12-19, [3.1.1] - 2026-05-20, [3.1.6] - 2026-05-21, Added, Added, Added (+6 more)

### Community 14 - "Community 14"
Cohesion: 0.14
Nodes (13): 10. Sensitive File Protection (V#12 & V#13), 11. Input Validation (V#14), 1. Login Rate Limiting (V#1), 2. WP-Cron Protection (V#2), 3. XML-RPC Protection (V#3), 4. Directory Listing Protection (V#4), 5. Contact Form Rate Limiting (V#5), 6. Banner Grabbing Protection (V#6) (+5 more)

### Community 17 - "Community 17"
Cohesion: 0.17
Nodes (11): 1. Accessing the Interface, 2. Managing Hardening Features (VAPT Report), 3. Monitoring & Verification, 4. Security Audit Logs, 5. Domain Control (Superadmin Only), 6. Pre-Delivery Checklist, Feature Toggles, How to Validate Login Protection (V#1) (+3 more)

### Community 19 - "Community 19"
Cohesion: 0.2
Nodes (9): 1. Core Documentation Updates, 2. New Folder: `DevDocs`, 3. Verification, `ARCHITECTURE.md`, `DOCUMENTATION.md`, Plan: Update Plugin Documentation for v3.1.2 & Beyond, `README.md`, `README.txt` (Critical Update) (+1 more)

### Community 20 - "Community 20"
Cohesion: 0.22
Nodes (8): Added, Changed, Fixed, Infrastructure, Security, v3.2.0 - [Previous Version], v3.2.1 - 2026-05-23, Version History

### Community 21 - "Community 21"
Cohesion: 0.29
Nodes (6): 1. Build Trigger Mechanism, 2. Phase I: Secure Configuration Generation, 3. Phase II: Dynamic Header Rewriting, 4. Phase III: Packaging & Exclusions, 5. Phase IV: Delivery, Technical Build Process

### Community 22 - "Community 22"
Cohesion: 0.29
Nodes (6): 1. Core Logic & Configuration (`vapt-security.php`), 2. Remote Management & Command System, 3. UI Implementation (`templates/admin-domain-control.php`), 4. Security & Optimization, 5. Deployment & Testing, VAPT Build Tracking & Callback System Implementation Plan

### Community 23 - "Community 23"
Cohesion: 0.33
Nodes (6): [1.0.0] - 2025-12-15, Added, Compatibility, Features, Performance, Security

### Community 27 - "Community 27"
Cohesion: 0.4
Nodes (4): Access Requirements:, Configuration Generator, Domain Admin Access, VAPT Security - Superadmin Guide

### Community 28 - "Community 28"
Cohesion: 0.4
Nodes (4): Backend Enhancements (`vapt-security.php`), Enhance-Build Plan, UI Enhancements (`templates/admin-domain-control.php`), Verification

### Community 31 - "Community 31"
Cohesion: 0.5
Nodes (4): Performance Improvements, Planned Improvements, Security Enhancements, [Unreleased]

### Community 32 - "Community 32"
Cohesion: 0.5
Nodes (4): Roadmap, Version 1.1.0 (Planned), Version 1.2.0 (Planned), Version 1.3.0 (Planned)

### Community 33 - "Community 33"
Cohesion: 0.67
Nodes (3): [2.5.0] - 2025-12-18, Added, Changed

### Community 34 - "Community 34"
Cohesion: 0.67
Nodes (3): [1.0.3] - 2025-12-15, Added, Changed

### Community 35 - "Community 35"
Cohesion: 0.67
Nodes (3): [2.0.0] - 2025-12-18, Added, Changed

### Community 36 - "Community 36"
Cohesion: 0.67
Nodes (3): [3.1.2] - 2026-05-20, Added, Changed

### Community 37 - "Community 37"
Cohesion: 0.67
Nodes (3): [1.0.2] - 2025-12-15, Added, Changed

### Community 38 - "Community 38"
Cohesion: 0.67
Nodes (3): [3.1.4] - 2026-05-21, Added, Changed

### Community 39 - "Community 39"
Cohesion: 0.67
Nodes (3): [3.1.5] - 2026-05-21, Added, Fixed

### Community 40 - "Community 40"
Cohesion: 0.67
Nodes (3): [3.2.0] - 2026-05-22, Added, Fixed

### Community 41 - "Community 41"
Cohesion: 0.67
Nodes (3): [1.0.1] - 2025-12-15, Changed, Fixed

### Community 42 - "Community 42"
Cohesion: 0.67
Nodes (3): [1.0.5] - 2025-12-15, Added, Fixed

### Community 43 - "Community 43"
Cohesion: 0.67
Nodes (3): [3.0.0] - 2026-05-20, Added, Changed

### Community 44 - "Community 44"
Cohesion: 0.67
Nodes (3): [3.1.0] - 2026-05-20, Added, Changed

### Community 45 - "Community 45"
Cohesion: 0.67
Nodes (3): [3.1.3] - 2026-05-20, Added, Changed

## Knowledge Gaps
- **256 isolated node(s):** `WPForms_Process`, `code:mermaid (graph TD)`, `code:mermaid (graph TD)`, `Key Features:`, `code:mermaid (graph TD)` (+251 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **11 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `sanitize_text_field()` connect `Community 0` to `Community 18`, `Community 11`, `Community 15`, `Community 7`?**
  _High betweenness centrality (0.047) - this node is a cross-community bridge._
- **Why does `VAPT_Security` connect `Community 0` to `Community 1`, `Community 7`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Why does `add_action()` connect `Community 1` to `Community 0`, `Community 7`?**
  _High betweenness centrality (0.012) - this node is a cross-community bridge._
- **Are the 20 inferred relationships involving `sanitize_text_field()` (e.g. with `.sanitize_options()` and `.render_sanitization_level_cb()`) actually correct?**
  _`sanitize_text_field()` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 2 inferred relationships involving `VAPT_Hardening` (e.g. with `.sanitize_options()` and `.activate_plugin()`) actually correct?**
  _`VAPT_Hardening` has 2 INFERRED edges - model-reasoned connections that need verification._
- **Are the 17 inferred relationships involving `esc_html_e()` (e.g. with `.render_enable_cron_cb()` and `.render_rate_limit_max_cb()`) actually correct?**
  _`esc_html_e()` has 17 INFERRED edges - model-reasoned connections that need verification._
- **What connects `WPForms_Process`, `code:mermaid (graph TD)`, `code:mermaid (graph TD)` to the rest of the system?**
  _256 weakly-connected nodes found - possible documentation gaps or missing edges._