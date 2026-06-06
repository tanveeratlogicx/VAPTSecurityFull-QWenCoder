<?php
// Superadmin Domain Control Page
// Check transient auth
$user_id = get_current_user_id();
$is_verified = get_transient( 'vapt_auth_' . $user_id );

// License Data
$license = VAPT_License::get_license();
$license_type = $license['type'] ?? 'standard';
$license_expires = $license['expires'] ?? 0;
$license_auto_renew = $license['auto_renew'] ?? false;
$expiry_date = $license_expires ? wp_date( get_option( 'date_format' ), $license_expires, wp_timezone() ) : __( 'Never', 'vapt-security' );

// Get Active Features
$features = VAPT_Features::get_active_features();
$all_features = VAPT_Features::get_defined_features();

// Pre-calculate future expiries for JS
$base_time = ! empty( $license['start'] ) ? $license['start'] : time();
$future_expiries = [
    'standard' => wp_date( get_option( 'date_format' ), $base_time + ( 30 * DAY_IN_SECONDS ), wp_timezone() ),
    'pro'      => wp_date( get_option( 'date_format' ), $base_time + ( 365 * DAY_IN_SECONDS ), wp_timezone() ),
    'developer' => __( 'Never', 'vapt-security' ),
    'trial' => wp_date( get_option( 'date_format' ), $base_time + ( 7 * DAY_IN_SECONDS ), wp_timezone() ),
    'demo'  => wp_date( get_option( 'date_format' ), $base_time + ( 15 * DAY_IN_SECONDS ), wp_timezone() ),
];

$csv_names = [
    'rate_limiting'              => 'Lack of Rate Limiting on Contact Form (V#5)',
    'input_validation'           => 'No Input Validation (V#14)',
    'cron_protection'            => 'WordPress Cron Job Vulnerability (DoS) (V#2)',
    'security_logging'           => 'Security Event Logging & Audit Trail',
    'login_protection'           => 'Lack of Rate Limiting on WordPress Login (V#1)',
    'login_enum_protection'      => 'Username Enumeration via wp-login.php (V#8)',
    'xmlrpc_protection'          => 'XML-RPC Leads to Unauthenticated Blind SSRF (V#3)',
    'directory_listing'          => 'Directory Listing Vulnerability (V#4)',
    'banner_grabbing'            => 'Banner Grabbing Vulnerability (V#6)',
    'rest_api_protection'        => 'Username Enumeration via WordPress REST API (V#7/10)',
    'security_headers'           => 'Clickjacking Protection (V#11)',
    'debug_log_protection'       => 'Public Exposure of Debug Log File (V#12)',
    'readme_protection'          => 'Information Disclosure via readme.html (V#13)',
];
?>
<style>
    /* Force Full Width for Domain Admin */
    .vapt-domain-admin-wrap {
        max-width: 100% !important;
        margin-right: 20px !important;
        width: auto !important;
        display: block !important;
    }
    .vapt-domain-admin-wrap .card {
        max-width: none !important;
        width: 100% !important;
        margin: 20px 0 !important;
        box-sizing: border-box !important;
    }
    .vapt-admin-row {
        display: flex;
        gap: 20px;
        width: 100%;
    }
    .vapt-admin-row .card {
        flex: 1;
        margin: 0 !important;
    }
    #wpbody-content {
        padding-bottom: 50px;
    }
    /* Sleek Feature Cards */
    .vapt-feature-grid {
        display: grid;
        grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
        gap: 20px;
        margin-bottom: 30px;
    }
    .vapt-feature-card {
        background: #fff;
        border: 1px solid #e5e5e5;
        border-radius: 8px;
        padding: 20px;
        display: flex;
        flex-direction: column;
        transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
        position: relative;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .vapt-feature-card:hover {
        border-color: #2271b1;
        box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        transform: translateY(-2px);
    }
    .vapt-feature-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 15px;
    }
    .vapt-feature-icon {
        width: 40px;
        height: 40px;
        background: #f0f6fb;
        color: #2271b1;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 20px;
    }
    .vapt-feature-card.active .vapt-feature-icon {
        background: #2271b1;
        color: #fff;
    }
    .vapt-feature-info {
        flex: 1;
    }
    .vapt-feature-info h4 {
        margin: 0;
        font-size: 14px;
        font-weight: 600;
        color: #1d2327;
    }
    .vapt-feature-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-top: auto;
        padding-top: 15px;
        border-top: 1px solid #f0f0f1;
    }
    .vapt-feature-status {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        padding: 2px 8px;
        border-radius: 12px;
        background: #f0f0f1;
        color: #646970;
    }
    .vapt-feature-card.active .vapt-feature-status {
        background: #edfaef;
        color: #008a20;
    }
    .vapt-ts-src {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 16px;
        height: 16px;
        border-radius: 999px;
        font-size: 10px;
        font-weight: 700;
        margin-left: 6px;
        border: 1px solid transparent;
        line-height: 16px;
        vertical-align: middle;
    }
    .vapt-ts-src-client {
        background: #edfaef;
        border-color: #b7e2c1;
        color: #008a20;
    }
    .vapt-ts-src-legacy {
        background: #f0f0f1;
        border-color: #dcdcde;
        color: #646970;
    }
    .vapt-ts-src-unknown {
        background: #fcf0f1;
        border-color: #f2b3b7;
        color: #d63638;
    }
    .vapt-ts-src-warn {
        background: #fff8e5;
        border-color: #f2c86a;
        color: #9a6a00;
    }
    .vapt-category-title {
        font-size: 16px;
        font-weight: 600;
        margin: 30px 0 15px 0;
        padding-bottom: 8px;
        border-bottom: 2px solid #f0f0f1;
        display: flex;
        align-items: center;
        gap: 10px;
        color: #1d2327;
    }

    /* Generator Grid Fixes */
    .vapt-generator-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
        gap: 25px;
        margin-top: 15px;
        max-width: 1150px;
    }
    .vapt-generator-table th {
        width: 130px !important;
        min-width: 130px !important;
        padding: 6px 0 !important;
        font-size: 12px;
        vertical-align: middle;
        color: #646970;
        text-align: left;
    }
    .vapt-generator-table td {
        padding: 6px 0 !important;
        vertical-align: middle;
    }
    .vapt-generator-table input[type="text"],
    .vapt-generator-table select,
    .vapt-generator-table textarea {
        width: 100% !important;
        font-size: 13px !important;
        padding: 4px 8px !important;
        min-height: 30px !important;
    }
    .vapt-generator-table textarea {
        height: 50px !important;
    }

    /* Build History Table */
    .vapt-build-history {
        margin-top: 30px;
        border-top: 1px solid #ddd;
        padding-top: 20px;
    }
    .vapt-history-table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 15px;
        background: #fff;
        border-radius: 4px;
        overflow: hidden;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .vapt-history-table th, .vapt-history-table td {
        padding: 12px 15px;
        text-align: left;
        border-bottom: 1px solid #eee;
    }
    .vapt-history-table th {
        background: #f8f9fa;
        font-weight: 600;
        color: #1d2327;
        font-size: 13px;
    }
    .vapt-row-suspended td:not(:last-child) {
        opacity: 0.5;
    }
    .vapt-row-suspended {
        background: #f9f9f9;
    }
    .vapt-btn-disabled {
        opacity: 0.4 !important;
        pointer-events: none !important;
        cursor: not-allowed !important;
        filter: grayscale(1);
    }
    .vapt-build-id {
        font-family: monospace;
        background: #f0f0f1;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 11px;
    }

    /* Tabs Styling */
    .vapt-tabs-nav {
        margin: 20px 0 0 0;
        border-bottom: 1px solid #ccc;
        display: flex;
        gap: 5px;
    }
    .vapt-tab-link {
        padding: 10px 20px;
        background: #e5e5e5;
        border: 1px solid #ccc;
        border-bottom: none;
        cursor: pointer;
        font-weight: 600;
        color: #50575e;
        border-radius: 4px 4px 0 0;
        transition: all 0.2s ease;
        text-decoration: none;
    }
    .vapt-tab-link:hover {
        background: #f0f0f1;
        color: #2271b1;
    }
    .vapt-tab-link.active {
        background: #fff;
        color: #000;
        border-bottom: 1px solid #fff;
        margin-bottom: -1px;
    }
    .vapt-tab-content {
        display: none;
        animation: fadeIn 0.3s ease;
    }
    .vapt-tab-content.active {
        display: block;
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(5px); }
        to { opacity: 1; transform: translateY(0); }
    }

    /* Professional React-style Notice Container */
    #vapt-notice-container {
        position: fixed;
        top: 40px;
        right: 20px;
        z-index: 100000;
        width: 350px;
        display: flex;
        flex-direction: column;
        gap: 10px;
    }
    .vapt-professional-notice {
        background: #fff;
        border-left: 4px solid #2271b1;
        box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        padding: 15px 20px;
        border-radius: 4px;
        display: flex;
        justify-content: space-between;
        align-items: flex-start;
        animation: vapt-notice-slide 0.3s ease;
        position: relative;
    }
    .vapt-professional-notice.success { border-left-color: #00a32a; }
    .vapt-professional-notice.error { border-left-color: #d63638; }
    .vapt-professional-notice.warning { border-left-color: #dba617; }
    .vapt-professional-notice.info { border-left-color: #2271b1; }
    
    @keyframes vapt-notice-slide {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    .vapt-notice-content { flex-grow: 1; margin-right: 10px; }
    .vapt-notice-title { font-weight: 700; display: block; margin-bottom: 4px; font-size: 14px; }
    .vapt-notice-text { font-size: 13px; color: #50575e; line-height: 1.4; }
    .vapt-notice-close {
        background: transparent;
        border: none;
        cursor: pointer;
        color: #ccd0d4;
        padding: 0;
        line-height: 1;
        font-size: 20px;
    }
    .vapt-notice-close:hover { color: #1d2327; }

    /* Build Generation Loading Overlay */
    #vapt-build-loading-overlay {
        position: fixed;
        inset: 0;
        background: rgba(0, 0, 0, 0.55);
        z-index: 200000;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        gap: 20px;
        backdrop-filter: blur(3px);
    }
    #vapt-build-loading-overlay .vapt-spinner-box {
        background: #fff;
        border-radius: 10px;
        padding: 36px 48px;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 18px;
        box-shadow: 0 20px 50px rgba(0,0,0,0.3);
        min-width: 260px;
        text-align: center;
    }
    #vapt-build-loading-overlay .vapt-spinner-ring {
        width: 52px;
        height: 52px;
        border: 5px solid #e0e7ef;
        border-top-color: #2271b1;
        border-radius: 50%;
        animation: vapt-spin 0.8s linear infinite;
    }
    @keyframes vapt-spin {
        to { transform: rotate(360deg); }
    }
    #vapt-build-loading-overlay .vapt-spinner-title {
        font-size: 16px;
        font-weight: 700;
        color: #1d2327;
        margin: 0;
    }
    #vapt-build-loading-overlay .vapt-spinner-sub {
        font-size: 12px;
        color: #646970;
        margin: 0;
    }

    /* Custom Confirm Modal */
    .vapt-modal-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 100001;
        backdrop-filter: blur(2px);
    }
    .vapt-modal {
        background: #fff;
        border-radius: 12px;
        width: 480px;
        max-width: 90%;
        box-shadow: 0 25px 60px rgba(0,0,0,0.3);
        overflow: hidden;
    }
    .vapt-modal-header {
        background: linear-gradient(135deg, #1d2327 0%, #2c3338 100%);
        padding: 20px 24px;
        color: #fff;
        position: relative;
    }
    .vapt-modal-header h2 {
        margin: 0;
        font-size: 18px;
        font-weight: 600;
        color: #fff;
    }
    .vapt-modal-header p {
        margin: 6px 0 0 0;
        font-size: 13px;
        color: rgba(255,255,255,0.7);
    }
    .vapt-modal-header .vapt-modal-build-badge {
        display: inline-block;
        background: rgba(255,255,255,0.15);
        padding: 3px 10px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 12px;
        margin-top: 8px;
    }
    .vapt-modal-close {
        position: absolute;
        top: 16px;
        right: 16px;
        background: rgba(255,255,255,0.1);
        border: none;
        color: #fff;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 18px;
        line-height: 1;
        transition: background 0.2s;
    }
    .vapt-modal-close:hover {
        background: rgba(255,255,255,0.2);
    }
    .vapt-modal-body {
        padding: 24px;
    }
    .vapt-modal-section {
        margin-bottom: 20px;
    }
    .vapt-modal-section:last-child {
        margin-bottom: 0;
    }
    .vapt-modal-section-title {
        display: flex;
        align-items: center;
        gap: 8px;
        margin: 0 0 14px 0;
        font-size: 13px;
        font-weight: 600;
        color: #1d2327;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .vapt-modal-section-title .dashicons {
        font-size: 16px;
        width: 16px;
        height: 16px;
    }
    .vapt-modal-actions {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
    }
    .vapt-modal-actions .button {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 14px;
        font-size: 13px;
        border-radius: 6px;
        transition: all 0.2s;
    }
    .vapt-modal-actions .button .dashicons {
        font-size: 14px;
        width: 14px;
        height: 14px;
    }
    .vapt-modal-actions .button:hover {
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    .vapt-modal-custom-row {
        display: flex;
        gap: 10px;
        align-items: center;
        margin-top: 12px;
        padding-top: 12px;
        border-top: 1px solid #f0f0f1;
    }
    .vapt-modal-custom-row input[type="date"] {
        flex: 1;
        max-width: 180px;
    }
    .vapt-modal-description {
        margin: 8px 0 0 0;
        font-size: 12px;
        color: #787c82;
        font-style: italic;
    }
    .vapt-modal-danger-zone {
        background: #fef2f2;
        border: 1px solid #fecaca;
        border-radius: 8px;
        padding: 16px;
    }
    .vapt-modal-danger-zone .vapt-modal-section-title {
        color: #b91c1c;
    }
    .vapt-modal-danger-zone .vapt-modal-section-title .dashicons {
        color: #dc2626;
    }
    .vapt-modal-danger-zone .button {
        background: #fff;
        border-color: #dc2626;
        color: #dc2626;
    }
    .vapt-modal-danger-zone .button:hover {
        background: #dc2626;
        color: #fff;
    }
    .vapt-modal-footer {
        background: #f8f9fa;
        padding: 16px 24px;
        display: flex;
        justify-content: flex-end;
        border-top: 1px solid #e5e5e5;
    }
    .vapt-spin {
        animation: vapt-spin-anim 1s linear infinite;
    }
    @keyframes vapt-spin-anim {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
    }
    #vapt-tab-tracking .vapt-history-table td,
    #vapt-tab-tracking .vapt-history-table th {
        padding: 6px 5px;
    }
    #vapt-tab-tracking .vapt-vtabs {
        display: flex;
        gap: 18px;
        align-items: flex-start;
    }
    #vapt-tab-tracking .vapt-vtabs-nav {
        width: 230px;
        flex: 0 0 230px;
        background: #f6f7f7;
        border: 1px solid #dcdcde;
        border-radius: 10px;
        padding: 10px;
    }
    #vapt-tab-tracking .vapt-vtabs-nav a {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        border-radius: 8px;
        text-decoration: none;
        color: #1d2327;
        border: 1px solid transparent;
        background: transparent;
    }
    #vapt-tab-tracking .vapt-vtabs-nav a:hover {
        background: #fff;
    }
    #vapt-tab-tracking .vapt-vtabs-nav a.active {
        background: #fff;
        border-color: #dcdcde;
        box-shadow: 0 1px 2px rgba(0,0,0,0.04);
        font-weight: 600;
    }
    #vapt-tab-tracking .vapt-vtab-panel {
        display: none;
    }
    #vapt-tab-tracking .vapt-vtab-panel.active {
        display: block;
    }
    #vapt-tab-tracking .vapt-attempts-info {
        color: #2271b1;
        cursor: pointer;
        margin-left: 6px;
        vertical-align: middle;
    }
    #vapt-tab-tracking .vapt-attempts-info:hover {
        color: #135e96;
    }
    #vapt-tab-tracking .vapt-attempts-count {
        display: inline-block;
        margin-left: 8px;
        padding: 2px 8px;
        border-radius: 999px;
        font-size: 11px;
        font-weight: 600;
        line-height: 16px;
        border: 1px solid transparent;
    }
    #vapt-tab-tracking .vapt-attempts-count.vapt-attempts-ok {
        background: #edfaef;
        border-color: #b7e2c1;
        color: #008a20;
    }
    #vapt-tab-tracking .vapt-attempts-count.vapt-attempts-warn {
        background: #fff8e5;
        border-color: #f2c86a;
        color: #9a6a00;
    }
    #vapt-tab-tracking .vapt-next-exec-eta {
        color: #646970;
        font-size: 12px;
        margin-left: 6px;
        font-family: monospace;
        white-space: nowrap;
    }
    #vapt-tab-tracking .vapt-next-exec-eta.vapt-clickable {
        cursor: pointer;
        text-decoration: underline;
        text-decoration-style: dotted;
        text-underline-offset: 2px;
    }
</style>
<div id="vapt-notice-container"></div>

<!-- Build Generation Loading Overlay -->
<div id="vapt-build-loading-overlay" style="display:none;">
    <div class="vapt-spinner-box">
        <div class="vapt-spinner-ring"></div>
        <p class="vapt-spinner-title"><?php esc_html_e( 'Generating Client Buildâ€¦', 'vapt-security' ); ?></p>
        <p class="vapt-spinner-sub"><?php esc_html_e( 'Packaging plugin files. This may take a few seconds.', 'vapt-security' ); ?></p>
    </div>
</div>
<div class="wrap vapt-domain-admin-wrap">
    <h1>
        <?php esc_html_e( 'VAPT Security - Domain Admin', 'vapt-security' ); ?><small style="font-size: 11px; color: #a2aab2; font-weight: 500; margin-left: 4px; vertical-align: baseline;">v<?php echo esc_html( VAPT_VERSION ); ?></small>
    </h1>
    
    <?php if ( ! $is_verified ) : ?>
        <!-- OTP Verification (Automated Send) -->
        <div class="vapt-otp-container card" style="max-width: 400px; margin-top: 20px; padding: 20px;">
            <h2><?php esc_html_e( 'Superadmin Authentication', 'vapt-security' ); ?></h2>
            <p><?php esc_html_e( 'Verify your identity to manage Domain Features. An OTP has been sent to your email.', 'vapt-security' ); ?></p>
            
            <div id="vapt-otp-step-2" style="margin-top: 20px;">
                <input type="text" id="vapt-otp-input" class="regular-text" placeholder="------" maxlength="6" style="width: 100%; text-align: center; letter-spacing: 5px;" />
                <button type="button" id="vapt-verify-otp" class="button button-primary button-hero" style="width: 100%; margin-top: 10px;">
                    <?php esc_html_e( 'Verify', 'vapt-security' ); ?>
                </button>
                <div style="margin-top: 10px; text-align: center;">
                    <span id="vapt-otp-timer-container"><?php esc_html_e( 'Resend in', 'vapt-security' ); ?> <span id="vapt-otp-timer">120</span>s</span>
                    <a href="#" id="vapt-resend-otp" style="display:none;"><?php esc_html_e( 'Resend OTP', 'vapt-security' ); ?></a>
                </div>
            </div>
            <div id="vapt-otp-message" style="margin-top: 15px;"></div>
        </div>

    <?php else : 
        // Categorize Features
        $categories = [
            'protection' => [
                'title' => __( 'Critical Protection', 'vapt-security' ),
                'icon'  => 'dashicons-shield-alt',
                'items' => [ 'rate_limiting', 'input_validation', 'cron_protection', 'security_logging' ]
            ],
            'access' => [
                'title' => __( 'Access Control', 'vapt-security' ),
                'icon'  => 'dashicons-lock',
                'items' => [ 'login_protection', 'login_enum_protection', 'xmlrpc_protection', 'rest_api_protection' ]
            ],
            'hardening' => [
                'title' => __( 'System Hardening', 'vapt-security' ),
                'icon'  => 'dashicons-admin-settings',
                'items' => [ 'directory_listing', 'banner_grabbing', 'security_headers', 'debug_log_protection', 'readme_protection' ]
            ],
        ];

        $dashicons = [
            'rate_limiting'         => 'dashicons-performance',
            'input_validation'      => 'dashicons-forms',
            'cron_protection'       => 'dashicons-clock',
            'security_logging'      => 'dashicons-list-view',
            'login_protection'      => 'dashicons-lock',
            'login_enum_protection' => 'dashicons-admin-users',
            'xmlrpc_protection'     => 'dashicons-cloud',
            'rest_api_protection'   => 'dashicons-rest-api',
            'directory_listing'     => 'dashicons-category',
            'banner_grabbing'       => 'dashicons-shield',
            'security_headers'      => 'dashicons-external',
            'debug_log_protection'  => 'dashicons-visibility',
            'readme_protection'     => 'dashicons-media-text',
        ];
    ?>
        <!-- Verified Superadmin UI -->


        <div class="vapt-tabs-nav">
            <a href="#vapt-tab-features" class="vapt-tab-link active" data-tab="features"><?php esc_html_e( 'Domain Features', 'vapt-security' ); ?></a>
            <a href="#vapt-tab-generator" class="vapt-tab-link" data-tab="generator"><?php esc_html_e( 'Build Generator', 'vapt-security' ); ?></a>
            <a href="#vapt-tab-tracking" class="vapt-tab-link" data-tab="tracking"><?php esc_html_e( 'Build Tracking', 'vapt-security' ); ?></a>
        </div>

        <!-- Tab Content: Features -->
        <div id="vapt-tab-features" class="vapt-tab-content active">
            <div class="card" style="margin-top: 0; border-top: none; padding: 20px; border-radius: 0 0 4px 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <div>
                        <h2 style="margin: 0;"><?php esc_html_e( 'Domain Features', 'vapt-security' ); ?></h2>
                        <p class="description"><?php esc_html_e( 'Enable or disable features for this domain. Disabled features are hidden from Admins.', 'vapt-security' ); ?></p>
                    </div>
                    <button type="button" id="vapt-save-features-top" class="button button-primary button-hero vapt-save-features-btn"><?php esc_html_e( 'Save Changes', 'vapt-security' ); ?></button>
                </div>
                
                <form id="vapt-domain-features-form">
                    <?php foreach ( $categories as $cat_id => $cat ) : ?>
                        <h3 class="vapt-category-title">
                            <span class="dashicons <?php echo esc_attr( $cat['icon'] ); ?>"></span>
                            <?php echo esc_html( $cat['title'] ); ?>
                        </h3>
                        <div class="vapt-feature-grid">
                            <?php foreach( $cat['items'] as $slug ) : 
                                if ( ! isset( $all_features[$slug] ) ) continue;
                                $display_name = isset($csv_names[$slug]) ? $csv_names[$slug] : ucwords( str_replace( '_', ' ', $slug ) );
                                $is_active = VAPT_Features::is_enabled( $slug );
                                $icon = isset($dashicons[$slug]) ? $dashicons[$slug] : 'dashicons-admin-generic';
                            ?>
                            <div class="vapt-feature-card <?php echo $is_active ? 'active' : ''; ?>">
                                <div class="vapt-feature-header">
                                    <div class="vapt-feature-icon">
                                        <span class="dashicons <?php echo esc_attr( $icon ); ?>"></span>
                                    </div>
                                    <div class="vapt-feature-info">
                                        <h4 title="<?php echo esc_attr($display_name); ?>"><?php echo esc_html( $display_name ); ?></h4>
                                    </div>
                                </div>
                                <div class="vapt-feature-footer">
                                    <span class="vapt-feature-status"><?php echo $is_active ? __( 'Active', 'vapt-security' ) : __( 'Inactive', 'vapt-security' ); ?></span>
                                    <label class="switch">
                                        <input type="checkbox" class="vapt-feature-toggle" name="features[<?php echo esc_attr( $slug ); ?>]" value="1" <?php checked( $is_active ); ?>>
                                        <span class="slider round"></span>
                                    </label>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                    
                    <p style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #f0f0f1;">
                        <button type="button" class="button button-primary button-hero vapt-save-features-btn"><?php esc_html_e( 'Save Domain Features', 'vapt-security' ); ?></button>
                        <span id="vapt-features-msg" style="margin-left: 15px; font-weight: 500;"></span>
                    </p>
                </form>
            </div>
        </div>

        <!-- Tab Content: Generator -->
        <div id="vapt-tab-generator" class="vapt-tab-content">
            <div class="vapt-admin-row" style="margin-top: 0;">
                <div class="card" style="width: 100%; margin: 0; padding: 20px; border-top: none; border-radius: 0 0 4px 4px;">
                    <h2><?php esc_html_e( 'Locked Configuration Generator', 'vapt-security' ); ?></h2>
                    <p class="description"><?php esc_html_e( 'Generate a portable configuration file locked to a specific domain pattern and customize plugin branding.', 'vapt-security' ); ?></p>
                    
                    <div class="vapt-generator-grid">
                        <!-- Column 1: Core Lock Settings -->
                        <div>
                            <h3 style="margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-lock"></span>
                                <?php esc_html_e( 'Core Lock Settings', 'vapt-security' ); ?>
                            </h3>
                            <table class="form-table vapt-generator-table" style="margin-top: 0;">
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Lock Type', 'vapt-security' ); ?></th>
                                    <td>
                                        <select id="vapt-lock-type" style="width: 100%;">
                                            <option value="domain"><?php esc_html_e( 'Domain', 'vapt-security' ); ?></option>
                                            <option value="ip"><?php esc_html_e( 'IPv4 Address', 'vapt-security' ); ?></option>
                                        </select>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row" id="vapt-lock-value-label"><?php esc_html_e( 'Domain Pattern', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-lock-value" class="regular-text" 
                                            placeholder="*.example.com" 
                                            value="<?php 
                                                $host = $_SERVER['HTTP_HOST'] ?? '';
                                                echo esc_attr($host); 
                                            ?>" 
                                            style="width: 100%;">
                                        <input type="hidden" id="vapt-build-id-tracking" value="">
                                        <p class="description" id="vapt-lock-value-desc" style="font-size: 11px; margin-top: 5px;"><?php esc_html_e( 'Use * for wildcards (e.g., *.example.com).', 'vapt-security' ); ?></p>
                                    </td>
                                </tr>
                                <tr id="vapt-domain-type-row">
                                    <th scope="row"><?php esc_html_e( 'Domain Type', 'vapt-security' ); ?></th>
                                    <td>
                                        <select id="vapt-domain-type" style="width: 100%;">
                                            <option value="standard"><?php esc_html_e( 'Standard - Full Match', 'vapt-security' ); ?></option>
                                            <option value="wildcard"><?php esc_html_e( 'Wildcard - Contains Match', 'vapt-security' ); ?></option>
                                            <option value="universal"><?php esc_html_e( 'Universal - Any Domain', 'vapt-security' ); ?></option>
                                        </select>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Single Instance', 'vapt-security' ); ?></th>
                                    <td>
                                        <label style="display: flex; align-items: center; gap: 8px; cursor: pointer;">
                                            <input type="checkbox" id="vapt-single-instance">
                                            <span><?php esc_html_e( 'Restrict to one server at a time (IP-based)', 'vapt-security' ); ?></span>
                                        </label>
                                        <p class="description" style="font-size: 11px; margin-top: 5px;"><?php esc_html_e( 'Once activated, this build can only run on the first server that uses it.', 'vapt-security' ); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'License Type', 'vapt-security' ); ?></th>
                                    <td>
                                        <select id="vapt-lock-license-type" style="width: 100%;">
                                            <option value="trial">Trial (7 days)</option>
                                            <option value="demo">Demo Build (15 days)</option>
                                            <option value="standard" style="font-weight: bold;">Standard (30 days) [Default]</option>
                                            <option value="pro">Pro (365 days)</option>
                                            <option value="developer">Developer/Perpetual (Never)</option>
                                        </select>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Expiry Date', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-lock-license-expiry" value="<?php echo esc_attr( $future_expiries['standard'] ); ?>" readonly class="regular-text" style="width: 100%; background: #f0f0f1;">
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Auto Renewal', 'vapt-security' ); ?></th>
                                    <td>
                                        <div style="display: flex; align-items: center; gap: 20px;">
                                            <div style="display: flex; align-items: center; gap: 8px;">
                                                <label class="switch">
                                                    <input type="checkbox" id="vapt-lock-license-auto-renew">
                                                    <span class="slider round"></span>
                                                </label>
                                            </div>
                                            <div style="display: flex; align-items: center; gap: 6px; background: #f0f6fb; padding: 4px 10px; border-radius: 6px; border: 1px solid #d0e2f1;">
                                                <span style="font-weight: 600; font-size: 11px; color: #2271b1; text-transform: uppercase;"><?php esc_html_e( 'Terms Renewed:', 'vapt-security' ); ?></span>
                                                <span id="vapt-lock-renewal-count" style="font-weight: 700; font-size: 13px; color: #1d2327;"><?php echo isset($license['renewal_count']) ? esc_html($license['renewal_count']) : '0'; ?></span>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Settings', 'vapt-security' ); ?></th>
                                    <td>
                                        <label>
                                            <input type="checkbox" id="vapt-lock-include-settings" checked>
                                            <?php esc_html_e( 'Export current configuration', 'vapt-security' ); ?>
                                        </label>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Tracking Mode', 'vapt-security' ); ?></th>
                                    <td>
                                        <select id="vapt-lock-tracking-mode" style="width: 100%;">
                                            <option value="production" <?php selected( ! $this->is_local_environment() ); ?>><?php esc_html_e( 'Production (vaptsecure.net)', 'vapt-security' ); ?></option>
                                            <option value="local" <?php selected( $this->is_local_environment() ); ?>><?php esc_html_e( 'This Install (local master)', 'vapt-security' ); ?></option>
                                            <option value="custom"><?php esc_html_e( 'Custom URL', 'vapt-security' ); ?></option>
                                        </select>
                                        <p class="description" style="font-size: 11px; margin-top: 5px;">
                                            <?php esc_html_e( 'Determines where the client build sends tracking heartbeats.', 'vapt-security' ); ?>
                                        </p>
                                    </td>
                                </tr>
                                <tr id="vapt-custom-url-wrapper" style="display: none;">
                                    <th scope="row"><?php esc_html_e( 'Custom URL', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-lock-custom-url" placeholder="http://192.168.1.100:10004/wp-admin/admin-ajax.php" style="width: 100%;">
                                        <p class="description" style="font-size: 11px; margin-top: 5px;">
                                            <?php esc_html_e( 'Override the tracking endpoint. Useful if local .local domains cannot be resolved between sites.', 'vapt-security' ); ?>
                                        </p>
                                    </td>
                                </tr>
                            </table>
                        </div>

                        <!-- Column 2: White Labeling -->
                        <div>
                            <h3 style="margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; display: flex; align-items: center; gap: 8px;">
                                <span class="dashicons dashicons-art"></span>
                                <?php esc_html_e( 'White Labeling', 'vapt-security' ); ?>
                            </h3>
                            <table class="form-table vapt-generator-table" style="margin-top: 0;">
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Plugin Name', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-name" class="regular-text" placeholder="VAPT Security" style="width: 100%;">
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Slug', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-slug" class="regular-text" readonly style="width: 100%; background: #f0f0f1;">
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Author', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-author" class="regular-text" placeholder="Your Name" style="width: 100%;">
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Company', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-company" class="regular-text" placeholder="Your Company" style="width: 100%;">
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Description', 'vapt-security' ); ?></th>
                                    <td>
                                        <textarea id="vapt-wl-description" class="regular-text" style="width: 100%; height: 60px;" placeholder="<?php esc_attr_e( 'Plugin description...', 'vapt-security' ); ?>"></textarea>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Build Version', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-version" class="regular-text" value="1.0.0" style="width: 100%;">
                                        <div id="vapt-version-suggestion-wrapper" style="margin-top: 5px; font-size: 11px; display: none;">
                                            <?php esc_html_e( 'Suggested:', 'vapt-security' ); ?> 
                                            <button type="button" id="vapt-version-apply-suggestion" class="button-link" style="font-size: 11px; vertical-align: baseline;"></button>
                                        </div>
                                        <p class="description" style="font-size: 11px; margin-top: 5px;"><?php esc_html_e( 'Track per-domain build versions.', 'vapt-security' ); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Min WP Version', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-wp-version" class="regular-text" placeholder="5.6" value="5.6" style="width: 100%;">
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Min PHP Version', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-wl-php-version" class="regular-text" placeholder="8.0" value="8.0" style="width: 100%;">
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>

                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                        <button type="button" id="vapt-generate-locked-config" class="button button-primary" style="height: 40px; padding: 0 20px;"><?php esc_html_e( 'Generate Config File', 'vapt-security' ); ?></button>
                        <button type="button" id="vapt-generate-client-zip" class="button button-secondary" style="height: 40px; padding: 0 20px;">
                            <?php esc_html_e( 'Generate Client Build', 'vapt-security' ); ?>
                        </button>
                        <label style="display:flex; align-items:center; gap:8px; font-size:13px; color:#50575e; cursor:pointer; margin-left:6px;">
                            <label class="switch" style="margin:0;">
                                <input type="checkbox" id="vapt-include-callback-test">
                                <span class="slider round"></span>
                            </label>
                            <?php esc_html_e( 'Include Callback Test', 'vapt-security' ); ?>
                        </label>
                        <div id="vapt-generate-msg" style="flex-grow: 1; font-weight: 500;"></div>
                    </div>

                    <!-- Build History Section -->
                    <div class="vapt-build-history">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h3 style="margin: 0;"><?php esc_html_e( 'Build History & Logs', 'vapt-security' ); ?></h3>
                            <div style="display: flex; gap: 10px;">
                                <button type="button" id="vapt-export-selected" class="button button-secondary">
                                    <span class="dashicons dashicons-upload" style="margin-top: 4px;"></span>
                                    <span class="vapt-btn-text"><?php esc_html_e( 'Export Logs', 'vapt-security' ); ?></span>
                                </button>
                                <button type="button" id="vapt-import-history-btn" class="button button-secondary">
                                    <span class="dashicons dashicons-download" style="margin-top: 4px;"></span>
                                    <span><?php esc_html_e( 'Import Logs', 'vapt-security' ); ?></span>
                                </button>
                                <input type="file" id="vapt-import-history-file" style="display: none;" accept=".json">
                            </div>
                        </div>
                        <table class="vapt-history-table" id="vapt-history-table">
                            <thead>
                                     <tr>
                                         <th style="width: 30px;"><input type="checkbox" id="vapt-select-all-builds"></th>
                                         <th><?php esc_html_e( 'Build ID', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Domain', 'vapt-security' ); ?></th>
                                         <th style="font-size: 11px; text-transform: capitalize; color: #666;"><?php esc_html_e( 'Type', 'vapt-security' ); ?></th>
                                          <th>Lock</th>
                                          <th>Single</th>
                                         <th><?php esc_html_e( 'Plugin Name', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Version', 'vapt-security' ); ?></th>
                                         <th><span class="badge" style="background: #2271b1; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 10px;"><?php esc_html_e( 'License', 'vapt-security' ); ?></span></th>
                                         <th style="font-size: 11px; color: #666; width: 80px;"><?php esc_html_e( 'Auto-Renew', 'vapt-security' ); ?></th>
                                         <th style="font-size: 11px; color: #666; width: 90px;"><?php esc_html_e( 'Terms Renewed', 'vapt-security' ); ?></th>
                                         <th style="font-size: 11px; color: #666;"><?php esc_html_e( 'Date', 'vapt-security' ); ?></th>
                                         <th style="font-size: 11px; color: #666;"><?php esc_html_e( 'Expires', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                                     </tr>
                            </thead>
                            <tbody>
                                <?php 
                                $build_history = get_option( 'vapt_build_history', [] );
                                if ( empty( $build_history ) ) : ?>
                                    <tr class="no-builds">
                                        <td colspan="14" style="text-align: center; color: #999; padding: 30px;">
                                            <?php esc_html_e( 'No builds generated yet.', 'vapt-security' ); ?>
                                        </td>
                                    </tr>
                                <?php else : 
                                    // Show last 10 builds
                                    $history = array_reverse( $build_history );
                                    $history = array_slice( $history, 0, 10 );
                                    foreach ( $history as $build ) : 
                                        $filename = !empty($build['filename']) ? $build['filename'] : '';
                                        if ( empty($filename) ) {
                                            // Fallback for older logs without filename
                                            $safe_domain = preg_replace( '/[^a-zA-Z0-9\-\.]/', '-', $build['domain'] );
                                            $safe_domain = trim( $safe_domain, '-' );
                                            $filename = ($build['type'] === 'zip') ? "vapt-security-{$safe_domain}.zip" : "vapt-{$safe_domain}-locked-config.php";
                                        }
                                        
                                        $sub_dir = ($build['type'] === 'zip') ? 'releases/builds/' : 'releases/configurations/';
                                        $file_path = plugin_dir_path( __FILE__ ) . '../' . $sub_dir . $filename;
                                        $file_exists = !empty($filename) && file_exists( $file_path );
                                        $download_url = $file_exists ? plugins_url( $sub_dir . $filename, dirname(__FILE__) . '/../vapt-security.php' ) : '';
                                        $lock_icon = !empty($build["lock_type"]) ? "dashicons-lock" : "dashicons-unlock";
                                        $single_icon = !empty($build["single_instance"]) ? "dashicons-yes" : "dashicons-no";
                                    ?>
                                        <tr class="<?php echo (isset($build['status']) && $build['status'] === 'suspended') ? 'vapt-row-suspended' : ''; ?>">
                                            <td><input type="checkbox" class="vapt-build-checkbox" value="<?php echo esc_attr( $build['id'] ); ?>"></td>
                                            <td><span class="vapt-build-id"><?php echo esc_html( $build['id'] ); ?></span></td>
                                             <td><?php echo esc_html( $build['domain'] ); ?></td>
                                             <td style="font-size: 11px; text-transform: capitalize; color: #666;"><?php echo esc_html( $build['domain_type'] ?? 'standard' ); ?></td>
                                              <td style="font-size: 11px; color: #666; text-align: center;"><span class="dashicons <?php echo esc_attr( $lock_icon ); ?>"></span></td>                                              <td style="font-size: 11px; color: #666; text-align: center;"><span class="dashicons <?php echo esc_attr( $single_icon ); ?>"></span></td>
                                              <td style="font-size: 11px; color: #666; text-align: center;"><span class="dashicons <?php echo esc_attr( $single_icon ); ?>"></span></td>
                                             <td><?php echo esc_html( $build['name'] ); ?></td>
                                             <td><?php echo esc_html( $build['version'] ); ?></td>
                                             <td><span class="badge" style="background: #2271b1; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 10px;"><?php echo esc_html( strtoupper($build['license']) ); ?></span></td>
                                             <td style="font-size: 11px; color: #666; width: 80px;">
                                                <?php echo ! empty( $build['auto_renew'] ) ? esc_html__( 'Yes', 'vapt-security' ) : esc_html__( 'No', 'vapt-security' ); ?>
                                             </td>
                                             <td style="font-size: 11px; color: #666; width: 90px;">
                                                 <?php echo esc_html( $build['renewal_count'] ?? 0 ); ?>
                                             </td>
                                             <td style="font-size: 11px; color: #666;">
                                                 <?php 
                                                     if ( empty($build['expires']) || $build['license'] === 'developer' ) {
                                                         echo esc_html__( 'Never', 'vapt-security' );
                                                     } else {
                                                        echo esc_html( wp_date( get_option( 'date_format' ), $build['expires'], wp_timezone() ) );
                                                     }
                                                 ?>
                                             </td>
                                            <td style="display: flex; gap: 5px; align-items: center;">
                                                <?php 
                                                $is_suspended = (isset($build['status']) && $build['status'] === 'suspended');
                                                $disabled_class = $is_suspended ? ' vapt-btn-disabled' : '';
                                                ?>
                                                <?php if ( $file_exists ) : ?>
                                                    <a href="<?php echo esc_url( $download_url ); ?>" class="button button-small<?php echo $disabled_class; ?>" download title="<?php echo ($build['type'] === 'zip') ? esc_attr__( 'Download ZIP Package', 'vapt-security' ) : esc_attr__( 'Download Config File', 'vapt-security' ); ?>" style="padding: 0 6px;">
                                                        <span class="dashicons <?php echo ($build['type'] === 'zip') ? 'dashicons-archive' : 'dashicons-download'; ?>" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                                    </a>
                                                <?php endif; ?>
                                                <button type="button" class="button button-small vapt-edit-build<?php echo $disabled_class; ?>" 
                                                     data-id="<?php echo esc_attr($build['id']); ?>" 
                                                     data-domain="<?php echo esc_attr($build['domain']); ?>"
                                                     data-lock-type="<?php echo esc_attr($build['lock_type'] ?? 'domain'); ?>"
                                                     data-lock-value="<?php echo esc_attr($build['lock_value'] ?? $build['domain']); ?>"
                                                     data-single-instance="<?php echo esc_attr( ! empty($build['single_instance']) ? '1' : '0' ); ?>"
                                                     data-domain-type="<?php echo esc_attr($build['domain_type'] ?? 'standard'); ?>"
                                                     data-license-type="<?php echo esc_attr($build['license']); ?>"
                                                     data-name="<?php echo esc_attr($build['name']); ?>"
                                                     data-version="<?php echo esc_attr($build['version']); ?>"
                                                     data-author="<?php echo esc_attr($build['white_label']['author'] ?? ''); ?>"
                                                     data-company="<?php echo esc_attr($build['white_label']['company'] ?? ''); ?>"
                                                     data-desc="<?php echo esc_attr($build['white_label']['description'] ?? ''); ?>"
                                                     data-wp="<?php echo esc_attr($build['white_label']['requires_at_least'] ?? '5.6'); ?>"
                                                     data-php="<?php echo esc_attr($build['white_label']['requires_php'] ?? '8.0'); ?>"
                                                     data-tracking-mode="<?php echo esc_attr($build['tracking_mode'] ?? 'production'); ?>"
                                                     data-custom-url="<?php echo esc_attr($build['integrity_url'] ?? ''); ?>"
                                                     data-callback-test="<?php echo esc_attr( ! empty( $build['callback_test'] ) ? '1' : '0' ); ?>"
                                                     data-auto-renew="<?php echo esc_attr( ! empty( $build['auto_renew'] ) ? '1' : '0' ); ?>"
                                                     data-renewal-count="<?php echo esc_attr( $build['renewal_count'] ?? 0 ); ?>"
                                                    title="<?php esc_attr_e( 'Edit/Reuse settings', 'vapt-security' ); ?>" style="padding: 0 6px;">
                                                    <span class="dashicons dashicons-edit" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                                </button>

                                                <button type="button" class="button button-small vapt-export-single" 
                                                    data-id="<?php echo esc_attr($build['id']); ?>" 
                                                    title="<?php esc_attr_e( 'Export Record', 'vapt-security' ); ?>" style="padding: 0 6px;">
                                                    <span class="dashicons dashicons-upload" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                                </button>
                                                <div class="vapt-action-group" style="display: flex; gap: 2px; border-left: 1px solid #eee; padding-left: 5px; margin-left: 2px;">
                                                    <?php if ( $is_suspended ) : ?>
                                                        <button type="button" class="button button-small vapt-suspend-build" 
                                                            data-id="<?php echo esc_attr($build['id']); ?>" 
                                                            data-status="suspended"
                                                            style="color: #2271b1; padding: 0 6px;" 
                                                            title="<?php esc_attr_e( 'Resume Build', 'vapt-security' ); ?>">
                                                            <span class="dashicons dashicons-undo" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                                        </button>
                                                        <button type="button" class="button button-small vapt-delete-build" 
                                                            data-id="<?php echo esc_attr($build['id']); ?>" 
                                                            style="color: #d63638; padding: 0 6px;" 
                                                            title="<?php esc_attr_e( 'Purge Record', 'vapt-security' ); ?>">
                                                            <span class="dashicons dashicons-trash" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                                        </button>
                                                    <?php else : ?>
                                                        <button type="button" class="button button-small vapt-suspend-build" 
                                                            data-id="<?php echo esc_attr($build['id']); ?>" 
                                                            data-status="active"
                                                            style="color: #46b450; padding: 0 6px;" 
                                                            title="<?php esc_attr_e( 'Suspend Build', 'vapt-security' ); ?>">
                                                            <span class="dashicons dashicons-lock" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span>
                                                        </button>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                    <?php endforeach; endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- Tab Content: Tracking -->
        <div id="vapt-tab-tracking" class="vapt-tab-content">
            <div class="card" style="padding: 20px; border-top: none;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <div>
                        <h2 style="margin: 0;"><?php esc_html_e( 'Build Installation Monitor', 'vapt-security' ); ?></h2>
                        <p class="description"><?php esc_html_e( 'Real-time tracking of generated builds across client domains.', 'vapt-security' ); ?></p>
                    </div>
                </div>

                <div class="vapt-vtabs">
                    <div class="vapt-vtabs-nav">
                        <a href="#" class="vapt-tracking-vtab active" data-vtab="monitor">
                            <span class="dashicons dashicons-visibility"></span>
                            <?php esc_html_e( 'Installation Monitor', 'vapt-security' ); ?>
                        </a>
                        <a href="#" class="vapt-tracking-vtab" data-vtab="queue">
                            <span class="dashicons dashicons-schedule"></span>
                            <?php esc_html_e( 'Queued Request', 'vapt-security' ); ?>
                        </a>
                    </div>

                    <div style="flex: 1;">
                        <div id="vapt-tracking-panel-monitor" class="vapt-vtab-panel active">
                            <div id="vapt-callback-result" style="display:none; margin-bottom: 20px; border-radius: 6px; overflow: hidden; border: 1px solid #e0e0e0; font-size: 13px;">
                                <div id="vapt-callback-result-header" style="padding: 12px 16px; font-weight: 700; display:flex; align-items:center; gap:8px;">
                                    <span id="vapt-callback-result-icon" style="font-size:18px;"></span>
                                    <span id="vapt-callback-result-title"></span>
                                </div>
                                <div style="padding: 14px 16px; background: #fafafa; border-top: 1px solid #e0e0e0;">
                                    <table style="width:100%; border-collapse:collapse; font-size:12px; font-family:monospace;">
                                        <tr><td style="padding:3px 12px 3px 0; color:#646970; white-space:nowrap; font-family:sans-serif;"><?php esc_html_e( 'Target URL', 'vapt-security' ); ?></td><td id="vcr-url" style="padding:3px 0; word-break:break-all;"></td></tr>
                                        <tr><td style="padding:3px 12px 3px 0; color:#646970; white-space:nowrap; font-family:sans-serif;"><?php esc_html_e( 'Tracking Mode', 'vapt-security' ); ?></td><td id="vcr-mode" style="padding:3px 0;"></td></tr>
                                        <tr><td style="padding:3px 12px 3px 0; color:#646970; white-space:nowrap; font-family:sans-serif;"><?php esc_html_e( 'Build ID', 'vapt-security' ); ?></td><td id="vcr-build-id" style="padding:3px 0;"></td></tr>
                                        <tr><td style="padding:3px 12px 3px 0; color:#646970; white-space:nowrap; font-family:sans-serif;"><?php esc_html_e( 'HTTP Status', 'vapt-security' ); ?></td><td id="vcr-status" style="padding:3px 0;"></td></tr>
                                        <tr><td style="padding:3px 12px 3px 0; color:#646970; white-space:nowrap; font-family:sans-serif;"><?php esc_html_e( 'SSL Verify', 'vapt-security' ); ?></td><td id="vcr-ssl" style="padding:3px 0;"></td></tr>
                                    </table>
                                    <div style="margin-top:10px;">
                                        <div style="font-size:11px; color:#646970; margin-bottom:4px; font-family:sans-serif;"><?php esc_html_e( 'Raw Response', 'vapt-security' ); ?></div>
                                        <pre id="vcr-body" style="margin:0; padding:8px; background:#fff; border:1px solid #e0e0e0; border-radius:4px; font-size:11px; max-height:120px; overflow:auto; white-space:pre-wrap; word-break:break-all;"></pre>
                                    </div>
                                </div>
                            </div>

                            <div style="margin-bottom: 10px;">
                                <button id="vapt-ping-selected" class="button" disabled>
                                    <span class="dashicons dashicons-update" style="margin-top:4px;"></span> <?php esc_html_e( 'Ping Selected', 'vapt-security' ); ?>
                                </button>
                            </div>

                            <table id="vapt-tracking-table" class="vapt-history-table" style="margin-top: 20px;">
                                <thead>
                                    <tr>
                                         <th style="width: 20px;"><?php esc_html_e( '#', 'vapt-security' ); ?></th>
                                         <th style="width: 20px;"><input type="checkbox" id="vapt-select-all-tracking"></th>
                                         <th><?php esc_html_e( 'Build ID', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Plugin Name', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Domain / IP', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'License', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Status', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Install', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Activation', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Auto-Renew', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Terms Renewed', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Expiry', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Last Seen', 'vapt-security' ); ?></th>
                                         <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr><td colspan="14" style="text-align:center; padding: 30px; color: #999;"><?php esc_html_e( 'Loading...', 'vapt-security' ); ?></td></tr>
                                </tbody>
                            </table>
                        </div>

                        <div id="vapt-tracking-panel-queue" class="vapt-vtab-panel">
                            <div style="margin-top: 2px; margin-bottom: 10px;">
                                <h3 style="margin: 0 0 6px 0;"><?php esc_html_e( 'Queued Requests', 'vapt-security' ); ?></h3>
                                <p class="description" style="margin: 0;"><?php esc_html_e( 'Requests waiting to be delivered on the next client check-in. Next execution time is estimated from the last heartbeat.', 'vapt-security' ); ?></p>
                            </div>

                            <?php
                                $vapt_auto_pause_seconds = absint( get_option( 'vapt_auto_pause_overdue_seconds', defined( 'VAPT_AUTO_PAUSE_OVERDUE_SECONDS' ) ? VAPT_AUTO_PAUSE_OVERDUE_SECONDS : ( 20 * MINUTE_IN_SECONDS ) ) );
                                if ( $vapt_auto_pause_seconds < 60 ) $vapt_auto_pause_seconds = 60;
                                $vapt_auto_pause_minutes = (int) max( 1, round( $vapt_auto_pause_seconds / 60 ) );
                            ?>
                            <div style="display:flex; align-items:center; gap:10px; padding:10px 12px; background:#f6f7f7; border:1px solid #dcdcde; border-radius:8px; margin-top: 10px;">
                                <div style="font-weight:600; font-size:12px;"><?php esc_html_e( 'Auto-Pause Window', 'vapt-security' ); ?></div>
                                <label style="display:flex; align-items:center; gap:8px; font-size:12px; color:#1d2327;">
                                    <?php esc_html_e( 'Pause after', 'vapt-security' ); ?>
                                    <input type="number" id="vapt-auto-pause-minutes" min="1" step="1" value="<?php echo esc_attr( (string) $vapt_auto_pause_minutes ); ?>" style="width:90px;">
                                    <?php esc_html_e( 'minutes overdue', 'vapt-security' ); ?>
                                </label>
                                <button type="button" class="button" id="vapt-save-auto-pause-window"><?php esc_html_e( 'Save', 'vapt-security' ); ?></button>
                                <span style="color:#646970; font-size:12px;"><?php esc_html_e( 'Auto-resumes when the client checks in again.', 'vapt-security' ); ?></span>
                            </div>

                            <table id="vapt-queued-requests-table" class="vapt-history-table" style="margin-top: 16px;">
                                <thead>
                                    <tr>
                                        <th><?php esc_html_e( 'Build ID', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Domain', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Requests', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Queued At', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Last Execution Result', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Next Execution', 'vapt-security' ); ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr><td colspan="6" style="text-align:center; padding: 30px; color: #999;"><?php esc_html_e( 'Loading...', 'vapt-security' ); ?></td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Remote Management Modal -->
        <div id="vapt-manage-modal" class="vapt-modal-overlay" style="display:none;">
            <div class="vapt-modal">
                <div class="vapt-modal-header">
                    <button type="button" class="vapt-modal-close" id="vapt-close-manage">&times;</button>
                    <h2><?php esc_html_e( 'Manage Remote Build', 'vapt-security' ); ?></h2>
                    <p style="margin-bottom: 12px;"><span id="vapt-manage-domain"></span></p>
                    <div style="display: flex; align-items: center; gap: 16px; padding: 10px 14px; background: rgba(0,0,0,0.2); border-radius: 6px; margin-top: 4px;">
                        <span class="vapt-modal-build-badge" style="margin: 0;"><span id="vapt-manage-build-id"></span></span>
                        <span id="vapt-manage-license-type" style="background: rgba(255,255,255,0.2); padding: 3px 10px; border-radius: 4px; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;"></span>
                        <span style="color: rgba(255,255,255,0.4);">|</span>
                        <span style="font-size: 12px; color: rgba(255,255,255,0.8); display: flex; align-items: center; gap: 6px;">
                            <span class="dashicons dashicons-calendar-alt" style="font-size: 14px; width: 14px; height: 14px; opacity: 0.7;"></span>
                            <?php esc_html_e( 'Expires:', 'vapt-security' ); ?> <span id="vapt-manage-license-expiry" style="font-weight: 500;"></span>
                        </span>
                    </div>
                </div>
                <div class="vapt-modal-body">
                    <!-- Extend License Section -->
                    <div class="vapt-modal-section" id="vapt-extend-section">
                        <h4 class="vapt-modal-section-title">
                            <span class="dashicons dashicons-update"></span>
                            <?php esc_html_e( 'Extend License Term', 'vapt-security' ); ?>
                        </h4>
                        <div class="vapt-modal-actions" id="vapt-extend-buttons">
                            <button type="button" class="button button-primary vapt-push-action" data-action="EXTEND" data-val="term">
                                <span class="dashicons dashicons-clock"></span>
                                <?php esc_html_e( 'Add Full Term', 'vapt-security' ); ?>
                            </button>
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="7">
                                <span class="dashicons dashicons-plus-alt2"></span>
                                <?php esc_html_e( '7 Days', 'vapt-security' ); ?>
                            </button>
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="15">
                                <span class="dashicons dashicons-plus-alt2"></span>
                                <?php esc_html_e( '15 Days', 'vapt-security' ); ?>
                            </button>
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="30">
                                <span class="dashicons dashicons-plus-alt2"></span>
                                <?php esc_html_e( '30 Days', 'vapt-security' ); ?>
                            </button>
                        </div>
                        <div class="vapt-modal-custom-row">
                            <input type="text" id="vapt-custom-expiry" class="regular-text" placeholder="<?php echo esc_attr( wp_date( get_option( 'date_format' ), time(), wp_timezone() ) ); ?>">
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="" id="vapt-apply-custom-term">
                                <span class="dashicons dashicons-yes"></span>
                                <?php esc_html_e( 'Apply', 'vapt-security' ); ?>
                            </button>
                            <label style="display: flex; align-items: center; gap: 5px; font-size: 12px; color: #666; cursor: pointer; margin-left: 8px;">
                                <input type="checkbox" id="vapt-toggle-license-type">
                                <?php esc_html_e( 'Change License', 'vapt-security' ); ?>
                            </label>
                        </div>
                        <p class="vapt-modal-description"><?php esc_html_e( 'Adds time to current expiry. Client receives an email confirmation.', 'vapt-security' ); ?></p>
                    </div>

                    <!-- Change License Type Section (hidden by default) -->
                    <div class="vapt-modal-section" id="vapt-change-type-section" style="display: none; background: #f8f9fa; border: 1px solid #e5e5e5; border-radius: 8px; padding: 16px;">
                        <h4 class="vapt-modal-section-title">
                            <span class="dashicons dashicons-admin-generic"></span>
                            <?php esc_html_e( 'Change License Type', 'vapt-security' ); ?>
                        </h4>
                        <div style="display: flex; gap: 10px; align-items: center;">
                            <select id="vapt-change-license-type" class="regular-text" style="flex: 1; max-width: 200px;">
                                <option value="trial"><?php esc_html_e( 'Trial (7 days)', 'vapt-security' ); ?></option>
                                <option value="demo"><?php esc_html_e( 'Demo (15 days)', 'vapt-security' ); ?></option>
                                <option value="standard"><?php esc_html_e( 'Standard (30 days)', 'vapt-security' ); ?></option>
                                <option value="pro"><?php esc_html_e( 'Pro (365 days)', 'vapt-security' ); ?></option>
                                <option value="developer"><?php esc_html_e( 'Developer (365 days)', 'vapt-security' ); ?></option>
                            </select>
                            <button type="button" class="button" id="vapt-apply-license-type">
                                <span class="dashicons dashicons-yes"></span>
                                <?php esc_html_e( 'Apply', 'vapt-security' ); ?>
                            </button>
                        </div>
                        <p class="vapt-modal-description"><?php esc_html_e( 'Changes the license type and sets expiry based on the selected term.', 'vapt-security' ); ?></p>
                    </div>

                    <!-- Danger Zone -->
                    <div class="vapt-modal-danger-zone">
                        <h4 class="vapt-modal-section-title">
                            <span class="dashicons dashicons-warning"></span>
                            <?php esc_html_e( 'Danger Zone', 'vapt-security' ); ?>
                        </h4>
                        <button type="button" class="button vapt-push-action" data-action="SUSPEND">
                            <span class="dashicons dashicons-controls-pause"></span>
                            <?php esc_html_e( 'Suspend Remote Build', 'vapt-security' ); ?>
                        </button>
                        <p class="vapt-modal-description"><?php esc_html_e( 'Immediately deactivates the plugin on the client site.', 'vapt-security' ); ?></p>
                    </div>
                </div>
                <div class="vapt-modal-footer">
                    <button type="button" class="button" id="vapt-close-manage-footer"><?php esc_html_e( 'Close', 'vapt-security' ); ?></button>
                </div>
            </div>
        </div>
    <?php endif; ?>
</div>

<script>
jQuery(document).ready(function($) {
    let timerInterval;

    const vaptNotify = {
        show: function(type, title, text, duration = 5000) {
            const container = $('#vapt-notice-container');
            const id = 'notice-' + Math.random().toString(36).substr(2, 9);
            const html = `
                <div id="${id}" class="vapt-professional-notice ${type}">
                    <div class="vapt-notice-content">
                        <span class="vapt-notice-title">${title}</span>
                        <span class="vapt-notice-text">${text}</span>
                    </div>
                    <button class="vapt-notice-close">&times;</button>
                </div>
            `;
            container.append(html);
            const notice = $(`#${id}`);
            notice.find('.vapt-notice-close').click(() => notice.remove());
            if (duration > 0) {
                setTimeout(() => notice.fadeOut(300, () => notice.remove()), duration);
            }
        },
        success: function(title, text) { this.show('success', title, text); },
        error: function(title, text) { this.show('error', title, text); },
        warning: function(title, text) { this.show('warning', title, text); },
        info: function(title, text) { this.show('info', title, text); },
        confirm: function(title, text, onConfirm, onCancel, confirmLabel, cancelLabel) {
            confirmLabel = confirmLabel || 'Confirm';
            cancelLabel  = cancelLabel  || 'Cancel';
            const overlay = $(`
                <div class="vapt-modal-overlay">
                    <div class="vapt-modal">
                        <div class="vapt-modal-header"><h2>${title}</h2></div>
                        <div class="vapt-modal-body">${text}</div>
                        <div class="vapt-modal-footer">
                            <button class="button vapt-cancel">${cancelLabel}</button>
                            <button class="button button-primary vapt-confirm">${confirmLabel}</button>
                        </div>
                    </div>
                </div>
            `);
            $('body').append(overlay);
            overlay.find('.vapt-cancel').click(() => {
                overlay.remove();
                if (typeof onCancel === 'function') onCancel();
            });
            overlay.find('.vapt-confirm').click(() => {
                overlay.remove();
                if (typeof onConfirm === 'function') onConfirm();
            });
        }
    };

    function startOtpTimer() {
        let timeLeft = 120;
        $('#vapt-otp-timer').text(timeLeft);
        $('#vapt-otp-timer-container').show();
        $('#vapt-resend-otp').hide();
        
        clearInterval(timerInterval);
        timerInterval = setInterval(function() {
            timeLeft--;
            $('#vapt-otp-timer').text(timeLeft);
            if(timeLeft <= 0) {
                clearInterval(timerInterval);
                $('#vapt-otp-timer-container').hide();
                $('#vapt-resend-otp').show();
            }
        }, 1000);
    }

    // Auto-send OTP on load if not verified
    function autoSendOtp() {
        $.post(ajaxurl, {action:'vapt_send_otp'}, function(r){
            if(r.success) {
                $('#vapt-otp-message').html('<span style="color:green">'+r.data.message+'</span>');
                startOtpTimer();
            } else {
                $('#vapt-otp-message').html('<span style="color:red">'+r.data.message+'</span>');
            }
        });
    }

    if ($('#vapt-otp-input').length > 0) {
        autoSendOtp();
    }

    // Resend Logic
    $('#vapt-resend-otp').click(function(e){
        e.preventDefault();
        
        // Disable buttons temporarily
        $(this).prop('disabled', true);
        
        $.post(ajaxurl, {action:'vapt_send_otp'}, function(r){
             // Re-enable (for send btn)
            $('#vapt-send-otp').prop('disabled', false);

            if(r.success) {
                $('#vapt-otp-step-1').hide();
                $('#vapt-otp-step-2').show();
                $('#vapt-otp-message').html('<span style="color:green">'+r.data.message+'</span>');
                startOtpTimer();
            } else {
                $('#vapt-otp-message').html('<span style="color:red">'+r.data.message+'</span>');
            }
        });
    });

    $('#vapt-verify-otp').click(function(){
        $.post(ajaxurl, {
            action:'vapt_verify_otp', 
            otp: $('#vapt-otp-input').val()
        }, function(r){
            if(r.success) location.reload();
            else $('#vapt-otp-message').html('<span style="color:red">'+r.data.message+'</span>');
        });
    });

        // Update active tab logic to use sessionStorage instead of URL hash
        $('.vapt-tab-link').click(function(e){
            e.preventDefault();
            var tabId = $(this).data('tab');
            
            $('.vapt-tab-link').removeClass('active');
            $(this).addClass('active');
            
            $('.vapt-tab-content').removeClass('active');
            $('#vapt-tab-' + tabId).addClass('active');
            
            // Persist tab state without cluttering URL
            sessionStorage.setItem('vapt_active_tab', tabId);

            if (tabId === 'tracking') {
                vaptRefreshTrackingTable();
                vaptRefreshQueuedRequestsTable();
            }
        });

        // Persistence on reload
        var savedTab = sessionStorage.getItem('vapt_active_tab');
        if(savedTab) {
            $('.vapt-tab-link[data-tab="' + savedTab + '"]').click();
        }

    // Save Features
    $('.vapt-save-features-btn').click(function(){
        var btn = $(this);
        var originalText = btn.text();
        btn.prop('disabled', true).text('<?php esc_html_e( 'Saving...', 'vapt-security' ); ?>');
        
        var data = $('#vapt-domain-features-form').serialize();
        $.post(ajaxurl, {
            action: 'vapt_save_domain_features',
            data: data
        }, function(r){
            btn.prop('disabled', false).text(originalText);
            if(r.success) {
                $('#vapt-features-msg').html('<span style="color:green">'+r.data.message+'</span>');
                setTimeout(function(){ $('#vapt-features-msg').fadeOut(); }, 3000);
            }
            else $('#vapt-features-msg').html('<span style="color:red">'+r.data.message+'</span>');
        });
    });

    // Real-time visual feedback for toggles
    $('.vapt-feature-toggle').change(function(){
        var card = $(this).closest('.vapt-feature-card');
        var status = card.find('.vapt-feature-status');
        if($(this).is(':checked')) {
            card.addClass('active');
            status.text('<?php echo esc_js( __( 'Active', 'vapt-security' ) ); ?>');
        } else {
            card.removeClass('active');
            status.text('<?php echo esc_js( __( 'Inactive', 'vapt-security' ) ); ?>');
        }
    });

    // Locked Config Generator
    // Real-time Expiry and License Type logic for the Generator
    var futureExpiries = <?php echo json_encode( $future_expiries ); ?>;

    $('#vapt-lock-license-type').change(function(){
        var type = $(this).val();
        if ( futureExpiries[type] ) {
            $('#vapt-lock-license-expiry').val( futureExpiries[type] );
        }
        
        // Developer/Universal Constraint
        if ( type === 'developer' ) {
            $('#vapt-lock-license-auto-renew').prop('checked', false).prop('disabled', true);
        } else {
            $('#vapt-lock-license-auto-renew').prop('disabled', false);
        }
    });

    // Lock Type logic (domain or ip)
    var currentServerIP = '<?php echo esc_js( $_SERVER['SERVER_ADDR'] ?? '' ); ?>';

    function updateLockTypeDisplay() {
        var type = $('#vapt-lock-type').val();
        if (type === 'ip') {
            // IP mode
            $('#vapt-lock-value-label').text('<?php echo esc_js( __( 'IPv4 Address', 'vapt-security' ) ); ?>');
            $('#vapt-lock-value').attr('placeholder', '192.168.1.1').val(currentServerIP);
            $('#vapt-lock-value-desc').text('<?php echo esc_js( __( 'Enter a valid IPv4 address to lock this build.', 'vapt-security' ) ); ?>');
            $('#vapt-domain-type-row').hide();
        } else {
            // Domain mode
            $('#vapt-lock-value-label').text('<?php echo esc_js( __( 'Domain Pattern', 'vapt-security' ) ); ?>');
            $('#vapt-lock-value').attr('placeholder', '*.example.com').val('<?php echo esc_js( esc_attr( $_SERVER['HTTP_HOST'] ?? '' ) ); ?>');
            $('#vapt-lock-value-desc').text('<?php echo esc_js( __( 'Use * for wildcards (e.g., *.example.com).', 'vapt-security' ) ); ?>');
            $('#vapt-domain-type-row').show();
        }
    }

    $('#vapt-lock-type').change(updateLockTypeDisplay);
    updateLockTypeDisplay(); // Initial call to set correct display on load

    // Tracking Mode logic
    $('#vapt-lock-tracking-mode').change(function(){
        var mode = $(this).val();
        if ( mode === 'custom' ) {
            $('#vapt-custom-url-wrapper').show();
        } else {
            $('#vapt-custom-url-wrapper').hide();
        }
    });

    // Version suggestion logic
    function suggestNextVersion(current) {
        if (!current) return 'v1.0.0';
        var hasV = current.charAt(0).toLowerCase() === 'v';
        var version = hasV ? current.substring(1) : current;
        
        if (!version.match(/^\d+\.\d+\.\d+$/)) return hasV ? 'v1.0.0' : '1.0.0';
        
        var parts = version.split('.').map(Number);
        parts[2]++; // Default to patch bump
        return (hasV ? 'v' : '') + parts.join('.');
    }

    function updateVersionSuggestion(version) {
        if (version) {
            var next = suggestNextVersion(version);
            $('#vapt-version-apply-suggestion').text(next);
            $('#vapt-version-suggestion-wrapper').show();
        } else {
            $('#vapt-version-suggestion-wrapper').hide();
        }
    }

    $('#vapt-version-apply-suggestion').click(function() {
        var next = $(this).text();
        $('#vapt-wl-version').val(next);
        updateVersionSuggestion(next);
    });

    $('#vapt-lock-value').on('change blur', function() {
        var lockValue = $(this).val();
        if (!lockValue || lockValue === '*') return;
        var lockType = $('#vapt-lock-type').val();

        $.post(ajaxurl, {
            action: 'vapt_get_last_build_version',
            domain: lockValue,
            lock_type: lockType,
            nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        }, function(r) {
            if (r.success && r.data.version) {
                updateVersionSuggestion(r.data.version);
            } else {
                updateVersionSuggestion('1.0.0');
            }
        });
    }).trigger('blur');

    $('#vapt-wl-version').on('input', function() {
        updateVersionSuggestion($(this).val());
    });

    $('#vapt-wl-name').on('input', function() {
        var name = $(this).val();
        var slug = name.toLowerCase()
            .replace(/[^\w\s-]/g, '') // Remove non-word chars
            .replace(/\s+/g, '-')     // Replace spaces with -
            .replace(/-+/g, '-')      // Replace multiple - with single -
            .trim();
        $('#vapt-wl-slug').val(slug);
    });

    $('#vapt-generate-locked-config').click(function(){
        var btn = $(this);
        var originalText = btn.text();
        btn.prop('disabled', true).text('<?php esc_html_e( 'Generating...', 'vapt-security' ); ?>');
        
        $.post(ajaxurl, {
            action: 'vapt_generate_locked_config',
            edit_id: $('#vapt-build-id-tracking').val(),
            lock_type: $('#vapt-lock-type').val(),
            lock_value: $('#vapt-lock-value').val(),
            single_instance: $('#vapt-single-instance').is(':checked') ? 1 : 0,
            domain_type: $('#vapt-domain-type').val(),
            license_type: $('#vapt-lock-license-type').val(),
            auto_renew: $('#vapt-lock-license-auto-renew').is(':checked') ? 1 : 0,
            include_settings: $('#vapt-lock-include-settings').is(':checked') ? 1 : 0,
            include_callback_test: $('#vapt-include-callback-test').is(':checked') ? 1 : 0,
            wl_name: $('#vapt-wl-name').val(),
            wl_slug: $('#vapt-wl-slug').val(),
            wl_description: $('#vapt-wl-description').val(),
            wl_author: $('#vapt-wl-author').val(),
            wl_company: $('#vapt-wl-company').val(),
            wl_version: $('#vapt-wl-version').val(),
            wl_wp_version: $('#vapt-wl-wp-version').val(),
            wl_php_version: $('#vapt-wl-php-version').val(),
            tracking_mode: $('#vapt-lock-tracking-mode').val(),
            custom_url: $('#vapt-lock-custom-url').val(),
            nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        }, function(r){
            btn.prop('disabled', false).text(originalText);
            if(r.success) {
                vaptNotify.success('<?php echo esc_js( __( 'Success', 'vapt-security' ) ); ?>', r.data.message);
                refreshHistoryTable(); // Refresh table immediately
            } else {
                vaptNotify.error('<?php echo esc_js( __( 'Error', 'vapt-security' ) ); ?>', r.data.message);
            }
        })
        .fail(function(){
            btn.prop('disabled', false).text(originalText);
            vaptNotify.error('<?php echo esc_js( __( 'Connection Error', 'vapt-security' ) ); ?>', '<?php echo esc_js( __( 'Request failed. Please try again.', 'vapt-security' ) ); ?>');
        });
    });

    // Helper: actually fire the generate-client-zip AJAX with optional overwrite flags
    function doGenerateClientZip(extraParams) {
        var params = {
            action: 'vapt_generate_client_zip',
            edit_id: $('#vapt-build-id-tracking').val(),
            lock_type: $('#vapt-lock-type').val(),
            lock_value: $('#vapt-lock-value').val(),
            single_instance: $('#vapt-single-instance').is(':checked') ? 1 : 0,
            domain_type: $('#vapt-domain-type').val(),
            license_type: $('#vapt-lock-license-type').val(),
            auto_renew: $('#vapt-lock-license-auto-renew').is(':checked') ? 1 : 0,
            include_settings: $('#vapt-lock-include-settings').is(':checked') ? 1 : 0,
            include_callback_test: $('#vapt-include-callback-test').is(':checked') ? 1 : 0,
            wl_name: $('#vapt-wl-name').val(),
            wl_slug: $('#vapt-wl-slug').val(),
            wl_description: $('#vapt-wl-description').val(),
            wl_author: $('#vapt-wl-author').val(),
            wl_company: $('#vapt-wl-company').val(),
            wl_version: $('#vapt-wl-version').val(),
            wl_wp_version: $('#vapt-wl-wp-version').val(),
            wl_php_version: $('#vapt-wl-php-version').val(),
            tracking_mode: $('#vapt-lock-tracking-mode').val(),
            custom_url: $('#vapt-lock-custom-url').val(),
            nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        };
        $.extend(params, extraParams || {});
        return $.post(ajaxurl, params);
    }

    $('#vapt-generate-client-zip').click(function(){
        var btn = $(this);
        var originalText = btn.text();

        function startBuild(extraParams) {
            btn.prop('disabled', true).text('<?php esc_html_e( 'Generating Build...', 'vapt-security' ); ?>');
            $('#vapt-build-loading-overlay').fadeIn(200);

            doGenerateClientZip(extraParams)
            .done(function(r){
                $('#vapt-build-loading-overlay').fadeOut(200);
                btn.prop('disabled', false).text(originalText);

                if ( r.success && r.data.needs_confirm ) {
                    // Duplicate filename â€” ask user what to do
                    vaptNotify.confirm(
                        '<?php echo esc_js( __( 'File Already Exists', 'vapt-security' ) ); ?>',
                        r.data.message + '<br><br><?php echo esc_js( __( 'Choose: <strong>Overwrite</strong> replaces the existing file. <strong>Save as New</strong> appends a timestamp.', 'vapt-security' ) ); ?>',
                        function() {
                            // "Confirm" = Overwrite
                            startBuild({ confirm_overwrite: 1 });
                        },
                        function() {
                            // "Cancel" = Save as new
                            startBuild({ confirm_overwrite: 1, save_as_new: 1 });
                        },
                        '<?php echo esc_js( __( 'Overwrite', 'vapt-security' ) ); ?>',
                        '<?php echo esc_js( __( 'Save as New', 'vapt-security' ) ); ?>'
                    );
                    return;
                }

                if ( r.success ) {
                    vaptNotify.success(
                        '<?php echo esc_js( __( 'Build Ready', 'vapt-security' ) ); ?>',
                        r.data.message + (r.data.filename ? ' &mdash; <strong>' + r.data.filename + '</strong>' : '')
                    );
                    refreshHistoryTable();
                } else {
                    vaptNotify.error('<?php echo esc_js( __( 'Error', 'vapt-security' ) ); ?>', r.data.message);
                }
            })
            .fail(function(){
                $('#vapt-build-loading-overlay').fadeOut(200);
                btn.prop('disabled', false).text(originalText);
                vaptNotify.error('<?php echo esc_js( __( 'Connection Error', 'vapt-security' ) ); ?>', '<?php echo esc_js( __( 'Request failed. Please try again.', 'vapt-security' ) ); ?>');
            });
        }

        startBuild();
    });
    // Edit/Reuse Build Settings
    $(document).on('click', '.vapt-edit-build', function(){
        var btn = $(this);
        $('#vapt-build-id-tracking').val(btn.data('id')); // Track ID for update
        
        // Set lock type and value
        $('#vapt-lock-type').val(btn.data('lock-type')).trigger('change');
        $('#vapt-lock-value').val(btn.data('lock-value'));
        $('#vapt-single-instance').prop('checked', btn.data('single-instance') === '1' || btn.data('single-instance') === 1);
        
        // Set domain type (only relevant when lock_type === 'domain')
        $('#vapt-domain-type').val(btn.data('domain-type'));
        
        $('#vapt-lock-license-type').val(btn.data('license-type')).trigger('change');
        $('#vapt-lock-tracking-mode').val(btn.data('tracking-mode')).trigger('change');
        $('#vapt-lock-custom-url').val(btn.data('custom-url'));
        
        $('#vapt-wl-name').val(btn.data('name')).trigger('input');
        $('#vapt-wl-author').val(btn.data('author'));
        $('#vapt-wl-company').val(btn.data('company'));
        $('#vapt-wl-description').val(btn.data('desc'));
        $('#vapt-wl-version').val(btn.data('version')).trigger('input');
        $('#vapt-wl-wp-version').val(btn.data('wp'));
        $('#vapt-wl-php-version').val(btn.data('php'));
        
         // Pre-populate callback test checkbox
         $('#vapt-include-callback-test').prop('checked', btn.data('callback-test') === '1' || btn.data('callback-test') === true);
         // Pre-populate auto renew checkbox
         $('#vapt-lock-license-auto-renew').prop('checked', btn.data('auto-renew') === '1' || btn.data('auto-renew') === true);
         // Set renewal count (display only)
         $('#vapt-lock-renewal-count').text(btn.data('renewal-count'));
        
        // Scroll to top of generator
        $('html, body').animate({
            scrollTop: $("#vapt-tab-generator").offset().top - 100
        }, 500);
        
        // Visual feedback
        $('#vapt-generate-msg').html('<span style="color:blue"><?php esc_html_e( 'Settings loaded into generator.', 'vapt-security' ); ?></span>').fadeIn();
        setTimeout(function(){ $('#vapt-generate-msg').fadeOut(); }, 3000);
    });

    // Suspend/Resume Build
    $(document).on('click', '.vapt-suspend-build', function(){
        var btn = $(this);
        var id = btn.data('id');
        var currentStatus = btn.data('status');
        var actionText = (currentStatus === 'suspended') ? 'resume' : 'suspend';
        
        vaptNotify.confirm(
            '<?php echo esc_js( __( 'Action Confirmation', 'vapt-security' ) ); ?>', 
            '<?php echo esc_js( __( 'Are you sure you want to ', 'vapt-security' ) ); ?>' + actionText + '<?php echo esc_js( __( ' this build?', 'vapt-security' ) ); ?>',
            function() {
                btn.prop('disabled', true).css('opacity', '0.5');
                
                $.post(ajaxurl, {
                    action: 'vapt_toggle_build_status',
                    id: id,
                    nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
                }, function(r){
                    btn.prop('disabled', false).css('opacity', '1');
                    if(r.success) {
                        vaptNotify.success('<?php echo esc_js( __( 'Status Updated', 'vapt-security' ) ); ?>', r.data.message || 'Build status toggled successfully.');
                        var tr = btn.closest('tr');
                        var downloadBtn = tr.find('a.button-small');
                        var editBtn = tr.find('.vapt-edit-build');
                        
                        if(r.data.status === 'suspended') {
                            tr.addClass('vapt-row-suspended');
                            btn.data('status', 'suspended');
                            btn.attr('title', '<?php echo esc_js( __( 'Resume Build', 'vapt-security' ) ); ?>');
                            btn.find('.dashicons').removeClass('dashicons-lock').addClass('dashicons-undo');
                            btn.css('color', '#2271b1');
                            
                            // Add Purge button if it doesn't exist
                            if (tr.find('.vapt-delete-build').length === 0) {
                                var purgeBtn = $('<button type="button" class="button button-small vapt-delete-build" data-id="' + id + '" style="color: #d63638; padding: 0 6px;" title="<?php esc_attr_e( 'Purge Record', 'vapt-security' ); ?>"><span class="dashicons dashicons-trash" style="font-size: 16px; width: 16px; height: 16px; line-height: 16px; margin-top: 3px;"></span></button>');
                                btn.after(purgeBtn);
                            }
                            
                            downloadBtn.addClass('vapt-btn-disabled');
                            editBtn.addClass('vapt-btn-disabled');
                        } else {
                            tr.removeClass('vapt-row-suspended');
                            btn.data('status', 'active');
                            btn.attr('title', '<?php echo esc_js( __( 'Suspend Build', 'vapt-security' ) ); ?>');
                            btn.find('.dashicons').removeClass('dashicons-undo').addClass('dashicons-lock');
                            btn.css('color', '#46b450');
                            
                            // Remove Purge button
                            tr.find('.vapt-delete-build').remove();
                            
                            downloadBtn.removeClass('vapt-btn-disabled');
                            editBtn.removeClass('vapt-btn-disabled');
                        }
                    } else {
                        vaptNotify.error('<?php echo esc_js( __( 'Operation Failed', 'vapt-security' ) ); ?>', r.data.message || 'Error toggling status');
                    }
                });
            }
        );
    });

    // Delete Build from History (Purge)
    $(document).on('click', '.vapt-delete-build', function(){
        const btn = $(this);
        const id = btn.data('id');
        
        vaptNotify.confirm(
            '<?php echo esc_js( __( 'Purge Record', 'vapt-security' ) ); ?>', 
            '<?php echo esc_js( __( 'Are you sure you want to PURGE this build record? This cannot be undone.', 'vapt-security' ) ); ?>',
            function() {
                btn.prop('disabled', true).css('opacity', '0.5');
                
                $.post(ajaxurl, {
                    action: 'vapt_delete_build',
                    id: id,
                    nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
                }, function(r){
                    if(r.success) {
                        vaptNotify.success('<?php echo esc_js( __( 'Record Purged', 'vapt-security' ) ); ?>', r.data.message || 'Build record deleted successfully.');
                        btn.closest('tr').fadeOut(function(){ 
                            $(this).remove(); 
                            if($('#vapt-history-table tbody tr').length === 0) {
                                $('#vapt-history-table tbody').append('<tr class="no-builds"><td colspan="10" style="text-align: center; color: #999; padding: 30px;"><?php esc_html_e( 'No builds generated yet.', 'vapt-security' ); ?></td></tr>');
                            }
                        });
                    } else {
                        btn.prop('disabled', false).css('opacity', '1');
                        vaptNotify.error('<?php echo esc_js( __( 'Error', 'vapt-security' ) ); ?>', r.data.message || 'Error purging record');
                    }
                });
            }
        );
    });

    // Combine Export Logs (Selected or All)
    function refreshHistoryTable() {
        var table = $('#vapt-history-table');
        table.css('opacity', '0.5');
        $.post(ajaxurl, {
            action: 'vapt_get_history_table',
            nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        }, function(r) {
            table.css('opacity', '1');
            if(r.success) {
                table.find('tbody').html(r.data.html);
                // Trigger checkbox listener update if needed
                $('.vapt-build-checkbox').trigger('change');
            }
        })
        .fail(function() {
            table.css('opacity', '1');
            vaptNotify.error('<?php echo esc_js( __( 'Table Refresh Failed', 'vapt-security' ) ); ?>', '<?php echo esc_js( __( 'Could not update build history table. Please reload the page.', 'vapt-security' ) ); ?>');
        });
    }

    $('#vapt-export-selected').click(function() {
        var selected = [];
        $('.vapt-build-checkbox:checked').each(function() {
            selected.push($(this).val());
        });
        
        var btn = $(this);
        var originalHtml = btn.html();
        var exportText = (selected.length > 0) ? '<?php esc_html_e( 'Exporting Selected...', 'vapt-security' ); ?>' : '<?php esc_html_e( 'Exporting All...', 'vapt-security' ); ?>';
        btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> ' + exportText);

        $.post(ajaxurl, {
            action: 'vapt_export_build_history',
            ids: (selected.length > 0) ? selected : '',
            nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        }, function(r) {
            btn.prop('disabled', false).html(originalHtml);
            if(r.success) {
                vaptNotify.success('<?php echo esc_js( __( 'Export Complete', 'vapt-security' ) ); ?>', r.data.message);
            } else {
                vaptNotify.error('<?php echo esc_js( __( 'Export Failed', 'vapt-security' ) ); ?>', r.data.message || 'Error exporting logs');
            }
        });
    });

    // Export Single Record
    $(document).on('click', '.vapt-export-single', function() {
        var btn = $(this);
        var id = btn.data('id');
        var originalHtml = btn.html();
        btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span>');

        $.post(ajaxurl, {
            action: 'vapt_export_build_history',
            ids: [id],
            nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        }, function(r) {
            btn.prop('disabled', false).html(originalHtml);
            if(r.success) {
                vaptNotify.success('<?php echo esc_js( __( 'Export Complete', 'vapt-security' ) ); ?>', r.data.message);
            } else {
                vaptNotify.error('<?php echo esc_js( __( 'Export Failed', 'vapt-security' ) ); ?>', r.data.message || 'Error exporting record');
            }
        });
    });

    // Select All Checkbox
    $('#vapt-select-all-builds').change(function() {
        $('.vapt-build-checkbox').prop('checked', $(this).prop('checked')).trigger('change');
    });

    // Toggle Export Selected Button label
    $(document).on('change', '.vapt-build-checkbox', function() {
        var checkedCount = $('.vapt-build-checkbox:checked').length;
        var btn = $('#vapt-export-selected');
        var textSpan = btn.find('.vapt-btn-text');
        
        if (checkedCount > 0) {
            textSpan.text('<?php esc_html_e( 'Export Selected', 'vapt-security' ); ?> (' + checkedCount + ')');
            btn.addClass('button-primary').removeClass('button-secondary');
        } else {
            textSpan.text('<?php esc_html_e( 'Export Logs', 'vapt-security' ); ?>');
            btn.removeClass('button-primary').addClass('button-secondary');
        }
    });

    // Import Build History
    $('#vapt-import-history-btn').click(function() {
        $('#vapt-import-history-file').click();
    });

    // Repair/Recreate Build
    $(document).on('click', '.vapt-repair-build', function() {
        var btn = $(this);
        var id = btn.data('id');
        var type = btn.data('type');
        
        vaptNotify.confirm(
            'Repair Build', 
            'The physical build file is missing from the server. Would you like to recreate it using the stored metadata?',
            function() {
                btn.prop('disabled', true).css('opacity', '0.5');
                
                $.post(ajaxurl, {
                    action: 'vapt_repair_build',
                    id: id,
                    nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
                }, function(r) {
                    btn.prop('disabled', false).css('opacity', '1');
                    if (r.success) {
                        vaptNotify.success('Repair Successful', r.data.message || 'Build file has been recreated.');
                        refreshHistoryTable();
                    } else {
                        vaptNotify.error('Repair Failed', r.data.message || 'Could not recreate build file.');
                    }
                });
            }
        );
    });

    $('#vapt-import-history-file').change(function() {
        var file_data = $(this).prop('files')[0];
        if (!file_data) return;

        var form_data = new FormData();
        form_data.append('action', 'vapt_import_build_history');
        form_data.append('nonce', '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>');
        form_data.append('history_file', file_data);

        var btn = $('#vapt-import-history-btn');
        var originalHtml = btn.html();
        btn.prop('disabled', true).html('<span class="dashicons dashicons-update spin"></span> <?php esc_html_e( 'Importing...', 'vapt-security' ); ?>');

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: form_data,
            contentType: false,
            processData: false,
            success: function(r) {
                btn.prop('disabled', false).html(originalHtml);
                if (r.success) {
                    vaptNotify.success('<?php echo esc_js( __( 'Import Successful', 'vapt-security' ) ); ?>', r.data.message);
                    refreshHistoryTable();
                } else {
                    vaptNotify.error('<?php echo esc_js( __( 'Import Failed', 'vapt-security' ) ); ?>', r.data.message || 'Error importing history');
                }
            },
            error: function() {
                btn.prop('disabled', false).html(originalHtml);
                vaptNotify.error('<?php echo esc_js( __( 'Connection Error', 'vapt-security' ) ); ?>', 'Connection error during import');
            }
        });
        
        // Reset input
        $(this).val('');
    });

    // Remote Management Actions
    $(document).on('click', '.vapt-manage-build', function() {
        var btn = $(this);
        var bid = btn.data('id');
        var domain = btn.data('domain');
        var licenseType = btn.data('type');
        var licenseExpiry = btn.data('expiry');
        var licenseExpiryFormatted = btn.data('expiry-formatted');
        
        $('#vapt-manage-build-id').text(bid);
        $('#vapt-manage-domain').text(domain);
        $('#vapt-manage-license-type').text(licenseType.toUpperCase());
        
        if (licenseExpiryFormatted) {
            $('#vapt-manage-license-expiry').text(licenseExpiryFormatted);
        } else if (licenseExpiry && licenseExpiry > 0) {
            $('#vapt-manage-license-expiry').text(String(licenseExpiry));
        } else {
            $('#vapt-manage-license-expiry').text('Never');
        }
        
        // Pre-select current license type in dropdown
        $('#vapt-change-license-type').val(licenseType);
        
        $('.vapt-push-action').data('id', bid);
        
        $('#vapt-manage-modal').fadeIn(200);
    });

    $('#vapt-close-manage').click(function() {
        $('#vapt-manage-modal').fadeOut(200);
    });

    $('#vapt-close-manage-footer').click(function() {
        $('#vapt-manage-modal').fadeOut(200);
    });

    // Close modal when clicking outside
    $('#vapt-manage-modal').on('click', function(e) {
        if ($(e.target).is('.vapt-modal-overlay')) {
            $(this).fadeOut(200);
        }
    });

    // Toggle Change License Type section
    $('#vapt-toggle-license-type').on('change', function() {
        var isChecked = $(this).is(':checked');
        if (isChecked) {
            $('#vapt-change-type-section').slideDown(200);
            $('#vapt-extend-buttons .button').prop('disabled', true).css('opacity', '0.5');
            $('#vapt-apply-custom-term').prop('disabled', true).css('opacity', '0.5');
            $('#vapt-custom-expiry').prop('disabled', true).css('opacity', '0.5');
        } else {
            $('#vapt-change-type-section').slideUp(200);
            $('#vapt-extend-buttons .button').prop('disabled', false).css('opacity', '1');
            $('#vapt-apply-custom-term').prop('disabled', false).css('opacity', '1');
            $('#vapt-custom-expiry').prop('disabled', false).css('opacity', '1');
        }
    });

    $('#vapt-apply-custom-term').click(function() {
        var btn = $(this);
        var bid = btn.data('id');
        var customDate = $('#vapt-custom-expiry').val();
        
        if ( ! customDate ) {
            vaptNotify.error('Error', 'Please select a date first.');
            return;
        }
        
        var confirmMsg = 'Are you sure you want to set a custom expiry date of <strong>' + customDate + '</strong>?';
        vaptNotify.confirm('Custom Term', confirmMsg, function() {
            btn.prop('disabled', true).css('opacity', '0.5');
            
            $.post(ajaxurl, {
                action: 'vapt_push_remote_command',
                build_id: bid,
                cmd_type: 'EXTEND',
                cmd_val: customDate,
                nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
            }, function(r) {
                btn.prop('disabled', false).css('opacity', '1');
                if (r.success) {
                    vaptNotify.success('Success', r.data.message);
                } else {
                    vaptNotify.error('Action Failed', r.data.message);
                }
            });
        });
    });

    // Change License Type
    $('#vapt-apply-license-type').click(function() {
        var btn = $(this);
        var bid = $('.vapt-push-action').first().data('id');
        var newType = $('#vapt-change-license-type').val();
        
        if ( ! newType ) {
            vaptNotify.error('Error', 'Please select a license type.');
            return;
        }
        
        var confirmMsg = 'Are you sure you want to change the license type to <strong>' + newType.toUpperCase() + '</strong>? This will update the expiry date accordingly.';
        vaptNotify.confirm('Change License Type', confirmMsg, function() {
            btn.prop('disabled', true).css('opacity', '0.5');
            
            $.post(ajaxurl, {
                action: 'vapt_push_remote_command',
                build_id: bid,
                cmd_type: 'CHANGE_TYPE',
                cmd_val: newType,
                nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
            }, function(r) {
                btn.prop('disabled', false).css('opacity', '1');
                if (r.success) {
                    vaptNotify.success('Success', r.data.message);
                } else {
                    vaptNotify.error('Action Failed', r.data.message);
                }
            });
        });
    });

    $('.vapt-push-action').click(function() {
        var btn = $(this);
        var bid = btn.data('id');
        var action = btn.data('action');
        var val = btn.data('val');
        
        var confirmMsg = 'Are you sure you want to perform this remote action?';
        if (action === 'SUSPEND') confirmMsg = 'WARNING: This will remotely DEACTIVATE the plugin on the client site. Proceed?';

        vaptNotify.confirm('Remote Action', confirmMsg, function() {
            btn.prop('disabled', true).css('opacity', '0.5');
            
            $.post(ajaxurl, {
                action: 'vapt_push_remote_command',
                build_id: bid,
                cmd_type: action,
                cmd_val: val,
                nonce: '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
            }, function(r) {
                btn.prop('disabled', false).css('opacity', '1');
                if (r.success) {
                    vaptNotify.success('Success', r.data.message);
                    if (action === 'SUSPEND') $('#vapt-manage-modal').fadeOut();
                } else {
                    vaptNotify.error('Action Failed', r.data.message);
                }
            });
        });
    });

    // Include Callback Test toggle â€” state is baked into the generated config, no server save needed here

    // Dismiss callback test notice (session only â€” re-appears until config is regenerated without the toggle)
    $('#vapt-diag-dismiss-btn').click(function() {
        $('#vapt-callback-diag').slideUp(200);
    });

    // TEMP: Callback diagnostic â€” fires from client site to master
    $('#vapt-diag-ping-btn').click(function() {
        var btn = $(this);
        btn.prop('disabled', true).text('<?php echo esc_js( __( 'Testing...', 'vapt-security' ) ); ?>');

        $.post(ajaxurl, {
            action: 'vapt_force_ping',
            nonce:  '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>'
        }, function(r) {
            btn.prop('disabled', false).html('<span class="dashicons dashicons-networking" style="margin-top:3px;font-size:16px;width:16px;height:16px;line-height:16px;"></span> <?php echo esc_js( __( 'Test Callback to Master', 'vapt-security' ) ); ?>');

            var d       = r.data || {};
            var result  = $('#vapt-diag-ping-result');
            var rawBody = d.body || '';
            try { rawBody = JSON.stringify(JSON.parse(rawBody), null, 2); } catch(e) {}
            var metaStr = 'HTTP ' + (d.status || '?') + ' | SSL: ' + (d.sslverify ? 'on' : 'off');

            if (r.success && d.ok) {
                result.css('border-left', '3px solid #00a32a');
                $('#vapt-diag-icon').text('[OK]');
                $('#vapt-diag-title').text('<?php echo esc_js( __( 'Master acknowledged the ping.', 'vapt-security' ) ); ?>');
            } else if (r.success && !d.ok) {
                result.css('border-left', '3px solid #dba617');
                $('#vapt-diag-icon').text('[WARN]');
                $('#vapt-diag-title').text('<?php echo esc_js( __( 'Reached master but got unexpected response.', 'vapt-security' ) ); ?>');
            } else {
                result.css('border-left', '3px solid #d63638');
                $('#vapt-diag-icon').text('[FAIL]');
                $('#vapt-diag-title').text(d.message || '<?php echo esc_js( __( 'Connection failed.', 'vapt-security' ) ); ?>');
            }

            $('#vapt-diag-meta').text(metaStr);
            if (rawBody) { $('#vapt-diag-body').text(rawBody).show(); }
            result.slideDown(200);
        }).fail(function() {
            btn.prop('disabled', false).html('<span class="dashicons dashicons-networking" style="margin-top:3px;font-size:16px;width:16px;height:16px;line-height:16px;"></span> <?php echo esc_js( __( 'Test Callback to Master', 'vapt-security' ) ); ?>');
            vaptNotify.error('<?php echo esc_js( __( 'Connection Error', 'vapt-security' ) ); ?>', '<?php echo esc_js( __( 'AJAX request failed.', 'vapt-security' ) ); ?>');
        });
    });

    // === Refresh/Ping/Track Functionality ===

    var vaptTrackingNonce = '<?php echo wp_create_nonce( "vapt_locked_config" ); ?>';
    var vaptPostPingTimer = null;
    var vaptPostPingCount = 0;
    var vaptPostPingMax = 12; // 12 * 5s = 60s max

    function vaptSetTrackingVTab(tab) {
        $('.vapt-tracking-vtab').removeClass('active');
        $('.vapt-tracking-vtab[data-vtab="' + tab + '"]').addClass('active');

        $('#vapt-tracking-panel-monitor').removeClass('active');
        $('#vapt-tracking-panel-queue').removeClass('active');

        if (tab === 'queue') {
            $('#vapt-tracking-panel-queue').addClass('active');
            vaptRefreshQueuedRequestsTable();
        } else {
            $('#vapt-tracking-panel-monitor').addClass('active');
            vaptRefreshTrackingTable();
        }

        sessionStorage.setItem('vapt_tracking_vtab', tab);
    }

    $(document).on('click', '.vapt-tracking-vtab', function(e) {
        e.preventDefault();
        vaptSetTrackingVTab($(this).data('vtab'));
    });

    $(document).on('click', '#vapt-save-auto-pause-window', function(e) {
        e.preventDefault();
        var btn = $(this);
        var minutes = parseInt($('#vapt-auto-pause-minutes').val() || '0', 10);
        if (!minutes || minutes < 1) {
            vaptNotify.error('Error', 'Minutes must be at least 1.');
            return;
        }

        btn.prop('disabled', true);
        $.post(ajaxurl, {
            action: 'vapt_set_auto_pause_window',
            nonce: vaptTrackingNonce,
            minutes: minutes
        }, function(r) {
            btn.prop('disabled', false);
            if (r && r.success) {
                vaptNotify.success('Saved', (r.data && r.data.message) ? r.data.message : 'Saved');
                vaptRefreshQueuedRequestsTable();
            } else {
                vaptNotify.error('Error', (r && r.data && r.data.message) ? r.data.message : 'Failed');
            }
        }).fail(function() {
            btn.prop('disabled', false);
            vaptNotify.error('Error', 'AJAX request failed.');
        });
    });

    var savedTrackingVTab = sessionStorage.getItem('vapt_tracking_vtab');
    if (savedTrackingVTab) {
        vaptSetTrackingVTab(savedTrackingVTab);
    }

    function vaptRefreshTrackingTable(callback) {
        $.post(ajaxurl, {
            action: 'vapt_get_tracking_table',
            nonce: vaptTrackingNonce
        }, function(r) {
            if (r.success && r.data.html) {
                $('#vapt-tracking-table tbody').html(r.data.html);
            }
            if (typeof callback === 'function') callback(r);
        });
    }

    function vaptRefreshQueuedRequestsTable(callback) {
        $.post(ajaxurl, {
            action: 'vapt_get_queued_requests_table',
            nonce: vaptTrackingNonce
        }, function(r) {
            if (r.success && r.data.html) {
                $('#vapt-queued-requests-table tbody').html(r.data.html);
                $('#vapt-queued-requests-table .vapt-next-exec-eta').addClass('vapt-clickable');
                vaptUpdateNextExecCountdowns();
            }
            if (typeof callback === 'function') callback(r);
        });
    }

    function vaptFormatCountdown(seconds) {
        seconds = Math.max(0, parseInt(seconds || 0, 10));
        if (seconds <= 0) return 'now';
        if (seconds < 60) return seconds + 's';
        var mins = Math.floor(seconds / 60);
        var secs = seconds % 60;
        if (mins < 60) return mins + 'm ' + secs + 's';
        var hours = Math.floor(mins / 60);
        mins = mins % 60;
        if (hours < 24) return hours + 'h ' + mins + 'm';
        var days = Math.floor(hours / 24);
        hours = hours % 24;
        return days + 'd ' + hours + 'h';
    }

    function vaptUpdateNextExecCountdowns() {
        if (document.hidden) return;
        if (!$('#vapt-tab-tracking').is(':visible')) return;

        var now = Math.floor(Date.now() / 1000);
        $('#vapt-queued-requests-table .vapt-next-exec-eta').each(function() {
            var el = $(this);
            var ts = parseInt(el.data('next-ts') || 0, 10);
            if (String(el.data('paused') || '0') === '1') return;
            if (!ts) return;
            var diff = ts - now;
            if (diff > 0) {
                el.text('(in ' + vaptFormatCountdown(diff) + ')');
            } else if (diff === 0) {
                el.text('(now)');
            } else {
                el.text('(overdue ' + vaptFormatCountdown(Math.abs(diff)) + ')');
            }
        });
    }

    function vaptSetQueuePaused(buildId, paused, reason) {
        var action = paused ? 'vapt_pause_build_queue' : 'vapt_resume_build_queue';
        var payload = {
            action: action,
            build_id: buildId,
            nonce: vaptTrackingNonce
        };
        if (paused && reason) payload.reason = reason;

        return $.post(ajaxurl, payload);
    }

    function vaptShowQueueDecisionModal(buildId, details, paused) {
        details = details || [];
        details.sort(function(a, b) {
            var at = parseInt(a.ts || 0, 10);
            var bt = parseInt(b.ts || 0, 10);
            return bt - at;
        });

        var top = details[0] || {};
        var summary = top.message ? $('<div>').text(top.message).html() : 'No additional details available.';
        var reason = '';
        if (top.type === 'OVERDUE') reason = 'Client has not checked in when expected (estimate).';
        else if (top.type === 'DELIVERY') reason = 'Client checked in, but did not acknowledge results.';
        else if (top.type === 'PAUSED') reason = 'Attempts are currently paused.';

        var actionBtn = paused
            ? '<button class="button button-primary vapt-queue-resume">Continue Attempting</button>'
            : '<button class="button vapt-queue-pause">Pause Attempts</button>';

        var overlay = $(`
            <div class="vapt-modal-overlay">
                <div class="vapt-modal" style="max-width: 720px;">
                    <div class="vapt-modal-header" style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <h2 style="margin:0;">Queue Status</h2>
                            <div style="margin-top:4px; color:rgba(255,255,255,0.75); font-size:12px;">Build ID: <span style="font-family:monospace;">${buildId}</span></div>
                        </div>
                        <button type="button" class="vapt-modal-close" style="position:static;">&times;</button>
                    </div>
                    <div class="vapt-modal-body">
                        <div style="padding:10px 12px; border:1px solid #dcdcde; border-radius:8px; background:#fff;">
                            <div style="font-weight:600; margin-bottom:6px;">Reason</div>
                            <div style="color:#1d2327;">${reason}</div>
                            <div style="margin-top:8px; color:#646970;">${summary}</div>
                        </div>
                        <div style="margin-top:14px;">
                            <div style="font-weight:600; margin-bottom:8px;">Details (latest first)</div>
                            <div id="vapt-queue-details"></div>
                        </div>
                    </div>
                    <div class="vapt-modal-footer" style="display:flex; justify-content:flex-end; gap:10px;">
                        <button class="button vapt-cancel">Close</button>
                        ${actionBtn}
                    </div>
                </div>
            </div>
        `);

        var detailsHtml = '';
        if (!details.length) {
            detailsHtml = '<div style="color:#646970;">No details available.</div>';
        } else {
            detailsHtml = '<div style="display:flex; flex-direction:column; gap:10px;">' + details.map(function(d) {
                var when = d.when || '';
                var type = d.type || '';
                var msg  = d.message || '';
                return '<div style="padding:10px 12px; border:1px solid #dcdcde; border-radius:8px; background:#fff;">' +
                    '<div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start;">' +
                        '<div style="font-weight:600; color:#d63638;">' + $('<div>').text(type || 'INFO').html() + '</div>' +
                        '<div style="font-size:12px; color:#646970; white-space:nowrap;">' + $('<div>').text(when).html() + '</div>' +
                    '</div>' +
                    '<div style="margin-top:6px; color:#1d2327;">' + $('<div>').text(msg).html() + '</div>' +
                '</div>';
            }).join('') + '</div>';
        }

        $('body').append(overlay);
        overlay.find('#vapt-queue-details').html(detailsHtml);

        function close() { overlay.remove(); }
        overlay.find('.vapt-modal-close, .vapt-cancel').on('click', close);
        overlay.on('click', function(e) { if (e.target === overlay[0]) close(); });

        overlay.find('.vapt-queue-pause').on('click', function() {
            vaptSetQueuePaused(buildId, true, reason).done(function(r) {
                if (r && r.success) {
                    vaptNotify.info('Paused', r.data.message || 'Paused');
                    close();
                    vaptRefreshQueuedRequestsTable();
                } else {
                    vaptNotify.error('Error', (r && r.data && r.data.message) ? r.data.message : 'Failed');
                }
            }).fail(function() {
                vaptNotify.error('Error', 'AJAX request failed.');
            });
        });

        overlay.find('.vapt-queue-resume').on('click', function() {
            vaptSetQueuePaused(buildId, false).done(function(r) {
                if (r && r.success) {
                    vaptNotify.success('Resumed', r.data.message || 'Resumed');
                    close();
                    vaptRefreshQueuedRequestsTable();
                } else {
                    vaptNotify.error('Error', (r && r.data && r.data.message) ? r.data.message : 'Failed');
                }
            }).fail(function() {
                vaptNotify.error('Error', 'AJAX request failed.');
            });
        });
    }

    function vaptShowAttemptsDetailsModal(bid, details) {
        details = details || [];
        details.sort(function(a, b) {
            var at = parseInt(a.ts || 0, 10);
            var bt = parseInt(b.ts || 0, 10);
            return bt - at;
        });

        var listHtml = '';
        if (!details.length) {
            listHtml = '<div style="color:#646970;">No details available.</div>';
        } else {
            listHtml = '<div style="display:flex; flex-direction:column; gap:10px;">' + details.map(function(d) {
                var when = d.when || '';
                var type = d.type || '';
                var msg  = d.message || '';
                return '<div style="padding:10px 12px; border:1px solid #dcdcde; border-radius:8px; background:#fff;">' +
                    '<div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start;">' +
                        '<div style="font-weight:600; color:#d63638;">FAIL' + (type ? (' • ' + type) : '') + '</div>' +
                        '<div style="font-size:12px; color:#646970; white-space:nowrap;">' + when + '</div>' +
                    '</div>' +
                    '<div style="margin-top:6px; color:#1d2327;">' + $('<div>').text(msg).html() + '</div>' +
                '</div>';
            }).join('') + '</div>';
        }

        var overlay = $(`
            <div class="vapt-modal-overlay">
                <div class="vapt-modal" style="max-width: 720px;">
                    <div class="vapt-modal-header" style="display:flex; justify-content:space-between; align-items:center;">
                        <div>
                            <h2 style="margin:0;">Attempt Details</h2>
                            <div style="margin-top:4px; color:rgba(255,255,255,0.75); font-size:12px;">Build ID: <span style="font-family:monospace;">${bid}</span></div>
                        </div>
                        <button type="button" class="vapt-modal-close" style="position:static;">&times;</button>
                    </div>
                    <div class="vapt-modal-body">${listHtml}</div>
                </div>
            </div>
        `);

        $('body').append(overlay);
        overlay.find('.vapt-modal-close').on('click', function() { overlay.remove(); });
        overlay.on('click', function(e) { if (e.target === overlay[0]) overlay.remove(); });
    }

    $(document).on('click', '.vapt-attempts-info', function(e) {
        e.preventDefault();
        var el = $(this);
        var bid = el.data('bid') || '';
        var raw = el.attr('data-details') || '[]';
        var details = [];
        try { details = JSON.parse(raw); } catch (err) { details = []; }
        vaptShowAttemptsDetailsModal(bid, details);
    });

    $(document).on('click', '#vapt-queued-requests-table .vapt-next-exec-eta', function(e) {
        e.preventDefault();
        var el = $(this);
        var bid = el.data('bid') || '';
        var raw = el.attr('data-details') || '[]';
        var paused = String(el.data('paused') || '0') === '1';
        var details = [];
        try { details = JSON.parse(raw); } catch (err) { details = []; }
        vaptShowQueueDecisionModal(bid, details, paused);
    });

    setInterval(vaptUpdateNextExecCountdowns, 1000);

    function vaptStartPostPingRefresh() {
        vaptPostPingCount = 0;
        if (vaptPostPingTimer) clearInterval(vaptPostPingTimer);
        vaptPostPingTimer = setInterval(function() {
            vaptPostPingCount++;
            vaptRefreshTrackingTable();
            vaptRefreshQueuedRequestsTable();
            if (vaptPostPingCount >= vaptPostPingMax) {
                clearInterval(vaptPostPingTimer);
                vaptPostPingTimer = null;
            }
        }, 5000);
    }

    // Per-row refresh button
    $(document).on('click', '.vapt-refresh-build', function() {
        var btn = $(this);
        var bid = btn.data('id');
        var icon = btn.find('.dashicons');

        btn.prop('disabled', true);
        icon.addClass('vapt-spin');

        $.post(ajaxurl, {
            action: 'vapt_refresh_build_status',
            build_ids: bid,
            nonce: vaptTrackingNonce
        }, function(r) {
            icon.removeClass('vapt-spin');
            btn.prop('disabled', false);
            if (r.success) {
                vaptNotify.success('<?php echo esc_js( __( 'Ping Queued', 'vapt-security' ) ); ?>', r.data.message);
                vaptStartPostPingRefresh();
            } else {
                vaptNotify.error('<?php echo esc_js( __( 'Failed', 'vapt-security' ) ); ?>', r.data.message);
            }
        }).fail(function() {
            icon.removeClass('vapt-spin');
            btn.prop('disabled', false);
            vaptNotify.error('<?php echo esc_js( __( 'Error', 'vapt-security' ) ); ?>', '<?php echo esc_js( __( 'AJAX request failed.', 'vapt-security' ) ); ?>');
        });
    });

    // Select All checkbox
    $(document).on('change', '#vapt-select-all-tracking', function() {
        var checked = this.checked;
        $('.vapt-tracking-checkbox').prop('checked', checked);
        $('#vapt-ping-selected').prop('disabled', !checked);
    });

    // Individual checkbox change
    $(document).on('change', '.vapt-tracking-checkbox', function() {
        var total = $('.vapt-tracking-checkbox').length;
        var checked = $('.vapt-tracking-checkbox:checked').length;
        $('#vapt-select-all-tracking').prop('checked', total > 0 && total === checked);
        $('#vapt-ping-selected').prop('disabled', checked === 0);
    });

    // Bulk Ping Selected
    $('#vapt-ping-selected').on('click', function() {
        var btn = $(this);
        var ids = [];
        $('.vapt-tracking-checkbox:checked').each(function() {
            ids.push($(this).val());
        });
        if (!ids.length) return;

        btn.prop('disabled', true).text('<?php echo esc_js( __( 'Pinging...', 'vapt-security' ) ); ?>');

        $.post(ajaxurl, {
            action: 'vapt_refresh_build_status',
            build_ids: ids.join(','),
            nonce: vaptTrackingNonce
        }, function(r) {
            btn.prop('disabled', false).html('<span class="dashicons dashicons-update" style="margin-top:4px;"></span> <?php echo esc_js( __( 'Ping Selected', 'vapt-security' ) ); ?>');
            if (r.success) {
                vaptNotify.success('<?php echo esc_js( __( 'Queued', 'vapt-security' ) ); ?>', r.data.message);
                vaptStartPostPingRefresh();
            } else {
                vaptNotify.error('<?php echo esc_js( __( 'Failed', 'vapt-security' ) ); ?>', r.data.message);
            }
        }).fail(function() {
            btn.prop('disabled', false).html('<span class="dashicons dashicons-update" style="margin-top:4px;"></span> <?php echo esc_js( __( 'Ping Selected', 'vapt-security' ) ); ?>');
            vaptNotify.error('<?php echo esc_js( __( 'Error', 'vapt-security' ) ); ?>', '<?php echo esc_js( __( 'AJAX request failed.', 'vapt-security' ) ); ?>');
        });
    });

    // Passive auto-refresh every 6 hours
    setInterval(function() {
        if (!document.hidden && $('#vapt-tab-tracking').is(':visible')) {
            vaptRefreshTrackingTable();
            vaptRefreshQueuedRequestsTable();
        }
    }, 6 * 60 * 60 * 1000);

});
</script>
