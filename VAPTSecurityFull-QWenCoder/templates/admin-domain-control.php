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
$expiry_date = $license_expires ? date_i18n( get_option( 'date_format' ), $license_expires ) : __( 'Never', 'vapt-security' );

// Get Active Features
$features = VAPT_Features::get_active_features();
$all_features = VAPT_Features::get_defined_features();

// Pre-calculate future expiries for JS
$base_time = ! empty( $license['start'] ) ? $license['start'] : time();
$future_expiries = [
    'standard' => date_i18n( get_option( 'date_format' ), $base_time + ( 30 * DAY_IN_SECONDS ) ),
    'pro'      => date_i18n( get_option( 'date_format' ), $base_time + ( 365 * DAY_IN_SECONDS ) ),
    'developer' => __( 'Never', 'vapt-security' ),
    'trial' => date_i18n( get_option( 'date_format' ), $base_time + ( 7 * DAY_IN_SECONDS ) ),
    'demo'  => date_i18n( get_option( 'date_format' ), $base_time + ( 15 * DAY_IN_SECONDS ) ),
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
        width: 110px !important;
        min-width: 110px !important;
        padding: 4px 0 !important;
        font-size: 12px;
        vertical-align: middle;
        color: #646970;
    }
    .vapt-generator-table td {
        padding: 4px 0 !important;
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
        border-radius: 8px;
        width: 450px;
        max-width: 90%;
        padding: 25px;
        box-shadow: 0 20px 40px rgba(0,0,0,0.25);
    }
    .vapt-modal-header h2 { margin-top: 0; font-size: 18px; color: #1d2327; }
    .vapt-modal-body { margin: 15px 0 25px 0; font-size: 14px; color: #50575e; line-height: 1.5; }
    .vapt-modal-footer { display: flex; justify-content: flex-end; gap: 12px; }
</style>
<div id="vapt-notice-container"></div>
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
                                    <th scope="row"><?php esc_html_e( 'Domain Pattern', 'vapt-security' ); ?></th>
                                    <td>
                                        <input type="text" id="vapt-lock-domain" class="regular-text" placeholder="*.example.com" value="<?php echo esc_attr( $_SERVER['HTTP_HOST'] ); ?>" style="width: 100%;">
                                        <input type="hidden" id="vapt-build-id-tracking" value="">
                                        <p class="description" style="font-size: 11px; margin-top: 5px;"><?php esc_html_e( 'Use * for wildcards (e.g., *.example.com).', 'vapt-security' ); ?></p>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Domain Type', 'vapt-security' ); ?></th>
                                    <td>
                                        <select id="vapt-lock-type" style="width: 100%;">
                                            <option value="standard"><?php esc_html_e( 'Standard - Full Match', 'vapt-security' ); ?></option>
                                            <option value="wildcard"><?php esc_html_e( 'Wildcard - Contains Match', 'vapt-security' ); ?></option>
                                            <option value="universal"><?php esc_html_e( 'Universal - Any Domain', 'vapt-security' ); ?></option>
                                        </select>
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
                                            <option value="testing" <?php selected( $this->is_local_environment() ); ?>><?php esc_html_e( 'Testing (vaptsecure.local)', 'vapt-security' ); ?></option>
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
                                        <input type="text" id="vapt-wl-php-version" class="regular-text" placeholder="8.3" value="8.3" style="width: 100%;">
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>

                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid #eee; display: flex; gap: 10px; align-items: center;">
                        <button type="button" id="vapt-generate-locked-config" class="button button-primary" style="height: 40px; padding: 0 20px;"><?php esc_html_e( 'Generate Config File', 'vapt-security' ); ?></button>
                        <button type="button" id="vapt-generate-client-zip" class="button button-secondary" style="height: 40px; padding: 0 20px;">
                            <?php esc_html_e( 'Generate Client Build', 'vapt-security' ); ?>
                        </button>
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
                                        <th><?php esc_html_e( 'Type', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Plugin Name', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Version', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'License', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Date', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Expires', 'vapt-security' ); ?></th>
                                        <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                                    </tr>
                            </thead>
                            <tbody>
                                <?php 
                                $build_history = get_option( 'vapt_build_history', [] );
                                if ( empty( $build_history ) ) : ?>
                                    <tr class="no-builds">
                                        <td colspan="9" style="text-align: center; color: #999; padding: 30px;">
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
                                    ?>
                                        <tr class="<?php echo (isset($build['status']) && $build['status'] === 'suspended') ? 'vapt-row-suspended' : ''; ?>">
                                            <td><input type="checkbox" class="vapt-build-checkbox" value="<?php echo esc_attr( $build['id'] ); ?>"></td>
                                            <td><span class="vapt-build-id"><?php echo esc_html( $build['id'] ); ?></span></td>
                                            <td><?php echo esc_html( $build['domain'] ); ?></td>
                                            <td style="font-size: 11px; text-transform: capitalize; color: #666;"><?php echo esc_html( $build['domain_type'] ?? 'standard' ); ?></td>
                                            <td><?php echo esc_html( $build['name'] ); ?></td>
                                            <td><?php echo esc_html( $build['version'] ); ?></td>
                                            <td><span class="badge" style="background: #2271b1; color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 10px;"><?php echo esc_html( strtoupper($build['license']) ); ?></span></td>
                                            <td style="font-size: 11px; color: #666;"><?php echo esc_html( date_i18n( get_option( 'date_format' ), $build['time'] ) ); ?></td>
                                            <td style="font-size: 11px; color: #666;">
                                                <?php 
                                                    if ( empty($build['expires']) || $build['license'] === 'developer' ) {
                                                        echo esc_html__( 'Never', 'vapt-security' );
                                                    } else {
                                                        echo esc_html( date_i18n( get_option( 'date_format' ), $build['expires'] ) );
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
                                                    data-domain-type="<?php echo esc_attr($build['domain_type'] ?? 'standard'); ?>"
                                                    data-license-type="<?php echo esc_attr($build['license']); ?>"
                                                    data-name="<?php echo esc_attr($build['name']); ?>"
                                                    data-version="<?php echo esc_attr($build['version']); ?>"
                                                    data-author="<?php echo esc_attr($build['white_label']['author'] ?? ''); ?>"
                                                    data-company="<?php echo esc_attr($build['white_label']['company'] ?? ''); ?>"
                                                    data-desc="<?php echo esc_attr($build['white_label']['description'] ?? ''); ?>"
                                                    data-wp="<?php echo esc_attr($build['white_label']['requires_at_least'] ?? '5.6'); ?>"
                                                    data-php="<?php echo esc_attr($build['white_label']['requires_php'] ?? '8.3'); ?>"
                                                    data-tracking-mode="<?php echo esc_attr($build['tracking_mode'] ?? 'production'); ?>"
                                                    data-custom-url="<?php echo esc_attr($build['integrity_url'] ?? ''); ?>"
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
                                    <?php endforeach;
                                endif; ?>
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
                
                <table class="vapt-history-table" style="margin-top: 20px;">
                    <thead>
                        <tr>
                            <th><?php esc_html_e( 'Build ID', 'vapt-security' ); ?></th>
                            <th><?php esc_html_e( 'Domain / IP', 'vapt-security' ); ?></th>
                            <th><?php esc_html_e( 'Status', 'vapt-security' ); ?></th>
                            <th><?php esc_html_e( 'Install / Activation', 'vapt-security' ); ?></th>
                            <th><?php esc_html_e( 'Last Seen', 'vapt-security' ); ?></th>
                            <th><?php esc_html_e( 'License / Version', 'vapt-security' ); ?></th>
                            <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php 
                        $tracking = get_option( 'vapt_build_tracking', [] );
                        if ( empty( $tracking ) ) : ?>
                            <tr><td colspan="7" style="text-align:center; padding: 40px; color: #999;"><?php esc_html_e( 'No active tracking data received yet.', 'vapt-security' ); ?></td></tr>
                        <?php else : 
                            foreach ( array_reverse($tracking) as $bid => $t ) : 
                                $is_online = (time() - $t['last_seen'] < 24 * HOUR_IN_SECONDS);
                                $install_date = !empty($t['initial_install']) ? date_i18n( get_option( 'date_format' ), $t['initial_install'] ) : 'N/A';
                                $activation_date = date_i18n( get_option( 'date_format' ), $t['first_activation'] );
                                $expiry_date = !empty($t['license']['expiry']) ? date_i18n( get_option( 'date_format' ), $t['license']['expiry'] ) : 'Never';
                        ?>
                            <tr>
                                <td><span class="vapt-build-id"><?php echo esc_html($bid); ?></span></td>
                                <td>
                                    <strong><?php echo esc_html($t['domain']); ?></strong><br>
                                    <small style="color: #666;"><?php echo esc_html($t['ip']); ?></small>
                                </td>
                                <td>
                                    <span class="vapt-feature-status" style="background: <?php echo $is_online ? '#edfaef' : '#fcf0f1'; ?>; color: <?php echo $is_online ? '#008a20' : '#d63638'; ?>;">
                                        <?php echo $is_online ? 'ONLINE' : 'OFFLINE'; ?>
                                    </span>
                                </td>
                                <td style="font-size: 11px;">
                                    I: <?php echo $install_date; ?><br>
                                    A: <?php echo $activation_date; ?>
                                </td>
                                <td style="font-size: 11px;">
                                    <?php echo human_time_diff( $t['last_seen'], time() ); ?> ago
                                </td>
                                <td>
                                    <span class="badge" style="background: #2271b1; color:#fff; padding: 2px 8px; border-radius:10px; font-size:10px;">
                                        <?php echo esc_html(strtoupper($t['license']['type'])); ?>
                                    </span>
                                    <small style="color:#666; margin-left: 5px;">v<?php echo esc_html($t['version']); ?></small>
                                    <div style="font-size: 10px; color: <?php echo ($t['license']['status'] === 'active') ? '#008a20' : '#d63638'; ?>; margin-top: 4px;">
                                        E: <?php echo $expiry_date; ?>
                                    </div>
                                </td>
                                <td>
                                    <button type="button" class="button button-small vapt-manage-build" 
                                        data-id="<?php echo esc_attr($bid); ?>" 
                                        data-domain="<?php echo esc_attr($t['domain']); ?>"
                                        data-expiry="<?php echo esc_attr($t['license']['expiry']); ?>"
                                        data-type="<?php echo esc_attr($t['license']['type']); ?>"
                                        title="<?php esc_attr_e( 'Manage Deployment', 'vapt-security' ); ?>">
                                        <span class="dashicons dashicons-admin-settings" style="font-size: 16px; margin-top: 3px;"></span>
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Remote Management Modal -->
        <div id="vapt-manage-modal" class="vapt-modal-overlay" style="display:none;">
            <div class="vapt-modal">
                <div class="vapt-modal-header">
                    <h2><?php esc_html_e( 'Manage Remote Build', 'vapt-security' ); ?></h2>
                    <p style="margin-top: -10px; font-size: 12px; color: #666;"><span id="vapt-manage-build-id"></span> on <span id="vapt-manage-domain"></span></p>
                </div>
                <div class="vapt-modal-body">
                    <div style="margin-bottom: 20px; padding: 15px; background: #f8f9fa; border-radius: 6px; border: 1px solid #eee;">
                        <h4 style="margin: 0 0 10px 0; font-size: 13px;"><?php esc_html_e( 'Extend License Term', 'vapt-security' ); ?></h4>
                        <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="term"><?php esc_html_e( 'Add Full Term', 'vapt-security' ); ?></button>
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="30"><?php esc_html_e( '+30 Days', 'vapt-security' ); ?></button>
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="90"><?php esc_html_e( '+90 Days', 'vapt-security' ); ?></button>
                        </div>
                        <div style="margin-top: 12px; display: flex; gap: 10px; align-items: center;">
                            <input type="date" id="vapt-custom-expiry" class="regular-text" style="width: 150px;" min="<?php echo esc_attr( date_i18n( 'Y-m-d' ) ); ?>">
                            <button type="button" class="button vapt-push-action" data-action="EXTEND" data-val="" id="vapt-apply-custom-term"><?php esc_html_e( 'Apply Custom Term', 'vapt-security' ); ?></button>
                        </div>
                        <p class="description"><?php esc_html_e( 'Adds time to current expiry. Client receives an email confirmation.', 'vapt-security' ); ?></p>
                    </div>

                    <div style="padding: 15px; background: #fff5f5; border-radius: 6px; border: 1px solid #fecaca;">
                        <h4 style="margin: 0 0 10px 0; font-size: 13px; color: #b91c1c;"><?php esc_html_e( 'Danger Zone', 'vapt-security' ); ?></h4>
                        <button type="button" class="button button-link-delete vapt-push-action" data-action="SUSPEND" style="color: #d63638;"><?php esc_html_e( 'Suspend Remote Build', 'vapt-security' ); ?></button>
                        <p class="description"><?php esc_html_e( 'Immediately deactivates the plugin on the client site.', 'vapt-security' ); ?></p>
                    </div>
                </div>
                <div class="vapt-modal-footer">
                    <button type="button" class="button" id="vapt-close-manage"><?php esc_html_e( 'Close', 'vapt-security' ); ?></button>
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
        confirm: function(title, text, onConfirm) {
            const overlay = $(`
                <div class="vapt-modal-overlay">
                    <div class="vapt-modal">
                        <div class="vapt-modal-header"><h2>${title}</h2></div>
                        <div class="vapt-modal-body">${text}</div>
                        <div class="vapt-modal-footer">
                            <button class="button vapt-cancel">Cancel</button>
                            <button class="button button-primary vapt-confirm">Confirm</button>
                        </div>
                    </div>
                </div>
            `);
            $('body').append(overlay);
            overlay.find('.vapt-cancel').click(() => overlay.remove());
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

    // Domain Type logic
    $('#vapt-lock-type').change(function(){
        var type = $(this).val();
        if (type === 'universal') {
            $('#vapt-lock-domain').val('*').prop('disabled', true).css('background', '#f0f0f1');
        } else {
            $('#vapt-lock-domain').prop('disabled', false).css('background', '#fff');
            if ($('#vapt-lock-domain').val() === '*') {
                $('#vapt-lock-domain').val('<?php echo esc_attr( $_SERVER['HTTP_HOST'] ); ?>');
            }
        }
    });

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

    $('#vapt-lock-domain').on('change blur', function() {
        var domain = $(this).val();
        if (!domain || domain === '*') return;
        
        $.post(ajaxurl, {
            action: 'vapt_get_last_build_version',
            domain: domain,
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
            domain: $('#vapt-lock-domain').val(),
            domain_type: $('#vapt-lock-type').val(),
            license_type: $('#vapt-lock-license-type').val(),
            auto_renew: $('#vapt-lock-license-auto-renew').is(':checked') ? 1 : 0,
            include_settings: $('#vapt-lock-include-settings').is(':checked') ? 1 : 0,
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
        });
    });

    $('#vapt-generate-client-zip').click(function(){
        var btn = $(this);
        var originalText = btn.text();
        btn.prop('disabled', true).text('<?php esc_html_e( 'Generating Build...', 'vapt-security' ); ?>');
        
        $.post(ajaxurl, {
            action: 'vapt_generate_client_zip',
            edit_id: $('#vapt-build-id-tracking').val(),
            domain: $('#vapt-lock-domain').val(),
            domain_type: $('#vapt-lock-type').val(),
            license_type: $('#vapt-lock-license-type').val(),
            auto_renew: $('#vapt-lock-license-auto-renew').is(':checked') ? 1 : 0,
            include_settings: $('#vapt-lock-include-settings').is(':checked') ? 1 : 0,
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
        });
    });
    // Edit/Reuse Build Settings
    $(document).on('click', '.vapt-edit-build', function(){
        var btn = $(this);
        $('#vapt-build-id-tracking').val(btn.data('id')); // Track ID for update
        $('#vapt-lock-domain').val(btn.data('domain')).trigger('change');
        $('#vapt-lock-type').val(btn.data('domain-type')).trigger('change');
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
        
        $('#vapt-manage-build-id').text(bid);
        $('#vapt-manage-domain').text(domain);
        $('.vapt-push-action').data('id', bid);
        
        $('#vapt-manage-modal').fadeIn(200);
    });

    $('#vapt-close-manage').click(function() {
        $('#vapt-manage-modal').fadeOut(200);
    });

    $('#vapt-apply-custom-term').click(function() {
        var btn = $(this);
        var bid = btn.data('id');
        var customDate = $('#vapt-custom-expiry').val();
        
        if ( ! customDate ) {
            vaptNotify.error('Error', 'Please select a date first.');
            return;
        }
        
        var confirmMsg = 'Are you sure you want to set a custom expiry date of ' + customDate + '?';
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
});
</script>
