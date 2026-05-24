<?php
/**
 * Settings page markup with modern horizontal tabs.
 *
 * @package VAPT_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Check for Superadmin
$current_user = wp_get_current_user();
$is_superadmin = ( $current_user->user_login === 'tanmalik786' && $current_user->user_email === 'tanmalik786@gmail.com' );
$is_verified_super = $is_superadmin ? get_transient( 'vapt_auth_' . $current_user->ID ) : false;
?>
<style>
    .vapt-settings-wrap {
        max-width: 100% !important;
        margin-right: 20px !important;
    }
    #vapt-security-tabs.ui-tabs {
        width: 100% !important;
    }
    .vapt-security-tab-content {
        width: 100% !important;
        box-sizing: border-box !important;
    }
    /* Subtabs styling to be full width */
    .vapt-subtabs-nav {
        width: 100% !important;
        border-bottom: none !important;
        gap: 15px;
        margin-bottom: 25px !important;
    }
    .vapt-subtabs-nav li {
        flex: 1 !important;
        text-align: center !important;
        margin: 0 !important;
        padding: 0 !important;
    }
    .vapt-subtabs-nav li a {
        display: block !important;
        width: 100% !important;
        padding: 12px 20px !important;
        text-decoration: none !important;
        font-weight: 600 !important;
        border: 1px solid #ccd0d4 !important;
        border-radius: 6px !important;
        background: #f6f7f7 !important;
        transition: all 0.2s ease-in-out !important;
        box-sizing: border-box !important;
    }
    .vapt-subtabs-nav li a:hover {
        background: #fff !important;
        border-color: #2271b1 !important;
    }
    /* Active states with colors matching risk levels */
    .vapt-subtabs-nav li.ui-tabs-active a {
        background: #fff !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1) !important;
        border-width: 2px !important;
    }
    .vapt-subtabs-nav li.ui-tabs-active a[href="#hardening-high"] { border-color: #d63638 !important; }
    .vapt-subtabs-nav li.ui-tabs-active a[href="#hardening-medium"] { border-color: #dba617 !important; }
    .vapt-subtabs-nav li.ui-tabs-active a[href="#hardening-low"] { border-color: #2271b1 !important; }
</style>
<div class="wrap vapt-settings-wrap">
    <h1><?php echo esc_html( $this->get_plugin_name() ) . ' ' . esc_html__( 'Settings', 'vapt-security' ); ?></h1>

    <form method="post" action="options.php">
        <?php
        // Output security fields.
        settings_fields( 'vapt_security_options_group' );

        // Count enabled tabs
        $tab_count = 2; // General + Stats
        if ( VAPT_Features::is_enabled( 'rate_limiting' ) && defined( 'VAPT_FEATURE_RATE_LIMITING' ) && VAPT_FEATURE_RATE_LIMITING ) $tab_count++;
        if ( VAPT_Features::is_enabled( 'input_validation' ) && defined( 'VAPT_FEATURE_INPUT_VALIDATION' ) && VAPT_FEATURE_INPUT_VALIDATION ) $tab_count++;
        if ( VAPT_Features::is_enabled( 'cron_protection' ) && defined( 'VAPT_FEATURE_WP_CRON_PROTECTION' ) && VAPT_FEATURE_WP_CRON_PROTECTION ) $tab_count++;
        if ( VAPT_Features::is_enabled( 'security_logging' ) && defined( 'VAPT_FEATURE_SECURITY_LOGGING' ) && VAPT_FEATURE_SECURITY_LOGGING ) $tab_count++;
        
        $vertical_tabs = ( $tab_count > 5 );
        $container_class = $vertical_tabs ? 'vapt-vertical-tabs' : '';
        ?>

        <?php if ( $vertical_tabs ) : ?>
        <style>
            .vapt-vertical-tabs {
                display: flex;
                border: 1px solid #c3c4c7;
                background: #fff;
            }
            .vapt-vertical-tabs .ui-tabs-nav {
                display: block;
                float: none;
                width: 200px;
                padding: 0;
                margin: 0;
                background: #f0f0f1;
                border-right: 1px solid #c3c4c7;
            }
            .vapt-vertical-tabs .ui-tabs-nav li {
                float: none;
                margin: 0;
                border: none;
                border-bottom: 1px solid #c3c4c7;
                background: #f0f0f1;
                white-space: normal;
            }
            .vapt-vertical-tabs .ui-tabs-nav li a {
                 display: block;
                 padding: 10px 15px;
                 font-weight: 600;
                 color: #2271b1 !important;
                 text-decoration: none;
            }
            .vapt-vertical-tabs .ui-tabs-nav li.ui-tabs-active {
                background: #fff;
                border-bottom: 1px solid #c3c4c7; 
                margin-right: -1px;
                border-right: 1px solid #fff;
            }
            .vapt-vertical-tabs .ui-tabs-nav li.ui-tabs-active a {
                color: #1d2327 !important;
            }
            .vapt-security-tab-content {
                flex-grow: 1;
                padding: 20px;
                border: none;
                background: #fff;
            }
            /* Hide default jQuery UI borders if we handle them */
            .vapt-vertical-tabs.ui-tabs {
                padding: 0;
            }
        </style>
        <?php endif; ?>

        <!-- Modern Horizontal/Vertical Tabs -->
        <div id="vapt-security-tabs" class="<?php echo esc_attr( $container_class ); ?>">
            <!-- Tab Navigation -->
            <ul class="vapt-security-tabs">
                <li class="vapt-security-tab"><a href="#tab-general"><?php esc_html_e( 'General', 'vapt-security' ); ?></a></li>
                <?php if ( VAPT_Features::is_enabled( 'rate_limiting' ) && defined( 'VAPT_FEATURE_RATE_LIMITING' ) && VAPT_FEATURE_RATE_LIMITING ) : ?>
                <li class="vapt-security-tab"><a href="#tab-rate-limiter"><?php esc_html_e( 'Rate Limiter', 'vapt-security' ); ?></a></li>
                <?php endif; ?>
                <?php if ( VAPT_Features::is_enabled( 'input_validation' ) && defined( 'VAPT_FEATURE_INPUT_VALIDATION' ) && VAPT_FEATURE_INPUT_VALIDATION ) : ?>
                <li class="vapt-security-tab"><a href="#tab-validation"><?php esc_html_e( 'Input Validation', 'vapt-security' ); ?></a></li>
                <?php endif; ?>
                <?php if ( VAPT_Features::is_enabled( 'cron_protection' ) && defined( 'VAPT_FEATURE_WP_CRON_PROTECTION' ) && VAPT_FEATURE_WP_CRON_PROTECTION ) : ?>
                <li class="vapt-security-tab"><a href="#tab-cron"><?php esc_html_e( 'WP‑Cron Protection', 'vapt-security' ); ?></a></li>
                <?php endif; ?>
                <?php if ( VAPT_Features::is_enabled( 'security_logging' ) && defined( 'VAPT_FEATURE_SECURITY_LOGGING' ) && VAPT_FEATURE_SECURITY_LOGGING ) : ?>
                <li class="vapt-security-tab"><a href="#tab-logging"><?php esc_html_e( 'Security Logging', 'vapt-security' ); ?></a></li>
                <?php endif; ?>
                <li class="vapt-security-tab"><a href="#tab-hardening"><?php esc_html_e( 'Hardening', 'vapt-security' ); ?></a></li>
                <li class="vapt-security-tab"><a href="#tab-stats"><?php esc_html_e( 'Statistics', 'vapt-security' ); ?></a></li>

            </ul>

            <!-- Tab Content -->
            <div id="tab-general" class="vapt-security-tab-content">
                <div class="settings-section">
                    <?php do_settings_sections( 'vapt_security_general' ); ?>
                </div>
            </div>

            <?php if ( VAPT_Features::is_enabled( 'rate_limiting' ) && defined( 'VAPT_FEATURE_RATE_LIMITING' ) && VAPT_FEATURE_RATE_LIMITING ) : ?>
            <div id="tab-rate-limiter" class="vapt-security-tab-content">
                <div class="settings-section">
                    <?php do_settings_sections( 'vapt_security_rate_limiter' ); ?>
                </div>
            </div>
            <?php endif; ?>

            <?php if ( VAPT_Features::is_enabled( 'input_validation' ) && defined( 'VAPT_FEATURE_INPUT_VALIDATION' ) && VAPT_FEATURE_INPUT_VALIDATION ) : ?>
            <div id="tab-validation" class="vapt-security-tab-content">
                <div class="settings-section">
                    <?php do_settings_sections( 'vapt_security_validation' ); ?>
                </div>
            </div>
            <?php endif; ?>

            <?php if ( VAPT_Features::is_enabled( 'cron_protection' ) && defined( 'VAPT_FEATURE_WP_CRON_PROTECTION' ) && VAPT_FEATURE_WP_CRON_PROTECTION ) : ?>
            <div id="tab-cron" class="vapt-security-tab-content">
                <div class="settings-section">
                    <?php do_settings_sections( 'vapt_security_cron' ); ?>
                </div>
            </div>
            <?php endif; ?>

            <?php if ( VAPT_Features::is_enabled( 'security_logging' ) && defined( 'VAPT_FEATURE_SECURITY_LOGGING' ) && VAPT_FEATURE_SECURITY_LOGGING ) : ?>
            <div id="tab-logging" class="vapt-security-tab-content">
                <div class="settings-section">
                    <?php do_settings_sections( 'vapt_security_logging' ); ?>
                    
                    <?php
                    // Display log statistics
                    $logger = new VAPT_Security_Logger();
                    $stats = $logger->get_statistics();
                    ?>
                    <h3><?php esc_html_e( 'Logging Statistics', 'vapt-security' ); ?></h3>
                    <table class="statistics-table">
                        <tr>
                            <td><?php esc_html_e( 'Total Events Logged:', 'vapt-security' ); ?></td>
                            <td><?php echo esc_html( $stats['total_events'] ); ?></td>
                        </tr>
                        <tr>
                            <td><?php esc_html_e( 'Events in Last 24 Hours:', 'vapt-security' ); ?></td>
                            <td><?php echo esc_html( $stats['last_24_hours'] ); ?></td>
                        </tr>
                    </table>

                    <?php if ( ! empty( $stats['event_types'] ) ) : ?>
                    <h4><?php esc_html_e( 'Event Types', 'vapt-security' ); ?></h4>
                    <table class="statistics-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'Event Type', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Count', 'vapt-security' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $stats['event_types'] as $type => $count ) : ?>
                            <tr>
                                <td><?php echo esc_html( $type ); ?></td>
                                <td><?php echo esc_html( $count ); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>

                    <?php if ( ! empty( $stats['top_ips'] ) ) : ?>
                    <h4><?php esc_html_e( 'Top IPs', 'vapt-security' ); ?></h4>
                    <table class="statistics-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'IP Address', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Event Count', 'vapt-security' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $stats['top_ips'] as $ip => $count ) : ?>
                            <tr>
                                <td><?php echo esc_html( $ip ); ?></td>
                                <td><?php echo esc_html( $count ); ?></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <div id="tab-hardening" class="vapt-security-tab-content">
                <div class="settings-section">
                    <!-- Horizontal Sub-Tabs for Hardening as Buttons -->
                    <div id="vapt-hardening-subtabs" style="margin-bottom: 30px; width: 100%;">
                        <ul class="vapt-subtabs-nav" style="display: flex; list-style: none; padding: 0; margin: 0 0 20px 0; width: 100%;">
                            <li><a href="#hardening-high" style="color: #d63638;"><?php esc_html_e( 'High Risk Mitigations', 'vapt-security' ); ?></a></li>
                            <li><a href="#hardening-medium" style="color: #dba617;"><?php esc_html_e( 'Medium Risk Mitigations', 'vapt-security' ); ?></a></li>
                            <li><a href="#hardening-low" style="color: #2271b1;"><?php esc_html_e( 'Low Risk Mitigations', 'vapt-security' ); ?></a></li>
                        </ul>
                        
                        <div id="hardening-high">
                            <?php do_settings_sections( 'vapt_security_hardening_high' ); ?>
                        </div>
                        <div id="hardening-medium">
                            <?php do_settings_sections( 'vapt_security_hardening_medium' ); ?>
                        </div>
                        <div id="hardening-low">
                            <?php do_settings_sections( 'vapt_security_hardening_low' ); ?>
                        </div>
                    </div>

                    <style>
                        /* Reset jQuery UI default tab styling for subtabs */
                        #vapt-hardening-subtabs.ui-tabs {
                            border: none !important;
                            padding: 0 !important;
                            background: transparent !important;
                        }
                        #vapt-hardening-subtabs .ui-tabs-panel {
                            padding: 0 !important;
                        }
                    </style>
                    <script>
                        jQuery(document).ready(function($) {
                            if ($('#vapt-hardening-subtabs').length) {
                                $('#vapt-hardening-subtabs').tabs();
                            }
                        });
                    </script>
                    
                    <h3><?php esc_html_e( 'Server-Level Hardening (.htaccess)', 'vapt-security' ); ?></h3>
                    <p class="description"><?php esc_html_e( 'The following rules are automatically managed in your .htaccess file when features are toggled.', 'vapt-security' ); ?></p>
                    
                    <div class="vapt-htaccess-preview" style="background: #f0f0f1; padding: 15px; border: 1px solid #c3c4c7; font-family: monospace; white-space: pre-wrap; margin: 10px 0;">
<?php
$rules = [
    '# BEGIN VAPT Security Hardening',
    'Options -Indexes',
    '<Files xmlrpc.php> ... </Files>',
    '<Files "debug.log"> ... </Files>',
    '<Files "readme.html"> ... </Files>',
    '# END VAPT Security Hardening'
];
echo esc_html( implode( "\n", $rules ) );
?>
                    </div>
                    
                    <h3><?php esc_html_e( 'Nginx Configuration', 'vapt-security' ); ?></h3>
                    <p class="description"><?php esc_html_e( 'If you are using Nginx, add these rules to your server block:', 'vapt-security' ); ?></p>
                    <textarea readonly rows="10" cols="50" class="large-text" style="font-family: monospace;">
# Block XML-RPC
location = /xmlrpc.php {
    deny all;
    access_log off;
    log_not_found off;
}

# Block sensitive files
location ~* /(?:readme\.html|debug\.log) {
    deny all;
}

# Prevent directory listing
location / {
    autoindex off;
}

# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
</textarea>
                </div>
            </div>

            <div id="tab-stats" class="vapt-security-tab-content">
                <div class="settings-section">
                    <?php
                    // Display rate limiting statistics
                    $limiter = new VAPT_Rate_Limiter();
                    $limiter_stats = $limiter->get_stats();
                    ?>
                    <h3><?php esc_html_e( 'Rate Limiting Statistics', 'vapt-security' ); ?></h3>
                    
                    <h4><?php esc_html_e( 'Regular Request Statistics', 'vapt-security' ); ?></h4>
                    <table class="statistics-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'IP Address', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Request Count', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $limiter_stats['regular_requests'] as $ip => $requests ) : ?>
                            <tr>
                                <td><?php echo esc_html( $ip ); ?></td>
                                <td><?php echo esc_html( count( $requests ) ); ?></td>
                                <td>
                                    <button type="button" class="button vapt-reset-ip" data-ip="<?php echo esc_attr( $ip ); ?>">
                                        <?php esc_html_e( 'Reset Data', 'vapt-security' ); ?>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>

                    <h4><?php esc_html_e( 'Cron Request Statistics', 'vapt-security' ); ?></h4>
                    <table class="statistics-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'IP Address', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Request Count', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $limiter_stats['cron_requests'] as $ip => $requests ) : ?>
                            <tr>
                                <td><?php echo esc_html( $ip ); ?></td>
                                <td><?php echo esc_html( count( $requests ) ); ?></td>
                                <td>
                                    <button type="button" class="button vapt-reset-ip" data-ip="<?php echo esc_attr( $ip ); ?>">
                                        <?php esc_html_e( 'Reset Data', 'vapt-security' ); ?>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>

                    <h4><?php esc_html_e( 'Login Request Statistics', 'vapt-security' ); ?></h4>
                    <table class="statistics-table">
                        <thead>
                            <tr>
                                <th><?php esc_html_e( 'IP Address', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Failed Attempts', 'vapt-security' ); ?></th>
                                <th><?php esc_html_e( 'Actions', 'vapt-security' ); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ( $limiter_stats['login_requests'] as $ip => $requests ) : ?>
                            <tr>
                                <td><?php echo esc_html( $ip ); ?></td>
                                <td><?php echo esc_html( count( $requests ) ); ?></td>
                                <td>
                                    <button type="button" class="button vapt-reset-ip" data-ip="<?php echo esc_attr( $ip ); ?>">
                                        <?php esc_html_e( 'Reset Data', 'vapt-security' ); ?>
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>

                    <script>
                    jQuery(document).ready(function($) {
                        $('.vapt-reset-ip').on('click', function() {
                            var ip = $(this).data('ip');
                            var confirmReset = confirm('<?php esc_html_e( 'Are you sure you want to reset data for IP:', 'vapt-security' ); ?> ' + ip);
                            
                            if (confirmReset) {
                                // In a real implementation, this would make an AJAX call to reset the IP data
                                alert('<?php esc_html_e( 'In a full implementation, this would reset data for IP: ', 'vapt-security' ); ?>' + ip);
                            }
                        });
                    });
                    </script>
                </div>
            </div>


        </div>

        <?php submit_button(); ?>
    </form>
</div>

<script>
jQuery( function( $ ) {
    $( '#vapt-security-tabs' ).tabs({
        active: 0,
        activate: function( event, ui ) {
            // Store the active tab in localStorage
            localStorage.setItem( 'vapt_security_active_tab', ui.newTab.index() );
        },
        create: function( event, ui ) {
            // Restore the active tab from localStorage
            var activeTab = localStorage.getItem( 'vapt_security_active_tab' );
            if ( activeTab !== null ) {
                $( this ).tabs( 'option', 'active', parseInt( activeTab ) );
            }
        }
    });
} );
</script>